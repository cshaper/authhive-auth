using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Base;
using AuthHive.Core.Entities.Business.Platform;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Core;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Repositories.Business.Platform;
using AuthHive.Core.Models.Auth.Authorization.Responses;
using AuthHive.Core.Models.Auth.Permissions.Common;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Events;
using AuthHive.Core.Models.Auth.ConnectedId.Common;
using AuthHive.Core.Models.Audit.Common;
using AuthHive.Core.Models.Common;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Infra.Security;
using AuthHive.Core.Models.Infra.Security.Common;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Models.External;
using AuthHive.Core.Constants.Common;
using System.Text.Json;

namespace AuthHive.Services.Auth.Validators
{
    /// <summary>
    /// Permission Validator - AuthHive v15
    /// 
    /// 이벤트 사용 가이드라인 적용:
    /// ✅ 이벤트 필요: 보안 위반, 플랜 제한, 비동기 처리(이메일)
    /// ❌ 이벤트 불필요: 일반 검증, 형식 오류, 내부 체크
    /// </summary>
    public class PermissionValidator : IPermissionValidator
    {
        private readonly ILogger<PermissionValidator> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPermissionRepository _permissionRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IRolePermissionRepository _rolePermissionRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationMembershipRepository _organizationMembershipRepository;
        private readonly IPlanSubscriptionRepository _planSubscriptionRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEmailService _emailService;

        // Cache configuration
        private const string CACHE_KEY_PREFIX = "perm:";
        private const int CACHE_DURATION_MINUTES = 15;
        private static readonly Regex ScopePattern = new Regex(@"^[a-zA-Z0-9_]+:[a-zA-Z0-9_*]+(?::[a-zA-Z0-9_*]+)?(?::[a-zA-Z0-9_*]+)?$");

        public PermissionValidator(
            ILogger<PermissionValidator> logger,
            ICacheService cacheService,
            IAuditService auditService,
            IEventBus eventBus,
            IUnitOfWork unitOfWork,
            IPermissionRepository permissionRepository,
            IRolePermissionRepository rolePermissionRepository,
            IRoleRepository roleRepository,
            IOrganizationRepository organizationRepository,
            IOrganizationMembershipRepository organizationMembershipRepository,
            IPlanSubscriptionRepository planSubscriptionRepository,
            IConnectedIdRepository connectedIdRepository,
            IDateTimeProvider dateTimeProvider,
            IEmailService emailService)
        {
            _logger = logger;
            _cacheService = cacheService;
            _auditService = auditService;
            _eventBus = eventBus;
            _unitOfWork = unitOfWork;
            _permissionRepository = permissionRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _roleRepository = roleRepository;
            _organizationRepository = organizationRepository;
            _organizationMembershipRepository = organizationMembershipRepository;
            _planSubscriptionRepository = planSubscriptionRepository;
            _connectedIdRepository = connectedIdRepository;
            _dateTimeProvider = dateTimeProvider;
            _emailService = emailService;
        }
        #region IPermissionValidator Implementation

        /// <summary>
        /// Validates permission creation request
        /// </summary>
        public async Task<ServiceResult> ValidateCreateAsync(
            CreatePermissionRequest request,
            ConnectedIdContext context,
            bool useCache = true)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                _logger.LogInformation(
                    "Validating permission creation for scope: {Scope} by ConnectedId: {ConnectedId}",
                    request.Scope, context.ConnectedId);

                // ========== 시스템 관리자 권한 확인 ==========
                var isSystemAdmin = context.OrganizationId == CommonConstants.System.AUTHHIVE_ORGANIZATION_ID;

                if (!isSystemAdmin)
                {
                    _logger.LogWarning(
                        "Non-admin attempted permission creation. ConnectedId: {ConnectedId}",
                        context.ConnectedId);

                    // 🔴 보안 이벤트 필요: 무단 시스템 권한 접근은 보안 이슈
                    await _eventBus.PublishAsync(new SystemPermissionModificationAttemptedEvent
                    {
                        AttemptedBy = context.ConnectedId,
                        PermissionId = Guid.Empty,
                        PermissionScope = request.Scope,
                        Action = "Create",
                        IsAuthorized = false,
                        OrganizationId = context.OrganizationId
                    });

                    // 감사 로그
                    await _auditService.LogActionAsync(
                        context.ConnectedId,
                        "PermissionCreationDenied",
                        AuditActionType.PermissionValidated,
                        "Permission",
                        request.Scope,
                        false,
                        JsonSerializer.Serialize(new
                        {
                            Scope = request.Scope,
                            OrganizationId = context.OrganizationId,
                            Reason = "System admin required"
                        }));

                    await _unitOfWork.RollbackTransactionAsync();

                    return ServiceResult.Failure(
                        PermissionConstants.ValidationMessages.SYSTEM_ADMIN_REQUIRED,
                        PermissionConstants.ErrorCodes.InsufficientPermission);
                }

                // ========== 1. 스코프 형식 검증 ==========
                var scopeValidation = await ValidateScopeFormatAsync(request.Scope, context, useCache);
                if (!scopeValidation.IsSuccess)
                {
                    _logger.LogWarning("Invalid scope format: {Scope}", request.Scope);

                    // ❌ 이벤트 불필요: 단순 형식 오류는 로그만
                    await _unitOfWork.RollbackTransactionAsync();
                    return scopeValidation;
                }

                // ========== 2. 중복 스코프 확인 ==========
                var existingPermission = await _permissionRepository.GetByScopeAsync(request.Scope);
                if (existingPermission != null)
                {
                    _logger.LogWarning("Duplicate permission scope attempted: {Scope}", request.Scope);

                    // ❌ 이벤트 불필요: 일반적인 검증 실패는 로그만
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        string.Format(PermissionConstants.ValidationMessages.DUPLICATE_SCOPE, request.Scope),
                        PermissionConstants.ErrorCodes.DuplicateScope);
                }

                // ========== 3. 부모 권한 검증 (계층 구조) ==========
                if (request.ParentPermissionId.HasValue)
                {
                    var parentValidation = await ValidateParentPermissionAsync(
                        request.ParentPermissionId.Value,
                        context.OrganizationId);

                    if (!parentValidation.IsSuccess)
                    {
                        // ❌ 이벤트 불필요: 내부 검증 단계
                        await _unitOfWork.RollbackTransactionAsync();
                        return parentValidation;
                    }
                }

                // ========== 4. 플랜별 스코프 깊이 제한 확인 (PricingConstants) ==========
                var scopeParts = request.Scope.Split(':');
                var subscription = await _planSubscriptionRepository
                    .GetActiveByOrganizationIdAsync(context.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var maxDepth = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey];

                if (maxDepth > 0 && scopeParts.Length > maxDepth)
                {
                    // 🔴 비즈니스 이벤트 필요: 플랜 제한 도달 = 영업 기회
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = context.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "PermissionScopeDepth",
                        CurrentValue = scopeParts.Length,
                        MaxValue = maxDepth
                    });

                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Failure(
                        $"Scope depth ({scopeParts.Length}) exceeds {planKey} plan limit ({maxDepth})",
                        PermissionConstants.ErrorCodes.InvalidScope);
                }

                // ========== ✅ 모든 검증 통과 - 성공 처리 ==========

                // 시스템 권한인 경우에만 이벤트
                if (request.IsSystemPermission)
                {
                    // 🔴 시스템 권한 생성은 중요 이벤트
                    await _eventBus.PublishAsync(new SystemPermissionModificationAttemptedEvent
                    {
                        AttemptedBy = context.ConnectedId,
                        PermissionId = Guid.Empty,
                        PermissionScope = request.Scope,
                        Action = "Create",
                        IsAuthorized = true,
                        OrganizationId = context.OrganizationId
                    });
                }

                // 감사 로그: 모든 성공은 감사 로그에 기록
                await _auditService.LogActionAsync(
                    context.ConnectedId,
                    "ValidatePermissionCreate",
                    AuditActionType.PermissionValidated,
                    "Permission",
                    request.Scope,
                    true,
                    JsonSerializer.Serialize(new
                    {
                        Scope = request.Scope,
                        OrganizationId = context.OrganizationId,
                        IsSystemPermission = request.IsSystemPermission,
                        ParentPermissionId = request.ParentPermissionId
                    }));

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation(
                    "Permission creation validation successful for scope: {Scope}",
                    request.Scope);

                return ServiceResult.Success(PermissionConstants.ValidationMessages.VALIDATION_SUCCESS);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();

                _logger.LogError(ex,
                    "Error validating permission creation for scope: {Scope}",
                    request.Scope);

                // 시스템 관리자 조직의 에러는 크리티컬
                if (context.OrganizationId == CommonConstants.System.AUTHHIVE_ORGANIZATION_ID)
                {
                    // 🔴 비동기 처리 필요: 이메일 알림
                    await SendCriticalErrorAlertAsync(context, ex, "PermissionCreateValidation");
                }

                return ServiceResult.Failure(
                    PermissionConstants.ValidationMessages.PERMISSION_NOT_FOUND,
                    PermissionConstants.ErrorCodes.InvalidScope);
            }
        }
        /// <summary>
        /// Validates permission update request
        /// </summary>
        public async Task<ServiceResult> ValidateUpdateAsync(
            Permission permission,
            Permission updatedPermission,
            ConnectedIdContext context)
        {
            await _unitOfWork.BeginTransactionAsync();

            try
            {
                _logger.LogInformation(
                    "Validating permission update for ID: {PermissionId} by ConnectedId: {ConnectedId}",
                    permission.Id, context.ConnectedId);

                // ========== 시스템 권한 수정 권한 확인 ==========
                if (permission.IsSystemPermission)
                {
                    var isSystemAdmin = context.OrganizationId == CommonConstants.System.AUTHHIVE_ORGANIZATION_ID;

                    if (!isSystemAdmin)
                    {
                        // 🔴 보안 이벤트 필요: 무단 시스템 권한 수정 시도
                        await _eventBus.PublishAsync(new SystemPermissionModificationAttemptedEvent
                        {
                            AttemptedBy = context.ConnectedId,
                            PermissionId = permission.Id,
                            PermissionScope = permission.Scope,
                            Action = "Update",
                            IsAuthorized = false,
                            OrganizationId = context.OrganizationId
                        });

                        await _auditService.LogActionAsync(
                            context.ConnectedId,
                            "SystemPermissionUpdateDenied",
                            AuditActionType.PermissionValidated,
                            "Permission",
                            permission.Id.ToString(),
                            false,
                            JsonSerializer.Serialize(new
                            {
                                PermissionId = permission.Id,
                                OldScope = permission.Scope,
                                NewScope = updatedPermission.Scope,
                                Reason = "System admin required"
                            }));

                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            "Cannot modify system permissions",
                            PermissionConstants.ErrorCodes.PermissionInactive);
                    }
                }

                // ========== 스코프 변경 검증 ==========
                if (permission.Scope != updatedPermission.Scope)
                {
                    var scopeValidation = await ValidateScopeFormatAsync(
                        updatedPermission.Scope, context, true);

                    if (!scopeValidation.IsSuccess)
                    {
                        // ❌ 이벤트 불필요: 형식 검증 실패
                        await _unitOfWork.RollbackTransactionAsync();
                        return scopeValidation;
                    }

                    // 플랜별 스코프 깊이 체크
                    var scopeParts = updatedPermission.Scope.Split(':');
                    var subscription = await _planSubscriptionRepository
                        .GetActiveByOrganizationIdAsync(context.OrganizationId);
                    var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                    var maxDepth = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey];

                    if (maxDepth > 0 && scopeParts.Length > maxDepth)
                    {
                        // 🔴 비즈니스 이벤트 필요: 플랜 제한
                        await _eventBus.PublishAsync(new PlanLimitReachedEvent
                        {
                            OrganizationId = context.OrganizationId,
                            PlanKey = planKey,
                            LimitType = "PermissionScopeDepth",
                            CurrentValue = scopeParts.Length,
                            MaxValue = maxDepth
                        });

                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult.Failure(
                            $"New scope depth exceeds {planKey} plan limit",
                            PermissionConstants.ErrorCodes.InvalidScope);
                    }
                }

                // ========== ✅ 검증 성공 ==========

                // 감사 로그만 기록 (일반 수정 성공은 이벤트 불필요)
                await _auditService.LogActionAsync(
                    context.ConnectedId,
                    "ValidatePermissionUpdate",
                    AuditActionType.PermissionValidated,
                    "Permission",
                    permission.Id.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        PermissionId = permission.Id,
                        OldScope = permission.Scope,
                        NewScope = updatedPermission.Scope
                    }));

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();

                _logger.LogError(ex,
                    "Error validating permission update for ID: {PermissionId}",
                    permission.Id);

                return ServiceResult.Failure(
                    PermissionConstants.ValidationMessages.PERMISSION_SCOPE_REQUIRED,
                    PermissionConstants.ErrorCodes.PermissionNotFound);
            }
        }

        /// <summary>
        /// Validates permission deletion
        /// </summary>
        public async Task<ServiceResult> ValidateDeleteAsync(
            Permission permission,
            ConnectedIdContext context)
        {
            try
            {
                var isSystemAdmin = context.OrganizationId == CommonConstants.System.AUTHHIVE_ORGANIZATION_ID;

                if (!isSystemAdmin)
                {
                    if (permission.IsSystemPermission)
                    {
                        // 🔴 보안 이벤트 필요: 시스템 권한 삭제 시도
                        await _eventBus.PublishAsync(new SystemPermissionModificationAttemptedEvent
                        {
                            AttemptedBy = context.ConnectedId,
                            PermissionId = permission.Id,
                            PermissionScope = permission.Scope,
                            Action = "Delete",
                            IsAuthorized = false,
                            OrganizationId = context.OrganizationId
                        });

                        return ServiceResult.Failure(
                            "System permissions can only be deleted by system administrators",
                            PermissionConstants.ErrorCodes.InsufficientPermission);
                    }

                    // 일반 권한은 조직 Owner/Admin만 삭제 가능
                    var membership = await _organizationMembershipRepository
                        .GetMembershipAsync(context.OrganizationId, context.ConnectedId);

                    if (membership?.MemberRole > OrganizationMemberRole.Admin)
                    {
                        return ServiceResult.Failure(
                            "Only organization owners and admins can delete permissions",
                            PermissionConstants.ErrorCodes.InsufficientPermission);
                    }
                }

                // 종속성 체크
                var roleAssignments = await _rolePermissionRepository
                    .GetByPermissionAsync(permission.Id, context.OrganizationId);

                if (roleAssignments.Any())
                {
                    // ❌ 이벤트 불필요: 일반 검증 실패
                    return ServiceResult.Failure(
                        "Cannot delete permission with active role assignments",
                        PermissionConstants.ErrorCodes.PermissionHasDependencies);
                }

                // 감사 로그만
                await _auditService.LogActionAsync(
                    context.ConnectedId,
                    "ValidatePermissionDelete",
                    AuditActionType.PermissionValidated,
                    "Permission",
                    permission.Id.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        PermissionId = permission.Id,
                        Scope = permission.Scope
                    }));

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error validating permission deletion for ID: {PermissionId}",
                    permission.Id);
                return ServiceResult.Failure(
                    PermissionConstants.ValidationMessages.PERMISSION_NOT_FOUND,
                    PermissionConstants.ErrorCodes.PermissionNotFound);
            }
        }
        /// <summary>
        /// Validates business rules for permission
        /// </summary>
        public Task<ServiceResult> ValidateBusinessRulesAsync(Permission permission)
        {
            try
            {
                // 스코프 패턴 검증
                if (!ScopePattern.IsMatch(permission.Scope))
                {
                    return Task.FromResult(ServiceResult.Failure(
                        PermissionConstants.ValidationMessages.INVALID_SCOPE_FORMAT,
                        PermissionConstants.ErrorCodes.InvalidScope));
                }

                // 스코프 깊이 검증
                var scopeParts = permission.Scope.Split(':');
                if (scopeParts.Length > PermissionConstants.Limits.MaxScopeDepth)
                {
                    return Task.FromResult(ServiceResult.Failure(
                        string.Format(
                            PermissionConstants.ValidationMessages.SCOPE_DEPTH_EXCEEDED,
                            PermissionConstants.Limits.MaxScopeDepth),
                        PermissionConstants.ErrorCodes.InvalidScope));
                }

                return Task.FromResult(ServiceResult.Success());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error validating business rules for permission: {PermissionId}",
                    permission.Id);
                return Task.FromResult(ServiceResult.Failure(
                    PermissionConstants.ValidationMessages.PERMISSION_INVALID,
                    PermissionConstants.ErrorCodes.SystemError));
            }
        }

        /// <summary>
        /// Validates batch permission operations
        /// </summary>
        public async Task<ServiceResult> ValidateBatchAsync(
            List<CreatePermissionRequest> requests,
            ConnectedIdContext context)
        {
            if (requests.Count > PermissionConstants.Limits.MaxBulkOperationSize)
            {
                // 대량 작업 제한은 플랜 업그레이드 기회
                var subscription = await _planSubscriptionRepository
                    .GetActiveByOrganizationIdAsync(context.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                if (planKey != PricingConstants.SubscriptionPlans.ENTERPRISE_KEY)
                {
                    // 🔴 비즈니스 이벤트: 대량 작업 제한 = 업그레이드 기회
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = context.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "BulkOperationSize",
                        CurrentValue = requests.Count,
                        MaxValue = PermissionConstants.Limits.MaxBulkOperationSize
                    });
                }

                return ServiceResult.Failure(
                    $"Batch size exceeds maximum limit of {PermissionConstants.Limits.MaxBulkOperationSize}",
                    "BATCH_SIZE_EXCEEDED");
            }

            // 각 요청 검증
            foreach (var request in requests)
            {
                var result = await ValidateCreateAsync(request, context, false);
                if (!result.IsSuccess)
                {
                    return result;
                }
            }

            return ServiceResult.Success();
        }

        /// <summary>
        /// Validates compliance requirements
        /// </summary>
        public async Task<ServiceResult> ValidateComplianceAsync(
            ComplianceStandard standard,
            ConnectedIdContext context,
            bool useCache = true)
        {
            // 컴플라이언스 검증 구현
            return await Task.FromResult(ServiceResult.Success());
        }

        /// <summary>
        /// Audits permission usage
        /// </summary>
        public async Task<ServiceResult> AuditPermissionUsageAsync(
            Guid permissionId,
            DateRange dateRange,
            ConnectedIdContext context)
        {
            try
            {
                // 감사 로그만 (이벤트 불필요)
                await _auditService.LogActionAsync(
                    context.ConnectedId,
                    "AuditPermissionUsage",
                    AuditActionType.PermissionAudited,
                    "Permission",
                    permissionId.ToString(),
                    true,
                    JsonSerializer.Serialize(new
                    {
                        PermissionId = permissionId,
                        DateRange = dateRange,
                        RequestedBy = context.ConnectedId
                    }));

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error auditing permission usage for ID: {PermissionId}",
                    permissionId);
                return ServiceResult.Failure(
                    "Failed to audit permission usage",
                    PermissionConstants.ErrorCodes.SystemError);
            }
        }

        /// <summary>
        /// Detects permission anomalies
        /// </summary>
        public async Task<ServiceResult> DetectPermissionAnomaliesAsync(
            ConnectedIdContext context,
            int lookbackDays = 30)
        {
            // 이상 징후 탐지 구현
            return await Task.FromResult(ServiceResult.Success());
        }

        #endregion
        #region 스코프 의미 검증

        /// <summary>
        /// 비즈니스 규칙에 따른 스코프 의미 검증
        /// </summary>
        public async Task<ServiceResult<ScopeSemanticValidation>> ValidateScopeSemanticAsync(
            string scope,
            ConnectedIdContext context,
            bool checkResourceExistence = true)
        {
            try
            {
                var validation = new ScopeSemanticValidation
                {
                    Scope = scope,
                    IsValid = true,
                    CheckedAt = _dateTimeProvider.UtcNow
                };

                var parts = scope.Split(':');
                validation.Resource = parts[0];
                validation.Action = parts.Length > 1 ? parts[1] : "*";
                validation.Constraint = parts.Length > 2 ? parts[2] : null;

                // 리소스 유효성 확인
                if (checkResourceExistence)
                {
                    var resourceExists = await ValidateResourceExistsAsync(validation.Resource);
                    if (!resourceExists)
                    {
                        validation.IsValid = false;
                        validation.Errors.Add($"Resource '{validation.Resource}' does not exist");
                    }
                }

                // 리소스에 대한 액션 유효성 검증
                if (!IsValidActionForResource(validation.Resource, validation.Action))
                {
                    validation.IsValid = false;
                    validation.Errors.Add($"Action '{validation.Action}' is not valid for resource '{validation.Resource}'");
                }

                // 제약 조건 유효성 확인
                if (!string.IsNullOrEmpty(validation.Constraint))
                {
                    if (!IsValidConstraint(validation.Constraint))
                    {
                        validation.IsValid = false;
                        validation.Errors.Add($"Invalid constraint: {validation.Constraint}");
                    }
                }

                return validation.IsValid
                    ? ServiceResult<ScopeSemanticValidation>.Success(validation)
                    : ServiceResult<ScopeSemanticValidation>.Failure(validation.Errors.FirstOrDefault() ?? "Semantic error");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating scope semantics: {Scope}", scope);
                return ServiceResult<ScopeSemanticValidation>.Failure("Semantic error");
            }
        }

        #endregion
        #region 스코프 계층 구조 검증

        /// <summary>
        /// 스코프 계층 구조 및 상속 검증
        /// </summary>
        public async Task<ServiceResult<ScopeHierarchy>> ValidateScopeHierarchyAsync(
            List<string> scopes,
            ConnectedIdContext context)
        {
            try
            {
                var hierarchy = new ScopeHierarchy
                {
                    Scopes = scopes,
                    IsValid = true
                };

                var scopeTree = new Dictionary<string, List<string>>();
                var scopesByDepth = new Dictionary<int, List<string>>();
                var maxDepth = 0;

                foreach (var scope in scopes)
                {
                    var parts = scope.Split(':');
                    var depth = parts.Length;
                    var parent = parts[0];

                    if (!scopeTree.ContainsKey(parent))
                        scopeTree[parent] = new List<string>();
                    scopeTree[parent].Add(scope);

                    if (!scopesByDepth.ContainsKey(depth))
                        scopesByDepth[depth] = new List<string>();
                    scopesByDepth[depth].Add(scope);

                    if (depth > maxDepth)
                        maxDepth = depth;
                }

                hierarchy.Tree = scopeTree;
                hierarchy.ScopesByDepth = scopesByDepth;
                hierarchy.MaxDepthFound = maxDepth;

                // 순환 의존성 확인
                foreach (var kvp in scopeTree)
                {
                    if (HasCircularDependency(kvp.Key, scopeTree))
                    {
                        hierarchy.IsValid = false;
                        hierarchy.CircularDependencies.Add(kvp.Key);
                    }
                }

                // PricingConstants 기반 플랜 제한 확인
                var subscription = await _planSubscriptionRepository
                    .GetActiveByOrganizationIdAsync(context.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var maxAllowedDepth = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey];

                foreach (var scope in scopes)
                {
                    var depth = scope.Split(':').Length;
                    if (maxAllowedDepth > 0 && depth > maxAllowedDepth)
                    {
                        hierarchy.IsValid = false;
                        hierarchy.DepthViolations.Add(
                            $"Scope '{scope}' has depth {depth}, exceeds {planKey} plan limit of {maxAllowedDepth}");
                    }
                }

                // 플랜 제한 위반 시에만 이벤트
                if (!hierarchy.IsValid && hierarchy.DepthViolations.Any())
                {
                    // 🔴 비즈니스 이벤트: 다수의 스코프가 플랜 제한 초과
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = context.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "PermissionScopeDepth",
                        CurrentValue = maxDepth,
                        MaxValue = maxAllowedDepth
                    });
                }

                return ServiceResult<ScopeHierarchy>.Success(hierarchy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating scope hierarchy");
                return ServiceResult<ScopeHierarchy>.Failure("Hierarchy validation error");
            }
        }

        #endregion

        #region 스코프 충돌 감지

        /// <summary>
        /// 스코프 간 충돌 감지
        /// </summary>
        public async Task<ServiceResult<List<ScopeConflict>>> DetectScopeConflictsAsync(
            List<string> scopes,
            ConnectedIdContext context,
            bool includeWarnings = true)
        {
            try
            {
                var conflicts = new List<ScopeConflict>();

                for (int i = 0; i < scopes.Count; i++)
                {
                    for (int j = i + 1; j < scopes.Count; j++)
                    {
                        var conflict = DetectConflictBetweenScopes(scopes[i], scopes[j]);
                        if (conflict != null)
                        {
                            conflicts.Add(conflict);
                        }

                        if (includeWarnings)
                        {
                            var warning = DetectPotentialConflict(scopes[i], scopes[j]);
                            if (warning != null)
                            {
                                conflicts.Add(warning);
                            }
                        }
                    }
                }

                // 중복 권한 확인
                var redundancies = DetectRedundantScopes(scopes);
                conflicts.AddRange(redundancies);

                // 위험한 충돌이 있을 때만 이벤트
                var criticalConflicts = conflicts.Where(c => c.Type == ScopeConflictType.Direct).ToList();
                if (criticalConflicts.Any() && criticalConflicts.Any(c =>
                    c.Description.Contains("audit") || c.Description.Contains("payment")))
                {
                    // 🔴 보안 이벤트: ScopeConflictDetectedEvent 사용
                    await _eventBus.PublishAsync(new ScopeConflictDetectedEvent
                    {
                        ConflictingScopes = criticalConflicts.SelectMany(c => new[] { c.Scope1, c.Scope2 }).Distinct().ToList(),
                        ConflictType = "Direct",
                        Description = "Critical permission conflicts detected",
                        DetectedBy = context.ConnectedId,
                        OrganizationId = context.OrganizationId
                    });
                }

                return ServiceResult<List<ScopeConflict>>.Success(conflicts);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting scope conflicts");
                return ServiceResult<List<ScopeConflict>>.Failure(
                    PermissionConstants.ValidationMessages.SCOPE_CONFLICT);
            }
        }

        #endregion
        #region 플랜 제한 검증

        /// <summary>
        /// 조직 플랜에 따른 권한 제한 검증
        /// </summary>
        public async Task<ServiceResult<PlanRestrictionValidation>> ValidatePlanRestrictionsAsync(
            string scope,
            ConnectedIdContext context)
        {
            try
            {
                var validation = new PlanRestrictionValidation
                {
                    Scope = scope,
                    IsAllowed = true,
                    CheckedAt = _dateTimeProvider.UtcNow
                };

                // 조직의 플랜 확인
                var subscription = await _planSubscriptionRepository
                    .GetActiveByOrganizationIdAsync(context.OrganizationId);

                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                validation.PlanKey = planKey;

                // PricingConstants 기반 스코프 깊이 제한 확인
                var scopeParts = scope.Split(':');
                var maxDepth = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey];

                if (maxDepth > 0 && scopeParts.Length > maxDepth)
                {
                    validation.IsAllowed = false;
                    validation.Restrictions.Add(
                        $"Scope depth ({scopeParts.Length}) exceeds {planKey} plan limit ({maxDepth})");
                }

                // Basic 플랜 제약사항
                if (planKey == PricingConstants.SubscriptionPlans.BASIC_KEY)
                {
                    if (scope.Contains("*"))
                    {
                        validation.IsAllowed = false;
                        validation.Restrictions.Add("Wildcard permissions not available in Basic plan");
                    }

                    if (scopeParts[0] == "billing" || scopeParts[0] == "payment")
                    {
                        validation.IsAllowed = false;
                        validation.Restrictions.Add("Financial permissions require Pro plan or higher");
                    }
                }

                // 역할 수 제한 확인
                var roleCount = await _roleRepository.CountByOrganizationAsync(context.OrganizationId);
                var roleLimit = PricingConstants.SubscriptionPlans.RoleLimits[planKey];

                if (roleLimit > 0 && roleCount >= roleLimit)
                {
                    validation.Warnings.Add(
                        $"Organization is at role limit ({roleLimit}) for {planKey} plan");

                    // 🔴 비즈니스 이벤트: 역할 제한 도달
                    await _eventBus.PublishAsync(new PlanLimitReachedEvent
                    {
                        OrganizationId = context.OrganizationId,
                        PlanKey = planKey,
                        LimitType = "RoleCount",
                        CurrentValue = roleCount,
                        MaxValue = roleLimit
                    });
                }

                return ServiceResult<PlanRestrictionValidation>.Success(validation);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating plan restrictions");
                return ServiceResult<PlanRestrictionValidation>.Failure(
                    PermissionConstants.ValidationMessages.PERMISSION_INVALID);
            }
        }

        #endregion

        #region 권한 조합 검증

        /// <summary>
        /// 권한 조합의 안전성 검증
        /// </summary>
        public async Task<ServiceResult<SafetyAssessment>> ValidatePermissionCombinationAsync(
            List<Guid> permissionIds,
            ConnectedIdContext context,
            bool includeRiskAnalysis = true)
        {
            try
            {
                var assessment = new SafetyAssessment
                {
                    PermissionIds = permissionIds,
                    IsSafe = true,
                    RiskLevel = RiskLevel.Low,
                    AssessedAt = _dateTimeProvider.UtcNow
                };

                // 권한 로드
                var permissions = new List<Permission>();
                foreach (var id in permissionIds)
                {
                    var permission = await _permissionRepository.GetByIdAsync(id);
                    if (permission != null)
                        permissions.Add(permission);
                }

                // 위험한 조합 확인
                var dangerousCombos = new List<(string, string)>
                {
                    ("users:delete", "audit:delete"),  // 사용자 삭제와 증거 은폐
                    ("payment:*", "audit:modify"),     // 결제 조작과 로그 수정
                    ("*:*", "security:bypass")         // 슈퍼 관리자와 보안 우회
                };

                foreach (var combo in dangerousCombos)
                {
                    var hasFirst = permissions.Any(p => MatchesScope(p.Scope, combo.Item1));
                    var hasSecond = permissions.Any(p => MatchesScope(p.Scope, combo.Item2));

                    if (hasFirst && hasSecond)
                    {
                        assessment.IsSafe = false;
                        assessment.RiskLevel = RiskLevel.Critical;
                        assessment.DangerousCombinations.Add(
                            $"Dangerous combination: {combo.Item1} + {combo.Item2}");
                    }
                }

                // Critical 위험 수준일 때만 이벤트
                if (assessment.RiskLevel == RiskLevel.Critical)
                {
                    // 기존 DangerousPermissionCombinationDetectedEvent 사용
                    await _eventBus.PublishAsync(new DangerousPermissionCombinationDetectedEvent
                    {
                        ConnectedId = context.ConnectedId,
                        OrganizationId = context.OrganizationId,
                        PermissionIds = permissionIds,
                        RiskLevel = "Critical", // string으로 변환
                        DangerousCombinations = assessment.DangerousCombinations
                    });
                }

                // 권한 상승 위험 확인
                if (permissions.Any(p => p.Scope.Contains("permission:create")) &&
                    permissions.Any(p => p.Scope.Contains("role:assign")))
                {
                    assessment.RiskLevel = RiskLevel.High;
                    assessment.Warnings.Add("Can create permissions and assign roles - privilege escalation risk");
                }

                if (includeRiskAnalysis)
                {
                    assessment.RiskAnalysis = await AnalyzeSecurityRisksAsync(permissions);
                }

                return ServiceResult<SafetyAssessment>.Success(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating permission combination");
                return ServiceResult<SafetyAssessment>.Failure("Error with permission combination validation");
            }
        }

        #endregion
        #region Helper Methods

        private Task<bool> ValidateResourceExistsAsync(string resource)
        {
            var validResources = new[] { "users", "orders", "billing", "permissions", "roles", "audit", "payment", "organization" };
            return Task.FromResult(validResources.Contains(resource.ToLower()));
        }

        private bool IsValidActionForResource(string resource, string action)
        {
            var validActions = new Dictionary<string, string[]>
            {
                ["users"] = new[] { "read", "write", "delete", "create", "update" },
                ["billing"] = new[] { "read", "create", "approve", "refund", "cancel" },
                ["permissions"] = new[] { "read", "create", "delete", "assign", "revoke" },
                ["payment"] = new[] { "read", "create", "approve", "refund", "cancel" },
                ["audit"] = new[] { "read", "export" }
            };

            if (action == "*") return true;

            return validActions.ContainsKey(resource) &&
                   validActions[resource].Contains(action);
        }

        private bool IsValidConstraint(string constraint)
        {
            var validConstraints = new[] { "own", "team", "all", "department", "subordinate", "organization" };
            return validConstraints.Contains(constraint.ToLower());
        }

        private bool HasCircularDependency(string node, Dictionary<string, List<string>> graph)
        {
            var visited = new HashSet<string>();
            var recursionStack = new HashSet<string>();
            return HasCycleDFS(node, graph, visited, recursionStack);
        }

        private bool HasCycleDFS(string node, Dictionary<string, List<string>> graph,
            HashSet<string> visited, HashSet<string> recursionStack)
        {
            visited.Add(node);
            recursionStack.Add(node);

            if (graph.ContainsKey(node))
            {
                foreach (var neighbor in graph[node])
                {
                    if (!visited.Contains(neighbor))
                    {
                        if (HasCycleDFS(neighbor, graph, visited, recursionStack))
                            return true;
                    }
                    else if (recursionStack.Contains(neighbor))
                    {
                        return true;
                    }
                }
            }

            recursionStack.Remove(node);
            return false;
        }
        private ScopeConflict? DetectConflictBetweenScopes(string scope1, string scope2)
        {
            // 직접적인 충돌 감지
            var conflictPairs = new List<(string, string, string)>
            {
                ("users:delete", "users:preserve", "Conflicting user management permissions"),
                ("audit:delete", "audit:preserve", "Conflicting audit retention policies"),
                ("payment:charge", "payment:void", "Conflicting payment operations")
            };

            foreach (var (pattern1, pattern2, description) in conflictPairs)
            {
                if ((scope1.StartsWith(pattern1) && scope2.StartsWith(pattern2)) ||
                    (scope1.StartsWith(pattern2) && scope2.StartsWith(pattern1)))
                {
                    return new ScopeConflict
                    {
                        Scope1 = scope1,
                        Scope2 = scope2,
                        Type = ScopeConflictType.Direct,
                        Description = description
                    };
                }
            }

            return null;
        }

        private ScopeConflict? DetectPotentialConflict(string scope1, string scope2)
        {
            // 잠재적 문제 감지
            if (scope1.Contains("*") && scope2.Contains("*"))
            {
                return new ScopeConflict
                {
                    Scope1 = scope1,
                    Scope2 = scope2,
                    Type = ScopeConflictType.Warning,
                    Description = "Multiple wildcard permissions may cause unexpected behavior"
                };
            }

            return null;
        }

        private List<ScopeConflict> DetectRedundantScopes(List<string> scopes)
        {
            var conflicts = new List<ScopeConflict>();

            foreach (var scope in scopes.Where(s => s.Contains("*")))
            {
                var baseScope = scope.Split(':')[0];
                var redundant = scopes.Where(s => s != scope && s.StartsWith(baseScope)).ToList();

                foreach (var r in redundant)
                {
                    conflicts.Add(new ScopeConflict
                    {
                        Scope1 = scope,
                        Scope2 = r,
                        Type = ScopeConflictType.Redundant,
                        Description = $"'{r}' is redundant because '{scope}' already covers it"
                    });
                }
            }

            return conflicts;
        }

        private bool MatchesScope(string permissionScope, string checkScope)
        {
            if (permissionScope == checkScope) return true;

            // 와일드카드 처리
            if (permissionScope.Contains("*"))
            {
                var pattern = permissionScope.Replace("*", ".*");
                return Regex.IsMatch(checkScope, pattern);
            }

            return false;
        }

        private Task<PermissionRiskAnalysis> AnalyzeSecurityRisksAsync(List<Permission> permissions)
        {
            return Task.FromResult(new PermissionRiskAnalysis
            {
                TotalPermissions = permissions.Count,
                CriticalPermissions = permissions.Count(p =>
                    p.Scope.Contains("delete") || p.Scope.Contains("*") || p.Scope.Contains("payment")),
                RecommendedActions = new List<string>
                {
                    "Review permission assignments quarterly",
                    "Enable audit logging for all critical permissions",
                    "Implement approval workflow for sensitive operations"
                }
            });
        }
        /// <summary>
        /// Validates scope format against business rules
        /// </summary>
        private async Task<ServiceResult> ValidateScopeFormatAsync(
            string scope,
            ConnectedIdContext context,
            bool useCache)
        {
            if (string.IsNullOrWhiteSpace(scope))
            {
                return ServiceResult.Failure(
                    "Scope cannot be empty",
                    PermissionConstants.ErrorCodes.InvalidScope);
            }

            if (scope.Length > PermissionConstants.Limits.ScopeMaxLength)
            {
                return ServiceResult.Failure(
                    $"Scope exceeds maximum length of {PermissionConstants.Limits.ScopeMaxLength}",
                    PermissionConstants.ErrorCodes.InvalidScope);
            }

            if (!ScopePattern.IsMatch(scope))
            {
                return ServiceResult.Failure(
                    PermissionConstants.ValidationMessages.INVALID_SCOPE_FORMAT,
                    PermissionConstants.ErrorCodes.InvalidScope);
            }

            // PricingConstants 기반 플랜 체크
            var scopeParts = scope.Split(':');
            if (context.OrganizationId != Guid.Empty &&
                context.OrganizationId != CommonConstants.System.AUTHHIVE_ORGANIZATION_ID)
            {
                var subscription = await _planSubscriptionRepository
                    .GetActiveByOrganizationIdAsync(context.OrganizationId);
                var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                var maxDepth = PricingConstants.SubscriptionPlans.PermissionScopeDepthLimits[planKey];

                if (maxDepth > 0 && scopeParts.Length > maxDepth)
                {
                    return ServiceResult.Failure(
                        $"Scope depth exceeds {planKey} plan limit of {maxDepth}",
                        PermissionConstants.ErrorCodes.InvalidScope);
                }
            }

            return ServiceResult.Success();
        }

        /// <summary>
        /// Validates parent permission exists and hierarchy depth
        /// </summary>
        private async Task<ServiceResult> ValidateParentPermissionAsync(
            Guid parentPermissionId,
            Guid organizationId)
        {
            var parentPermission = await _permissionRepository.GetByIdAsync(parentPermissionId);
            if (parentPermission == null)
            {
                return ServiceResult.Failure(
                    PermissionConstants.ValidationMessages.PARENT_NOT_FOUND,
                    PermissionConstants.ErrorCodes.ParentNotFound);
            }

            // Calculate hierarchy depth
            var hierarchyDepth = await GetPermissionHierarchyDepthAsync(parentPermission);

            // PricingConstants 기반 조직 계층 깊이 체크
            var subscription = await _planSubscriptionRepository
                .GetActiveByOrganizationIdAsync(organizationId);
            var planKey = subscription?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
            var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits[planKey];

            if (maxDepth > 0 && hierarchyDepth + 1 > maxDepth)
            {
                return ServiceResult.Failure(
                    $"Hierarchy depth exceeds {planKey} plan limit of {maxDepth}",
                    PermissionConstants.ErrorCodes.HierarchyDepthExceeded);
            }

            return ServiceResult.Success();
        }

        /// <summary>
        /// Calculates permission hierarchy depth
        /// </summary>
        private async Task<int> GetPermissionHierarchyDepthAsync(Permission permission)
        {
            int depth = 0;
            var current = permission;

            while (current?.ParentPermissionId != null && depth < PermissionConstants.Limits.MaxHierarchyDepth)
            {
                current = await _permissionRepository.GetByIdAsync(current.ParentPermissionId.Value);
                depth++;
            }

            return depth;
        }

        /// <summary>
        /// Sends critical error alert for system administrators
        /// </summary>
        private async Task SendCriticalErrorAlertAsync(
            ConnectedIdContext context,
            Exception exception,
            string operation)
        {
            try
            {
                // 🔴 비동기 처리: 이메일 발송
                var message = new EmailMessageDto
                {
                    To = "admin@authhive.com",
                    Subject = $"[Critical Error] {operation}",
                    Body = $@"
                        Operation: {operation}
                        ConnectedId: {context.ConnectedId}
                        OrganizationId: {context.OrganizationId}
                        Error: {exception.Message}
                        StackTrace: {exception.StackTrace}
                        Time: {_dateTimeProvider.UtcNow}"
                };

                await _emailService.SendEmailAsync(message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to send critical error alert for operation: {Operation}",
                    operation);
            }
        }

        #endregion
    }
}