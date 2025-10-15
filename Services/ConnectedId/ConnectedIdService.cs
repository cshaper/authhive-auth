using AuthHive.Auth.Data.Context;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Interfaces.Repositories.Business.Platform; // CORRECT NAMESPACE
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.Common;
using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using ConnectedIdEntity = AuthHive.Core.Entities.Auth.ConnectedId;
namespace AuthHive.Auth.Services
{
    public class ConnectedIdService : IConnectedIdService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationPlanRepository _organizationPlanRepository;
        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly ILogger<ConnectedIdService> _logger;
        private readonly IMapper _mapper;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly AuthDbContext _context;
        private readonly IOrganizationContext _organizationContext;
        private readonly IConnectedIdContext _connectedIdContext;
        public ConnectedIdService(
            IUnitOfWork unitOfWork,
            IConnectedIdRepository connectedIdRepository,
            IOrganizationRepository organizationRepository,
            IOrganizationPlanRepository organizationPlanRepository,
            IPlatformApplicationRepository applicationRepository,
            ILogger<ConnectedIdService> logger,
            IMapper mapper,
            IDateTimeProvider dateTimeProvider,
            IEventBus eventBus,
            IAuditService auditService,
            ICacheService cacheService,
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IConnectedIdContext connectedIdContext)
        {
            _unitOfWork = unitOfWork;
            _connectedIdRepository = connectedIdRepository;
            _applicationRepository = applicationRepository;
            _organizationRepository = organizationRepository;
            _organizationPlanRepository = organizationPlanRepository;
            _logger = logger;
            _mapper = mapper;
            _dateTimeProvider = dateTimeProvider;
            _eventBus = eventBus;
            _auditService = auditService;
            _cacheService = cacheService;
            _context = context;
            _organizationContext = organizationContext;
            _connectedIdContext = connectedIdContext;
        }
        #region IService Implementation

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                return await _context.Database.CanConnectAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConnectedIdService health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdService initialized.");
            return Task.CompletedTask;
        }

        #endregion


        #region CRUD Operations

        public async Task<ServiceResult<ConnectedIdResponse>> CreateAsync(CreateConnectedIdRequest request, CancellationToken cancellationToken = default)
        {
            var createdByConnectedId = Guid.NewGuid();

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var validationResult = await ValidateMemberLimitAsync(request.OrganizationId, createdByConnectedId, cancellationToken);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure(
                        validationResult.ErrorMessage ?? "Validation failed with an unknown error.",
                        validationResult.ErrorCode
                    );
                }

                var existing = await _connectedIdRepository.GetByUserAndOrganizationAsync(
                    request.UserId,
                    request.OrganizationId,
                    cancellationToken
                );

                if (existing != null && !existing.IsDeleted)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure(
                        "User is already an active member of this organization.",
                        "ALREADY_MEMBER"
                    );
                }

                var newEntity = _mapper.Map<ConnectedIdEntity>(request);
                newEntity.Status = ConnectedIdStatus.Active;
                newEntity.JoinedAt = _dateTimeProvider.UtcNow;

                await _connectedIdRepository.AddAsync(newEntity, cancellationToken);
                await _eventBus.PublishAsync(
                    new MemberAddedToOrganizationEvent(newEntity.Id, newEntity.UserId, newEntity.OrganizationId, createdByConnectedId),
                    cancellationToken
                );
                await _auditService.LogActionAsync(
                    performedByConnectedId: createdByConnectedId,
                    action: "Create ConnectedId",
                    actionType: AuditActionType.Create,
                    resourceType: nameof(ConnectedId),
                    resourceId: newEntity.Id.ToString(),
                    cancellationToken: cancellationToken
                );
                await InvalidateOrganizationCache(request.OrganizationId, cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                var response = _mapper.Map<ConnectedIdResponse>(newEntity);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Error creating ConnectedId for User {UserId} in Organization {OrganizationId}", request.UserId, request.OrganizationId);
                return ServiceResult<ConnectedIdResponse>.Failure($"Failed to create ConnectedId: {ex.Message}", "CREATE_ERROR");
            }
        }

        public async Task<ServiceResult<ConnectedIdResponse>> UpdateAsync(Guid id, UpdateConnectedIdRequest request, CancellationToken cancellationToken = default)
        {
            var updatedByConnectedId = Guid.NewGuid();

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null)
                {
                    return ServiceResult<ConnectedIdResponse>.NotFound("ConnectedId not found.");
                }

                var originalStatus = entity.Status;
                _mapper.Map(request, entity);
                entity.UpdatedAt = _dateTimeProvider.UtcNow;

                await _connectedIdRepository.UpdateAsync(entity);

                if (originalStatus != entity.Status)
                {
                    await _eventBus.PublishAsync(new MemberStatusChangedEvent(id, entity.UserId, entity.OrganizationId, entity.Status, updatedByConnectedId));
                }
                await _auditService.LogActionAsync(
                    performedByConnectedId: updatedByConnectedId,
                    action: "Update ConnectedId",
                    actionType: AuditActionType.Update,
                    resourceType: nameof(ConnectedId),
                    resourceId: entity.Id.ToString()
                );

                await _unitOfWork.CommitTransactionAsync();

                var response = _mapper.Map<ConnectedIdResponse>(entity);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error updating ConnectedId: {Id}", id);
                return ServiceResult<ConnectedIdResponse>.Failure($"Failed to update ConnectedId: {ex.Message}", "UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var deletedByConnectedId = Guid.NewGuid();

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null || entity.IsDeleted)
                {
                    return ServiceResult.NotFound("ConnectedId not found.");
                }

                // 👈 필수 로직 추가: 소프트 삭제 플래그 및 시간 설정
                entity.IsDeleted = true;
                entity.DeletedAt = _dateTimeProvider.UtcNow;
                entity.Status = ConnectedIdStatus.Inactive;

                // DB에 변경 사항 반영
                await _connectedIdRepository.UpdateAsync(entity!, cancellationToken);

                await _eventBus.PublishAsync(new MemberRemovedFromOrganizationEvent(entity.Id, entity.UserId, entity.OrganizationId, deletedByConnectedId));
                await _auditService.LogActionAsync(
                   performedByConnectedId: deletedByConnectedId,
                   action: "Delete ConnectedId (Soft)",
                   actionType: AuditActionType.Delete,
                   resourceType: nameof(ConnectedId),
                   resourceId: entity.Id.ToString(),
                   cancellationToken: cancellationToken
               );

                await InvalidateSingleConnectedIdCache(id, entity.OrganizationId, entity.UserId, cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                return ServiceResult.Success("ConnectedId deleted successfully.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Error deleting ConnectedId: {Id}", id);
                return ServiceResult.Failure($"Failed to delete ConnectedId: {ex.Message}", "DELETE_ERROR");
            }
        }
        public async Task<ServiceResult<ConnectedIdEntity>> GetOrCreateAsync(Guid userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            var existingEntity = await _connectedIdRepository.GetByUserAndOrganizationAsync(userId, organizationId, cancellationToken);
            if (existingEntity != null)
            {
                return ServiceResult<ConnectedIdEntity>.Success(existingEntity);
            }

            var createRequest = new CreateConnectedIdRequest { UserId = userId, OrganizationId = organizationId };
            var creationResult = await CreateAsync(createRequest, cancellationToken);

            if (!creationResult.IsSuccess)
            {
                return ServiceResult<ConnectedIdEntity>.Failure(
                    creationResult.ErrorMessage ?? "Failed to create ConnectedId for an unknown reason.",
                    creationResult.ErrorCode
                );
            }

            if (creationResult.Data == null)
            {
                return ServiceResult<ConnectedIdEntity>.Failure("Creation succeeded but returned no data.", "DATA_INCONSISTENCY");
            }

            var newEntity = await _connectedIdRepository.GetByIdAsync(creationResult.Data.Id, cancellationToken);
            if (newEntity == null)
            {
                return ServiceResult<ConnectedIdEntity>.Failure("Failed to retrieve the newly created ConnectedId.", "RETRIEVAL_ERROR");
            }

            return ServiceResult<ConnectedIdEntity>.Success(newEntity);
        }

        #endregion

        #region Query Operations

        public async Task<ServiceResult<ConnectedIdDetailResponse>> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"cache:connectedid:{id}";
            var cachedResponse = await _cacheService.GetAsync<ConnectedIdDetailResponse>(cacheKey);
            if (cachedResponse != null)
                return ServiceResult<ConnectedIdDetailResponse>.Success(cachedResponse);

            try
            {
                var entity = await _connectedIdRepository.GetWithDetailsAsync(id, cancellationToken);
                if (entity == null)
                    return ServiceResult<ConnectedIdDetailResponse>.NotFound("ConnectedId not found.");

                var response = _mapper.Map<ConnectedIdDetailResponse>(entity);
                await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromHours(1));
                return ServiceResult<ConnectedIdDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedId by ID: {Id}", id);
                return ServiceResult<ConnectedIdDetailResponse>.Failure($"Failed to get ConnectedId: {ex.Message}", "GET_ERROR");
            }
        }


        public async Task<ServiceResult<ConnectedIdListResponse>> GetByOrganizationAsync(Guid organizationId, SearchConnectedIdsRequest request)
        {
            try
            {
                var (pagedEntities, totalCount) = await _connectedIdRepository.GetPagedAsync(
                    request.PageNumber, request.PageSize,
                    predicate: c => c.OrganizationId == organizationId && !c.IsDeleted,
                    orderBy: c => c.CreatedAt, isDescending: true
                );

                var response = new ConnectedIdListResponse
                {
                    Items = _mapper.Map<List<ConnectedIdResponse>>(pagedEntities),
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };
                return ServiceResult<ConnectedIdListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedIds by organization: {OrgId}", organizationId);
                return ServiceResult<ConnectedIdListResponse>.Failure($"Failed to get organization members: {ex.Message}", "QUERY_ERROR");
            }
        }

        public async Task<ServiceResult<IEnumerable<ConnectedIdResponse>>> GetByUserAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"cache:user:{userId}:connections";
            var cachedConnections = await _cacheService.GetAsync<IEnumerable<ConnectedIdResponse>>(cacheKey);
            if (cachedConnections != null) return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(cachedConnections);

            try
            {
                var entities = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
                var response = _mapper.Map<IEnumerable<ConnectedIdResponse>>(entities);
                await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(10));
                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedIds by user: {UserId}", userId);
                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Failure($"Failed to get user connections: {ex.Message}", "QUERY_ERROR");
            }
        }

        public async Task<ServiceResult<Guid>> GetActiveConnectedIdByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var allConnections = await _connectedIdRepository.GetByUserIdAsync(userId, cancellationToken);
                var activeConnection = allConnections
                    .Where(c => c.Status == ConnectedIdStatus.Active && !c.IsDeleted)
                    .OrderByDescending(c => c.LastActiveAt)
                    .FirstOrDefault();

                if (activeConnection == null)
                {
                    return ServiceResult<Guid>.NotFound("No active ConnectedId found for the user.");
                }
                return ServiceResult<Guid>.Success(activeConnection.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active ConnectedId for User: {UserId}", userId);
                return ServiceResult<Guid>.Failure($"Failed to get active connection: {ex.Message}", "QUERY_ERROR");
            }
        }

        #endregion

        #region Activity & Validation

        public async Task<ServiceResult> UpdateLastActivityAsync(Guid id, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null || entity.IsDeleted)
                {
                    return ServiceResult.NotFound("ConnectedId not found to update activity.");
                }

                entity.LastActiveAt = _dateTimeProvider.UtcNow;
                await _connectedIdRepository.UpdateAsync(entity);
                await InvalidateSingleConnectedIdCache(id, entity.OrganizationId, entity.UserId, cancellationToken);

                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult.Success("Last activity updated.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error updating last activity: {Id}", id);
                return ServiceResult.Failure($"Failed to update last activity: {ex.Message}", "UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult> ValidateConnectedIdAsync(Guid connectedId)
        {
            var validationResult = await ValidateAsync(connectedId);
            if (!validationResult.IsSuccess) return ServiceResult.Failure(validationResult.ErrorMessage ?? "Validation check failed unexpectedly.", validationResult.ErrorCode);
            if (!validationResult.Data) return ServiceResult.Failure("ConnectedId is not valid (inactive or deleted).", "VALIDATION_FAILED");
            return ServiceResult.Success("ConnectedId is valid.");
        }

        public async Task<ServiceResult<bool>> ValidateAsync(Guid id)
        {
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                var isValid = entity != null && entity.Status == ConnectedIdStatus.Active && !entity.IsDeleted;
                return ServiceResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating ConnectedId: {Id}", id);
                return ServiceResult<bool>.Failure($"Failed to validate: {ex.Message}", "VALIDATION_ERROR");
            }
        }
        public async Task<ServiceResult<bool>> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                var isMember = await _connectedIdRepository.IsMemberOfOrganizationAsync(userId, organizationId, cancellationToken);
                return ServiceResult<bool>.Success(isMember);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking membership for User {UserId} in Org {OrgId}", userId, organizationId);
                return ServiceResult<bool>.Failure($"Failed to check membership: {ex.Message}", "QUERY_ERROR");
            }
        }


        #endregion

        #region Private Helpers

        private async Task<ServiceResult> ValidateMemberLimitAsync(Guid organizationId, Guid? triggeredBy, CancellationToken cancellationToken)
        {
            var plan = await _organizationPlanRepository.GetActivePlanByOrganizationIdAsync(organizationId, cancellationToken);
            var planKey = plan?.PlanKey ?? PricingConstants.DefaultPlanKey;

            if (!PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var memberLimit))
            {
                _logger.LogWarning("Member limit for plan key '{PlanKey}' not found. Falling back to default.", planKey);
                memberLimit = PricingConstants.SubscriptionPlans.MemberLimits[PricingConstants.DefaultPlanKey];
            }

            if (memberLimit == -1)
                return ServiceResult.Success();

            var activeMembers = await _connectedIdRepository.GetByOrganizationAndStatusAsync(
                organizationId,
                ConnectedIdStatus.Active,
                cancellationToken
            );

            var currentMemberCount = activeMembers.Count();

            if (currentMemberCount >= memberLimit)
            {
                var errorMessage = $"Organization member limit of {memberLimit} for the '{planKey}' plan has been exceeded.";
                var limitEvent = new PlanLimitReachedEvent(
                    organizationId,
                    planKey,
                    PlanLimitType.OrganizationMemberCount,
                    currentMemberCount,
                    memberLimit,
                    triggeredBy
                );

                await _eventBus.PublishAsync(limitEvent, cancellationToken);
                return ServiceResult.Failure(errorMessage, "PLAN_LIMIT_EXCEEDED");
            }

            return ServiceResult.Success();
        }

        private async Task InvalidateOrganizationCache(Guid organizationId, CancellationToken cancellationToken)
        {
            await _cacheService.RemoveAsync($"cache:org:{organizationId}:members:page:1:size:10", cancellationToken);
        }
        private async Task InvalidateSingleConnectedIdCache(Guid connectedId, Guid organizationId, Guid? userId, CancellationToken cancellationToken)
        {
            var cacheKey = $"cache:connectedId:{connectedId}:org:{organizationId}:user:{userId}";
            await _cacheService.RemoveAsync(cacheKey, cancellationToken);
        }


        // Path: AuthHive.Auth/Services/ConnectedId/ConnectedIdService.cs

        // ... inside the ConnectedIdService class ...

        #region Service Account Management

        /// <summary>
        /// 지정된 애플리케이션을 대표하는 서비스 계정 ConnectedId를 조회하거나 생성합니다.
        /// 이 작업은 원자성을 보장하기 위해 데이터베이스 트랜잭션 내에서 수행됩니다.
        /// </summary>
        public async Task<ServiceResult<Guid>> GetOrCreateServiceAccountForApplicationAsync(Guid applicationId)
        {
            // 서비스 계정은 ApplicationId가 일치하고 UserId가 null인 ConnectedId로 식별합니다.
            var existingServiceAccount = (await _connectedIdRepository.FindAsync(
                cid => cid.ApplicationId == applicationId &&
                       cid.UserId == null &&
                       cid.MembershipType == MembershipType.ServiceAccount
            )).FirstOrDefault();

            if (existingServiceAccount != null)
            {
                _logger.LogDebug("Found existing service account ConnectedId {ConnectedId} for ApplicationId {ApplicationId}", existingServiceAccount.Id, applicationId);
                return ServiceResult<Guid>.Success(existingServiceAccount.Id);
            }

            // 트랜잭션 내에서 생성하여 동시성 문제를 방지합니다.
            await _unitOfWork.BeginTransactionAsync();
            try
            {
                // 트랜잭션 진입 후 다시 한번 확인 (Double-checked locking)
                var recheckServiceAccount = (await _connectedIdRepository.FindAsync(
                    cid => cid.ApplicationId == applicationId &&
                           cid.UserId == null &&
                           cid.MembershipType == MembershipType.ServiceAccount
                )).FirstOrDefault();

                if (recheckServiceAccount != null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<Guid>.Success(recheckServiceAccount.Id);
                }

                // 애플리케이션 정보를 조회하여 OrganizationId를 가져옵니다.
                var application = await _applicationRepository.GetByIdAsync(applicationId);
                if (application == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<Guid>.Failure($"Application with ID '{applicationId}' not found.");
                }

                // 새로운 서비스 계정 ConnectedId를 생성합니다.
                var newServiceAccount = new ConnectedIdEntity
                {
                    OrganizationId = application.OrganizationId,
                    ApplicationId = applicationId, // 이제 이 속성이 존재합니다.
                    UserId = null,
                    MembershipType = MembershipType.ServiceAccount,
                    Status = ConnectedIdStatus.Active,
                };

                var createdEntity = await _connectedIdRepository.AddAsync(newServiceAccount);
                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation("Created new service account ConnectedId {ConnectedId} for ApplicationId {ApplicationId}", createdEntity.Id, applicationId);

                return ServiceResult<Guid>.Success(createdEntity.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get or create service account for ApplicationId {ApplicationId}", applicationId);
                await _unitOfWork.RollbackTransactionAsync();
                return ServiceResult<Guid>.Failure("An internal error occurred while creating the service account.");
            }
        }
        #endregion


        #region 누락된 인터페이스 구현

        /// <summary>
        /// 현재 요청 컨텍스트에서 조직 ID를 동기적으로 가져옵니다.
        /// </summary>
        public ServiceResult<Guid> GetCurrentOrganizationId()
        {
            if (!_organizationContext.CurrentOrganizationId.HasValue)
            {
                return ServiceResult<Guid>.Failure("현재 요청에서 조직 컨텍스트를 찾을 수 없습니다.");
            }
            return ServiceResult<Guid>.Success(_organizationContext.CurrentOrganizationId.Value);
        }

        /// <summary>
        /// 현재 요청 컨텍스트에서 ConnectedId를 동기적으로 가져옵니다.
        /// </summary>
        public ServiceResult<Guid> GetCurrentConnectedId()
        {
            if (!_connectedIdContext.CurrentConnectedId.HasValue)
            {
                return ServiceResult<Guid>.Failure("현재 요청에서 ConnectedId 컨텍스트를 찾을 수 없습니다.");
            }
            return ServiceResult<Guid>.Success(_connectedIdContext.CurrentConnectedId.Value);
        }

        /// <summary>
        /// 지정된 ConnectedId가 대상 조직에 대해 관리자 권한(Admin/Owner)을 가졌는지 확인합니다.
        /// </summary>
        public async Task<bool> HasAdminAccessToOrganizationAsync(
        Guid connectedId,
        Guid organizationId,
        CancellationToken cancellationToken = default)
        {
            // 💡 Cache-first approach to reduce DB load on repeated permission checks.
            string cacheKey = $"auth:access:conn:{connectedId}:org:{organizationId}:admin";

            // 1. ✅ Get the cached value as a string.
            var cachedString = await _cacheService.GetStringAsync(cacheKey, cancellationToken);

            // 2. ✅ If the string exists, parse it back to a boolean.
            if (!string.IsNullOrEmpty(cachedString) && bool.TryParse(cachedString, out var cachedValue))
            {
                _logger.LogDebug("Admin access check cache hit for ConnectedId: {ConnectedId}", connectedId);
                return cachedValue;
            }

            _logger.LogDebug("Admin access check cache miss for ConnectedId: {ConnectedId}. Querying DB.", connectedId);

            // List of roles that grant admin access.
            var adminRoles = new[] { "Admin", "Owner" };

            // Query the database to see if the ConnectedId has any of the admin roles.
            var hasAccess = await _context.ConnectedIds
                .Where(c => c.Id == connectedId && c.OrganizationId == organizationId)
                .AnyAsync(c => c.RoleAssignments.Any(ra => adminRoles.Contains(ra.Role.Name)),
                          cancellationToken);

            // 3. ✅ Store the boolean result as a string in the cache for future requests.
            await _cacheService.SetStringAsync(cacheKey, hasAccess.ToString(), TimeSpan.FromMinutes(5), cancellationToken);

            return hasAccess;
        }

        /// <summary>
        /// 지정된 ConnectedId가 특정 역할을 가졌는지 확인합니다.
        /// </summary>
        public async Task<bool> HasRequiredRoleAsync(
     Guid connectedId,
     string requiredRole,
     CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(requiredRole))
            {
                return false;
            }

            string cacheKey = $"auth:access:conn:{connectedId}:role:{requiredRole}";

            // 1. ✅ Get the cached value as a string.
            var cachedString = await _cacheService.GetStringAsync(cacheKey, cancellationToken);

            // 2. ✅ If the string exists, parse it back to a boolean and return.
            if (!string.IsNullOrEmpty(cachedString) && bool.TryParse(cachedString, out var cachedValue))
            {
                _logger.LogDebug("Role check cache hit for ConnectedId: {ConnectedId}, Role: {Role}", connectedId, requiredRole);
                return cachedValue;
            }

            _logger.LogDebug("Role check cache miss for ConnectedId: {ConnectedId}, Role: {Role}. Querying DB.", connectedId, requiredRole);

            // Check if the ConnectedId has any role assignment where the role's name matches the required role (case-insensitive).
            var hasRole = await _context.ConnectedIds
                .Where(c => c.Id == connectedId)
                .AnyAsync(c => c.RoleAssignments.Any(ra => ra.Role.Name.Equals(requiredRole, StringComparison.OrdinalIgnoreCase)),
                          cancellationToken);

            // 3. ✅ Store the boolean result as a string in the cache.
            await _cacheService.SetStringAsync(cacheKey, hasRole.ToString(), TimeSpan.FromMinutes(5), cancellationToken);

            return hasRole;
        }

        #endregion
        #endregion

    }
}