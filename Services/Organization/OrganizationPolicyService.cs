using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AutoMapper;
using Newtonsoft.Json;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 정책 관리 서비스 - AuthHive v15
    /// 조직의 보안 정책, 데이터 정책, 컴플라이언스 정책 등을 관리
    /// 정책 상속 및 오버라이드 메커니즘 지원
    /// </summary>
    public class OrganizationPolicyService : IOrganizationPolicyService
    {
        private readonly IOrganizationPolicyRepository _repository;
        private readonly IOrganizationRepository _orgRepository;
        private readonly AuthDbContext _context;
        private readonly IOrganizationHierarchyService _hierarchyService;
        private readonly IOrganizationHierarchyRepository _hierarchyRepository;
        private readonly IMapper _mapper;
        private readonly IMemoryCache _cache;
        private readonly ILogger<OrganizationPolicyService> _logger;

        // 캐시 키 상수
        private const string CACHE_KEY_POLICY = "org:policy:";
        private const string CACHE_KEY_EFFECTIVE = "org:policy:effective:";
        private const int CACHE_DURATION_MINUTES = 20;

        public OrganizationPolicyService(
            IOrganizationPolicyRepository repository,
            IOrganizationRepository orgRepository,
            AuthDbContext context,
            IOrganizationHierarchyRepository hierarchyRepository, // 추가
            IOrganizationHierarchyService hierarchyService,
            IMapper mapper,
            IMemoryCache cache,
            ILogger<OrganizationPolicyService> logger)
        {
            _repository = repository;
            _orgRepository = orgRepository;
            _context = context;
            _hierarchyService = hierarchyService;
            _hierarchyRepository = hierarchyRepository; // 추가
            _mapper = mapper;
            _cache = cache;
            _logger = logger;
        }

        #region IService Implementation

        // OrganizationPolicyService.cs

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            try
            {
                // Pass the token to the database connection check for cancellation support.
                return await _context.Database.CanConnectAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationPolicyService health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            // The method body is already optimized for returning a completed task.
            _logger.LogInformation("OrganizationPolicyService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region 정책 CRUD

        /// <summary>
        /// 정책 조회
        /// </summary>
        public async Task<ServiceResult<OrganizationPolicyDto>> GetByIdAsync(Guid policyId)
        {
            try
            {
                // 캐시 확인
                var cacheKey = $"{CACHE_KEY_POLICY}{policyId}";
                if (_cache.TryGetValue<OrganizationPolicyDto>(cacheKey, out var cached) && cached != null)
                {
                    return ServiceResult<OrganizationPolicyDto>.Success(cached);
                }

                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult<OrganizationPolicyDto>.Failure("Policy not found");
                }

                var dto = _mapper.Map<OrganizationPolicyDto>(policy);

                // 캐시 저장
                _cache.Set(cacheKey, dto, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));

                return ServiceResult<OrganizationPolicyDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get policy {PolicyId}", policyId);
                return ServiceResult<OrganizationPolicyDto>.Failure("Failed to get policy");
            }
        }

        /// <summary>
        /// 조직의 모든 정책 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<OrganizationPolicyDto>>> GetByOrganizationAsync(
            Guid organizationId,
            bool includeInherited = false,
            bool includeInactive = false)
        {
            try
            {
                // Repository에 없는 메서드를 다른 방법으로 대체
                IEnumerable<OrganizationPolicy> policies;

                if (includeInactive)
                {
                    // 모든 정책 조회 (비활성 포함)
                    policies = await _context.OrganizationPolicies
                        .Where(p => p.OrganizationId == organizationId && !p.IsDeleted)
                        .ToListAsync();
                }
                else
                {
                    // 활성 정책만 조회
                    policies = await _repository.GetEnabledPoliciesAsync(organizationId);
                }

                var policyDtos = _mapper.Map<List<OrganizationPolicyDto>>(policies);

                if (includeInherited)
                {
                    var inheritedPolicies = await GetInheritedPoliciesAsync(organizationId);
                    if (inheritedPolicies.IsSuccess && inheritedPolicies.Data != null)
                    {
                        policyDtos.AddRange(inheritedPolicies.Data);
                    }
                }

                return ServiceResult<IEnumerable<OrganizationPolicyDto>>.Success(policyDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get policies for organization {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<OrganizationPolicyDto>>.Failure("Failed to get policies");
            }
        }
        /// <summary>
        /// 정책 타입별 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<OrganizationPolicyDto>>> GetByTypeAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            bool includeInherited = false)
        {
            try
            {
                var policies = await _repository.GetByTypeAsync(organizationId, policyType);
                var policyDtos = _mapper.Map<List<OrganizationPolicyDto>>(policies);

                if (includeInherited)
                {
                    var inheritedPolicies = await GetInheritedPoliciesAsync(organizationId);
                    if (inheritedPolicies.IsSuccess && inheritedPolicies.Data != null)
                    {
                        var filteredInherited = inheritedPolicies.Data
                            .Where(p => p.PolicyType == policyType);
                        policyDtos.AddRange(filteredInherited);
                    }
                }

                return ServiceResult<IEnumerable<OrganizationPolicyDto>>.Success(policyDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get policies by type");
                return ServiceResult<IEnumerable<OrganizationPolicyDto>>.Failure("Failed to get policies by type");
            }
        }

        /// <summary>
        /// 새 정책 생성
        /// </summary>
        public async Task<ServiceResult<OrganizationPolicyDto>> CreateAsync(
            CreateOrganizationPolicyRequest request,
            Guid createdByConnectedId)
        {
            try
            {
                // OrganizationId가 request에 포함되어 있다고 가정
                var organizationId = request.OrganizationId;

                // 중복 체크
                var existing = await _repository.GetByNameAsync(organizationId, request.PolicyName);
                if (existing != null)
                {
                    return ServiceResult<OrganizationPolicyDto>.Failure($"Policy with name '{request.PolicyName}' already exists");
                }

                // 엔티티 생성
                var policy = new OrganizationPolicy
                {
                    OrganizationId = organizationId,
                    PolicyType = request.PolicyType,
                    PolicyName = request.PolicyName,
                    Description = request.Description,
                    PolicyRules = request.PolicyRules,
                    ApplicableCapabilities = request.ApplicableCapabilities,
                    Priority = request.Priority,
                    EffectiveFrom = request.EffectiveFrom ?? DateTime.UtcNow,
                    EffectiveUntil = request.EffectiveTo,
                    IsEnabled = request.IsEnabled,
                    IsInheritable = request.IsInheritable,
                    ComplianceStandards = request.ComplianceStandards,
                    ViolationAction = request.ViolationAction,
                    IsDetailedAuditEnabled = request.IsDetailedAuditEnabled,
                    IsActivityTrackingEnabled = request.IsActivityTrackingEnabled,
                    IsRealTimeMonitoringEnabled = request.IsRealTimeMonitoringEnabled,
                    Metadata = request.Metadata,
                    Version = 1,
                    CreatedByConnectedId = createdByConnectedId,
                    CreatedAt = DateTime.UtcNow
                };

                var created = await _repository.AddAsync(policy);
                var dto = _mapper.Map<OrganizationPolicyDto>(created);

                // 캐시 무효화
                InvalidatePolicyCache(organizationId);

                _logger.LogInformation(
                    "Policy {PolicyName} created for organization {OrganizationId} by {ConnectedId}",
                    request.PolicyName, organizationId, createdByConnectedId);

                return ServiceResult<OrganizationPolicyDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create policy");
                return ServiceResult<OrganizationPolicyDto>.Failure("Failed to create policy");
            }
        }

        /// <summary>
        /// 정책 수정
        /// </summary>
        public async Task<ServiceResult<OrganizationPolicyDto>> UpdateAsync(
            Guid policyId,
            UpdateOrganizationPolicyRequest request,
            Guid updatedByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult<OrganizationPolicyDto>.Failure("Policy not found");
                }

                if (policy.IsSystemPolicy)
                {
                    return ServiceResult<OrganizationPolicyDto>.Failure("System policies cannot be modified");
                }

                // 업데이트 적용 (null이 아닌 값만 업데이트)
                if (!string.IsNullOrWhiteSpace(request.PolicyName))
                    policy.PolicyName = request.PolicyName;

                if (request.Description != null)
                    policy.Description = request.Description;

                if (!string.IsNullOrWhiteSpace(request.PolicyRules))
                    policy.PolicyRules = request.PolicyRules;

                if (request.Priority.HasValue)
                    policy.Priority = request.Priority.Value;

                if (request.IsEnabled.HasValue)
                    policy.IsEnabled = request.IsEnabled.Value;

                if (request.EffectiveFrom.HasValue)
                    policy.EffectiveFrom = request.EffectiveFrom.Value;

                if (request.EffectiveTo.HasValue)
                    policy.EffectiveUntil = request.EffectiveTo;

                if (request.IsInheritable.HasValue)
                    policy.IsInheritable = request.IsInheritable.Value;

                if (!string.IsNullOrWhiteSpace(request.ViolationAction))
                    policy.ViolationAction = request.ViolationAction;

                if (request.IsDetailedAuditEnabled.HasValue)
                    policy.IsDetailedAuditEnabled = request.IsDetailedAuditEnabled.Value;

                if (request.IsActivityTrackingEnabled.HasValue)
                    policy.IsActivityTrackingEnabled = request.IsActivityTrackingEnabled.Value;

                if (request.IsRealTimeMonitoringEnabled.HasValue)
                    policy.IsRealTimeMonitoringEnabled = request.IsRealTimeMonitoringEnabled.Value;

                policy.Version++;
                policy.UpdatedAt = DateTime.UtcNow;
                policy.UpdatedByConnectedId = updatedByConnectedId;

                await _repository.UpdateAsync(policy);

                var dto = _mapper.Map<OrganizationPolicyDto>(policy);

                // 캐시 무효화
                InvalidatePolicyCache(policy.OrganizationId);

                _logger.LogInformation(
                    "Policy {PolicyId} updated by {ConnectedId}",
                    policyId, updatedByConnectedId);

                return ServiceResult<OrganizationPolicyDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update policy {PolicyId}", policyId);
                return ServiceResult<OrganizationPolicyDto>.Failure("Failed to update policy");
            }
        }

        /// <summary>
        /// 정책 삭제
        /// </summary>
        public async Task<ServiceResult> DeleteAsync(
            Guid policyId,
            Guid deletedByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult.Failure("Policy not found");
                }

                if (policy.IsSystemPolicy)
                {
                    return ServiceResult.Failure("System policies cannot be deleted");
                }

                policy.IsDeleted = true;
                policy.DeletedAt = DateTime.UtcNow;
                policy.DeletedByConnectedId = deletedByConnectedId;

                await _repository.UpdateAsync(policy);

                // 캐시 무효화
                InvalidatePolicyCache(policy.OrganizationId);

                _logger.LogInformation(
                    "Policy {PolicyId} deleted by {ConnectedId}",
                    policyId, deletedByConnectedId);

                return ServiceResult.Success("Policy deleted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete policy {PolicyId}", policyId);
                return ServiceResult.Failure("Failed to delete policy");
            }
        }

        #endregion

        #region 정책 활성화 및 적용

        /// <summary>
        /// 정책 활성화/비활성화
        /// </summary>
        public async Task<ServiceResult<OrganizationPolicyDto>> SetEnabledStatusAsync(
            Guid policyId,
            bool isEnabled,
            Guid changedByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult<OrganizationPolicyDto>.Failure("Policy not found");
                }

                policy.IsEnabled = isEnabled;
                policy.UpdatedAt = DateTime.UtcNow;
                policy.UpdatedByConnectedId = changedByConnectedId;

                await _repository.UpdateAsync(policy);

                var dto = _mapper.Map<OrganizationPolicyDto>(policy);

                // 캐시 무효화
                InvalidatePolicyCache(policy.OrganizationId);

                _logger.LogInformation(
                    "Policy {PolicyId} {Status} by {ConnectedId}",
                    policyId, isEnabled ? "enabled" : "disabled", changedByConnectedId);

                return ServiceResult<OrganizationPolicyDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set policy status");
                return ServiceResult<OrganizationPolicyDto>.Failure("Failed to set policy status");
            }
        }

        /// <summary>
        /// 정책 적용
        /// </summary>
        public async Task<ServiceResult> ApplyPolicyAsync(
            Guid policyId,
            Guid appliedByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult.Failure("Policy not found");
                }

                if (!policy.IsEnabled)
                {
                    return ServiceResult.Failure("Cannot apply disabled policy");
                }

                // TODO: 실제 정책 적용 로직 구현
                // 예: 정책 타입에 따른 실제 설정 적용

                _logger.LogInformation(
                    "Policy {PolicyId} applied by {ConnectedId}",
                    policyId, appliedByConnectedId);

                return ServiceResult.Success("Policy applied successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to apply policy");
                return ServiceResult.Failure("Failed to apply policy");
            }
        }

        /// <summary>
        /// 정책 검증
        /// </summary>
        public async Task<ServiceResult<ValidationResult>> ValidatePolicyAsync(
            Guid policyId,
            Guid validatedByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult<ValidationResult>.Failure("Policy not found");
                }

                var result = new ValidationResult
                {
                    IsValid = true,
                    Errors = new List<ValidationError>(),  // ValidationError 타입 유지
                    Warnings = new List<string>()
                };

                // JSON 유효성 검사
                try
                {
                    var parsed = JsonConvert.DeserializeObject(policy.PolicyRules);
                    if (parsed == null)
                    {
                        result.AddError("PolicyRules", "Invalid JSON format", ValidationErrorCodes.InvalidFormat);
                    }
                }
                catch (JsonException ex)
                {
                    result.AddError("PolicyRules", $"JSON parse error - {ex.Message}", ValidationErrorCodes.InvalidFormat);
                }

                // 정책 충돌 검사
                var conflicts = await _repository.GetConflictingPoliciesAsync(
                    policy.OrganizationId,
                    policy.PolicyType,
                    policy.Priority);

                if (conflicts.Any(c => c.Id != policy.Id))
                {
                    result.AddWarning($"Priority: Policy conflicts with {conflicts.Count() - 1} other policies at the same priority");
                }

                // 검증 시간 업데이트
                policy.LastValidatedAt = DateTime.UtcNow;
                policy.LastValidatedByConnectedId = validatedByConnectedId;
                await _repository.UpdateAsync(policy);

                return ServiceResult<ValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate policy");
                return ServiceResult<ValidationResult>.Failure("Failed to validate policy");
            }
        }
        #endregion

        #region 정책 상속

        /// <summary>
        /// 상속된 정책 조회
        /// </summary>
        public async Task<ServiceResult<IEnumerable<OrganizationPolicyDto>>> GetInheritedPoliciesAsync(
            Guid organizationId)
        {
            try
            {
                var pathResult = await _hierarchyService.GetOrganizationPathAsync(organizationId);
                if (!pathResult.IsSuccess || string.IsNullOrEmpty(pathResult.Data))
                {
                    return ServiceResult<IEnumerable<OrganizationPolicyDto>>.Success(
                        new List<OrganizationPolicyDto>());
                }

                var inheritedPolicies = new List<OrganizationPolicyDto>();

                // 경로상의 상위 조직들의 정책 수집
                var pathIds = pathResult.Data.Split('/')
                    .Where(id => !string.IsNullOrEmpty(id) && Guid.TryParse(id, out _))
                    .Select(Guid.Parse)
                    .Where(id => id != organizationId)
                    .ToList();

                foreach (var parentId in pathIds)
                {
                    var policies = await _repository.GetInheritablePoliciesAsync(parentId);
                    var dtos = _mapper.Map<List<OrganizationPolicyDto>>(policies);
                    inheritedPolicies.AddRange(dtos);
                }

                return ServiceResult<IEnumerable<OrganizationPolicyDto>>.Success(inheritedPolicies);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get inherited policies");
                return ServiceResult<IEnumerable<OrganizationPolicyDto>>.Failure(
                    "Failed to get inherited policies");
            }
        }

        /// <summary>
        /// 정책 상속 설정
        /// </summary>
        public async Task<ServiceResult> SetInheritableAsync(
            Guid policyId,
            bool isInheritable,
            Guid setByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult.Failure("Policy not found");
                }

                policy.IsInheritable = isInheritable;
                policy.UpdatedAt = DateTime.UtcNow;
                policy.UpdatedByConnectedId = setByConnectedId;

                await _repository.UpdateAsync(policy);

                // 캐시 무효화
                InvalidatePolicyCache(policy.OrganizationId);

                _logger.LogInformation(
                    "Policy {PolicyId} inheritable set to {IsInheritable} by {ConnectedId}",
                    policyId, isInheritable, setByConnectedId);

                return ServiceResult.Success($"Policy inheritable status set to {isInheritable}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set inheritable status");
                return ServiceResult.Failure("Failed to set inheritable status");
            }
        }
        /// <summary>
        /// 하위 조직에 정책 전파
        /// WHO: 시스템 관리자, 상위 조직 정책 관리자
        /// WHEN: 정책 일괄 적용 필요 시
        /// WHERE: 정책 관리 콘솔
        /// WHAT: 상위 조직 정책을 하위 조직에 복사
        /// WHY: 일관된 정책 적용 및 중앙 관리
        /// HOW: 하위 조직 조회 → 정책 복사 → 결과 집계
        /// </summary>
        public async Task<ServiceResult<PolicyPropagationResult>> PropagatePolicyAsync(
            Guid policyId,
            bool includeAllDescendants,
            Guid propagatedByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult<PolicyPropagationResult>.Failure("Policy not found");
                }

                if (!policy.IsInheritable)
                {
                    return ServiceResult<PolicyPropagationResult>.Failure("Policy is not inheritable");
                }

                var result = new PolicyPropagationResult
                {
                    PolicyId = policyId,
                    SourceOrganizationId = policy.OrganizationId,
                    StartedAt = DateTime.UtcNow
                };

                // 하위 조직 조회 - IOrganizationHierarchyRepository 사용
                var children = await _hierarchyRepository.GetChildrenAsync(
                    policy.OrganizationId,
                    includeAllDescendants);

                result.TargetOrganizationCount = children.Count();

                foreach (var child in children)
                {
                    var detail = new OrganizationPropagationDetail
                    {
                        OrganizationId = child.Id,
                        OrganizationName = child.Name
                    };

                    try
                    {
                        // 기존 정책 확인
                        var existingPolicy = await _repository.GetByNameAsync(child.Id, policy.PolicyName);

                        if (existingPolicy != null)
                        {
                            // 이미 존재하는 경우 건너뛰기
                            detail.Success = false;
                            detail.ErrorMessage = "Policy already exists";
                            result.SkippedCount++;
                        }
                        else
                        {
                            // 정책 복사
                            var newPolicy = new OrganizationPolicy
                            {
                                OrganizationId = child.Id,
                                PolicyType = policy.PolicyType,
                                PolicyName = policy.PolicyName,
                                Description = policy.Description + " (Inherited)",
                                PolicyRules = policy.PolicyRules,
                                ApplicableCapabilities = policy.ApplicableCapabilities,
                                Priority = policy.Priority,
                                EffectiveFrom = policy.EffectiveFrom,
                                EffectiveUntil = policy.EffectiveUntil,
                                IsEnabled = policy.IsEnabled,
                                IsInheritable = false, // 재상속 방지
                                ComplianceStandards = policy.ComplianceStandards,
                                ViolationAction = policy.ViolationAction,
                                IsDetailedAuditEnabled = policy.IsDetailedAuditEnabled,
                                IsActivityTrackingEnabled = policy.IsActivityTrackingEnabled,
                                IsRealTimeMonitoringEnabled = policy.IsRealTimeMonitoringEnabled,
                                Metadata = policy.Metadata,
                                Version = 1,
                                CreatedByConnectedId = propagatedByConnectedId,
                                CreatedAt = DateTime.UtcNow
                            };

                            await _repository.AddAsync(newPolicy);
                            detail.Success = true;
                            result.SuccessCount++;
                        }
                    }
                    catch (Exception ex)
                    {
                        detail.Success = false;
                        detail.ErrorMessage = ex.Message;
                        result.FailureCount++;
                    }

                    result.Details.Add(detail);
                }

                result.CompletedAt = DateTime.UtcNow;
                result.IsSuccess = result.FailureCount == 0;

                _logger.LogInformation(
                    "Policy {PolicyId} propagated to {SuccessCount}/{TargetCount} organizations by {ConnectedId}",
                    policyId, result.SuccessCount, result.TargetOrganizationCount, propagatedByConnectedId);

                return ServiceResult<PolicyPropagationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to propagate policy");
                return ServiceResult<PolicyPropagationResult>.Failure("Failed to propagate policy");
            }
        }

        #endregion

        #region 정책 충돌 및 우선순위

        /// <summary>
        /// 정책 충돌 확인
        /// </summary>
        public async Task<ServiceResult<PolicyConflictResult>> CheckConflictsAsync(
            Guid organizationId,
            OrganizationPolicyType policyType)
        {
            try
            {
                var policies = await _repository.GetByTypeAsync(organizationId, policyType);

                var result = new PolicyConflictResult
                {
                    HasConflicts = false,
                    ConflictingPolicies = new List<ConflictingPolicy>()
                };

                // 우선순위별 그룹화
                var priorityGroups = policies.GroupBy(p => p.Priority);

                foreach (var group in priorityGroups.Where(g => g.Count() > 1))
                {
                    result.HasConflicts = true;
                    result.ConflictType = "Priority";

                    foreach (var policy in group)
                    {
                        result.ConflictingPolicies.Add(new ConflictingPolicy
                        {
                            PolicyId = policy.Id,
                            PolicyName = policy.PolicyName,
                            Priority = policy.Priority,
                            ConflictReason = $"Multiple policies with priority {group.Key}"
                        });
                    }
                }

                if (result.HasConflicts)
                {
                    result.ResolutionSuggestion = "Adjust policy priorities to ensure unique values within the same policy type";
                    result.CanAutoResolve = true;
                }

                return ServiceResult<PolicyConflictResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check conflicts");
                return ServiceResult<PolicyConflictResult>.Failure("Failed to check conflicts");
            }
        }

        /// <summary>
        /// 정책 우선순위 변경
        /// </summary>
        public async Task<ServiceResult> ChangePriorityAsync(
            Guid policyId,
            int newPriority,
            Guid changedByConnectedId)
        {
            try
            {
                var policy = await _repository.GetByIdAsync(policyId);
                if (policy == null)
                {
                    return ServiceResult.Failure("Policy not found");
                }

                // 충돌 확인
                var conflicts = await _repository.GetConflictingPoliciesAsync(
                    policy.OrganizationId,
                    policy.PolicyType,
                    newPriority);

                if (conflicts.Any(c => c.Id != policy.Id))
                {
                    return ServiceResult.Failure($"Priority {newPriority} is already in use by another policy");
                }

                policy.Priority = newPriority;
                policy.UpdatedAt = DateTime.UtcNow;
                policy.UpdatedByConnectedId = changedByConnectedId;

                await _repository.UpdateAsync(policy);

                // 캐시 무효화
                InvalidatePolicyCache(policy.OrganizationId);

                _logger.LogInformation(
                    "Policy {PolicyId} priority changed to {Priority} by {ConnectedId}",
                    policyId, newPriority, changedByConnectedId);

                return ServiceResult.Success($"Policy priority changed to {newPriority}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change priority");
                return ServiceResult.Failure("Failed to change priority");
            }
        }

        /// <summary>
        /// 효과적인 정책 계산
        /// </summary>
        public async Task<ServiceResult<OrganizationPolicyDto>> GetEffectivePolicyAsync(
            Guid organizationId,
            OrganizationPolicyType policyType)
        {
            try
            {
                // 캐시 확인
                var cacheKey = $"{CACHE_KEY_EFFECTIVE}{organizationId}_{policyType}";
                if (_cache.TryGetValue<OrganizationPolicyDto>(cacheKey, out var cached) && cached != null)
                {
                    return ServiceResult<OrganizationPolicyDto>.Success(cached);
                }

                // 최고 우선순위 정책 조회
                var policy = await _repository.GetHighestPriorityAsync(organizationId, policyType);

                if (policy == null)
                {
                    // 상속된 정책 확인
                    var inheritedPolicies = await GetInheritedPoliciesAsync(organizationId);
                    if (inheritedPolicies.IsSuccess && inheritedPolicies.Data != null)
                    {
                        var inheritedPolicy = inheritedPolicies.Data
                            .Where(p => p.PolicyType == policyType && p.IsEffective)
                            .OrderBy(p => p.Priority)
                            .FirstOrDefault();

                        if (inheritedPolicy != null)
                        {
                            // 캐시 저장
                            _cache.Set(cacheKey, inheritedPolicy, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));
                            return ServiceResult<OrganizationPolicyDto>.Success(inheritedPolicy);
                        }
                    }

                    return ServiceResult<OrganizationPolicyDto>.Failure("No effective policy found");
                }

                var dto = _mapper.Map<OrganizationPolicyDto>(policy);

                // 캐시 저장
                _cache.Set(cacheKey, dto, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));

                return ServiceResult<OrganizationPolicyDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get effective policy");
                return ServiceResult<OrganizationPolicyDto>.Failure("Failed to get effective policy");
            }
        }

        #endregion

        #region 모니터링 정책

        /// <summary>
        /// 감사 로그 정책 설정
        /// </summary>
        public async Task<ServiceResult> SetAuditPolicyAsync(
            Guid organizationId,
            AuditPolicySettings settings,
            Guid setByConnectedId)
        {
            try
            {
                var policyRules = JsonConvert.SerializeObject(settings);

                var request = new CreateOrganizationPolicyRequest
                {
                    OrganizationId = organizationId,
                    PolicyType = OrganizationPolicyType.Monitoring,
                    PolicyName = "Audit Policy",
                    Description = "Audit logging and retention policy",
                    PolicyRules = policyRules,
                    IsDetailedAuditEnabled = true,
                    Priority = 10,
                    ViolationAction = "LOG"
                };

                var result = await CreateAsync(request, setByConnectedId);

                return result.IsSuccess
                    ? ServiceResult.Success("Audit policy set successfully")
                    : ServiceResult.Failure(result.ErrorMessage ?? "Failed to set audit policy");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set audit policy");
                return ServiceResult.Failure("Failed to set audit policy");
            }
        }

        /// <summary>
        /// 활동 추적 정책 설정
        /// </summary>
        public async Task<ServiceResult> SetActivityTrackingPolicyAsync(
            Guid organizationId,
            ActivityTrackingSettings settings,
            Guid setByConnectedId)
        {
            try
            {
                var policyRules = JsonConvert.SerializeObject(settings);

                var request = new CreateOrganizationPolicyRequest
                {
                    OrganizationId = organizationId,
                    PolicyType = OrganizationPolicyType.Monitoring,
                    PolicyName = "Activity Tracking Policy",
                    Description = "User activity tracking policy",
                    PolicyRules = policyRules,
                    IsActivityTrackingEnabled = true,
                    Priority = 20,
                    ViolationAction = "LOG"
                };

                var result = await CreateAsync(request, setByConnectedId);

                return result.IsSuccess
                    ? ServiceResult.Success("Activity tracking policy set successfully")
                    : ServiceResult.Failure(result.ErrorMessage ?? "Failed to set activity tracking policy");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set activity tracking policy");
                return ServiceResult.Failure("Failed to set activity tracking policy");
            }
        }

        /// <summary>
        /// 실시간 모니터링 정책 설정
        /// </summary>
        public async Task<ServiceResult> SetRealTimeMonitoringPolicyAsync(
            Guid organizationId,
            RealTimeMonitoringSettings settings,
            Guid setByConnectedId)
        {
            try
            {
                var policyRules = JsonConvert.SerializeObject(settings);

                var request = new CreateOrganizationPolicyRequest
                {
                    OrganizationId = organizationId,
                    PolicyType = OrganizationPolicyType.Security,
                    PolicyName = "Real-time Monitoring Policy",
                    Description = "Real-time security monitoring policy",
                    PolicyRules = policyRules,
                    IsRealTimeMonitoringEnabled = true,
                    Priority = 5,
                    ViolationAction = "WARN"
                };

                var result = await CreateAsync(request, setByConnectedId);

                return result.IsSuccess
                    ? ServiceResult.Success("Real-time monitoring policy set successfully")
                    : ServiceResult.Failure(result.ErrorMessage ?? "Failed to set real-time monitoring policy");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set real-time monitoring policy");
                return ServiceResult.Failure("Failed to set real-time monitoring policy");
            }
        }

        #endregion

        #region Private Helper Methods

        private void InvalidatePolicyCache(Guid organizationId)
        {
            // 간단한 캐시 무효화
            // 실제로는 Redis 등을 사용하여 패턴 매칭으로 무효화
            var keys = new[]
            {
                $"{CACHE_KEY_POLICY}*",
                $"{CACHE_KEY_EFFECTIVE}{organizationId}*"
            };

            // MemoryCache는 패턴 매칭을 지원하지 않으므로
            // 실제 구현에서는 캐시 키를 추적하거나 Redis 사용 필요
        }

        #endregion
    }
}