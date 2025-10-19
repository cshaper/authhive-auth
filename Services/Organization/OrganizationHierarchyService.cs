using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Proxy.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Events;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
using Microsoft.Extensions.Logging;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;


namespace AuthHive.Business.Services.Organization
{
    /// <summary>
    /// 조직 계층 구조 관리 서비스 - AuthHive v16
    /// </summary>
    public class OrganizationHierarchyService : IOrganizationHierarchyService
    {
        private readonly IOrganizationRepository _repository;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly IOrganizationHierarchyRepository _hierarchyRepository;
        private readonly IOrganizationService _organizationService;
        private readonly IPlanService _planService;
        private readonly IUsageTrackingService _usageTrackingService;
        private readonly IOrganizationSettingsService _settingsService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ICacheService _cacheService;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<OrganizationHierarchyService> _logger;

        public OrganizationHierarchyService(
            IOrganizationRepository repository,
            IPrincipalAccessor principalAccessor,
            IOrganizationHierarchyRepository hierarchyRepository,
            IOrganizationService organizationService,
            IPlanService planService,
            IUsageTrackingService usageTrackingService,
            IOrganizationSettingsService settingsService,
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ICacheService cacheService,
            IEventBus eventBus,
            IAuditService auditService,
            IDateTimeProvider dateTimeProvider,
            ILogger<OrganizationHierarchyService> logger)
        {
            _repository = repository;
            _principalAccessor = principalAccessor;
            _hierarchyRepository = hierarchyRepository;
            _organizationService = organizationService;
            _planService = planService;
            _usageTrackingService = usageTrackingService;
            _settingsService = settingsService;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _cacheService = cacheService;
            _eventBus = eventBus;
            _auditService = auditService;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _repository.CountAsync(null, cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationHierarchyService health check failed.");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("OrganizationHierarchyService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region IOrganizationHierarchyService Implementation

        public async Task<ServiceResult<Guid?>> GetParentOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"org:hierarchy:parent:{organizationId}";
                var cachedResult = await _cacheService.GetAsync<ParentIdCache>(cacheKey, cancellationToken);
                if (cachedResult != null)
                {
                    return ServiceResult<Guid?>.Success(cachedResult.ParentId);
                }

                var organization = await _repository.GetByIdAsync(organizationId, cancellationToken);
                if (organization == null)
                {
                    return ServiceResult<Guid?>.NotFound("Organization not found.");
                }

                var cacheValue = new ParentIdCache { ParentId = organization.ParentId };
                await _cacheService.SetAsync(cacheKey, cacheValue, TimeSpan.FromMinutes(15), cancellationToken);
                return ServiceResult<Guid?>.Success(organization.ParentId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get parent organization ID for {OrganizationId}", organizationId);
                return ServiceResult<Guid?>.Failure("An error occurred while retrieving the parent organization ID.");
            }
        }
        public async Task<ServiceResult<OrganizationDto>> CreateChildOrganizationAsync(
                    Guid parentOrganizationId, CreateOrganizationRequest request, CancellationToken cancellationToken = default)
        {
            // v16 원칙: 서비스가 직접 IPrincipalAccessor를 통해 '누가' 요청했는지 알아냅니다.
            var createdByConnectedId = _principalAccessor.ConnectedId;

            if (!createdByConnectedId.HasValue)
            {
                return ServiceResult<OrganizationDto>.Unauthorized("User is not authenticated or ConnectedId is missing.");
            }

            try
            {
                var depthLimitResult = await GetDepthLimitAsync(parentOrganizationId, cancellationToken);
                if (!depthLimitResult.IsSuccess || depthLimitResult.Data == null)
                {
                    return ServiceResult<OrganizationDto>.Failure("Failed to verify depth limit.", "DEPTH_CHECK_FAILED");
                }

                if (depthLimitResult.Data.IsAtLimit)
                {
                    return ServiceResult<OrganizationDto>.Failure(
                        $"Maximum hierarchy depth ({depthLimitResult.Data.MaxAllowedDepth}) exceeded for the {depthLimitResult.Data.CurrentPlan} plan.",
                        "HIERARCHY_DEPTH_LIMIT_EXCEEDED");
                }

                request.ParentId = parentOrganizationId;

                // IPrincipalAccessor에서 가져온 createdByConnectedId.Value를 전달합니다.
                var createResult = await _organizationService.CreateAsync(request, createdByConnectedId.Value, cancellationToken);

                if (createResult.IsSuccess && createResult.Data != null)
                {
                    await InvalidateHierarchyCache(parentOrganizationId, cancellationToken);
                    var createdOrgResponse = createResult.Data;
                    var newOrg = await _repository.GetByIdAsync(createdOrgResponse.Id, cancellationToken);
                    var newOrgDto = _mapper.Map<OrganizationDto>(newOrg);

                    // 수정: 불변 객체 원칙에 따라 새로운 생성자를 사용하여 이벤트를 생성합니다.
                    await _eventBus.PublishAsync(new OrganizationCreatedEvent(
                        organizationId: newOrgDto.Id,
                        parentOrganizationId: parentOrganizationId,
                        createdByConnectedId: createdByConnectedId.Value,
                        organizationKey: newOrgDto.OrganizationKey,
                        name: newOrgDto.Name,
                        type: newOrgDto.Type
                    ), cancellationToken);

                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Create,
                        action: "CHILD_ORGANIZATION_CREATED",
                        connectedId: createdByConnectedId.Value,
                        success: true,
                        resourceType: "Organization",
                        resourceId: newOrgDto.Id.ToString(),
                        metadata: new Dictionary<string, object> { { "ParentId", parentOrganizationId } },
                        cancellationToken: cancellationToken);

                    return ServiceResult<OrganizationDto>.Success(newOrgDto);
                }

                return ServiceResult<OrganizationDto>.Failure(
                    createResult.ErrorMessage ?? "Failed to create child organization.",
                    createResult.ErrorCode);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create child organization for parent {ParentId}", parentOrganizationId);
                return ServiceResult<OrganizationDto>.Failure("An unexpected error occurred.");
            }
        }
        public async Task<ServiceResult<OrganizationHierarchyTree>> GetOrganizationTreeAsync(
            Guid organizationId, int? maxDepth = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"org:hierarchy:tree:{organizationId}_{maxDepth.GetValueOrDefault(0)}";
                var cachedTree = await _cacheService.GetAsync<OrganizationHierarchyTree>(cacheKey, cancellationToken);
                if (cachedTree != null)
                {
                    return ServiceResult<OrganizationHierarchyTree>.Success(cachedTree);
                }

                var organization = await _repository.GetByIdAsync(organizationId, cancellationToken);
                if (organization == null)
                {
                    return ServiceResult<OrganizationHierarchyTree>.NotFound("Organization not found.");
                }

                var tree = await BuildHierarchyTreeAsync(organization, maxDepth.GetValueOrDefault(10), cancellationToken);
                await _cacheService.SetAsync(cacheKey, tree, TimeSpan.FromMinutes(30), cancellationToken);
                return ServiceResult<OrganizationHierarchyTree>.Success(tree);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization tree for {OrganizationId}", organizationId);
                return ServiceResult<OrganizationHierarchyTree>.Failure("Failed to retrieve organization tree.");
            }
        }

        public async Task<ServiceResult<bool>> MoveOrganizationAsync(
            Guid organizationId, Guid? newParentId, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            var movedBy = _principalAccessor.ConnectedId;

            if (!movedBy.HasValue)
            {
                return ServiceResult<bool>.Unauthorized("User is not authenticated.");
            }
            try
            {
                var validationResult = await ValidateHierarchyAsync(organizationId, newParentId, cancellationToken);
                if (!validationResult.IsSuccess || validationResult.Data?.IsValid == false)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult<bool>.Failure(
                        validationResult.Data?.ValidationErrors.FirstOrDefault() ?? "Invalid hierarchy move operation.",
                        "HIERARCHY_VALIDATION_FAILED");
                }

                var organization = await _repository.GetByIdAsync(organizationId, cancellationToken);
                if (organization == null)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult<bool>.Failure("Organization not found.", "ORGANIZATION_NOT_FOUND");
                }

                var oldParentId = organization.ParentId;
                organization.ParentId = newParentId;
                organization.UpdatedByConnectedId = movedBy;
                organization.UpdatedAt = DateTime.UtcNow;

                await _repository.UpdateAsync(organization, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                await InvalidateHierarchyCache(organizationId, cancellationToken);
                if (oldParentId.HasValue) await InvalidateHierarchyCache(oldParentId.Value, cancellationToken);
                if (newParentId.HasValue) await InvalidateHierarchyCache(newParentId.Value, cancellationToken);

                await _eventBus.PublishAsync(
                    new OrganizationParentChangedEvent(
                        organizationId, oldParentId, newParentId, "Organization hierarchy was restructured.", movedBy
                    ), cancellationToken);

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    "ORGANIZATION_MOVED",
                    connectedId: movedBy.Value,
                    true,
                    resourceType: "OrganizationHierarchy",
                    resourceId: organizationId.ToString(),
                    metadata: new Dictionary<string, object>
                    {
                        { "OldParentId", (object?)oldParentId ?? "ROOT" },
                        { "NewParentId", (object?)newParentId ?? "ROOT" }
                    },
                    cancellationToken: cancellationToken);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to move organization {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure("Failed to move organization.");
            }
        }

        public async Task<ServiceResult<HierarchyValidationResult>> ValidateHierarchyAsync(
            Guid organizationId, Guid? proposedParentId, CancellationToken cancellationToken = default)
        {
            try
            {
                var result = new HierarchyValidationResult
                {
                    IsValid = true,
                    OrganizationId = organizationId,
                    ProposedParentId = proposedParentId,
                    ValidationErrors = new List<string>(),
                    ValidatedAt = DateTime.UtcNow
                };

                if (proposedParentId == organizationId)
                {
                    result.IsValid = false;
                    result.ValidationErrors.Add("An organization cannot be its own parent.");
                    return ServiceResult<HierarchyValidationResult>.Success(result);
                }

                if (proposedParentId.HasValue)
                {
                    var hasCircular = await CheckCircularReferenceAsync(organizationId, proposedParentId.Value, cancellationToken);
                    if (hasCircular)
                    {
                        result.IsValid = false;
                        result.HasCircularReference = true;
                        result.ValidationErrors.Add("Circular reference detected in hierarchy.");
                    }

                    var depthCheck = await CheckDepthLimitForMoveAsync(organizationId, proposedParentId.Value, cancellationToken);
                    if (!depthCheck.IsWithinLimit)
                    {
                        result.IsValid = false;
                        result.ExceedsMaxDepth = true;
                        result.MaxAllowedDepth = depthCheck.MaxAllowedDepth;
                        result.CurrentDepth = depthCheck.CurrentDepth;
                        result.ValidationErrors.Add($"Maximum depth ({depthCheck.MaxAllowedDepth}) would be exceeded.");
                    }
                }

                var descendants = await _hierarchyRepository.GetDescendantsAsync(organizationId, null, cancellationToken);
                result.AffectedChildOrganizations = descendants.Count();
                result.HierarchyPath = await GetHierarchyPathIdsAsync(organizationId, cancellationToken);

                return ServiceResult<HierarchyValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate hierarchy for {OrganizationId}", organizationId);
                return ServiceResult<HierarchyValidationResult>.Failure("Failed to validate hierarchy.");
            }
        }

        public async Task<ServiceResult<int>> InheritSettingsToChildrenAsync(
            Guid parentOrganizationId, PolicyInheritanceMode inheritanceMode, CancellationToken cancellationToken = default)
        {
            // 수정: IPrincipalAccessor를 통해 현재 요청의 주체를 직접 가져옵니다.
            var initiatedByConnectedId = _principalAccessor.ConnectedId;

            // 보안 강화: 요청 주체가 확인되지 않으면 작업을 중단합니다.
            if (!initiatedByConnectedId.HasValue)
            {
                return ServiceResult<int>.Unauthorized("User is not authenticated or ConnectedId is missing.");
            }

            try
            {
                var propagateRequest = new PropagateOrganizationSettingsRequest
                {
                    ParentOrganizationId = parentOrganizationId,
                    InheritanceMode = inheritanceMode
                };

                // 수정: 서비스 호출 시 initiatedByConnectedId를 전달하지 않습니다.
                // _settingsService가 v16 원칙에 따라 IPrincipalAccessor를 직접 사용해야 합니다.
                var result = await _settingsService.PropagateToChildrenAsync(propagateRequest, cancellationToken);

                // 수정: ServiceResult의 표준적인 성공/실패 처리 방식을 사용합니다.
                if (result.IsSuccess && result.Data != null)
                {
                    await _auditService.LogActionAsync(
                        actionType: AuditActionType.Update,
                        action: "SETTINGS_INHERITED",
                        connectedId: initiatedByConnectedId.Value,
                        success: true,
                        resourceType: "OrganizationSettings",
                        resourceId: parentOrganizationId.ToString(),
                        metadata: new Dictionary<string, object>
                        {
                            { "Mode", inheritanceMode.ToString() },
                            { "AffectedChildren", result.Data.AffectedOrganizationsCount }
                        },
                        cancellationToken: cancellationToken);

                    return ServiceResult<int>.Success(result.Data.AffectedOrganizationsCount);
                }

                _logger.LogWarning("Settings propagation failed for parent {ParentId}. Reason: {Error}", parentOrganizationId, result.ErrorMessage);
                return ServiceResult<int>.Failure(result.ErrorMessage ?? "Propagation failed with unspecified errors.", result.ErrorCode ?? "PROPAGATION_FAILED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during InheritSettingsToChildrenAsync for parent {ParentId}", parentOrganizationId);
                return ServiceResult<int>.Failure("An unexpected error occurred while inheriting settings.");
            }
        }
        public async Task<ServiceResult<HierarchyUsageDto>> GetHierarchyUsageAsync(
            Guid organizationId, DateTime startDate, DateTime endDate, CancellationToken cancellationToken = default)
        {
            try
            {
                var organization = await _repository.GetByIdAsync(organizationId, cancellationToken);
                if (organization == null)
                {
                    return ServiceResult<HierarchyUsageDto>.NotFound("Organization not found.");
                }

                var usageHierarchy = await BuildUsageHierarchyAsync(organization, startDate, endDate, 0, "/", cancellationToken);
                return ServiceResult<HierarchyUsageDto>.Success(usageHierarchy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get hierarchy usage for {OrganizationId}", organizationId);
                return ServiceResult<HierarchyUsageDto>.Failure("Failed to retrieve hierarchy usage.");
            }
        }

        public async Task<ServiceResult<HierarchyDepthLimit>> GetDepthLimitAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                var planResult = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId, cancellationToken);
                if (planResult == null)
                {
                    return ServiceResult<HierarchyDepthLimit>.Failure("Could not determine organization's plan.");
                }

                var planKey = planResult.PlanKey;
                var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits.GetValueOrDefault(planKey, 1);
                var currentDepth = await _hierarchyRepository.GetHierarchyDepthAsync(organizationId, cancellationToken);

                var depthLimit = new HierarchyDepthLimit
                {
                    OrganizationId = organizationId,
                    CurrentPlan = planKey,
                    MaxAllowedDepth = maxDepth,
                    CurrentDepth = currentDepth
                };

                return ServiceResult<HierarchyDepthLimit>.Success(depthLimit);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get depth limit for {OrganizationId}", organizationId);
                return ServiceResult<HierarchyDepthLimit>.Failure("Failed to retrieve depth limit.");
            }
        }

        public async Task<ServiceResult<string>> GetOrganizationPathAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"org:hierarchy:path:{organizationId}";
                var cachedPath = await _cacheService.GetAsync<string>(cacheKey, cancellationToken);
                if (!string.IsNullOrEmpty(cachedPath))
                {
                    return ServiceResult<string>.Success(cachedPath);
                }

                var ancestors = await _hierarchyRepository.GetAncestorsAsync(organizationId, cancellationToken);
                var organization = await _repository.GetByIdAsync(organizationId, cancellationToken);
                if (organization == null)
                {
                    return ServiceResult<string>.NotFound("Organization not found.");
                }

                var path = string.Join(" / ", ancestors.OrderBy(a => a.Level).Select(a => a.Name).Append(organization.Name));
                await _cacheService.SetAsync(cacheKey, path, TimeSpan.FromMinutes(30), cancellationToken);
                return ServiceResult<string>.Success(path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization path for {OrganizationId}", organizationId);
                return ServiceResult<string>.Failure("Failed to retrieve organization path.");
            }
        }

        public async Task<ServiceResult<bool>> ReorderSiblingsAsync(
                    Guid organizationId, int newSortOrder, CancellationToken cancellationToken = default)
        {
            // 수정: IPrincipalAccessor를 통해 현재 요청의 주체를 직접 가져옵니다.
            var reorderedByConnectedId = _principalAccessor.ConnectedId;

            // 보안 강화: 요청 주체가 확인되지 않으면 작업을 중단합니다.
            if (!reorderedByConnectedId.HasValue)
            {
                return ServiceResult<bool>.Unauthorized("User is not authenticated or ConnectedId is missing.");
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var organization = await _repository.GetByIdAsync(organizationId, cancellationToken);
                if (organization == null)
                {
                    return ServiceResult<bool>.NotFound("Organization not found.");
                }

                var siblings = organization.ParentId.HasValue
                    ? await _repository.GetDirectChildrenAsync(organization.ParentId.Value, cancellationToken)
                    : Enumerable.Empty<OrganizationEntity>();

                var siblingsList = siblings.OrderBy(s => s.SortOrder).ToList();
                var currentOrgInList = siblingsList.FirstOrDefault(s => s.Id == organization.Id);
                if (currentOrgInList != null)
                {
                    siblingsList.Remove(currentOrgInList);
                }

                // 새 순서가 리스트 범위를 벗어나지 않도록 조정합니다.
                var insertIndex = Math.Clamp(newSortOrder, 0, siblingsList.Count);
                siblingsList.Insert(insertIndex, organization);

                // 재정렬된 리스트를 기반으로 SortOrder와 감사 정보를 업데이트합니다.
                for (int i = 0; i < siblingsList.Count; i++)
                {
                    var siblingToUpdate = siblingsList[i];
                    if (siblingToUpdate.SortOrder != i)
                    {
                        siblingToUpdate.SortOrder = i;
                        // 수정: AuditableEntity의 속성을 업데이트합니다.
                        siblingToUpdate.UpdatedByConnectedId = reorderedByConnectedId.Value;
                        siblingToUpdate.UpdatedAt = _dateTimeProvider.UtcNow; // 수정: IDateTimeProvider 사용
                        await _repository.UpdateAsync(siblingToUpdate, cancellationToken);
                    }
                }

                await _unitOfWork.SaveChangesAsync(cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                if (organization.ParentId.HasValue)
                {
                    await InvalidateHierarchyCache(organization.ParentId.Value, cancellationToken);
                }

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "SIBLINGS_REORDERED",
                    connectedId: reorderedByConnectedId.Value,
                    success: true,
                    resourceType: "Organization",
                    resourceId: organizationId.ToString(),
                    metadata: new Dictionary<string, object> { { "NewSortOrder", newSortOrder } },
                    cancellationToken: cancellationToken);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to reorder siblings for {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure("Failed to reorder siblings.");
            }
        }
        public async Task<ServiceResult<HierarchyValidationResult>> ValidateHierarchyDepthForPlanAsync(
            Guid organizationId, string planKey, CancellationToken cancellationToken = default)
        {
            try
            {
                var result = new HierarchyValidationResult
                {
                    IsValid = true,
                    OrganizationId = organizationId,
                    ValidationErrors = new List<string>(),
                    ValidatedAt = DateTime.UtcNow
                };

                var currentDepth = await GetSubtreeMaxDepthAsync(organizationId, cancellationToken);
                var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits.GetValueOrDefault(planKey, 1);

                result.CurrentDepth = currentDepth;
                result.MaxAllowedDepth = maxDepth;

                if (currentDepth > maxDepth)
                {
                    result.IsValid = false;
                    result.ExceedsMaxDepth = true;
                    result.ValidationErrors.Add(
                        $"Current hierarchy depth ({currentDepth}) exceeds the maximum allowed ({maxDepth}) for plan {planKey}");
                }

                var descendants = await _hierarchyRepository.GetDescendantsAsync(organizationId, null, cancellationToken);
                result.AffectedChildOrganizations = descendants.Count();

                return ServiceResult<HierarchyValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate hierarchy depth for plan {PlanKey}", planKey);
                return ServiceResult<HierarchyValidationResult>.Failure("Failed to validate hierarchy depth.");
            }
        }

        public async Task InvalidateAncestorCachesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var currentOrg = await _repository.GetByIdAsync(organizationId, cancellationToken);
            Guid? parentId = currentOrg?.ParentId;

            while (parentId.HasValue)
            {
                var parent = await _repository.GetByIdAsync(parentId.Value, cancellationToken);
                if (parent == null) break;

                await _cacheService.RemoveByPatternAsync($"org:id:{parent.Id}:children:*", cancellationToken);

                parentId = parent.ParentId;
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task InvalidateHierarchyCache(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var ancestors = await _hierarchyRepository.GetAncestorsAsync(organizationId, cancellationToken);
            var allAffectedIds = new HashSet<Guid> { organizationId };
            foreach (var ancestor in ancestors)
            {
                allAffectedIds.Add(ancestor.Id);
            }

            foreach (var id in allAffectedIds)
            {
                for (int i = 0; i <= 20; i++)
                {
                    await _cacheService.RemoveAsync($"org:hierarchy:tree:{id}_{i}", cancellationToken);
                }
                await _cacheService.RemoveAsync($"org:hierarchy:path:{id}", cancellationToken);
                await _cacheService.RemoveAsync($"org:hierarchy:parent:{id}", cancellationToken);
            }
        }

        private async Task<OrganizationHierarchyTree> BuildHierarchyTreeAsync(
            OrganizationEntity rootOrg, int maxDepth, CancellationToken cancellationToken = default)
        {
            var tree = new OrganizationHierarchyTree
            {
                Root = await BuildNodeAsync(rootOrg, 0, maxDepth, "/", cancellationToken),
                PathMap = new Dictionary<Guid, string>()
            };
            PopulateTreeMetadata(tree, tree.Root);
            return tree;
        }

        private async Task<OrganizationNode> BuildNodeAsync(
            OrganizationEntity org, int currentLevel, int maxDepth, string parentPath, CancellationToken cancellationToken = default)
        {
            var node = new OrganizationNode
            {
                Id = org.Id,
                Name = org.Name,
                OrganizationKey = org.OrganizationKey,
                Level = currentLevel,
                Path = $"{parentPath}{org.Name}/",
                Children = new List<OrganizationNode>()
            };

            if (currentLevel < maxDepth)
            {
                var children = await _repository.GetDirectChildrenAsync(org.Id, cancellationToken);
                foreach (var child in children.OrderBy(c => c.SortOrder))
                {
                    var childNode = await BuildNodeAsync(child, currentLevel + 1, maxDepth, node.Path, cancellationToken);
                    node.Children.Add(childNode);
                }
            }
            return node;
        }

        private void PopulateTreeMetadata(OrganizationHierarchyTree tree, OrganizationNode? node)
        {
            if (node == null) return;
            tree.TotalNodes++;
            tree.MaxDepth = Math.Max(tree.MaxDepth, node.Level);
            if (node.Id != Guid.Empty)
                tree.PathMap[node.Id] = node.Path;

            foreach (var child in node.Children)
            {
                PopulateTreeMetadata(tree, child);
            }
        }

        private async Task<bool> CheckCircularReferenceAsync(Guid organizationId, Guid proposedParentId, CancellationToken cancellationToken = default)
        {
            var current = proposedParentId;
            var visited = new HashSet<Guid> { organizationId };
            while (true)
            {
                if (visited.Contains(current))
                {
                    return true;
                }
                visited.Add(current);

                var parent = await _repository.GetByIdAsync(current, cancellationToken);
                if (parent?.ParentId == null)
                {
                    break;
                }
                current = parent.ParentId.Value;
            }
            return false;
        }

        private async Task<(bool IsWithinLimit, int MaxAllowedDepth, int CurrentDepth)> CheckDepthLimitForMoveAsync(
            Guid organizationId, Guid proposedParentId, CancellationToken cancellationToken = default)
        {
            var planResult = await _planService.GetCurrentSubscriptionForOrgAsync(proposedParentId, cancellationToken);
            var planKey = planResult?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
            var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits.GetValueOrDefault(planKey, 1);

            var parentDepth = await _hierarchyRepository.GetHierarchyDepthAsync(proposedParentId, cancellationToken);
            var subtreeMaxDepth = await GetSubtreeMaxDepthAsync(organizationId, cancellationToken);
            var totalDepthAfterMove = parentDepth + subtreeMaxDepth;

            return (totalDepthAfterMove <= maxDepth, maxDepth, totalDepthAfterMove);
        }

        private async Task<List<Guid>> GetHierarchyPathIdsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var path = new List<Guid>();
            var currentId = (Guid?)organizationId;
            while (currentId.HasValue)
            {
                path.Insert(0, currentId.Value);
                var org = await _repository.GetByIdAsync(currentId.Value, cancellationToken);
                currentId = org?.ParentId;
            }
            return path;
        }

        private async Task<int> GetSubtreeMaxDepthAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var descendants = await _hierarchyRepository.GetDescendantsAsync(organizationId, null, cancellationToken);
            if (!descendants.Any())
            {
                return 1;
            }

            int maxRelativeDepth = 0;
            var baseDepth = await _hierarchyRepository.GetHierarchyDepthAsync(organizationId, cancellationToken);

            foreach (var descendant in descendants)
            {
                var descendantDepth = await _hierarchyRepository.GetHierarchyDepthAsync(descendant.Id, cancellationToken);
                var relativeDepth = descendantDepth - baseDepth;
                if (relativeDepth > maxRelativeDepth)
                {
                    maxRelativeDepth = relativeDepth;
                }
            }
            return maxRelativeDepth + 1;
        }

        private async Task<HierarchyUsageDto> BuildUsageHierarchyAsync(
            OrganizationEntity organization, DateTime startDate, DateTime endDate, int level, string path, CancellationToken cancellationToken = default)
        {
            var directUsageResult = await _usageTrackingService.GetOrganizationUsageAsync(organization.Id, startDate, endDate, cancellationToken);
            var directUsage = _mapper.Map<UsageMetrics>(directUsageResult);

            var hierarchyDto = new HierarchyUsageDto
            {
                OrganizationId = organization.Id,
                OrganizationName = organization.Name,
                StartDate = startDate,
                EndDate = endDate,
                DirectUsage = directUsage,
                TotalUsage = _mapper.Map<UsageMetrics>(directUsage),
                HierarchyLevel = level,
                HierarchyPath = $"{path}{organization.Name}/"
            };

            var children = await _repository.GetDirectChildrenAsync(organization.Id, cancellationToken);
            foreach (var child in children)
            {
                var childUsageDto = await BuildUsageHierarchyAsync(child, startDate, endDate, level + 1, hierarchyDto.HierarchyPath, cancellationToken);

                hierarchyDto.TotalUsage.ApiCalls += childUsageDto.TotalUsage.ApiCalls;
                hierarchyDto.TotalUsage.StorageUsed += childUsageDto.TotalUsage.StorageUsed;
                hierarchyDto.TotalUsage.ActiveUsers += childUsageDto.TotalUsage.ActiveUsers;

                hierarchyDto.ChildrenUsage.Add(childUsageDto);
            }

            hierarchyDto.TotalOrganizations = 1 + hierarchyDto.ChildrenUsage.Sum(c => c.TotalOrganizations);
            return hierarchyDto;
        }

        #endregion

        #region Event and Cache Wrapper Classes

        private class ParentIdCache
        {
            public Guid? ParentId { get; set; }
        }

        #endregion
    }
}

