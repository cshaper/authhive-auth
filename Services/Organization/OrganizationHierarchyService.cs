using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Constants.Business;
using AutoMapper;
using Microsoft.Extensions.Logging;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Core.Interfaces.Proxy.Service; // PropagateOrganizationSettingsResponse 등을 위해 추가

namespace AuthHive.Business.Services.Organization
{
    /// <summary>
    /// 조직 계층 구조 관리 서비스 - AuthHive v16
    /// IMemoryCache를 ICacheService로 교체하고, IPlanService 연동, IEventBus 및 IAuditService를 통합
    /// </summary>
    public class OrganizationHierarchyService : IOrganizationHierarchyService
    {
        private readonly IOrganizationRepository _repository;
        private readonly IOrganizationHierarchyRepository _hierarchyRepository;
        private readonly IOrganizationService _organizationService;
        private readonly IPlanService _planService;
        private readonly IUsageTrackingService _usageTrackingService;
        private readonly IOrganizationSettingsService _settingsService; // <<-- 수정: 설정 전문가 서비스 주입
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ICacheService _cacheService;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly ILogger<OrganizationHierarchyService> _logger;

        public OrganizationHierarchyService(
            IOrganizationRepository repository,
            IOrganizationHierarchyRepository hierarchyRepository,
            IOrganizationService organizationService,
            IPlanService planService,
            IUsageTrackingService usageTrackingService,
            IOrganizationSettingsService settingsService, // <<-- 수정: 생성자에서 주입
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ICacheService cacheService,
            IEventBus eventBus,
            IAuditService auditService,
            ILogger<OrganizationHierarchyService> logger)
        {
            _repository = repository;
            _hierarchyRepository = hierarchyRepository;
            _organizationService = organizationService;
            _planService = planService;
            _usageTrackingService = usageTrackingService;
            _settingsService = settingsService; // <<-- 수정: 필드 할당
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _cacheService = cacheService;
            _eventBus = eventBus;
            _auditService = auditService;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                await _repository.CountAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationHierarchyService health check failed.");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationHierarchyService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region IOrganizationHierarchyService Implementation

        public async Task<ServiceResult<Guid?>> GetParentOrganizationIdAsync(Guid organizationId)
        {
            try
            {
                var cacheKey = $"org:hierarchy:parent:{organizationId}";
                var cachedResult = await _cacheService.GetAsync<ParentIdCache>(cacheKey);
                if (cachedResult != null)
                {
                    return ServiceResult<Guid?>.Success(cachedResult.ParentId);
                }

                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<Guid?>.NotFound("Organization not found.");
                }

                var cacheValue = new ParentIdCache { ParentId = organization.ParentId };
                await _cacheService.SetAsync(cacheKey, cacheValue, TimeSpan.FromMinutes(15));
                return ServiceResult<Guid?>.Success(organization.ParentId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get parent organization ID for {OrganizationId}", organizationId);
                return ServiceResult<Guid?>.Failure("An error occurred while retrieving the parent organization ID.");
            }
        }

        public async Task<ServiceResult<OrganizationDto>> CreateChildOrganizationAsync(
                    Guid parentOrganizationId, CreateOrganizationRequest request, Guid createdByConnectedId)
        {
            try
            {
                var depthLimitResult = await GetDepthLimitAsync(parentOrganizationId);
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
                var createResult = await _organizationService.CreateAsync(request, createdByConnectedId);

                if (createResult.IsSuccess && createResult.Data != null)
                {
                    await InvalidateHierarchyCache(parentOrganizationId);
                    var createdOrgResponse = createResult.Data;

                    // 응답 객체의 정보로 OrganizationDto를 직접 생성합니다.
                    var newOrg = new OrganizationDto
                    {
                        Id = createdOrgResponse.Id,
                        Name = createdOrgResponse.Name,
                    };

                    await _eventBus.PublishAsync(new OrganizationCreatedEvent(newOrg.Id)
                    {
                        OrganizationId = newOrg.Id,
                        ParentOrganizationId = parentOrganizationId,
                        CreatedByConnectedId = createdByConnectedId,
                        CreatedAt = DateTime.UtcNow
                    });

                    await _auditService.LogActionAsync(
                        createdByConnectedId, "CHILD_ORGANIZATION_CREATED", AuditActionType.Create,
                        "Organization", newOrg.Id.ToString(), true,
                        $"Created child organization under parent {parentOrganizationId}");

                    return ServiceResult<OrganizationDto>.Success(newOrg);

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
            Guid organizationId,
            int? maxDepth = null)
        {
            try
            {
                // <<-- 수정: ?? 연산자를 GetValueOrDefault로 변경
                var cacheKey = $"org:hierarchy:tree:{organizationId}_{maxDepth.GetValueOrDefault(0)}";
                var cachedTree = await _cacheService.GetAsync<OrganizationHierarchyTree>(cacheKey);
                if (cachedTree != null)
                {
                    return ServiceResult<OrganizationHierarchyTree>.Success(cachedTree);
                }

                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationHierarchyTree>.NotFound("Organization not found.");
                }

                // <<-- 수정: ?? 연산자를 GetValueOrDefault로 변경
                var tree = await BuildHierarchyTreeAsync(organization, maxDepth.GetValueOrDefault(10));
                await _cacheService.SetAsync(cacheKey, tree, TimeSpan.FromMinutes(30));
                return ServiceResult<OrganizationHierarchyTree>.Success(tree);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization tree for {OrganizationId}", organizationId);
                return ServiceResult<OrganizationHierarchyTree>.Failure("Failed to retrieve organization tree.");
            }
        }

        public async Task<ServiceResult<bool>> MoveOrganizationAsync(
            Guid organizationId,
            Guid? newParentId,
            Guid movedByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var validationResult = await ValidateHierarchyAsync(organizationId, newParentId);
                if (!validationResult.IsSuccess || validationResult.Data?.IsValid == false)
                {
                    return ServiceResult<bool>.Failure(
                        validationResult.Data?.ValidationErrors.FirstOrDefault() ?? "Invalid hierarchy move operation.",
                        "HIERARCHY_VALIDATION_FAILED");
                }

                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<bool>.Failure("Organization not found.", "ORGANIZATION_NOT_FOUND");
                }

                var oldParentId = organization.ParentId;
                organization.ParentId = newParentId;
                organization.UpdatedByConnectedId = movedByConnectedId;
                organization.UpdatedAt = DateTime.UtcNow;

                await _repository.UpdateAsync(organization);
                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                await InvalidateHierarchyCache(organizationId);
                if (oldParentId.HasValue) await InvalidateHierarchyCache(oldParentId.Value);
                if (newParentId.HasValue) await InvalidateHierarchyCache(newParentId.Value);

                // <<-- 수정: BaseEvent 상속 및 생성자 호출
                await _eventBus.PublishAsync(new OrganizationMovedEvent(organizationId)
                {
                    OrganizationId = organizationId,
                    OldParentId = oldParentId,
                    NewParentId = newParentId,
                    MovedByConnectedId = movedByConnectedId,
                    MovedAt = DateTime.UtcNow
                });

                await _auditService.LogActionAsync(
                    movedByConnectedId, "ORGANIZATION_MOVED", AuditActionType.Update,
                    "OrganizationHierarchy", organizationId.ToString(), true,
                    $"Moved from parent '{oldParentId}' to '{newParentId}'");

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Failed to move organization {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure("Failed to move organization.");
            }
        }

        public async Task<ServiceResult<HierarchyValidationResult>> ValidateHierarchyAsync(
            Guid organizationId,
            Guid? proposedParentId)
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
                    var hasCircular = await CheckCircularReferenceAsync(organizationId, proposedParentId.Value);
                    if (hasCircular)
                    {
                        result.IsValid = false;
                        result.HasCircularReference = true;
                        result.ValidationErrors.Add("Circular reference detected in hierarchy.");
                    }

                    var depthCheck = await CheckDepthLimitForMoveAsync(organizationId, proposedParentId.Value);
                    if (!depthCheck.IsWithinLimit)
                    {
                        result.IsValid = false;
                        result.ExceedsMaxDepth = true;
                        result.MaxAllowedDepth = depthCheck.MaxAllowedDepth;
                        result.CurrentDepth = depthCheck.CurrentDepth;
                        result.ValidationErrors.Add($"Maximum depth ({depthCheck.MaxAllowedDepth}) would be exceeded.");
                    }
                }

                var descendants = await _hierarchyRepository.GetDescendantsAsync(organizationId);
                result.AffectedChildOrganizations = descendants.Count();
                result.HierarchyPath = await GetHierarchyPathIdsAsync(organizationId);

                return ServiceResult<HierarchyValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate hierarchy for {OrganizationId}", organizationId);
                return ServiceResult<HierarchyValidationResult>.Failure("Failed to validate hierarchy.");
            }
        }

        // <<-- 수정: 로직 전체를 IOrganizationSettingsService에 위임
        public async Task<ServiceResult<int>> InheritSettingsToChildrenAsync(
                    Guid parentOrganizationId, PolicyInheritanceMode inheritanceMode, Guid initiatedByConnectedId)
        {
            try
            {
                var propagateRequest = new PropagateOrganizationSettingsRequest
                {
                    ParentOrganizationId = parentOrganizationId,
                    InheritanceMode = inheritanceMode
                };

                var result = await _settingsService.PropagateToChildrenAsync(propagateRequest, initiatedByConnectedId);

                // <<-- 수정: 결과 처리 로직 변경
                if (!result.ErrorMessages.Any()) // 성공은 Errors 리스트가 비어있는지로 판단
                {
                    return ServiceResult<int>.Success(result.AffectedOrganizationsCount);
                }

                // 실패 시, Errors 리스트를 하나의 문자열로 합쳐서 반환
                var combinedErrorMessage = string.Join("; ", result.ErrorMessages);
                return ServiceResult<int>.Failure(combinedErrorMessage, "PROPAGATION_FAILED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to call PropagateToChildrenAsync for {ParentId}", parentOrganizationId);
                return ServiceResult<int>.Failure("An unexpected error occurred.");
            }
        }
        // <<-- 수정: 새 DTO에 맞게 전체 로직 수정
        public async Task<ServiceResult<HierarchyUsageDto>> GetHierarchyUsageAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            try
            {
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<HierarchyUsageDto>.NotFound("Organization not found.");
                }

                var usageHierarchy = await BuildUsageHierarchyAsync(organization, startDate, endDate, 0, "/");
                return ServiceResult<HierarchyUsageDto>.Success(usageHierarchy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get hierarchy usage for {OrganizationId}", organizationId);
                return ServiceResult<HierarchyUsageDto>.Failure("Failed to retrieve hierarchy usage.");
            }
        }

        // <<-- 수정: 새 DTO에 맞게 전체 로직 수정
        public async Task<ServiceResult<HierarchyDepthLimit>> GetDepthLimitAsync(Guid organizationId)
        {
            try
            {
                var planResult = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
                if (planResult == null)
                {
                    return ServiceResult<HierarchyDepthLimit>.Failure("Could not determine organization's plan.");
                }

                var planKey = planResult.PlanKey;
                var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits.GetValueOrDefault(planKey, 1);
                var currentDepth = await _hierarchyRepository.GetHierarchyDepthAsync(organizationId);

                var depthLimit = new HierarchyDepthLimit
                {
                    OrganizationId = organizationId,
                    CurrentPlan = planKey,
                    MaxAllowedDepth = maxDepth,
                    CurrentDepth = currentDepth
                    // RemainingDepth, IsAtLimit 등은 계산 속성이므로 설정 불필요
                };

                return ServiceResult<HierarchyDepthLimit>.Success(depthLimit);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get depth limit for {OrganizationId}", organizationId);
                return ServiceResult<HierarchyDepthLimit>.Failure("Failed to retrieve depth limit.");
            }
        }

        public async Task<ServiceResult<string>> GetOrganizationPathAsync(Guid organizationId)
        {
            try
            {
                var cacheKey = $"org:hierarchy:path:{organizationId}";
                var cachedPath = await _cacheService.GetAsync<string>(cacheKey);
                if (!string.IsNullOrEmpty(cachedPath))
                {
                    return ServiceResult<string>.Success(cachedPath);
                }

                var ancestors = await _hierarchyRepository.GetAncestorsAsync(organizationId);
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<string>.NotFound("Organization not found.");
                }

                var path = string.Join(" / ", ancestors.OrderBy(a => a.Level).Select(a => a.Name).Append(organization.Name));
                await _cacheService.SetAsync(cacheKey, path, TimeSpan.FromMinutes(30));
                return ServiceResult<string>.Success(path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization path for {OrganizationId}", organizationId);
                return ServiceResult<string>.Failure("Failed to retrieve organization path.");
            }
        }

        public async Task<ServiceResult<bool>> ReorderSiblingsAsync(
            Guid organizationId,
            int newSortOrder,
            Guid reorderedByConnectedId)
        {
            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<bool>.NotFound("Organization not found.");
                }

                var siblings = organization.ParentId.HasValue
                    ? await _repository.GetDirectChildrenAsync(organization.ParentId.Value)
                    : Enumerable.Empty<OrganizationEntity>();

                var siblingsList = siblings.OrderBy(s => s.SortOrder).ToList();
                var currentOrgInList = siblingsList.FirstOrDefault(s => s.Id == organization.Id);
                if (currentOrgInList != null)
                {
                    siblingsList.Remove(currentOrgInList);
                }

                var insertIndex = Math.Min(newSortOrder, siblingsList.Count);
                siblingsList.Insert(insertIndex, organization);

                for (int i = 0; i < siblingsList.Count; i++)
                {
                    if (siblingsList[i].SortOrder != i)
                    {
                        siblingsList[i].SortOrder = i;
                        siblingsList[i].UpdatedByConnectedId = reorderedByConnectedId;
                        siblingsList[i].UpdatedAt = DateTime.UtcNow;
                        await _repository.UpdateAsync(siblingsList[i]);
                    }
                }

                await _unitOfWork.SaveChangesAsync();
                await _unitOfWork.CommitTransactionAsync();

                if (organization.ParentId.HasValue)
                {
                    await InvalidateHierarchyCache(organization.ParentId.Value);
                }

                await _auditService.LogActionAsync(
                    reorderedByConnectedId, "SIBLINGS_REORDERED", AuditActionType.Update,
                    "Organization", organizationId.ToString(), true,
                    $"Reordered to position {newSortOrder}");

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Failed to reorder siblings for {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure("Failed to reorder siblings.");
            }
        }

        public async Task<ServiceResult<HierarchyValidationResult>> ValidateHierarchyDepthForPlanAsync(
            Guid organizationId,
            string planKey)
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

                // <<-- 수정: 없는 메서드 대신 로컬 헬퍼 메서드 사용
                var currentDepth = await GetSubtreeMaxDepthAsync(organizationId);
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

                var descendants = await _hierarchyRepository.GetDescendantsAsync(organizationId);
                result.AffectedChildOrganizations = descendants.Count();

                return ServiceResult<HierarchyValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate hierarchy depth for plan {PlanKey}", planKey);
                return ServiceResult<HierarchyValidationResult>.Failure("Failed to validate hierarchy depth.");
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task InvalidateHierarchyCache(Guid organizationId)
        {
            var ancestors = await _hierarchyRepository.GetAncestorsAsync(organizationId);
            var allAffectedIds = new HashSet<Guid> { organizationId };
            foreach (var ancestor in ancestors)
            {
                allAffectedIds.Add(ancestor.Id);
            }

            // 하위 조직의 캐시도 무효화해야 할 수 있으나, 상위 트리만 무효화하는 것이 일반적
            foreach (var id in allAffectedIds)
            {
                // 다양한 깊이의 트리 캐시를 모두 무효화 (와일드카드 삭제가 지원되지 않는 경우)
                for (int i = 0; i <= 20; i++) // 최대 깊이를 상수로 관리하는 것이 좋음
                {
                    await _cacheService.RemoveAsync($"org:hierarchy:tree:{id}_{i}");
                }
                await _cacheService.RemoveAsync($"org:hierarchy:path:{id}");
                await _cacheService.RemoveAsync($"org:hierarchy:parent:{id}");
            }
        }

        private async Task<OrganizationHierarchyTree> BuildHierarchyTreeAsync(
            OrganizationEntity rootOrg,
            int maxDepth)
        {
            var tree = new OrganizationHierarchyTree
            {
                Root = await BuildNodeAsync(rootOrg, 0, maxDepth, "/"),
                PathMap = new Dictionary<Guid, string>()
            };

            PopulateTreeMetadata(tree, tree.Root);
            return tree;
        }

        private async Task<OrganizationNode> BuildNodeAsync(
            OrganizationEntity org,
            int currentLevel,
            int maxDepth,
            string parentPath)
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
                var children = await _repository.GetDirectChildrenAsync(org.Id);
                foreach (var child in children.OrderBy(c => c.SortOrder))
                {
                    var childNode = await BuildNodeAsync(child, currentLevel + 1, maxDepth, node.Path);
                    node.Children.Add(childNode);
                }
            }
            return node;
        }

        private void PopulateTreeMetadata(OrganizationHierarchyTree tree, OrganizationNode node)
        {
            if (node == null) return;
            tree.TotalNodes++;
            tree.MaxDepth = Math.Max(tree.MaxDepth, node.Level);
            tree.PathMap[node.Id] = node.Path;
            foreach (var child in node.Children)
            {
                PopulateTreeMetadata(tree, child);
            }
        }

        private async Task<bool> CheckCircularReferenceAsync(Guid organizationId, Guid proposedParentId)
        {
            var current = proposedParentId;
            var visited = new HashSet<Guid> { organizationId }; // 자기 자신부터 추가
            while (true)
            {
                if (visited.Contains(current))
                {
                    return true;
                }
                visited.Add(current);

                var parent = await _repository.GetByIdAsync(current);
                if (parent?.ParentId == null)
                {
                    break;
                }
                current = parent.ParentId.Value;
            }
            return false;
        }

        private async Task<(bool IsWithinLimit, int MaxAllowedDepth, int CurrentDepth)> CheckDepthLimitForMoveAsync(
            Guid organizationId,
            Guid proposedParentId)
        {
            var planResult = await _planService.GetCurrentSubscriptionForOrgAsync(proposedParentId);
            var planKey = planResult?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
            var maxDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits.GetValueOrDefault(planKey, 1);

            var parentDepth = await _hierarchyRepository.GetHierarchyDepthAsync(proposedParentId);
            // <<-- 수정: 없는 메서드 대신 로컬 헬퍼 메서드 사용
            var subtreeMaxDepth = await GetSubtreeMaxDepthAsync(organizationId);
            var totalDepthAfterMove = parentDepth + subtreeMaxDepth;

            return (totalDepthAfterMove <= maxDepth, maxDepth, totalDepthAfterMove);
        }

        private async Task<List<Guid>> GetHierarchyPathIdsAsync(Guid organizationId)
        {
            var path = new List<Guid>();
            var currentId = (Guid?)organizationId;
            while (currentId.HasValue)
            {
                path.Insert(0, currentId.Value);
                var org = await _repository.GetByIdAsync(currentId.Value);
                currentId = org?.ParentId;
            }
            return path;
        }

        // <<-- 추가: GetHierarchyUsageAsync를 위한 재귀 헬퍼 메서드
        private async Task<HierarchyUsageDto> BuildUsageHierarchyAsync(
            OrganizationEntity organization, DateTime startDate, DateTime endDate, int level, string path)
        {
            // AutoMapper 설정이 필요함: IUsageTrackingService의 반환 모델 -> UsageMetrics
            var directUsageResult = await _usageTrackingService.GetOrganizationUsageAsync(organization.Id, startDate, endDate);
            var directUsage = _mapper.Map<UsageMetrics>(directUsageResult);

            var hierarchyDto = new HierarchyUsageDto
            {
                OrganizationId = organization.Id,
                OrganizationName = organization.Name,
                StartDate = startDate,
                EndDate = endDate,
                DirectUsage = directUsage,
                TotalUsage = _mapper.Map<UsageMetrics>(directUsage), // 깊은 복사를 위해 매퍼 사용
                HierarchyLevel = level,
                HierarchyPath = $"{path}{organization.Name}/"
            };

            var children = await _repository.GetDirectChildrenAsync(organization.Id);
            foreach (var child in children)
            {
                var childUsageDto = await BuildUsageHierarchyAsync(child, startDate, endDate, level + 1, hierarchyDto.HierarchyPath);

                // 자식의 TotalUsage를 현재 조직의 TotalUsage에 합산
                hierarchyDto.TotalUsage.ApiCalls += childUsageDto.TotalUsage.ApiCalls;
                hierarchyDto.TotalUsage.StorageUsed += childUsageDto.TotalUsage.StorageUsed;
                hierarchyDto.TotalUsage.ActiveUsers += childUsageDto.TotalUsage.ActiveUsers;
                // ... 나머지 UsageMetrics 속성들 합산 ...

                hierarchyDto.ChildrenUsage.Add(childUsageDto);
            }

            hierarchyDto.TotalOrganizations = 1 + hierarchyDto.ChildrenUsage.Sum(c => c.TotalOrganizations);
            return hierarchyDto;
        }

        // <<-- 추가: GetMaxDepthInHierarchyAsync를 대체하는 로컬 헬퍼 메서드
        private async Task<int> GetSubtreeMaxDepthAsync(Guid organizationId)
        {
            var descendants = await _hierarchyRepository.GetDescendantsAsync(organizationId);
            if (!descendants.Any())
            {
                return 1; // 자식이 없으면 깊이는 1
            }

            int maxDepth = 0;
            var baseDepth = await _hierarchyRepository.GetHierarchyDepthAsync(organizationId);

            foreach (var descendant in descendants)
            {
                var descendantDepth = await _hierarchyRepository.GetHierarchyDepthAsync(descendant.Id);
                var relativeDepth = descendantDepth - baseDepth;
                if (relativeDepth > maxDepth)
                {
                    maxDepth = relativeDepth;
                }
            }
            return maxDepth + 1;
        }

        #endregion

        #region Event and Cache Wrapper Classes

        // <<-- 수정: BaseEvent 상속 및 생성자 추가
        public class OrganizationCreatedEvent : BaseEvent
        {

            public Guid ParentOrganizationId { get; init; }
            public Guid CreatedByConnectedId { get; init; }
            public DateTime CreatedAt { get; init; }
            public OrganizationCreatedEvent(Guid aggregateId) : base(aggregateId) { }
        }

        public class OrganizationMovedEvent : BaseEvent
        {

            public Guid? OldParentId { get; init; }
            public Guid? NewParentId { get; init; }
            public Guid MovedByConnectedId { get; init; }
            public DateTime MovedAt { get; init; }
            public OrganizationMovedEvent(Guid aggregateId) : base(aggregateId) { }
        }

        public class SettingsInheritedEvent : BaseEvent
        {
            public Guid ParentOrganizationId { get; init; }
            public int AffectedOrganizations { get; init; }
            public PolicyInheritanceMode InheritanceMode { get; init; }
            public Guid InitiatedByConnectedId { get; init; }
            public DateTime InheritedAt { get; init; }
            public SettingsInheritedEvent(Guid aggregateId) : base(aggregateId) { }
        }

        private class ParentIdCache
        {
            public Guid? ParentId { get; set; }
        }

        #endregion
    }
}