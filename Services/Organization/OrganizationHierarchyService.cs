using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 계층 구조 관리 서비스 - AuthHive v15
    /// 조직 간의 부모-자식 관계, 계층 탐색, 경로 관리 등을 담당
    /// AWS Organizations 스타일의 계층 구조 지원
    /// </summary>
    public class OrganizationHierarchyService : IOrganizationHierarchyService
    {
        private readonly IOrganizationRepository _repository;
        private readonly AuthDbContext _context;
        private readonly IOrganizationService _organizationService;
        private readonly IMapper _mapper;
        private readonly IMemoryCache _cache;
        private readonly ILogger<OrganizationHierarchyService> _logger;

        // 캐시 키 상수
        private const string CACHE_KEY_TREE = "org:hierarchy:tree:";
        private const string CACHE_KEY_PATH = "org:hierarchy:path:";
        private const int CACHE_DURATION_MINUTES = 15;

        public OrganizationHierarchyService(
            IOrganizationRepository repository,
            AuthDbContext context,
            IOrganizationService organizationService,
            IMapper mapper,
            IMemoryCache cache,
            ILogger<OrganizationHierarchyService> logger)
        {
            _repository = repository;
            _context = context;
            _organizationService = organizationService;
            _mapper = mapper;
            _cache = cache;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                return await _context.Database.CanConnectAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationHierarchyService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationHierarchyService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region IOrganizationHierarchyService Implementation

        /// <summary>
        /// 하위 조직 생성
        /// </summary>
        /// <summary>
        /// 하위 조직 생성
        /// </summary>
        public async Task<ServiceResult<OrganizationDto>> CreateChildOrganizationAsync(
            Guid parentOrganizationId,
            CreateOrganizationRequest request,
            Guid createdByConnectedId)
        {
            try
            {
                // 깊이 제한 확인
                var depthLimit = await GetDepthLimitAsync(parentOrganizationId);
                if (!depthLimit.IsSuccess || depthLimit.Data?.IsAtLimit == true)
                {
                    return ServiceResult<OrganizationDto>.Failure(
                        $"Maximum hierarchy depth ({depthLimit.Data?.MaxAllowedDepth}) exceeded for {depthLimit.Data?.CurrentPlan}");
                }

                // 부모 조직 설정
                request.ParentId = parentOrganizationId;

                // OrganizationService를 통해 생성
                var result = await _organizationService.CreateAsync(request, createdByConnectedId);

                if (result.IsSuccess && result.Data != null)
                {
                    // CreateOrganizationResponse에서 OrganizationDto를 다시 조회
                    var orgResult = await _organizationService.GetByIdAsync(result.Data.Id);

                    if (orgResult.IsSuccess && orgResult.Data != null)
                    {
                        // 캐시 무효화
                        InvalidateHierarchyCache(parentOrganizationId);
                        return ServiceResult<OrganizationDto>.Success(orgResult.Data);
                    }
                }

                return ServiceResult<OrganizationDto>.Failure(result.ErrorMessage ?? "Failed to create child organization");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create child organization for parent {ParentId}", parentOrganizationId);
                return ServiceResult<OrganizationDto>.Failure("Failed to create child organization");
            }
        }
        /// <summary>
        /// 조직 계층 트리 조회
        /// </summary>
        public async Task<ServiceResult<OrganizationHierarchyTree>> GetOrganizationTreeAsync(
            Guid organizationId,
            int? maxDepth = null)
        {
            try
            {
                maxDepth ??= 10;

                // 캐시 확인
                var cacheKey = $"{CACHE_KEY_TREE}{organizationId}_{maxDepth}";
                if (_cache.TryGetValue<OrganizationHierarchyTree>(cacheKey, out var cached) && cached != null)
                {
                    return ServiceResult<OrganizationHierarchyTree>.Success(cached);
                }

                // 루트 조직 조회
                var rootResult = await _organizationService.GetByIdAsync(organizationId);
                if (!rootResult.IsSuccess || rootResult.Data == null)
                {
                    return ServiceResult<OrganizationHierarchyTree>.Failure("Organization not found");
                }

                // 트리 구성
                var tree = new OrganizationHierarchyTree();
                tree.Root = await BuildTreeNodeAsync(rootResult.Data, 0, maxDepth.Value);
                tree.TotalNodes = CountNodes(tree.Root);
                tree.MaxDepth = GetMaxDepth(tree.Root);
                BuildPathMap(tree.Root, "", tree.PathMap);

                // 캐시 저장
                _cache.Set(cacheKey, tree, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));

                return ServiceResult<OrganizationHierarchyTree>.Success(tree);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization tree for {OrganizationId}", organizationId);
                return ServiceResult<OrganizationHierarchyTree>.Failure("Failed to get organization tree");
            }
        }

        /// <summary>
        /// 조직을 다른 부모로 이동
        /// </summary>
        public async Task<ServiceResult<bool>> MoveOrganizationAsync(
            Guid organizationId,
            Guid? newParentId,
            Guid movedByConnectedId)
        {
            try
            {
                // 계층 구조 검증
                var validationResult = await ValidateHierarchyAsync(organizationId, newParentId);
                if (!validationResult.IsSuccess || !validationResult.Data?.IsValid == true)
                {
                    return ServiceResult<bool>.Failure(
                        validationResult.Data?.ValidationErrors.FirstOrDefault() ?? "Invalid hierarchy");
                }

                // 조직 이동
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<bool>.Failure("Organization not found");
                }

                var oldParentId = organization.ParentId;
                organization.ParentId = newParentId;

                await _repository.UpdateAsync(organization);

                // 캐시 무효화
                InvalidateHierarchyCache(organizationId);
                if (oldParentId.HasValue) InvalidateHierarchyCache(oldParentId.Value);
                if (newParentId.HasValue) InvalidateHierarchyCache(newParentId.Value);

                _logger.LogInformation(
                    "Organization {OrganizationId} moved from {OldParent} to {NewParent} by {ConnectedId}",
                    organizationId, oldParentId, newParentId, movedByConnectedId);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to move organization {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure("Failed to move organization");
            }
        }

        /// <summary>
        /// 조직 계층 구조 검증
        /// </summary>
        public async Task<ServiceResult<HierarchyValidationResult>> ValidateHierarchyAsync(
            Guid organizationId,
            Guid? proposedParentId)
        {
            var result = new HierarchyValidationResult
            {
                OrganizationId = organizationId,
                ProposedParentId = proposedParentId,
                IsValid = true
            };

            try
            {
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    result.IsValid = false;
                    result.ValidationErrors.Add("Organization not found");
                    return ServiceResult<HierarchyValidationResult>.Success(result);
                }

                result.CurrentParentId = organization.ParentId;

                // 자기 자신을 부모로 설정할 수 없음
                if (proposedParentId == organizationId)
                {
                    result.IsValid = false;
                    result.ValidationErrors.Add("Organization cannot be its own parent");
                    result.HasCircularReference = true;
                    return ServiceResult<HierarchyValidationResult>.Success(result);
                }

                // 순환 참조 검사
                if (proposedParentId.HasValue)
                {
                    var isDescendant = await IsDescendantOfAsync(proposedParentId.Value, organizationId);
                    if (isDescendant)
                    {
                        result.IsValid = false;
                        result.ValidationErrors.Add("Circular reference detected");
                        result.HasCircularReference = true;
                    }

                    // 깊이 제한 검사
                    var depthLimit = await GetDepthLimitAsync(proposedParentId.Value);
                    if (depthLimit.IsSuccess && depthLimit.Data != null)
                    {
                        result.CurrentDepth = depthLimit.Data.CurrentDepth;
                        result.MaxAllowedDepth = depthLimit.Data.MaxAllowedDepth;

                        if (depthLimit.Data.IsAtLimit)
                        {
                            result.IsValid = false;
                            result.ExceedsMaxDepth = true;
                            result.ValidationErrors.Add($"Maximum depth ({depthLimit.Data.MaxAllowedDepth}) exceeded for {depthLimit.Data.CurrentPlan}");
                        }
                    }

                    // 경로 구성
                    result.HierarchyPath = await BuildHierarchyPath(proposedParentId.Value);
                }

                // 영향받는 하위 조직 계산
                var children = await _repository.GetChildOrganizationsAsync(organizationId, true);
                result.AffectedChildOrganizations = children.Count();

                // 영향받는 멤버 수 계산
                result.AffectedMembers = await CountAffectedMembers(organizationId);

                return ServiceResult<HierarchyValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate hierarchy");
                result.IsValid = false;
                result.ValidationErrors.Add("Validation failed: " + ex.Message);
                return ServiceResult<HierarchyValidationResult>.Failure("Failed to validate hierarchy");
            }
        }

        /// <summary>
        /// 하위 조직에 설정 상속
        /// </summary>
        public async Task<ServiceResult<int>> InheritSettingsToChildrenAsync(
            Guid parentOrganizationId,
            PolicyInheritanceMode inheritanceMode,
            Guid initiatedByConnectedId)
        {
            try
            {
                var children = await _repository.GetChildOrganizationsAsync(parentOrganizationId, true);
                int updatedCount = 0;

                foreach (var child in children)
                {
                    child.PolicyInheritanceMode = inheritanceMode;
                    await _repository.UpdateAsync(child);
                    updatedCount++;
                }

                _logger.LogInformation(
                    "Inherited settings to {Count} children of {ParentId} by {ConnectedId}",
                    updatedCount, parentOrganizationId, initiatedByConnectedId);

                return ServiceResult<int>.Success(updatedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to inherit settings");
                return ServiceResult<int>.Failure("Failed to inherit settings");
            }
        }

        /// <summary>
        /// 계층별 사용량 집계
        /// </summary>
        public async Task<ServiceResult<HierarchyUsageDto>> GetHierarchyUsageAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            try
            {
                var orgResult = await _organizationService.GetByIdAsync(organizationId);
                if (!orgResult.IsSuccess || orgResult.Data == null)
                {
                    return ServiceResult<HierarchyUsageDto>.Failure("Organization not found");
                }

                var usage = new HierarchyUsageDto
                {
                    OrganizationId = organizationId,
                    OrganizationName = orgResult.Data.Name,
                    StartDate = startDate,
                    EndDate = endDate,
                    HierarchyLevel = orgResult.Data.Level,
                    HierarchyPath = orgResult.Data.Path
                };

                // TODO: 실제 사용량 데이터 집계
                usage.DirectUsage = new UsageMetrics
                {
                    ApiCalls = 1000,
                    StorageUsed = 1073741824, // 1GB in bytes
                    ActiveUsers = 10,
                    TransactionCount = 50,
                    PointsUsed = 100,
                    TotalCost = 99.99m
                };

                // 하위 조직 사용량 집계
                var children = await _repository.GetChildOrganizationsAsync(organizationId, false);
                foreach (var child in children)
                {
                    var childUsageResult = await GetHierarchyUsageAsync(child.Id, startDate, endDate);
                    if (childUsageResult.IsSuccess && childUsageResult.Data != null)
                    {
                        usage.ChildrenUsage.Add(childUsageResult.Data);
                    }
                }

                // 총 사용량 계산
                usage.TotalUsage = AggregateUsage(usage.DirectUsage, usage.ChildrenUsage);

                return ServiceResult<HierarchyUsageDto>.Success(usage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get hierarchy usage");
                return ServiceResult<HierarchyUsageDto>.Failure("Failed to get hierarchy usage");
            }
        }

        /// <summary>
        /// 최대 깊이 제한 확인
        /// </summary>
        public async Task<ServiceResult<HierarchyDepthLimit>> GetDepthLimitAsync(Guid organizationId)
        {
            try
            {
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<HierarchyDepthLimit>.Failure("Organization not found");
                }

                // TODO: 실제 플랜 정보 조회
                var currentPlan = "Business"; // 실제로는 PlanSubscription에서 가져와야 함

                var limit = new HierarchyDepthLimit
                {
                    OrganizationId = organizationId,
                    CurrentPlan = currentPlan,
                    CurrentDepth = organization.Level,
                    MaxAllowedDepth = PricingConstants.SubscriptionPlans.OrganizationDepthLimits
                        .GetValueOrDefault($"plan.{currentPlan.ToLower()}", 3)
                };

                // 업그레이드 제안
                if (limit.IsAtLimit && currentPlan != "Enterprise")
                {
                    limit.UpgradeSuggestion = new UpgradeSuggestion
                    {
                        SuggestedPlan = GetNextPlan(currentPlan),
                        SuggestedMaxDepth = GetMaxDepthForPlan(GetNextPlan(currentPlan)),
                        Reason = "Current plan depth limit reached"
                    };
                }

                return ServiceResult<HierarchyDepthLimit>.Success(limit);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get depth limit");
                return ServiceResult<HierarchyDepthLimit>.Failure("Failed to get depth limit");
            }
        }

        /// <summary>
        /// 조직 경로 조회
        /// </summary>
        public async Task<ServiceResult<string>> GetOrganizationPathAsync(Guid organizationId)
        {
            try
            {
                // 캐시 확인
                var cacheKey = $"{CACHE_KEY_PATH}{organizationId}";
                if (_cache.TryGetValue<string>(cacheKey, out var cachedPath) && !string.IsNullOrEmpty(cachedPath))
                {
                    return ServiceResult<string>.Success(cachedPath);
                }

                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<string>.Failure("Organization not found");
                }

                // 캐시 저장
                _cache.Set(cacheKey, organization.Path, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));

                return ServiceResult<string>.Success(organization.Path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization path");
                return ServiceResult<string>.Failure("Failed to get organization path");
            }
        }

        /// <summary>
        /// 형제 조직 순서 변경
        /// </summary>
        public async Task<ServiceResult<bool>> ReorderSiblingsAsync(
            Guid organizationId,
            int newSortOrder,
            Guid reorderedByConnectedId)
        {
            try
            {
                var organization = await _repository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<bool>.Failure("Organization not found");
                }

                organization.SortOrder = newSortOrder;
                await _repository.UpdateAsync(organization);

                // 캐시 무효화
                if (organization.ParentId.HasValue)
                {
                    InvalidateHierarchyCache(organization.ParentId.Value);
                }

                _logger.LogInformation(
                    "Organization {OrganizationId} reordered to {SortOrder} by {ConnectedId}",
                    organizationId, newSortOrder, reorderedByConnectedId);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reorder siblings");
                return ServiceResult<bool>.Failure("Failed to reorder siblings");
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task<OrganizationNode> BuildTreeNodeAsync(OrganizationDto org, int currentDepth, int maxDepth)
        {
            var node = new OrganizationNode
            {
                Id = org.Id,
                Name = org.Name,
                OrganizationKey = org.OrganizationKey,
                Level = org.Level,
                Path = org.Path
            };

            if (currentDepth < maxDepth)
            {
                var children = await _repository.GetChildOrganizationsAsync(org.Id, false);
                foreach (var child in children)
                {
                    var childDto = _mapper.Map<OrganizationDto>(child);
                    var childNode = await BuildTreeNodeAsync(childDto, currentDepth + 1, maxDepth);
                    node.Children.Add(childNode);
                }
            }

            return node;
        }

        private int CountNodes(OrganizationNode? node)
        {
            if (node == null) return 0;
            return 1 + node.Children.Sum(CountNodes);
        }

        private int GetMaxDepth(OrganizationNode? node, int currentDepth = 0)
        {
            if (node == null || !node.Children.Any()) return currentDepth;
            return node.Children.Max(c => GetMaxDepth(c, currentDepth + 1));
        }

        private void BuildPathMap(OrganizationNode? node, string parentPath, Dictionary<Guid, string> pathMap)
        {
            if (node == null) return;

            var currentPath = string.IsNullOrEmpty(parentPath)
                ? node.Name
                : $"{parentPath} > {node.Name}";

            pathMap[node.Id] = currentPath;

            foreach (var child in node.Children)
            {
                BuildPathMap(child, currentPath, pathMap);
            }
        }

        private async Task<bool> IsDescendantOfAsync(Guid organizationId, Guid possibleAncestorId)
        {
            var current = await _repository.GetByIdAsync(organizationId);

            while (current?.ParentId != null)
            {
                if (current.ParentId == possibleAncestorId)
                    return true;

                current = await _repository.GetByIdAsync(current.ParentId.Value);
            }

            return false;
        }

        private async Task<List<Guid>> BuildHierarchyPath(Guid organizationId)
        {
            var path = new List<Guid>();
            var current = await _repository.GetByIdAsync(organizationId);

            while (current != null)
            {
                path.Insert(0, current.Id);
                if (current.ParentId.HasValue)
                {
                    current = await _repository.GetByIdAsync(current.ParentId.Value);
                }
                else
                {
                    break;
                }
            }

            return path;
        }

        private async Task<int> CountAffectedMembers(Guid organizationId)
        {
            var count = await _context.OrganizationMemberships
                .CountAsync(m => m.OrganizationId == organizationId && !m.IsDeleted);

            var children = await _repository.GetChildOrganizationsAsync(organizationId, true);
            foreach (var child in children)
            {
                count += await _context.OrganizationMemberships
                    .CountAsync(m => m.OrganizationId == child.Id && !m.IsDeleted);
            }

            return count;
        }

        private UsageMetrics AggregateUsage(UsageMetrics direct, List<HierarchyUsageDto> children)
        {
            var total = new UsageMetrics
            {
                ApiCalls = direct.ApiCalls,
                StorageUsed = direct.StorageUsed,
                ActiveUsers = direct.ActiveUsers,
                TransactionCount = direct.TransactionCount,
                PointsUsed = direct.PointsUsed,
                TotalCost = direct.TotalCost
            };

            foreach (var child in children)
            {
                total.ApiCalls += child.TotalUsage.ApiCalls;
                total.StorageUsed += child.TotalUsage.StorageUsed;
                total.ActiveUsers += child.TotalUsage.ActiveUsers;
                total.TransactionCount += child.TotalUsage.TransactionCount;
                total.PointsUsed += child.TotalUsage.PointsUsed;
                total.TotalCost += child.TotalUsage.TotalCost;
            }

            return total;
        }

        private void InvalidateHierarchyCache(Guid organizationId)
        {
            _cache.Remove($"{CACHE_KEY_TREE}{organizationId}");
            _cache.Remove($"{CACHE_KEY_PATH}{organizationId}");
        }

        private string GetNextPlan(string currentPlan)
        {
            return currentPlan.ToLower() switch
            {
                "basic" => "Pro",
                "pro" => "Business",
                "business" => "Enterprise",
                _ => "Enterprise"
            };
        }

        private int GetMaxDepthForPlan(string plan)
        {
            return PricingConstants.SubscriptionPlans.OrganizationDepthLimits
                .GetValueOrDefault($"plan.{plan.ToLower()}", -1);
        }

        #endregion
    }
}