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
   /// WHO: 조직 관리자, 시스템 관리자
   /// WHEN: 조직 계층 구조 생성/수정/조회 시
   /// WHERE: AuthHive.Auth 서비스 레이어
   /// WHAT: Organization 엔티티의 HierarchicalEntity 기능을 활용한 계층 관리
   /// WHY: AWS Organizations 스타일의 계층적 조직 관리 구현
   /// HOW: Repository를 통한 계층 데이터 접근 + 비즈니스 규칙 적용
   /// </summary>
   public class OrganizationHierarchyService : IOrganizationHierarchyService
   {
       private readonly IOrganizationRepository _repository;
       private readonly IOrganizationHierarchyRepository _hierarchyRepository;
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
           IOrganizationHierarchyRepository hierarchyRepository,
           AuthDbContext context,
           IOrganizationService organizationService,
           IMapper mapper,
           IMemoryCache cache,
           ILogger<OrganizationHierarchyService> logger)
       {
           _repository = repository;
           _hierarchyRepository = hierarchyRepository;
           _context = context;
           _organizationService = organizationService;
           _mapper = mapper;
           _cache = cache;
           _logger = logger;
       }

       #region IService Implementation

       /// <summary>
       /// 서비스 헬스 체크
       /// WHO: 모니터링 시스템, 로드 밸런서
       /// WHEN: 주기적인 헬스 체크
       /// WHERE: /health 엔드포인트
       /// WHAT: 데이터베이스 연결 상태 확인
       /// WHY: 서비스 가용성 모니터링
       /// HOW: DB 연결 테스트
       /// </summary>
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

       /// <summary>
       /// 서비스 초기화
       /// WHO: DI 컨테이너
       /// WHEN: 애플리케이션 시작 시
       /// WHERE: Startup/Program.cs
       /// WHAT: 서비스 초기 설정
       /// WHY: 필요한 리소스 준비
       /// HOW: 로깅 및 초기화 작업
       /// </summary>
       public Task InitializeAsync()
       {
           _logger.LogInformation("OrganizationHierarchyService initialized");
           return Task.CompletedTask;
       }

       #endregion

       #region IOrganizationHierarchyService Implementation

       /// <summary>
       /// 하위 조직 생성
       /// WHO: 상위 조직 관리자, 리셀러
       /// WHEN: 부서/자회사/하위 테넌트 생성 시
       /// WHERE: 조직 관리 콘솔, 리셀러 포털
       /// WHAT: 현재 조직 하위에 새 조직 생성
       /// WHY: 계층적 조직 구조 확장
       /// HOW: 플랜 깊이 제한 검증 → 하위 조직 생성 → 권한 상속
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
       /// WHO: 조직 뷰어, 관리자
       /// WHEN: 조직 구조 시각화, 네비게이션
       /// WHERE: 조직 트리 뷰, 대시보드
       /// WHAT: 지정 조직을 루트로 하는 계층 트리
       /// WHY: 시각적 계층 구조 표현
       /// HOW: 재귀적 조직 조회 → 트리 구조 생성
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
       /// WHO: 시스템 관리자, 상위 조직 소유자
       /// WHEN: 조직 재구성, M&A, 부서 이동
       /// WHERE: 조직 구조 재편성 도구
       /// WHAT: 조직의 부모를 변경하여 계층 이동
       /// WHY: 유연한 조직 구조 변경 지원
       /// HOW: 순환 참조 검증 → 깊이 제한 확인 → 부모 변경 → 권한 재계산
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
       /// 조직 계층 구조 검증 (순환 참조, 깊이 제한, 플랜 제약)
       /// WHO: 조직 생성/이동 서비스, 플랜 변경 서비스
       /// WHEN: 계층 변경 전 사전 검증, 플랜 다운그레이드 시
       /// WHERE: 조직 CRUD 작업 전처리, PlanService.ChangePlanAsync
       /// WHAT: 순환 참조, 깊이 제한, 플랜 제약 종합 검증
       /// WHY: 데이터 무결성 및 비즈니스 규칙 보장
       /// HOW: 순환 체크 → 깊이 계산 → 플랜 제한 비교 → 검증 결과 반환
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

               // 순환 참조 검사 - IOrganizationHierarchyRepository 사용
               if (proposedParentId.HasValue)
               {
                   var wouldCreateCycle = await _hierarchyRepository.WouldCreateCycleAsync(organizationId, proposedParentId.Value);
                   if (wouldCreateCycle)
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
                   var ancestors = await _hierarchyRepository.GetAncestorsAsync(proposedParentId.Value);
                   result.HierarchyPath = ancestors.Select(a => a.Id).ToList();
                   result.HierarchyPath.Add(proposedParentId.Value);
               }

               // 영향받는 하위 조직 계산 - IOrganizationHierarchyRepository 사용
               var children = await _hierarchyRepository.GetChildrenAsync(organizationId, true);
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
       /// WHO: 상위 조직 관리자
       /// WHEN: 정책/설정 일괄 적용 필요 시
       /// WHERE: 정책 관리 콘솔
       /// WHAT: 상위 조직 설정을 하위 조직에 전파
       /// WHY: 일관된 정책 적용 및 중앙 관리
       /// HOW: 설정 조회 → 상속 모드별 처리 → 하위 조직 업데이트
       /// </summary>
       public async Task<ServiceResult<int>> InheritSettingsToChildrenAsync(
           Guid parentOrganizationId,
           PolicyInheritanceMode inheritanceMode,
           Guid initiatedByConnectedId)
       {
           try
           {
               var children = await _hierarchyRepository.GetChildrenAsync(parentOrganizationId, true);
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
       /// WHO: 빌링 서비스, 사용량 분석 서비스
       /// WHEN: 월간 정산, 사용량 리포트 생성
       /// WHERE: 빌링 대시보드, 사용량 분석 화면
       /// WHAT: 조직과 하위 조직의 총 사용량 합계
       /// WHY: 계층별 비용 분석 및 청구
       /// HOW: 하위 조직 재귀 조회 → 사용량 집계 → 통합 리포트
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
               var children = await _hierarchyRepository.GetChildrenAsync(organizationId, false);
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
       /// 최대 깊이 제한 확인 (플랜별)
       /// WHO: 조직 생성 검증 서비스
       /// WHEN: 하위 조직 추가 가능 여부 확인
       /// WHERE: 조직 생성 UI, API 검증
       /// WHAT: 현재 플랜의 계층 깊이 제한
       /// WHY: 플랜별 제약 사항 적용
       /// HOW: 플랜 조회 → PricingConstants 매핑 → 제한값 반환
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
       /// WHO: UI 컴포넌트, 감사 로그
       /// WHEN: Breadcrumb 표시, 전체 경로 필요 시
       /// WHERE: 네비게이션 바, 감사 로그 기록
       /// WHAT: 루트부터 현재까지의 조직 경로 문자열
       /// WHY: 사용자 위치 표시 및 컨텍스트 제공
       /// HOW: 조상 조회 → 경로 문자열 생성 (예: "Root/Dept1/Team1")
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
       /// WHO: 조직 관리자
       /// WHEN: 조직 표시 순서 조정 필요 시
       /// WHERE: 조직 목록 관리 UI
       /// WHAT: 같은 부모를 가진 조직들의 정렬 순서
       /// WHY: 사용자 정의 조직 정렬 지원
       /// HOW: 형제 조회 → SortOrder 재배열 → 일괄 업데이트
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

       /// <summary>
       /// 플랜에 따른 계층 깊이 제한 검증 (특화 검증)
       /// WHO: 플랜 업그레이드/다운그레이드 서비스
       /// WHEN: 플랜 변경 요청 시 사전 검증
       /// WHERE: PlanService.ChangePlanAsync 사전 검증
       /// WHAT: 특정 플랜으로 변경 시 현재 계층 구조 호환성 검증
       /// WHY: 플랜 다운그레이드 시 계층 구조 위반 방지
       /// HOW: 현재 계층 깊이와 대상 플랜의 제한 비교
       /// </summary>
       public async Task<ServiceResult<HierarchyValidationResult>> ValidateHierarchyDepthForPlanAsync(
           Guid organizationId,
           string planKey)
       {
           var result = new HierarchyValidationResult
           {
               OrganizationId = organizationId,
               IsValid = true
           };

           try
           {
               // 현재 계층 깊이 확인
               var currentDepth = await _hierarchyRepository.GetHierarchyDepthAsync(organizationId);
               
               // 플랜의 최대 깊이 제한 확인
               var maxDepthForPlan = PricingConstants.SubscriptionPlans.OrganizationDepthLimits
                   .GetValueOrDefault(planKey, 3);

               result.CurrentDepth = currentDepth;
               result.MaxAllowedDepth = maxDepthForPlan;

               if (maxDepthForPlan != -1 && currentDepth > maxDepthForPlan)
               {
                   result.IsValid = false;
                   result.ExceedsMaxDepth = true;
                   result.ValidationErrors.Add(
                       $"Current hierarchy depth ({currentDepth}) exceeds the limit ({maxDepthForPlan}) for plan {planKey}");
               }

               return ServiceResult<HierarchyValidationResult>.Success(result);
           }
           catch (Exception ex)
           {
               _logger.LogError(ex, "Failed to validate hierarchy depth for plan");
               result.IsValid = false;
               result.ValidationErrors.Add("Validation failed: " + ex.Message);
               return ServiceResult<HierarchyValidationResult>.Failure("Failed to validate hierarchy depth");
           }
       }

       #endregion

       #region Private Helper Methods

       /// <summary>
       /// 트리 노드 생성 헬퍼
       /// WHO: GetOrganizationTreeAsync 내부 프로세스
       /// WHEN: 조직 트리 구성 시
       /// WHERE: 트리 빌드 로직
       /// WHAT: OrganizationDto를 OrganizationNode로 변환
       /// WHY: 계층 구조 시각화를 위한 트리 구성
       /// HOW: 재귀적 자식 노드 생성
       /// </summary>
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
               var children = await _hierarchyRepository.GetChildrenAsync(org.Id, false);
               foreach (var child in children)
               {
                   var childDto = _mapper.Map<OrganizationDto>(child);
                   var childNode = await BuildTreeNodeAsync(childDto, currentDepth + 1, maxDepth);
                   node.Children.Add(childNode);
               }
           }

           return node;
       }

       /// <summary>
       /// 트리 노드 개수 계산
       /// WHO: GetOrganizationTreeAsync
       /// WHEN: 트리 생성 후
       /// WHERE: 트리 통계 계산
       /// WHAT: 트리의 전체 노드 수
       /// WHY: 트리 크기 파악
       /// HOW: 재귀적 카운팅
       /// </summary>
       private int CountNodes(OrganizationNode? node)
       {
           if (node == null) return 0;
           return 1 + node.Children.Sum(CountNodes);
       }

       /// <summary>
       /// 트리 최대 깊이 계산
       /// WHO: GetOrganizationTreeAsync
       /// WHEN: 트리 생성 후
       /// WHERE: 트리 통계 계산
       /// WHAT: 트리의 최대 깊이
       /// WHY: 계층 구조 깊이 파악
       /// HOW: 재귀적 깊이 탐색
       /// </summary>
       private int GetMaxDepth(OrganizationNode? node, int currentDepth = 0)
       {
           if (node == null || !node.Children.Any()) return currentDepth;
           return node.Children.Max(c => GetMaxDepth(c, currentDepth + 1));
       }

       /// <summary>
       /// 트리 경로 맵 생성
       /// WHO: GetOrganizationTreeAsync
       /// WHEN: 트리 생성 후
       /// WHERE: 트리 경로 매핑
       /// WHAT: 각 노드의 전체 경로
       /// WHY: Breadcrumb 및 네비게이션 지원
       /// HOW: 재귀적 경로 문자열 생성
       /// </summary>
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

       /// <summary>
       /// 영향받는 멤버 수 계산
       /// WHO: ValidateHierarchyAsync
       /// WHEN: 조직 이동/삭제 검증 시
       /// WHERE: 계층 변경 영향 분석
       /// WHAT: 조직과 하위 조직의 전체 멤버 수
       /// WHY: 변경 영향도 파악
       /// HOW: 재귀적 멤버십 카운팅
       /// </summary>
       private async Task<int> CountAffectedMembers(Guid organizationId)
       {
           var count = await _context.OrganizationMemberships
               .CountAsync(m => m.OrganizationId == organizationId && !m.IsDeleted);

           var children = await _hierarchyRepository.GetChildrenAsync(organizationId, true);
           foreach (var child in children)
           {
               count += await _context.OrganizationMemberships
                   .CountAsync(m => m.OrganizationId == child.Id && !m.IsDeleted);
           }

           return count;
       }

       /// <summary>
       /// 사용량 집계
       /// WHO: GetHierarchyUsageAsync
       /// WHEN: 계층별 사용량 계산 시
       /// WHERE: 빌링 및 사용량 분석
       /// WHAT: 직접 사용량과 하위 사용량 합계
       /// WHY: 통합 사용량 리포트
       /// HOW: 각 메트릭 합산
       /// </summary>
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

       /// <summary>
       /// 계층 캐시 무효화
       /// WHO: 데이터 변경 프로세스
       /// WHEN: 조직 계층 변경 시
       /// WHERE: 조직 생성/이동/삭제
       /// WHAT: 계층 관련 캐시 제거
       /// WHY: 데이터 일관성 보장
       /// HOW: 트리 및 경로 캐시 제거
       /// </summary>
       private void InvalidateHierarchyCache(Guid organizationId)
       {
           // 트리 캐시 무효화 (여러 maxDepth 값에 대해)
           for (int i = 1; i <= 20; i++)
           {
               _cache.Remove($"{CACHE_KEY_TREE}{organizationId}_{i}");
           }
           
           // 경로 캐시 무효화
           _cache.Remove($"{CACHE_KEY_PATH}{organizationId}");
       }

       /// <summary>
       /// 다음 플랜 추천
       /// WHO: GetDepthLimitAsync
       /// WHEN: 플랜 제한 도달 시
       /// WHERE: 업그레이드 제안
       /// WHAT: 현재 플랜의 다음 단계
       /// WHY: 업셀링 기회 제공
       /// HOW: 플랜 시퀀스 매핑
       /// </summary>
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

       /// <summary>
       /// 플랜별 최대 깊이 조회
       /// WHO: 플랜 검증 서비스
       /// WHEN: 플랜 제한 확인 시
       /// WHERE: 계층 깊이 검증
       /// WHAT: 특정 플랜의 최대 허용 깊이
       /// WHY: 플랜별 제한 적용
       /// HOW: PricingConstants에서 조회
       /// </summary>
       private int GetMaxDepthForPlan(string plan)
       {
           return PricingConstants.SubscriptionPlans.OrganizationDepthLimits
               .GetValueOrDefault($"plan.{plan.ToLower()}", -1);
       }

       #endregion
   }
}