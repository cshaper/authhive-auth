using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Constants.Common;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.Business.Platform;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 검증 서비스 구현 - AuthHive v15
    /// 조직 관련 다양한 검증 작업을 담당 (캐시 적용)
    /// </summary>
    public class OrganizationValidationService : IOrganizationValidationService
    {
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationStatisticsRepository _statisticsRepository;
        private readonly IOrganizationMembershipRepository _membershipRepository;
        private readonly IRepository<PlanSubscription> _planSubscriptionRepository;
        private readonly IUserRepository _userRepository;
        private readonly IMemoryCache _cache;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<OrganizationValidationService> _logger;

        // 캐시 키 상수
        private const string CACHE_KEY_RESERVED_KEYS = "org_validation:reserved_keys";
        private const string CACHE_KEY_ORG_EXISTS = "org_validation:exists:{0}";
        private const string CACHE_KEY_ORG_KEY_AVAILABLE = "org_validation:key_available:{0}";
        private const string CACHE_KEY_USER_ORG_COUNT = "org_validation:user_org_count:{0}";

        public OrganizationValidationService(
            IOrganizationRepository organizationRepository,
            IOrganizationStatisticsRepository statisticsRepository,
            IOrganizationMembershipRepository membershipRepository,
            IRepository<PlanSubscription> planSubscriptionRepository,
            IUserRepository userRepository,
            IMemoryCache cache,
            IUnitOfWork unitOfWork,
            ILogger<OrganizationValidationService> logger)
        {
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _statisticsRepository = statisticsRepository ?? throw new ArgumentNullException(nameof(statisticsRepository));
            _membershipRepository = membershipRepository ?? throw new ArgumentNullException(nameof(membershipRepository));
            _planSubscriptionRepository = planSubscriptionRepository ?? throw new ArgumentNullException(nameof(planSubscriptionRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService Implementation

        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Repository 연결 상태 확인
                var testQuery = await _organizationRepository.ExistsAsync(Guid.Empty);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationValidationService health check failed");
                return false;
            }
        }

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing OrganizationValidationService");

            // 시스템 예약어 캐시 워밍
            await GetReservedKeysAsync();

            _logger.LogInformation("OrganizationValidationService initialized successfully");
        }

        #endregion

        #region IOrganizationValidationService Implementation

        /// <summary>
        /// 조직 키 사용 가능 여부 확인
        /// </summary>
        public async Task<ServiceResult<bool>> IsKeyAvailableAsync(string organizationKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(organizationKey))
                {
                    return ServiceResult<bool>.Failure("Organization key cannot be empty", "VALIDATION_ERROR");
                }

                // 캐시에서 최근 검증 결과 확인 (5분간 캐싱)
                var cacheKey = string.Format(CACHE_KEY_ORG_KEY_AVAILABLE, organizationKey.ToLower());
                if (_cache.TryGetValue<bool>(cacheKey, out var cachedResult))
                {
                    _logger.LogDebug("Organization key availability retrieved from cache: {Key} = {Available}",
                        organizationKey, cachedResult);
                    return ServiceResult<bool>.Success(cachedResult,
                        cachedResult ? "Organization key is available (cached)" : "Organization key is already in use (cached)");
                }

                // 조직 키 형식 검증
                if (!IsValidOrganizationKey(organizationKey))
                {
                    return ServiceResult<bool>.Failure(
                        "Invalid organization key format. Must be 3-50 characters, alphanumeric with hyphens only",
                        "INVALID_FORMAT");
                }

                // 시스템 예약어 확인
                var reservedKeys = await GetReservedKeysAsync();
                if (reservedKeys.Contains(organizationKey.ToLower()))
                {
                    return ServiceResult<bool>.Failure(
                        "This organization key is reserved and cannot be used",
                        "RESERVED_KEY");
                }

                // DB에서 중복 확인
                var exists = await _organizationRepository.IsOrganizationKeyExistsAsync(organizationKey);

                // 결과 캐싱
                var isAvailable = !exists;
                _cache.Set(cacheKey, isAvailable, TimeSpan.FromMinutes(5));

                if (exists)
                {
                    return ServiceResult<bool>.Success(false, "Organization key is already in use");
                }

                return ServiceResult<bool>.Success(true, "Organization key is available");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization key availability: {Key}", organizationKey);
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking key availability",
                    "SYSTEM_ERROR");
            }
        }

        /// <summary>
        /// 조직 존재 여부 확인
        /// </summary>
        public async Task<ServiceResult<bool>> ExistsAsync(Guid organizationId)
        {
            try
            {
                if (organizationId == Guid.Empty)
                {
                    return ServiceResult<bool>.Success(false, "Invalid organization ID");
                }

                // 캐시 확인 (10분간 캐싱)
                var cacheKey = string.Format(CACHE_KEY_ORG_EXISTS, organizationId);
                if (_cache.TryGetValue<bool>(cacheKey, out var cachedExists))
                {
                    return ServiceResult<bool>.Success(
                        cachedExists,
                        cachedExists ? "Organization exists (cached)" : "Organization not found (cached)");
                }

                var exists = await _organizationRepository.ExistsAsync(organizationId);

                // 결과 캐싱
                _cache.Set(cacheKey, exists, TimeSpan.FromMinutes(10));

                return ServiceResult<bool>.Success(
                    exists,
                    exists ? "Organization exists" : "Organization not found");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization existence: {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking organization existence",
                    "SYSTEM_ERROR");
            }
        }

        /// <summary>
        /// 조직 활성 상태 확인
        /// </summary>
        public async Task<ServiceResult<bool>> IsActiveAsync(Guid organizationId)
        {
            try
            {
                if (organizationId == Guid.Empty)
                {
                    return ServiceResult<bool>.Success(false, "Invalid organization ID");
                }

                var organization = await _organizationRepository.GetByIdAsync(organizationId);

                if (organization == null)
                {
                    return ServiceResult<bool>.Success(false, "Organization not found");
                }

                // 조직 상태 확인
                var isActive = organization.Status == OrganizationStatus.Active &&
                              !organization.IsDeleted;

                return ServiceResult<bool>.Success(
                    isActive,
                    isActive ? "Organization is active" : "Organization is not active");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization active status: {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure(
                    "An error occurred while checking organization status",
                    "SYSTEM_ERROR");
            }
        }

        /// <summary>
        /// 조직 생성 가능 여부 확인
        /// </summary>
        public async Task<ServiceResult<OrganizationCreationEligibility>> CheckCreationEligibilityAsync(
            Guid creatorUserId)
        {
            try
            {
                var eligibility = new OrganizationCreationEligibility
                {
                    UserId = creatorUserId,
                    CheckedAt = DateTime.UtcNow
                };

                // 사용자 정보 확인
                var user = await _userRepository.GetByIdAsync(creatorUserId);
                if (user == null)
                {
                    eligibility.CanCreate = false;
                    eligibility.Restrictions.Add("User not found");
                    return ServiceResult<OrganizationCreationEligibility>.Success(eligibility);
                }

                // 사용자 상태 확인 (User 엔티티에 Status 속성이 있다고 가정)
                // TODO: User 엔티티에 Status 속성 추가 필요
                eligibility.AccountStatus = "Active"; // 임시 값
                eligibility.IsAccountVerified = true;
                eligibility.IsEmailVerified = true; // TODO: User 엔티티에서 확인

                // 사용자가 Owner인 조직들 조회
                var userOwnedOrgs = await GetUserOwnedOrganizationsAsync(creatorUserId);

                // 사용자가 소유한 조직들의 플랜 중 가장 높은 플랜 확인
                var highestPlan = await GetUserHighestPlanAsync(userOwnedOrgs);
                eligibility.CurrentPlan = highestPlan ?? PricingConstants.SubscriptionPlans.BASIC_KEY;

                // 플랜별 조직 수 제한 확인
                var maxOrganizations = PricingConstants.SubscriptionPlans.OrganizationLimits
                    .GetValueOrDefault(eligibility.CurrentPlan, 1);
                eligibility.MaxOrganizationsAllowed = maxOrganizations;

                // 현재 보유 조직 수 확인 (캐시 활용)
                var currentOrgCount = await GetUserOrganizationCountAsync(creatorUserId);
                eligibility.CurrentOrganizationCount = currentOrgCount;

                // 생성 가능 여부 판단
                if (maxOrganizations == -1) // 무제한
                {
                    eligibility.CanCreate = true;
                }
                else if (currentOrgCount >= maxOrganizations)
                {
                    eligibility.CanCreate = false;
                    eligibility.RequiresPlanUpgrade = true;
                    eligibility.Restrictions.Add($"Organization limit reached ({currentOrgCount}/{maxOrganizations})");

                    // 추천 플랜 제안
                    eligibility.RecommendedPlan = GetRecommendedPlan(eligibility.CurrentPlan);
                }
                else
                {
                    eligibility.CanCreate = true;
                }

                // 사용자가 소유한 조직들의 미납금 확인
                if (userOwnedOrgs.Any())
                {
                    var hasAnyOutstandingBalance = await _organizationRepository.AnyAsync(
                        o => userOwnedOrgs.Contains(o.Id) && o.HasOutstandingBalance);

                    if (hasAnyOutstandingBalance)
                    {
                        eligibility.HasOutstandingBalance = true;
                        eligibility.CanCreate = false;
                        eligibility.Restrictions.Add("Outstanding balance exists in one or more owned organizations");
                    }
                }

                // 최종 생성 가능 여부 결정
                if (eligibility.Restrictions.Count == 0 && eligibility.CanCreate)
                {
                    return ServiceResult<OrganizationCreationEligibility>.Success(
                        eligibility,
                        "Organization can be created");
                }
                else
                {
                    return ServiceResult<OrganizationCreationEligibility>.Success(
                        eligibility,
                        "Organization creation restricted");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization creation eligibility for user: {UserId}", creatorUserId);
                return ServiceResult<OrganizationCreationEligibility>.Failure(
                    "An error occurred while checking creation eligibility",
                    "SYSTEM_ERROR");
            }
        }

        /// <summary>
        /// 조직 삭제 가능 여부 확인
        /// </summary>
        public async Task<ServiceResult<OrganizationDeletionEligibility>> CheckDeletionEligibilityAsync(
            Guid organizationId)
        {
            try
            {
                var eligibility = new OrganizationDeletionEligibility
                {
                    OrganizationId = organizationId,
                    CheckedAt = DateTime.UtcNow
                };

                // 조직 정보 확인
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    eligibility.CanDelete = false;
                    eligibility.BlockingReasons.Add("Organization not found");
                    return ServiceResult<OrganizationDeletionEligibility>.Success(eligibility);
                }

                eligibility.OrganizationName = organization.Name;

                // 하위 조직 확인
                var childCount = await _organizationRepository.CountAsync(
                    o => o.ParentOrganizationId == organizationId && !o.IsDeleted);

                if (childCount > 0)
                {
                    eligibility.HasChildOrganizations = true;
                    eligibility.ChildOrganizationCount = childCount;
                    eligibility.BlockingReasons.Add($"Has {childCount} child organization(s)");
                }

                // 활성 멤버 수 확인
                var memberCount = await _statisticsRepository.GetMemberCountAsync(
                    organizationId,
                    activeOnly: true);
                eligibility.ActiveMemberCount = memberCount;

                if (memberCount > 1) // Owner 제외
                {
                    eligibility.BlockingReasons.Add($"Has {memberCount - 1} active member(s)");
                }

                // 활성 구독 확인
                var activeSubscriptions = await _planSubscriptionRepository.CountAsync(
                    p => p.OrganizationId == organizationId &&
                    (p.Status == SubscriptionStatus.Active || p.Status == SubscriptionStatus.Trial));

                if (activeSubscriptions > 0)
                {
                    eligibility.HasActiveSubscriptions = true;
                    eligibility.ActiveSubscriptionCount = activeSubscriptions;
                    eligibility.BlockingReasons.Add($"Has {activeSubscriptions} active subscription(s)");
                }

                // 활성 애플리케이션 확인
                var applicationCount = await _statisticsRepository.GetApplicationCountAsync(organizationId);
                if (applicationCount > 0)
                {
                    eligibility.ActiveApplicationCount = applicationCount;
                    eligibility.BlockingReasons.Add($"Has {applicationCount} active application(s)");
                }

                // 영향도 평가
                eligibility.ImpactLevel = EvaluateDeletionImpact(eligibility);

                // 권장 조치 사항 생성
                eligibility.RecommendedActions = GenerateRecommendedActions(eligibility);

                // 최종 삭제 가능 여부 결정
                eligibility.CanDelete = eligibility.BlockingReasons.Count == 0;

                return ServiceResult<OrganizationDeletionEligibility>.Success(
                    eligibility,
                    eligibility.CanDelete ? "Organization can be deleted" : "Organization deletion blocked");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization deletion eligibility: {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDeletionEligibility>.Failure(
                    "An error occurred while checking deletion eligibility",
                    "SYSTEM_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 시스템 예약어 목록 가져오기 (캐시 적용)
        /// </summary>
        /// <summary>
        /// 시스템 예약어 목록 가져오기 (캐시 적용)
        /// </summary>
        private async Task<HashSet<string>> GetReservedKeysAsync()
        {
            return await _cache.GetOrCreateAsync(CACHE_KEY_RESERVED_KEYS, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24); // 24시간 캐싱

                // Task.FromResult를 사용하여 비동기 컨텍스트 유지
                await Task.CompletedTask; // 비동기 경고 제거용

                return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
            "admin", "api", "app", "auth", "authhive",
            "dashboard", "docs", "help", "login", "logout",
            "oauth", "organization", "platform", "portal",
            "register", "root", "settings", "signup", "support",
            "system", "test", "user", "www", "mail", "ftp",
            "blog", "news", "shop", "store", "forum"
                };
            }) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase); // null 방어 코드 추가
        }

        /// <summary>
        /// 사용자가 소유한 조직 목록 가져오기
        /// </summary>
        private async Task<List<Guid>> GetUserOwnedOrganizationsAsync(Guid userId)
        {
            // OrganizationMembership를 통해 사용자가 Owner인 조직 찾기
            // ConnectedId -> User 관계를 통해 접근
            var memberships = await _membershipRepository.FindAsync(
                m => m.Member.User.Id == userId &&
                m.MemberRole == "Owner" &&
                m.Status == OrganizationMembershipStatus.Active);

            return memberships.Select(m => m.OrganizationId).ToList();
        }

        /// <summary>
        /// 사용자가 소유한 조직 수 가져오기 (캐시 적용)
        /// </summary>
        private async Task<int> GetUserOrganizationCountAsync(Guid userId)
        {
            var cacheKey = string.Format(CACHE_KEY_USER_ORG_COUNT, userId);

            return await _cache.GetOrCreateAsync(cacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10); // 10분 캐싱

                // ConnectedId -> User 관계를 통해 접근
                var count = await _membershipRepository.CountAsync(
                    m => m.Member.User.Id == userId &&
                    m.MemberRole == "Owner" &&
                    m.Status == OrganizationMembershipStatus.Active);

                return count;
            });
        }

        /// <summary>
        /// 사용자의 가장 높은 플랜 확인
        /// </summary>
        private async Task<string?> GetUserHighestPlanAsync(List<Guid> organizationIds)
        {
            if (!organizationIds.Any())
                return null;

            var subscriptions = await _planSubscriptionRepository.FindAsync(
                p => organizationIds.Contains(p.OrganizationId) &&
                p.IsActive);

            // 플랜 우선순위 정의
            var planPriority = new Dictionary<string, int>
            {
                [PricingConstants.SubscriptionPlans.ENTERPRISE_KEY] = 4,
                [PricingConstants.SubscriptionPlans.BUSINESS_KEY] = 3,
                [PricingConstants.SubscriptionPlans.PRO_KEY] = 2,
                [PricingConstants.SubscriptionPlans.BASIC_KEY] = 1
            };

            var highestPlan = subscriptions
                .Select(s => s.Plan?.PlanKey ?? PricingConstants.SubscriptionPlans.BASIC_KEY)
                .OrderByDescending(key => planPriority.GetValueOrDefault(key, 0))
                .FirstOrDefault();

            return highestPlan;
        }

        /// <summary>
        /// 조직 키 형식 검증
        /// </summary>
        private bool IsValidOrganizationKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return false;

            // 3-50자, 영문 소문자, 숫자, 하이픈만 허용
            // 첫글자와 마지막 글자는 영문 소문자 또는 숫자
            var pattern = @"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$";
            return Regex.IsMatch(key, pattern);
        }

        /// <summary>
        /// 추천 플랜 결정
        /// </summary>
        private string GetRecommendedPlan(string currentPlan)
        {
            return currentPlan switch
            {
                var p when p == PricingConstants.SubscriptionPlans.BASIC_KEY =>
                    PricingConstants.SubscriptionPlans.PRO_KEY,
                var p when p == PricingConstants.SubscriptionPlans.PRO_KEY =>
                    PricingConstants.SubscriptionPlans.BUSINESS_KEY,
                var p when p == PricingConstants.SubscriptionPlans.BUSINESS_KEY =>
                    PricingConstants.SubscriptionPlans.ENTERPRISE_KEY,
                _ => PricingConstants.SubscriptionPlans.ENTERPRISE_KEY
            };
        }

        /// <summary>
        /// 삭제 영향도 평가
        /// </summary>
        private string EvaluateDeletionImpact(OrganizationDeletionEligibility eligibility)
        {
            var score = 0;

            score += eligibility.ChildOrganizationCount * 10;
            score += eligibility.ActiveMemberCount * 5;
            score += eligibility.ActiveApplicationCount * 8;
            score += eligibility.ActiveSubscriptionCount * 7;

            if (eligibility.OutstandingBalance > 0) score += 20;
            if (eligibility.IsUnderLegalHold) score += 50;

            return score switch
            {
                >= 50 => "High",
                >= 20 => "Medium",
                _ => "Low"
            };
        }

        /// <summary>
        /// 권장 조치 사항 생성
        /// </summary>
        private List<string> GenerateRecommendedActions(OrganizationDeletionEligibility eligibility)
        {
            var actions = new List<string>();

            if (eligibility.HasChildOrganizations)
                actions.Add("Delete or reassign all child organizations");

            if (eligibility.ActiveMemberCount > 1)
                actions.Add("Remove all members except the owner");

            if (eligibility.HasActiveSubscriptions)
                actions.Add("Cancel all active subscriptions");

            if (eligibility.ActiveApplicationCount > 0)
                actions.Add("Delete or transfer all applications");

            if (eligibility.OutstandingBalance > 0)
                actions.Add("Pay all outstanding balances");

            if (eligibility.IsUnderLegalHold)
                actions.Add("Contact legal department to remove legal hold");

            if (eligibility.RequiresDataRetention)
                actions.Add("Wait for data retention period to expire or export data");

            return actions;
        }

        #endregion
    }
}