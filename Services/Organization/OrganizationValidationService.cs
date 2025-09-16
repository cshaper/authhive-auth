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

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                var testQuery = await _organizationRepository.ExistsAsync(Guid.Empty);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationValidationService health check failed");
                return false;
            }
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing OrganizationValidationService");
            await GetReservedKeysAsync();
            _logger.LogInformation("OrganizationValidationService initialized successfully");
        }

        #endregion

        #region IOrganizationValidationService Implementation

        public async Task<ServiceResult<bool>> IsKeyAvailableAsync(string organizationKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(organizationKey))
                {
                    return ServiceResult<bool>.Failure("Organization key cannot be empty", "VALIDATION_ERROR");
                }
                
                var cacheKey = string.Format(CACHE_KEY_ORG_KEY_AVAILABLE, organizationKey.ToLower());
                if (_cache.TryGetValue<bool>(cacheKey, out var cachedResult))
                {
                    _logger.LogDebug("Organization key availability retrieved from cache: {Key} = {Available}", organizationKey, cachedResult);
                    return ServiceResult<bool>.Success(cachedResult, cachedResult ? "Organization key is available (cached)" : "Organization key is already in use (cached)");
                }

                if (!IsValidOrganizationKey(organizationKey))
                {
                    return ServiceResult<bool>.Failure("Invalid organization key format. Must be 3-50 characters, alphanumeric with hyphens only", "INVALID_FORMAT");
                }

                var reservedKeys = await GetReservedKeysAsync();
                if (reservedKeys.Contains(organizationKey.ToLower()))
                {
                    return ServiceResult<bool>.Failure("This organization key is reserved and cannot be used", "RESERVED_KEY");
                }

                var exists = await _organizationRepository.IsOrganizationKeyExistsAsync(organizationKey);
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
                return ServiceResult<bool>.Failure("An error occurred while checking key availability", "SYSTEM_ERROR");
            }
        }

        public async Task<ServiceResult<bool>> ExistsAsync(Guid organizationId)
        {
            try
            {
                if (organizationId == Guid.Empty)
                {
                    return ServiceResult<bool>.Success(false, "Invalid organization ID");
                }
                
                var cacheKey = string.Format(CACHE_KEY_ORG_EXISTS, organizationId);
                if (_cache.TryGetValue<bool>(cacheKey, out var cachedExists))
                {
                    return ServiceResult<bool>.Success(cachedExists, cachedExists ? "Organization exists (cached)" : "Organization not found (cached)");
                }

                var exists = await _organizationRepository.ExistsAsync(organizationId);
                _cache.Set(cacheKey, exists, TimeSpan.FromMinutes(10));

                return ServiceResult<bool>.Success(exists, exists ? "Organization exists" : "Organization not found");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization existence: {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure("An error occurred while checking organization existence", "SYSTEM_ERROR");
            }
        }

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
                
                var isActive = organization.Status == OrganizationStatus.Active && !organization.IsDeleted;
                return ServiceResult<bool>.Success(isActive, isActive ? "Organization is active" : "Organization is not active");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization active status: {OrganizationId}", organizationId);
                return ServiceResult<bool>.Failure("An error occurred while checking organization status", "SYSTEM_ERROR");
            }
        }

        public async Task<ServiceResult<OrganizationCreationEligibility>> CheckCreationEligibilityAsync(Guid creatorUserId)
        {
            try
            {
                var eligibility = new OrganizationCreationEligibility
                {
                    UserId = creatorUserId,
                    CheckedAt = DateTime.UtcNow
                };

                var user = await _userRepository.GetByIdAsync(creatorUserId);
                if (user == null)
                {
                    eligibility.CanCreate = false;
                    eligibility.Restrictions.Add("User not found");
                    return ServiceResult<OrganizationCreationEligibility>.Success(eligibility);
                }
                
                eligibility.AccountStatus = "Active"; // 임시 값
                eligibility.IsAccountVerified = true;
                eligibility.IsEmailVerified = true; // TODO: User 엔티티에서 확인

                var userOwnedOrgs = await GetUserOwnedOrganizationsAsync(creatorUserId);
                var highestPlan = await GetUserHighestPlanAsync(userOwnedOrgs);
                eligibility.CurrentPlan = highestPlan ?? PricingConstants.SubscriptionPlans.BASIC_KEY;
                
                var maxOrganizations = PricingConstants.SubscriptionPlans.OrganizationLimits.GetValueOrDefault(eligibility.CurrentPlan, 1);
                eligibility.MaxOrganizationsAllowed = maxOrganizations;
                
                var currentOrgCount = await GetUserOrganizationCountAsync(creatorUserId);
                eligibility.CurrentOrganizationCount = currentOrgCount;
                
                if (maxOrganizations == -1) // 무제한
                {
                    eligibility.CanCreate = true;
                }
                else if (currentOrgCount >= maxOrganizations)
                {
                    eligibility.CanCreate = false;
                    eligibility.RequiresPlanUpgrade = true;
                    eligibility.Restrictions.Add($"Organization limit reached ({currentOrgCount}/{maxOrganizations})");
                    eligibility.RecommendedPlan = GetRecommendedPlan(eligibility.CurrentPlan);
                }
                else
                {
                    eligibility.CanCreate = true;
                }
                
                if (userOwnedOrgs.Any())
                {
                    var hasAnyOutstandingBalance = await _organizationRepository.AnyAsync(o => userOwnedOrgs.Contains(o.Id) && o.HasOutstandingBalance);
                    if (hasAnyOutstandingBalance)
                    {
                        eligibility.HasOutstandingBalance = true;
                        eligibility.CanCreate = false;
                        eligibility.Restrictions.Add("Outstanding balance exists in one or more owned organizations");
                    }
                }

                if (eligibility.Restrictions.Count == 0 && eligibility.CanCreate)
                {
                    return ServiceResult<OrganizationCreationEligibility>.Success(eligibility, "Organization can be created");
                }
                else
                {
                    return ServiceResult<OrganizationCreationEligibility>.Success(eligibility, "Organization creation restricted");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization creation eligibility for user: {UserId}", creatorUserId);
                return ServiceResult<OrganizationCreationEligibility>.Failure("An error occurred while checking creation eligibility", "SYSTEM_ERROR");
            }
        }

        public async Task<ServiceResult<OrganizationDeletionEligibility>> CheckDeletionEligibilityAsync(Guid organizationId)
        {
            try
            {
                var eligibility = new OrganizationDeletionEligibility
                {
                    OrganizationId = organizationId,
                    CheckedAt = DateTime.UtcNow
                };

                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    eligibility.CanDelete = false;
                    eligibility.BlockingReasons.Add("Organization not found");
                    return ServiceResult<OrganizationDeletionEligibility>.Success(eligibility);
                }

                eligibility.OrganizationName = organization.Name;
                
                var childCount = await _organizationRepository.CountAsync(o => o.ParentOrganizationId == organizationId && !o.IsDeleted);
                if (childCount > 0)
                {
                    eligibility.HasChildOrganizations = true;
                    eligibility.ChildOrganizationCount = childCount;
                    eligibility.BlockingReasons.Add($"Has {childCount} child organization(s)");
                }

                var memberCount = await _statisticsRepository.GetMemberCountAsync(organizationId, activeOnly: true);
                eligibility.ActiveMemberCount = memberCount;
                if (memberCount > 1)
                {
                    eligibility.BlockingReasons.Add($"Has {memberCount - 1} active member(s)");
                }

                var activeSubscriptions = await _planSubscriptionRepository.CountAsync(
                    p => p.OrganizationId == organizationId && (p.Status == SubscriptionStatus.Active || p.Status == SubscriptionStatus.Trial));
                if (activeSubscriptions > 0)
                {
                    eligibility.HasActiveSubscriptions = true;
                    eligibility.ActiveSubscriptionCount = activeSubscriptions;
                    eligibility.BlockingReasons.Add($"Has {activeSubscriptions} active subscription(s)");
                }

                var applicationCount = await _statisticsRepository.GetApplicationCountAsync(organizationId);
                if (applicationCount > 0)
                {
                    eligibility.ActiveApplicationCount = applicationCount;
                    eligibility.BlockingReasons.Add($"Has {applicationCount} active application(s)");
                }
                
                eligibility.ImpactLevel = EvaluateDeletionImpact(eligibility);
                eligibility.RecommendedActions = GenerateRecommendedActions(eligibility);
                eligibility.CanDelete = eligibility.BlockingReasons.Count == 0;

                return ServiceResult<OrganizationDeletionEligibility>.Success(eligibility, eligibility.CanDelete ? "Organization can be deleted" : "Organization deletion blocked");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking organization deletion eligibility: {OrganizationId}", organizationId);
                return ServiceResult<OrganizationDeletionEligibility>.Failure("An error occurred while checking deletion eligibility", "SYSTEM_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task<HashSet<string>> GetReservedKeysAsync()
        {
            return await _cache.GetOrCreateAsync(CACHE_KEY_RESERVED_KEYS, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24);
                await Task.CompletedTask;
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "admin", "api", "app", "auth", "authhive", "dashboard", "docs", "help", "login", "logout",
                    "oauth", "organization", "platform", "portal", "register", "root", "settings", "signup",
                    "support", "system", "test", "user", "www", "mail", "ftp", "blog", "news", "shop", "store", "forum"
                };
            }) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        private async Task<List<Guid>> GetUserOwnedOrganizationsAsync(Guid userId)
        {
            // ✨ 1. [오류 수정] CS0019: '==' 연산자를 'OrganizationMemberRole' 및 'string'에 적용할 수 없음
            // "Owner" 문자열 대신 OrganizationMemberRole.Owner Enum을 사용하여 비교합니다.
            var memberships = await _membershipRepository.FindAsync(
                m => m.Member.User.Id == userId &&
                m.MemberRole == OrganizationMemberRole.Owner &&
                m.Status == OrganizationMembershipStatus.Active);

            return memberships.Select(m => m.OrganizationId).ToList();
        }

        private async Task<int> GetUserOrganizationCountAsync(Guid userId)
        {
            var cacheKey = string.Format(CACHE_KEY_USER_ORG_COUNT, userId);
            return await _cache.GetOrCreateAsync(cacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10);
                // ✨ 2. [오류 수정] CS0019: '==' 연산자를 'OrganizationMemberRole' 및 'string'에 적용할 수 없음
                // "Owner" 문자열 대신 OrganizationMemberRole.Owner Enum을 사용하여 비교합니다.
                var count = await _membershipRepository.CountAsync(
                    m => m.Member.User.Id == userId &&
                    m.MemberRole == OrganizationMemberRole.Owner &&
                    m.Status == OrganizationMembershipStatus.Active);
                return count;
            });
        }

        private async Task<string?> GetUserHighestPlanAsync(List<Guid> organizationIds)
        {
            if (!organizationIds.Any())
                return null;

            var subscriptions = await _planSubscriptionRepository.FindAsync(
                p => organizationIds.Contains(p.OrganizationId) && p.IsActive);

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

        private bool IsValidOrganizationKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return false;
            var pattern = @"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$";
            return Regex.IsMatch(key, pattern);
        }

        private string GetRecommendedPlan(string currentPlan)
        {
            return currentPlan switch
            {
                var p when p == PricingConstants.SubscriptionPlans.BASIC_KEY => PricingConstants.SubscriptionPlans.PRO_KEY,
                var p when p == PricingConstants.SubscriptionPlans.PRO_KEY => PricingConstants.SubscriptionPlans.BUSINESS_KEY,
                var p when p == PricingConstants.SubscriptionPlans.BUSINESS_KEY => PricingConstants.SubscriptionPlans.ENTERPRISE_KEY,
                _ => PricingConstants.SubscriptionPlans.ENTERPRISE_KEY
            };
        }

        private string EvaluateDeletionImpact(OrganizationDeletionEligibility eligibility)
        {
            var score = 0;
            score += eligibility.ChildOrganizationCount * 10;
            score += eligibility.ActiveMemberCount * 5;
            score += eligibility.ActiveApplicationCount * 8;
            score += eligibility.ActiveSubscriptionCount * 7;
            if (eligibility.OutstandingBalance > 0) score += 20;
            if (eligibility.IsUnderLegalHold) score += 50;
            return score switch { >= 50 => "High", >= 20 => "Medium", _ => "Low" };
        }

        private List<string> GenerateRecommendedActions(OrganizationDeletionEligibility eligibility)
        {
            var actions = new List<string>();
            if (eligibility.HasChildOrganizations) actions.Add("Delete or reassign all child organizations");
            if (eligibility.ActiveMemberCount > 1) actions.Add("Remove all members except the owner");
            if (eligibility.HasActiveSubscriptions) actions.Add("Cancel all active subscriptions");
            if (eligibility.ActiveApplicationCount > 0) actions.Add("Delete or transfer all applications");
            if (eligibility.OutstandingBalance > 0) actions.Add("Pay all outstanding balances");
            if (eligibility.IsUnderLegalHold) actions.Add("Contact legal department to remove legal hold");
            if (eligibility.RequiresDataRetention) actions.Add("Wait for data retention period to expire or export data");
            return actions;
        }

        #endregion
    }
}