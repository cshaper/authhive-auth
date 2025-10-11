using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Enums.Audit; // AuditEnums 사용을 위해 필요
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Core.Models.Infra.Events;
using AuthHive.Auth.Middleware; // IOrganizationSettingsQueryRepository


namespace AuthHive.Auth.Services.Authorization
{
    /// <summary>
    /// 플랜 제한 및 기능 토글 서비스 구현 - AuthHive v16
    /// IOrganizationSettingsQueryRepository를 사용하여 조직별 토글 상태를 확인합니다.
    /// AuthHive 조직 ID에 대한 모든 제한을 우회합니다.
    /// </summary>
    public class PlanRestrictionService : IPlanRestrictionService
    {
        private readonly ICacheService _cacheService;
        private readonly ILogger<PlanRestrictionService> _logger;
        private readonly IOrganizationSettingsQueryRepository _settingsQueryRepository;
        private readonly IEventBus _eventBus;

        // PricingConstants에서 정의된 ID 사용
        private static readonly Guid AuthHiveSuperOrgId = PricingConstants.AuthHiveSuperOrgId;
        private static readonly string[] DefaultTiers = {
            PricingConstants.SubscriptionPlans.BASIC_KEY,
            PricingConstants.SubscriptionPlans.PRO_KEY,
            PricingConstants.SubscriptionPlans.BUSINESS_KEY,
            PricingConstants.SubscriptionPlans.ENTERPRISE_KEY
        };

        public PlanRestrictionService(
            ICacheService cacheService,
            ILogger<PlanRestrictionService> logger,
            IOrganizationSettingsQueryRepository settingsQueryRepository,
            IEventBus eventBus)
        {
            _cacheService = cacheService;
            _logger = logger;
            _settingsQueryRepository = settingsQueryRepository;
            _eventBus = eventBus;
        }

        #region IPlanRestrictionService 구현

        public async Task<HashSet<string>> GetRestrictionsAsync(
            string pricingTier,
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            //(SuperOrgId)인 경우, 모든 유료 플랜 및 기능 제한을 우회하고 무제한 사용을 허용하기 위해 빈 제한 목록을 즉시 반환합니다.
            if (organizationId == AuthHiveSuperOrgId)
            {
                return new HashSet<string>();
            }

            var cacheKey = $"plan_restrictions:{pricingTier}:{organizationId}";
            var cached = await _cacheService.GetAsync<HashSet<string>>(cacheKey, cancellationToken);

            if (cached != null)
            {
                return cached;
            }

            // 2. 제한 목록 빌드
            var restrictions = BuildRestrictions(pricingTier);

            await _cacheService.SetAsync(cacheKey, restrictions, TimeSpan.FromHours(1), cancellationToken);
            return restrictions;
        }

        public async Task WarmUpCacheAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogDebug("Warming up plan restriction cache...");

                var warmUpTasks = DefaultTiers.Select(tier =>
                    // Guid.Empty 대신 임시로 AuthHiveSuperOrgId 사용 (제한 없음 결과를 캐싱)
                    GetRestrictionsAsync(tier, AuthHiveSuperOrgId, cancellationToken)
                );

                await Task.WhenAll(warmUpTasks);

                _logger.LogInformation("Plan restriction cache warmed up for {Count} tiers.", DefaultTiers.Length);
            }
            catch (Exception ex)
            {
                await _eventBus.PublishAsync(
                    new InfraErrorEvent(
                        // 1. aggregateId: AuthHive 슈퍼 조직 ID를 주체로 사용
                        PricingConstants.AuthHiveSuperOrgId,

                        // 2. ErrorCode: 오류 유형을 나타내는 코드 사용 (예시 코드)
                        "PLAN_RESTRICTION_CACHE_FAILURE",

                        // 3. ErrorMessage: 실제 예외 메시지
                        $"Plan restriction cache failed to warm up: {ex.Message}"),
                    cancellationToken);

                // 로깅은 유지
                _logger.LogWarning(ex, "Failed to warm up plan restriction cache");
            }
        }

        /// <summary>
        /// [핵심 기능] 조직 설정 기반으로 기능 토글 상태를 확인합니다.
        /// </summary>
        public async Task<bool> IsFeatureToggleEnabledAsync(
            Guid organizationId,
            string featureKey,
            CancellationToken cancellationToken = default)
        {
            // 1. [슈퍼 조직 우회] AuthHive 조직은 모든 기능을 무제한으로 사용합니다.
            if (organizationId == AuthHiveSuperOrgId)
            {
                return true;
            }

            // 2. [설정 조회] IOrganizationSettingsQueryRepository를 사용하여 설정을 조회합니다.
            var setting = await _settingsQueryRepository.GetSettingAsync(
                organizationId,
                "CostOptimization",
                featureKey, // SettingKey로 사용 (예: "EnableAdvancedCaching")
                true); // 상속된 설정 포함

            // 3. 설정 값 해석: 설정이 존재하고 값이 "true"일 경우에만 활성화된 것으로 간주 (기본값은 false)
            if (setting == null)
            {
                return false;
            }

            // setting.SettingValue는 string이므로, bool.TryParse로 안전하게 파싱
            return bool.TryParse(setting.SettingValue, out bool isEnabled) && isEnabled;
        }

        /// <summary>
        /// 기능을 강제하며 비활성화 시 예외를 발생시킵니다.
        /// </summary>
        public async Task EnforceFeatureEnabledAsync(
            Guid organizationId,
            string featureKey,
            CancellationToken cancellationToken = default)
        {
            if (!await IsFeatureToggleEnabledAsync(organizationId, featureKey, cancellationToken))
            {
                // FeatureRestrictionException은 Service Layer에서 ServiceResult.Forbidden 또는 Conflict로 변환될 것입니다.
                throw new FeatureRestrictionException(
                    PricingConstants.BusinessErrorCodes.UpgradeRequired,
                    $"Feature '{featureKey}' is not enabled. Please check your plan or Organization settings.");
            }
        }

        #endregion

        // ============ [누락된 함수 추가] 빌드 로직 ============
        /// <summary>
        /// 플랜 타입에 따른 제한 목록을 생성합니다. (BuildRestrictions)
        /// </summary>
        private static HashSet<string> BuildRestrictions(string? pricingTier)
        {
            var restrictions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            switch (pricingTier?.ToLower())
            {
                case PricingConstants.SubscriptionPlans.BASIC_KEY:
                case "basic":
                    restrictions.Add("role:max_count"); // 역할 개수 제한 (PricingConstants.RoleLimits)
                    restrictions.Add("member:max_count"); // 멤버 수 제한
                    restrictions.Add("mau:max_limit"); // MAU 한도 제한
                    restrictions.Add("permissions:complexity"); // 권한 복잡도 제한
                    restrictions.Add("api:rate_strict"); // API 속도 제한 (Strict)
                    restrictions.Add("data:storage_limit"); // 스토리지 제한
                    restrictions.Add("admin:bulk_ops"); // Bulk 작업 금지
                    break;

                case PricingConstants.SubscriptionPlans.PRO_KEY:
                case "pro":
                    restrictions.Add("mau:overage_fee"); // MAU 초과 요금 부과
                    restrictions.Add("api:rate_burst"); // API 속도 제한 (Burst)
                    restrictions.Add("data:egress_charge"); // 데이터 송신 요금 부과
                    restrictions.Add("integration:sso_saml_limit"); // SSO 연동 개수 제한
                    break;

                case PricingConstants.SubscriptionPlans.BUSINESS_KEY:
                case "business":
                    restrictions.Add("api:rate_queue"); // API 속도 제한 (Queue)
                    restrictions.Add("org:depth_limit"); // 조직 계층 깊이 제한
                    break;

                case PricingConstants.SubscriptionPlans.ENTERPRISE_KEY:
                case "enterprise":
                    // 엔터프라이즈는 기본적으로 모든 제한을 해제하지만, 커스텀 제한이 있을 수 있음
                    // restrictions.Add("custom:security_audit_required"); 
                    break;

                default:
                    // 정의되지 않은 플랜에 대한 안전장치 (기본적으로 가장 엄격한 제한 적용)
                    restrictions.Add("all:access_denied");
                    break;
            }

            return restrictions;
        }
    }
}