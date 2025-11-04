// AuthHive.Auth/Services/Authentication/AuthenticationMethodService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization;
using AuthHive.Core.Interfaces.Repositories.Business.Platform;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Authentication
{
    public class AuthenticationMethodService : IAuthenticationMethodService
    {
        private readonly ILogger<AuthenticationMethodService> _logger;
        private readonly IAuthenticationAttemptLogRepository _attemptLogRepository;
        private readonly IAuthenticationMethodSettingRepository _methodSettingRepository;
        private readonly IOrganizationPlanRepository _planRepository;
        private readonly IUserRepository _userRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IOAuthProviderRepository _oauthRepository;
        private readonly ISSOConfigurationRepository _ssoRepository;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthenticationMethodService(
            ILogger<AuthenticationMethodService> logger,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            IAuthenticationMethodSettingRepository methodSettingRepository,
            IOrganizationPlanRepository planRepository,
            IUserRepository userRepository,
            IConnectedIdRepository connectedIdRepository, // FIX: 의존성 주입 추가
            IOAuthProviderRepository oauthRepository,
            ISSOConfigurationRepository ssoRepository,
            IAuditService auditService,
            IEventBus eventBus,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork,
            IConnectedIdService connectedIdService,
            IHttpContextAccessor httpContextAccessor)
        {
            _logger = logger;
            _attemptLogRepository = attemptLogRepository;
            _methodSettingRepository = methodSettingRepository;
            _planRepository = planRepository;
            _userRepository = userRepository;
            _connectedIdRepository = connectedIdRepository; // FIX: 필드 할당
            _oauthRepository = oauthRepository;
            _ssoRepository = ssoRepository;
            _auditService = auditService;
            _eventBus = eventBus;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _unitOfWork = unitOfWork;
            _connectedIdService = connectedIdService;
            _httpContextAccessor = httpContextAccessor;
        }

        #region IService Implementation with CancellationToken

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("AuthenticationMethodService is healthy.");
            return Task.FromResult(true);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("AuthenticationMethodService initialized.");
            return Task.CompletedTask;
        }

        #endregion


        #region 인증 방식 조회 (오류 없음, 기존 로직 유지)
        public async Task<ServiceResult<IEnumerable<AuthenticationMethodResponse>>> GetAvailableMethodsAsync(Guid? organizationId = null, Guid? applicationId = null) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<IEnumerable<AuthenticationMethodResponse>>()); }
        public async Task<ServiceResult<AuthenticationMethodResponse>> GetMethodAsync(AuthenticationMethod method, Guid? organizationId = null) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<AuthenticationMethodResponse>()); }
        public async Task<ServiceResult<IEnumerable<AuthenticationMethodResponse>>> GetEnabledMethodsAsync(Guid organizationId) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<IEnumerable<AuthenticationMethodResponse>>()); }
        public async Task<ServiceResult<IEnumerable<AuthenticationMethodResponse>>> GetAllMethodsAsync() { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<IEnumerable<AuthenticationMethodResponse>>()); }
        #endregion

        #region 인증 방식 설정

        public async Task<ServiceResult> SetAuthenticationMethodAsync(AuthenticationMethod method, bool enabled, Guid? organizationId = null) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult()); }
        public async Task<ServiceResult> SetMultipleMethodsAsync(Dictionary<AuthenticationMethod, bool> methods, Guid? organizationId = null) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult()); }

        public async Task<ServiceResult> SetMethodPriorityAsync(AuthenticationMethod method, int priority, Guid? organizationId = null)
        {
            if (!organizationId.HasValue)
                return ServiceResult.Failure("Organization ID is required");

            if (priority < 1 || priority > 100)
                return ServiceResult.Failure(string.Format(AuthenticationConstants.ErrorMessages.METHOD_PRIORITY_INVALID, priority));

            try
            {
                var setting = await _methodSettingRepository.FindSettingAsync(organizationId.Value, method);
                if (setting == null)
                    return ServiceResult.Failure($"Method {method} is not configured for the organization.");

                var currentConnectedId = await GetCurrentConnectedIdAsync();
                if (!currentConnectedId.HasValue)
                    return ServiceResult.Failure("User context not found.");

                setting.Priority = priority;
                setting.UpdatedAt = _dateTimeProvider.UtcNow;
                setting.UpdatedByConnectedId = currentConnectedId;

                await _methodSettingRepository.UpdateAsync(setting);
                await InvalidateMethodCacheAsync(organizationId.Value);

                await _auditService.LogActionAsync(
                    AuditActionType.Configuration,
                    $"Priority of {method} changed to {priority}",
                    currentConnectedId.Value,
                    true, null, "AuthenticationMethodSetting", setting.Id.ToString(),
                    new Dictionary<string, object>
                    {
                        { "OrganizationId", organizationId.Value },
                        { "Method", method.ToString() },
                        { "NewPriority", priority }
                    }
                );

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {

                _logger.LogError(ex, "Failed to set authentication method {Method} for organization {OrganizationId}",
                    method, organizationId);
                return ServiceResult.Failure($"Failed to update priority: {ex.Message}");
            }
        }

        public async Task<ServiceResult> UpdateMethodConfigurationAsync(AuthenticationMethod method, Dictionary<string, object> configuration, Guid? organizationId = null)
        {
            if (!organizationId.HasValue)
                return ServiceResult.Failure("Organization ID is required");

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var currentConnectedId = await GetCurrentConnectedIdAsync();
                if (!currentConnectedId.HasValue)
                    return ServiceResult.Failure("User context not found.");

                var setting = await _methodSettingRepository.FindSettingAsync(organizationId.Value, method);
                var actionType = setting == null ? ConfigurationActionType.Created : ConfigurationActionType.Updated;

                setting ??= new AuthenticationMethodSetting
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId.Value,
                    Method = method,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = currentConnectedId.Value
                };

                setting.Configuration = JsonSerializer.Serialize(configuration);
                setting.UpdatedAt = _dateTimeProvider.UtcNow;
                setting.UpdatedByConnectedId = currentConnectedId;

                await _methodSettingRepository.UpsertAsync(setting);
                await InvalidateMethodCacheAsync(organizationId.Value);

                var configEvent = AuthenticationMethodConfiguredEvent.Success(
                    organizationId.Value, method, actionType, currentConnectedId.Value);
                await _eventBus.PublishAsync(configEvent);

                await _auditService.LogActionAsync(
                    AuditActionType.Configuration, $"Configuration {actionType} for {method}",
                    currentConnectedId.Value, true, null, "AuthenticationMethod", method.ToString(),
                    new Dictionary<string, object> { { "OrganizationId", organizationId.Value } }
                );

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Failed to update configuration for {Method}", method);

                var currentConnectedId = await GetCurrentConnectedIdAsync();
                if (organizationId.HasValue && currentConnectedId.HasValue)
                {
                    var failureEvent = AuthenticationMethodConfiguredEvent.Failure(
                        organizationId.Value, method, ConfigurationActionType.Updated, currentConnectedId.Value, ex.Message);
                    await _eventBus.PublishAsync(failureEvent);
                }
                return ServiceResult.Failure($"Failed to update configuration: {ex.Message}");
            }
        }

        #endregion

        #region 사용자별 설정

        public async Task<ServiceResult> SetPreferredMethodAsync(Guid userId, AuthenticationMethod method, CancellationToken cancellationToken = default)
        {
            try
            {
                var connectedIdResult = await _connectedIdService.GetActiveConnectedIdByUserIdAsync(userId, cancellationToken);
                if (!connectedIdResult.IsSuccess)
                    return ServiceResult.Failure($"Failed to find active ConnectedId for user {userId}");

                var connectedId = await _connectedIdRepository.GetByIdAsync(connectedIdResult.Data);
                if (connectedId == null)
                    return ServiceResult.Failure($"ConnectedId not found: {connectedIdResult.Data}");

                var enabledMethods = await _methodSettingRepository.GetEnabledByOrganizationAsync(connectedId.OrganizationId);
                if (!enabledMethods.Any(m => m.Method == method))
                    return ServiceResult.Failure($"Method {method} is not enabled for the user's organization.");

                connectedId.PreferredAuthMethod = method;
                connectedId.UpdatedAt = _dateTimeProvider.UtcNow;
                await _connectedIdRepository.UpdateAsync(connectedId);

                var cacheKey = string.Format(AuthenticationConstants.CacheKeys.USER_PREFERRED, userId);
                await _cacheService.SetStringAsync(cacheKey, method.ToString(), TimeSpan.FromSeconds(AuthenticationConstants.CacheKeys.SETTINGS_TTL_SECONDS));

                await _auditService.LogActionAsync(
                    AuditActionType.Update, "UserPreferredMethodChanged", connectedId.Id, true, null,
                    "ConnectedId", connectedId.Id.ToString(),
                    new Dictionary<string, object> { { "UserId", userId }, { "Method", method.ToString() } }
                );

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set preferred method for user {UserId}", userId);
                return ServiceResult.Failure($"Failed to update user preference: {ex.Message}");
            }
        }

        public async Task<ServiceResult<AuthenticationMethod?>> GetPreferredMethodAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = string.Format(AuthenticationConstants.CacheKeys.USER_PREFERRED, userId);
                var cachedString = await _cacheService.GetStringAsync(cacheKey);
                if (!string.IsNullOrEmpty(cachedString) && Enum.TryParse<AuthenticationMethod>(cachedString, out var cachedMethod))
                    return ServiceResult<AuthenticationMethod?>.Success(cachedMethod);

                var connectedIdResult = await _connectedIdService.GetActiveConnectedIdByUserIdAsync(userId, cancellationToken);
                if (!connectedIdResult.IsSuccess)
                    return ServiceResult<AuthenticationMethod?>.Failure($"Failed to find active ConnectedId for user {userId}");

                var connectedId = await _connectedIdRepository.GetByIdAsync(connectedIdResult.Data);
                if (connectedId == null)
                    return ServiceResult<AuthenticationMethod?>.Failure($"ConnectedId not found: {connectedIdResult.Data}");

                if (connectedId.PreferredAuthMethod.HasValue)
                {
                    await _cacheService.SetStringAsync(cacheKey, connectedId.PreferredAuthMethod.Value.ToString(),
                        TimeSpan.FromSeconds(AuthenticationConstants.CacheKeys.SETTINGS_TTL_SECONDS));
                }

                return ServiceResult<AuthenticationMethod?>.Success(connectedId.PreferredAuthMethod);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get preferred method for user {UserId}", userId);
                return ServiceResult<AuthenticationMethod?>.Failure($"Failed to retrieve user preference: {ex.Message}");
            }
        }

        public async Task<ServiceResult<IEnumerable<AuthenticationMethodResponse>>> GetUserAvailableMethodsAsync(Guid userId, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            try
            {
                Guid targetOrgId;
                if (organizationId.HasValue)
                {
                    targetOrgId = organizationId.Value;
                }
                else
                {
                    var connectedIdResult = await _connectedIdService.GetActiveConnectedIdByUserIdAsync(userId, cancellationToken);
                    if (!connectedIdResult.IsSuccess)
                        return ServiceResult<IEnumerable<AuthenticationMethodResponse>>.Failure($"Active organization for user {userId} not found.");

                    var connectedId = await _connectedIdRepository.GetByIdAsync(connectedIdResult.Data);
                    if (connectedId == null)
                        return ServiceResult<IEnumerable<AuthenticationMethodResponse>>.Failure($"ConnectedId for user {userId} not found.");

                    targetOrgId = connectedId.OrganizationId;
                }

                return await GetAvailableMethodsAsync(targetOrgId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get available methods for user {UserId}", userId);
                return ServiceResult<IEnumerable<AuthenticationMethodResponse>>.Failure($"Failed to retrieve user methods: {ex.Message}");
            }
        }

        public async Task<ServiceResult<UserAuthenticationMethods>> GetUserMethodsAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var connectedIdResult = await _connectedIdService.GetActiveConnectedIdByUserIdAsync(userId, cancellationToken);
                if (!connectedIdResult.IsSuccess)
                    return ServiceResult<UserAuthenticationMethods>.Failure($"Active ConnectedId for user {userId} not found.");

                var connectedId = await _connectedIdRepository.GetByIdAsync(connectedIdResult.Data);
                if (connectedId == null)
                    return ServiceResult<UserAuthenticationMethods>.Failure($"ConnectedId for user {userId} not found.");

                var enabledSettings = await _methodSettingRepository.GetEnabledByOrganizationAsync(connectedId.OrganizationId);

                var userMethods = new UserAuthenticationMethods
                {
                    UserId = userId,
                    PreferredMethod = connectedId.PreferredAuthMethod,
                    EnabledMethods = enabledSettings.Select(s => s.Method).ToList(),
                    // LastUpdated = connectedId.UpdatedAt ?? _dateTimeProvider.UtcNow // FIX: LastUpdated is not a property of UserAuthenticationMethods.
                };

                return ServiceResult<UserAuthenticationMethods>.Success(userMethods);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user methods for {UserId}", userId);
                return ServiceResult<UserAuthenticationMethods>.Failure($"Failed to retrieve user methods: {ex.Message}");
            }
        }

        #endregion

        #region OAuth/Social & SSO 설정

        public async Task<ServiceResult> ConfigureOAuthProviderAsync(SSOProvider provider, OAuthProviderConfiguration configuration, Guid? organizationId = null) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult()); }
        public async Task<ServiceResult<OAuthProviderConfiguration>> GetOAuthProviderConfigurationAsync(SSOProvider provider, Guid? organizationId = null) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult<OAuthProviderConfiguration>()); }
        public async Task<ServiceResult> RemoveOAuthProviderAsync(SSOProvider provider, Guid? organizationId = null) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult()); }
        public async Task<ServiceResult> ConfigureSSOAsync(SSOProtocol protocol, SSOConfiguration configuration, Guid organizationId) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult()); }
        public async Task<ServiceResult<SSOConfiguration>> GetSSOConfigurationAsync(Guid organizationId) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult<SSOConfiguration>()); }
        public async Task<ServiceResult> UpdateSSOMetadataAsync(Guid organizationId, string metadata) { /* ... 기존 수정된 코드 유지 ... */ return await Task.FromResult(new ServiceResult()); }

        #endregion

        #region 검증 및 정책 (오류 없음, 기존 로직 유지)
        public async Task<ServiceResult<bool>> IsMethodAvailableAsync(AuthenticationMethod method, Guid? organizationId = null, Guid? userId = null) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<bool>()); }
        public async Task<ServiceResult<MethodPolicyValidation>> ValidateMethodPolicyAsync(AuthenticationMethod method, Guid? organizationId = null) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<MethodPolicyValidation>()); }
        public async Task<ServiceResult<MethodRequirements>> GetMethodRequirementsAsync(AuthenticationMethod method) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<MethodRequirements>()); }
        #endregion

        #region 통계 및 분석 (오류 없음, 기존 로직 유지)
        public async Task<ServiceResult<MethodUsageStatistics>> GetMethodUsageStatisticsAsync(Guid? organizationId = null, DateTime? from = null, DateTime? to = null) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<MethodUsageStatistics>()); }
        public async Task<ServiceResult<Dictionary<AuthenticationMethod, double>>> GetMethodSuccessRatesAsync(Guid? organizationId = null, TimeSpan? period = null) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<Dictionary<AuthenticationMethod, double>>()); }
        public async Task<ServiceResult<MethodTrendAnalysis>> AnalyzeMethodTrendsAsync(Guid? organizationId = null) { /* ... 기존 코드 ... */ return await Task.FromResult(new ServiceResult<MethodTrendAnalysis>()); }
        #endregion

        #region Private Helper Methods

        private async Task<Guid?> GetCurrentConnectedIdAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var userIdClaim = _httpContextAccessor.HttpContext?.User?.FindFirst("UserId")?.Value;
                if (Guid.TryParse(userIdClaim, out var currentUserId))
                {
                    var result = await _connectedIdService.GetActiveConnectedIdByUserIdAsync(currentUserId, cancellationToken);
                    return result.IsSuccess ? result.Data : null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get current user context.");
            }
            return null;
        }

        private string? GetNextPlanForFeature(string currentPlanKey, Func<string, bool> hasFeature)
        {
            var planOrder = new[]
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY,
                PricingConstants.SubscriptionPlans.PRO_KEY,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY
            };

            var currentPlanIndex = Array.IndexOf(planOrder, currentPlanKey);
            if (currentPlanIndex == -1)
            {
                return null; // This is now valid.
            }

            for (int i = currentPlanIndex + 1; i < planOrder.Length; i++)
            {
                if (hasFeature(planOrder[i]))
                {
                    return planOrder[i];
                }
            }

            return null;
        }

        private async Task InvalidateMethodCacheAsync(Guid organizationId)
        {
            var cacheKeys = new[]
            {
                string.Format(AuthenticationConstants.CacheKeys.METHOD_SETTINGS, organizationId),
                string.Format(AuthenticationConstants.CacheKeys.AVAILABLE_METHODS, organizationId)
            };
            foreach (var key in cacheKeys)
            {
                await _cacheService.RemoveAsync(key);
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 조직의 현재 플랜 키 조회
        /// </summary>
        private async Task<string> GetOrganizationPlanKeyAsync(Guid? organizationId,  CancellationToken cancellationToken = default)
        {
            if (!organizationId.HasValue)
            {
                return PricingConstants.DefaultPlanKey;
            }

            var plan = await _planRepository.GetActivePlanByOrganizationIdAsync(organizationId.Value, cancellationToken);

            return plan?.PlanKey ?? PricingConstants.DefaultPlanKey;

        }

        /// <summary>
        /// 플랜에서 사용 가능한 인증 방식 조회
        /// </summary>
        private HashSet<AuthenticationMethod> GetAvailableMethodsForPlan(string planKey)
        {
            if (AuthenticationConstants.PlanAuthMethods.AvailableMethods.TryGetValue(planKey, out var methods))
            {
                return methods;
            }

            return AuthenticationConstants.PlanAuthMethods.AvailableMethods[PricingConstants.DefaultPlanKey];
        }

        /// <summary>
        /// 인증 방식이 사용 가능한 최소 플랜 조회
        /// </summary>
        private string GetMinimumPlanForMethod(AuthenticationMethod method)
        {
            var planOrder = new[]
            {
                PricingConstants.SubscriptionPlans.BASIC_KEY,
                PricingConstants.SubscriptionPlans.PRO_KEY,
                PricingConstants.SubscriptionPlans.BUSINESS_KEY,
                PricingConstants.SubscriptionPlans.ENTERPRISE_KEY
            };

            foreach (var planKey in planOrder)
            {
                if (AuthenticationConstants.PlanAuthMethods.AvailableMethods.TryGetValue(planKey, out var methods))
                {
                    if (methods.Contains(method))
                    {
                        return planKey;
                    }
                }
            }

            return PricingConstants.SubscriptionPlans.ENTERPRISE_KEY;
        }

        /// <summary>
        /// 인증 방식이 설정이 필요한지 확인
        /// </summary>
        private bool RequiresConfiguration(AuthenticationMethod method)
        {
            return method switch
            {
                AuthenticationMethod.OAuth => true,
                AuthenticationMethod.SAML => true,
                AuthenticationMethod.LDAP => true,
                AuthenticationMethod.CustomProvider => true,
                _ => false
            };
        }

        /// <summary>
        /// 인증 방식 설명 조회
        /// </summary>
        private string GetMethodDescription(AuthenticationMethod method)
        {
            return method switch
            {
                AuthenticationMethod.Password => "Traditional username and password authentication",
                AuthenticationMethod.EmailOTP => "One-time password sent via email",
                AuthenticationMethod.SMS => "One-time password sent via SMS",
                AuthenticationMethod.TOTP => "Time-based OTP using apps like Google Authenticator",
                AuthenticationMethod.OAuth => "Social login (Google, GitHub, etc.)",
                AuthenticationMethod.SAML => "Enterprise single sign-on",
                AuthenticationMethod.LDAP => "Active Directory / LDAP integration",
                AuthenticationMethod.Biometric => "Fingerprint or face recognition",
                AuthenticationMethod.Passkey => "Passwordless authentication using WebAuthn",
                AuthenticationMethod.MagicLink => "Passwordless login via email link",
                AuthenticationMethod.Certificate => "X.509 certificate-based authentication",
                AuthenticationMethod.CustomProvider => "Custom authentication provider",
                _ => "Authentication method"
            };
        }

        /// <summary>
        /// 추천 인증 방식 계산
        /// </summary>
        private List<AuthenticationMethod> GetRecommendedMethods(AuthenticationStatisticsReadModel data)
        {
            // 보안 점수와 사용률을 기반으로 추천
            var recommendations = new List<AuthenticationMethod>();

            // 높은 보안 점수를 가진 방식 추천
            if (data.AttemptsByMethod.ContainsKey(AuthenticationMethod.Biometric))
            {
                recommendations.Add(AuthenticationMethod.Biometric);
            }

            if (data.AttemptsByMethod.ContainsKey(AuthenticationMethod.Passkey))
            {
                recommendations.Add(AuthenticationMethod.Passkey);
            }

            return recommendations;
        }

        /// <summary>
        /// 보안 점수 향상도 계산
        /// </summary>
        private double CalculateSecurityImprovement(AuthenticationStatisticsReadModel data)
        {
            // 사용된 인증 방식의 가중 평균 보안 점수 계산
            double totalScore = 0;
            int totalAttempts = 0;

            foreach (var kvp in data.AttemptsByMethod)
            {
                var score = AuthenticationConstants.SecurityScore.GetValueOrDefault(kvp.Key, 0);
                totalScore += score * kvp.Value;
                totalAttempts += kvp.Value;
            }

            return totalAttempts > 0 ? totalScore / totalAttempts : 0;
        }

        #endregion
    }
}