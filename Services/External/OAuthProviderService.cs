// 파일: AuthHive.Auth.Services.External/OAuthProviderService.cs (최종 수정)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Validation;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.Repositories.Business.Platform;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User;
using Microsoft.Extensions.Logging;

// 엔티티 클래스 별칭
using OAuthProviderEntity = AuthHive.Core.Entities.Auth.OAuthProvider;
using UserEntity = AuthHive.Core.Entities.User.User;
using OrganizationMemberRole = AuthHive.Core.Enums.Core.OrganizationMemberRole;

namespace AuthHive.Auth.Services.External
{
    public class OAuthProviderService : IOAuthProviderService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ICacheService _cacheService;
        private readonly IEncryptionService _encryptionService;
        private readonly IOrganizationPlanRepository _planRepository;
        private readonly IOAuthProviderRepository _oauthProviderRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly ILogger<OAuthProviderService> _logger;
        private readonly IReadOnlyDictionary<PlanLimitType, ILimitChecker> _limitCheckers;
        private readonly Dictionary<SSOProvider, OAuthProviderConfiguration> _providerConfigs = new(); 

        #region IExternalService Properties (생략)
        public string ServiceName => "OAuthProviderService";
        public string Provider => "Multi-Provider OAuth";
        public string? ApiVersion => "2.0";
        public RetryPolicy RetryPolicy { get; set; } = new();
        public int TimeoutSeconds { get; set; } = 30;
        public bool EnableCircuitBreaker { get; set; } = true;
        public IExternalService? FallbackService { get; set; }
        public event EventHandler<ExternalServiceCalledEventArgs>? ServiceCalled;
        public event EventHandler<ExternalServiceFailedEventArgs>? ServiceFailed;
        public event EventHandler<ExternalServiceRecoveredEventArgs>? ServiceRecovered;
        #endregion

        public OAuthProviderService(
            IHttpClientFactory httpClientFactory, ICacheService cacheService, IEncryptionService encryptionService,
            IOrganizationPlanRepository planRepository, IOAuthProviderRepository oauthProviderRepository,
            IUnitOfWork unitOfWork, IEventBus eventBus, IAuditService auditService,
            IPrincipalAccessor principalAccessor, ILogger<OAuthProviderService> logger,
            IEnumerable<ILimitChecker> limitCheckers)
        {
            _httpClientFactory = httpClientFactory; _cacheService = cacheService; _encryptionService = encryptionService;
            _planRepository = planRepository; _oauthProviderRepository = oauthProviderRepository;
            _unitOfWork = unitOfWork; _eventBus = eventBus; _auditService = auditService;
            _principalAccessor = principalAccessor; _logger = logger;
            _limitCheckers = limitCheckers.ToDictionary(c => c.HandledLimitType);
        }

        #region IOAuthProviderService Implementation
        // ... (RegisterProviderAsync 및 GetProviderConfigAsync 등 다른 메서드 유지) ...
        
        public async Task<ServiceResult> RegisterProviderAsync(OAuthProviderConfiguration config, CancellationToken cancellationToken = default)
        {
            var organizationId = _principalAccessor.OrganizationId;
            var performingConnectedId = _principalAccessor.ConnectedId;

            if (organizationId == null || performingConnectedId == null)
                return ServiceResult.Failure("Valid organization and user context are required.", "CONTEXT_NOT_FOUND");
            
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var planCheckResult = await CheckOrganizationPlanLimitsAsync(organizationId.Value, PlanLimitType.OAuthProvider, cancellationToken);
                if (!planCheckResult.IsSuccess) 
                    return await RollbackAndReturn(planCheckResult, cancellationToken);

                string providerName = config.Provider.ToString();

                var existingProvider = await _oauthProviderRepository.GetByProviderNameAsync(organizationId.Value, providerName, cancellationToken);
                if (existingProvider != null) 
                    return await RollbackAndReturn(ServiceResult.Failure($"Provider '{providerName}' is already registered.", "CONFLICT"), cancellationToken);

                var encryptedClientSecret = await _encryptionService.EncryptAsync(config.ClientSecret ?? string.Empty);
                var newProviderEntity = new OAuthProviderEntity
                {
                    OrganizationId = organizationId.Value, Provider = providerName, ClientId = config.ClientId,
                    ClientSecretEncrypted = encryptedClientSecret, IsEnabled = config.IsEnabled,
                    AuthorizationEndpoint = config.AuthorizationEndpoint ?? string.Empty, 
                    TokenEndpoint = config.TokenEndpoint ?? string.Empty,
                    UserInfoEndpoint = config.UserInfoEndpoint ?? string.Empty, 
                    Scopes = config.Scopes?.Any() == true ? string.Join(" ", config.Scopes) : "openid profile email",
                    CreatedBy = performingConnectedId.Value 
                };

                await _oauthProviderRepository.AddAsync(newProviderEntity, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                await _auditService.LogActionAsync(AuditActionType.Create, "OAuthProvider.Registered", performingConnectedId.Value,
                    resourceType: "OAuthProvider", resourceId: newProviderEntity.Id.ToString(),
                    metadata: new Dictionary<string, object> { { "ProviderName", providerName } }, 
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to register OAuth provider {Provider} for organization {OrganizationId}", config.Provider, organizationId);
                ServiceFailed?.Invoke(this, new ExternalServiceFailedEventArgs(nameof(RegisterProviderAsync), ex)
                {
                    ServiceName = this.ServiceName, Method = nameof(RegisterProviderAsync), Error = ex.Message
                });
                return ServiceResult.Failure($"An unexpected error occurred while registering the provider: {ex.Message}");
            }
        }
        
        public async Task<ServiceResult<OAuthProviderConfiguration>> GetProviderConfigAsync(
            string providerName, 
            CancellationToken cancellationToken = default)
        {
            var organizationId = _principalAccessor.OrganizationId ?? Guid.Empty;
            
            // 1. DB에서 조직별 커스텀 설정 조회
            var entity = await _oauthProviderRepository.GetByProviderNameAsync(organizationId, providerName, cancellationToken);

            if (entity != null)
            {
                var config = new OAuthProviderConfiguration 
                { 
                    Provider = Enum.TryParse<SSOProvider>(entity.Provider, true, out var p) ? p : SSOProvider.Custom, 
                    ClientId = entity.ClientId, 
                    ClientSecret = "(Encrypted)", 
                    AuthorizationEndpoint = entity.AuthorizationEndpoint,
                    TokenEndpoint = entity.TokenEndpoint,
                    UserInfoEndpoint = entity.UserInfoEndpoint,
                    Scopes = entity.Scopes?.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).ToList() ?? new List<string>(),
                    IsEnabled = entity.IsEnabled
                }; 
                return ServiceResult<OAuthProviderConfiguration>.Success(config);
            }

            // 2. 로컬/기본 설정 조회 (Fallback)
            if (Enum.TryParse<SSOProvider>(providerName, true, out var providerEnum))
            {
                if (_providerConfigs.TryGetValue(providerEnum, out var localConfig))
                {
                    return ServiceResult<OAuthProviderConfiguration>.Success(localConfig);
                }
            }
            
            return ServiceResult<OAuthProviderConfiguration>.Failure($"Provider '{providerName}' not found or configured.", "NOT_FOUND");
        }

        public Task<ServiceResult<List<OAuthProviderConfiguration>>> GetAllProvidersAsync(
            CancellationToken cancellationToken = default)
        {
            var providers = _providerConfigs.Values.ToList();
            return Task.FromResult(ServiceResult<List<OAuthProviderConfiguration>>.Success(providers));
        }

        public Task<ServiceResult<AuthenticationResult>> InitiateAuthAsync(
            string provider, string redirectUri, List<string>? scopes = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult<AuthenticationResult>.Failure("Not implemented", "NOT_IMPLEMENTED"));
        }

        public Task<ServiceResult<AuthenticationResult>> ProcessCallbackAsync(
            string provider, string code, string state, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult<AuthenticationResult>.Failure("Not implemented", "NOT_IMPLEMENTED"));
        }

        public Task<ServiceResult<TokenIssueResult>> ExchangeTokenAsync(
            string provider, string code, string redirectUri, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult<TokenIssueResult>.Failure("Not implemented", "NOT_IMPLEMENTED"));
        }

        public Task<ServiceResult<TokenRefreshResult>> RefreshTokenAsync(
            string provider, string refreshToken, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult<TokenRefreshResult>.Failure("Not implemented", "NOT_IMPLEMENTED"));
        }

        public async Task<ServiceResult<UserProfileDto>> GetUserProfileAsync(
            string provider, string accessToken, CancellationToken cancellationToken = default)
        {
            var configResult = await GetProviderConfigAsync(provider, cancellationToken);

            if (!configResult.IsSuccess || configResult.Data?.UserInfoEndpoint == null)
                return ServiceResult<UserProfileDto>.NotFound(configResult.ErrorMessage ?? "UserInfo endpoint not configured for this provider.");

            var config = configResult.Data;
            var client = _httpClientFactory.CreateClient("OAuthClient");
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            client.Timeout = TimeSpan.FromSeconds(TimeoutSeconds);

            try
            {
                ServiceCalled?.Invoke(this, new ExternalServiceCalledEventArgs(nameof(GetUserProfileAsync))
                {
                    ServiceName = this.ServiceName,
                    Method = nameof(GetUserProfileAsync),
                });

                var responseNode = await client.GetFromJsonAsync<JsonNode>(config.UserInfoEndpoint, cancellationToken);
                if (responseNode == null)
                    return ServiceResult<UserProfileDto>.Failure("Failed to deserialize user profile response.", "EXTERNAL_API_ERROR");

                await RecordMetricsAsync(new ExternalServiceMetrics { ResponseTimeMs = 0, Success = true }, cancellationToken);

                var userProfileDto = MapExternalProfileToDto(responseNode, provider);
                return ServiceResult<UserProfileDto>.Success(userProfileDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user profile from {Provider}", provider);
                await RecordMetricsAsync(new ExternalServiceMetrics { ResponseTimeMs = 0, Success = false, ErrorMessage = ex.Message }, cancellationToken);
                ServiceFailed?.Invoke(this, new ExternalServiceFailedEventArgs(nameof(GetUserProfileAsync), ex)
                {
                    ServiceName = this.ServiceName, Method = nameof(GetUserProfileAsync), Error = ex.Message
                });
                return ServiceResult<UserProfileDto>.Failure($"Failed to get user profile: {ex.Message}", "EXTERNAL_API_FAILURE");
            }
        }

        #endregion

        #region IExternalService Implementation (v16 Compliance)

        public Task<ServiceHealthStatus> CheckHealthAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new ServiceHealthStatus { ServiceName = ServiceName, Provider = Provider, IsHealthy = true, CheckedAt = DateTime.UtcNow });
        }

        public Task<ServiceResult> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult.Success("Connection successful."));
        }

        public Task<ServiceResult> ValidateConfigurationAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult.Success("Configuration is valid."));
        }

        public Task<ServiceResult<ExternalServiceUsage>> GetUsageAsync(
            DateTime startDate, DateTime endDate, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult<ExternalServiceUsage>.Success(new ExternalServiceUsage()));
        }
        
        public Task RecordMetricsAsync(ExternalServiceMetrics metrics, CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Metrics recorded for {Service}: Success={Success}, Error={Error}", 
                ServiceName, metrics.Success, metrics.ErrorMessage);
            return Task.CompletedTask;
        }

        #endregion

        #region Private Helper Methods

        private async Task<ServiceResult> RollbackAndReturn(ServiceResult result, CancellationToken cancellationToken)
        {
            await _unitOfWork.RollbackTransactionAsync(cancellationToken);
            return result;
        }

        private async Task<ServiceResult> CheckOrganizationPlanLimitsAsync(
            Guid organizationId, PlanLimitType limitType, CancellationToken cancellationToken = default)
        {
            if (!_limitCheckers.TryGetValue(limitType, out var checker))
            {
                _logger.LogWarning("No ILimitChecker registered for limit type {LimitType}", limitType);
                return ServiceResult.Success();
            }

            var plan = await _planRepository.GetActivePlanByOrganizationIdAsync(organizationId, cancellationToken);
            var planKey = plan?.PlanKey ?? PricingConstants.DefaultPlanKey;
            var maxLimit = GetMaxLimitForType(planKey, limitType);

            if (maxLimit == -1) return ServiceResult.Success();

            var currentUsage = await checker.GetCurrentUsageAsync(organizationId, cancellationToken);
            if (currentUsage >= maxLimit)
            {
                var limitEvent = new PlanLimitReachedEvent(
                    organizationId: organizationId, planKey: planKey, limitType: limitType,
                    currentValue: (int)currentUsage, maxValue: (int)maxLimit);
                
                await _eventBus.PublishAsync(limitEvent, cancellationToken);
                return ServiceResult.Failure(limitEvent.Message, "PLAN_LIMIT_EXCEEDED");
            }

            return ServiceResult.Success();
        }

        private long GetMaxLimitForType(string planKey, PlanLimitType limitType)
        {
            var limitsDict = limitType switch
            {
                PlanLimitType.MemberCount => PricingConstants.SubscriptionPlans.MemberLimits,
                PlanLimitType.OrganizationCount => PricingConstants.SubscriptionPlans.OrganizationLimits,
                PlanLimitType.MAU => PricingConstants.SubscriptionPlans.MAULimits,
                PlanLimitType.StorageLimits => PricingConstants.SubscriptionPlans.StorageLimits,
                PlanLimitType.Domain => PricingConstants.SubscriptionPlans.DomainLimits,
                PlanLimitType.OAuthProvider => PricingConstants.SubscriptionPlans.OAuthProviderLimits,
                PlanLimitType.RoleCount => PricingConstants.SubscriptionPlans.RoleLimits,
                PlanLimitType.OrganizationDepth => PricingConstants.SubscriptionPlans.OrganizationDepthLimits,
                _ => null
            };

            return (limitsDict != null && limitsDict.TryGetValue(planKey, out var limit)) ? limit : -1;
        }

        private ServiceResult<UserEntity> ProcessOAuthUserAsync(UserProfileDto oauthProfile, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return ServiceResult<UserEntity>.Failure("Not implemented");
        }

        /// <summary>
        /// 외부 OAuth 응답(JsonNode)을 내부 UserProfileDto로 매핑합니다.
        /// </summary>
        private UserProfileDto MapExternalProfileToDto(JsonNode responseNode, string provider)
        {
            // OAuth 응답에서 이름 필드를 추출합니다.
            var firstName = responseNode["given_name"]?.GetValue<string>();
            var lastName = responseNode["family_name"]?.GetValue<string>();

            // DisplayName을 위해 이름 필드를 조합합니다.
            var calculatedName = responseNode["name"]?.GetValue<string>();
            if (string.IsNullOrEmpty(calculatedName) && !string.IsNullOrEmpty(firstName))
            {
                calculatedName = $"{firstName} {lastName}";
            }
            else if (string.IsNullOrEmpty(calculatedName))
            {
                calculatedName = responseNode["email"]?.GetValue<string>() ?? "External User";
            }
            
            return new UserProfileDto
            {
                UserId = Guid.Empty, 
                ExternalId = responseNode["sub"]?.GetValue<string>() ?? responseNode["id"]?.GetValue<string>() ?? Guid.NewGuid().ToString(),
                Email = responseNode["email"]?.GetValue<string>(),
                
                Provider = provider,
                FirstName = firstName, 
                LastName = lastName,
                MiddleName = responseNode["middle_name"]?.GetValue<string>(),
                
                DisplayName = calculatedName,
            };
        }

        #endregion
    }
}