// File Path: D:/Works/Projects/Auth_V2/AuthHive/authhive.auth/Services/External/SamlProviderService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Business.Platform;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Models.Organization.Events;
using System.Text.Json;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Service; // Correct namespace for AuditActionType

namespace AuthHive.Auth.Services.External
{
    public class SamlProviderService : ISamlProviderService, IService
    {
        private readonly ILogger<SamlProviderService> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IRepository<SamlConfiguration> _samlConfigRepository;
        private readonly IPlanRestrictionService _planRestrictionService;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly IEventBus _eventBus;

        private const string CACHE_KEY_PREFIX = "saml";
        private const int CONFIG_CACHE_HOURS = 4;
        private const int REQUEST_CACHE_MINUTES = 5;

        #region IExternalService Properties
        // ... (Properties remain the same) ...
        public string ServiceName => "SAML";
        public string Provider => "SAML2.0";
        public string? ApiVersion => "2.0";
        public RetryPolicy RetryPolicy { get; set; } = new() { MaxRetries = 2, InitialDelayMs = 500 };
        public int TimeoutSeconds { get; set; } = 15;
        public bool EnableCircuitBreaker { get; set; } = true;
        public IExternalService? FallbackService { get; set; }

        public event EventHandler<ExternalServiceCalledEventArgs>? ServiceCalled;
        public event EventHandler<ExternalServiceFailedEventArgs>? ServiceFailed;
        public event EventHandler<ExternalServiceRecoveredEventArgs>? ServiceRecovered;
        #endregion

        public SamlProviderService(
            ILogger<SamlProviderService> logger, ICacheService cacheService, IAuditService auditService,
            IUnitOfWork unitOfWork, IDateTimeProvider dateTimeProvider, IRepository<SamlConfiguration> samlConfigRepository,
            IPlanRestrictionService planRestrictionService, IPrincipalAccessor principalAccessor, IEventBus eventBus)
        {
            _logger = logger; _cacheService = cacheService; _auditService = auditService;
            _unitOfWork = unitOfWork; _dateTimeProvider = dateTimeProvider; _samlConfigRepository = samlConfigRepository;
            _planRestrictionService = planRestrictionService; _principalAccessor = principalAccessor; _eventBus = eventBus;
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) { _logger.LogInformation("SAML Provider Service initialized"); return Task.CompletedTask; }
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) { return await _cacheService.IsHealthyAsync(cancellationToken); }
        #endregion

        #region ISamlProviderService Implementation

        public async Task<ServiceResult> ConfigureIdpAsync(Guid organizationId, SamlIdpConfiguration config, CancellationToken cancellationToken = default)
        {
            // ✅ [FIX CS1061] Use correct method name
            bool isFeatureEnabled = await _planRestrictionService.IsFeatureToggleEnabledAsync(organizationId, AuthConstants.SSO.SAML, cancellationToken);
            if (!isFeatureEnabled)
            {
                return ServiceResult.Failure($"Feature '{AuthConstants.SSO.SAML}' is not enabled for this organization's plan.", ServiceErrorReason.PlanRestriction);
            }

            var connectedId = _principalAccessor.ConnectedId;
            if (!connectedId.HasValue) // Ensure we have an actor
            {
                _logger.LogWarning("Attempted to configure SAML IdP for org {OrgId} without a valid connectedId.", organizationId);
                return ServiceResult.Failure("User context (ConnectedId) is required to configure SAML.", ServiceErrorReason.Unauthorized); // Or appropriate error
            }


            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                // ... Certificate validation logic ...

                var configEntity = await _samlConfigRepository.FirstOrDefaultAsync(
                    c => c.OrganizationId == organizationId && c.Protocol == AuthConstants.SSO.SAML, cancellationToken);

                bool isNew = configEntity == null;
                if (isNew)
                {
                    configEntity = new SamlConfiguration(organizationId);
                    configEntity.CreatedByConnectedId = connectedId;
                }

                // Map DTO to Entity
                configEntity!.Protocol = AuthConstants.SSO.SAML;
                configEntity.Provider = config.ProviderName ?? AuthConstants.SSO.SAML;
                configEntity.DisplayName = config.DisplayName;
                configEntity.EntityId = config.EntityId;
                configEntity.SsoUrl = config.SsoUrl;
                configEntity.SloUrl = config.SloUrl ?? string.Empty;
                configEntity.Certificate = config.Certificate ?? string.Empty;
                configEntity.MetadataUrl = config.MetadataUrl ?? string.Empty;
                configEntity.IsEnabled = config.IsEnabled;
                configEntity.EnableJitProvisioning = config.EnableJitProvisioning;
                configEntity.UpdatedAt = _dateTimeProvider.UtcNow;
                configEntity.UpdatedByConnectedId = connectedId;

                configEntity.AttributeMapping = config.AttributeMappings != null ? JsonSerializer.Serialize(config.AttributeMappings) : "{}";
                configEntity.AllowedDomains = config.AllowedDomains != null ? JsonSerializer.Serialize(config.AllowedDomains) : "[]";

                if (isNew) await _samlConfigRepository.AddAsync(configEntity, cancellationToken);
                else await _samlConfigRepository.UpdateAsync(configEntity, cancellationToken);

                // ✅ [FIX CS1503] Pass arguments in the correct order for LogActionAsync
                await _auditService.LogActionAsync(
                    actionType: isNew ? AuditActionType.Create : AuditActionType.Update,
                    action: "SAML_CONFIG",
                    connectedId: connectedId.Value, // Pass the non-nullable Guid
                    success: true,                  // Pass the success bool (4th param)
                    errorMessage: null,             // Pass null for error message
                    resourceType: nameof(SamlConfiguration), // Optionally add resource type
                    resourceId: configEntity.Id.ToString(),
                    metadata: null, // Optionally add metadata
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                var cacheKey = GetCacheKey("config", organizationId.ToString());
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);

                await _eventBus.PublishAsync(new SamlConfigurationUpdatedEvent(organizationId, connectedId), cancellationToken);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "SAML config failed for {OrgId}", organizationId);
                return ServiceResult.Failure("Configuration failed");
            }
        }

        public async Task<ServiceResult<string>> GenerateSpMetadataAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = GetCacheKey("metadata_template", organizationId.ToString());
                var template = await _cacheService.GetAsync<string>(cacheKey, cancellationToken);

                if (!string.IsNullOrEmpty(template))
                {
                    var metadata = template
                        .Replace("{organizationId}", organizationId.ToString())
                        .Replace("{timestamp}", _dateTimeProvider.UtcNow.ToString("O"));
                    return ServiceResult<string>.Success(metadata);
                }

                var defaultMetadata = $@"<?xml version=""1.0""?>
<EntityDescriptor entityID=""https://authhive.com/saml/{organizationId}"" xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"">
<SPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
 <AssertionConsumerService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
     Location=""https://authhive.com/api/saml/acs/{organizationId}"" index=""0""/>
</SPSSODescriptor>
</EntityDescriptor>";

                return ServiceResult<string>.Success(defaultMetadata);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Metadata generation failed for {OrgId}", organizationId);
                return ServiceResult<string>.Failure("Generation failed");
            }
        }

        public async Task<ServiceResult<SamlAuthRequest>> CreateAuthRequestAsync(Guid organizationId, string returnUrl, CancellationToken cancellationToken = default)
        {
            try
            {
                var config = await GetConfigAsync(organizationId, cancellationToken);
                if (config == null)
                    return ServiceResult<SamlAuthRequest>.Failure("Not configured or not enabled");

                var requestId = $"S_{Guid.NewGuid():N}";
                var timestamp = _dateTimeProvider.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

                var samlRequest = $@"<samlp:AuthnRequest ID=""{requestId}"" Version=""2.0""
                        IssueInstant=""{timestamp}"" Destination=""{config.SsoUrl}""
                        xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"">
                        <saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">https://authhive.com/{organizationId}</saml:Issuer>
                </samlp:AuthnRequest>";

                var authRequest = new SamlAuthRequest
                {
                    RequestId = requestId,
                    SsoUrl = config.SsoUrl,
                    SamlRequest = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlRequest)),
                    RelayState = returnUrl
                };

                var cacheKey = GetCacheKey("request", requestId);
                await _cacheService.SetAsync(cacheKey, authRequest, TimeSpan.FromMinutes(REQUEST_CACHE_MINUTES), cancellationToken);

                // ✅ [FIX CS7036] Pass operation to constructor
                ServiceCalled?.Invoke(this, new ExternalServiceCalledEventArgs(operation: "CreateAuthRequest") { ServiceName = ServiceName });
                return ServiceResult<SamlAuthRequest>.Success(authRequest);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Auth request failed for {OrgId}", organizationId);
                return ServiceResult<SamlAuthRequest>.Failure("Request failed");
            }
        }

        public Task<ServiceResult<AuthenticationResponse>> ProcessSamlResponseAsync(string samlResponse, string? relayState = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var decodedXml = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponse));
                var xmlDoc = new XmlDocument { PreserveWhitespace = true };
                xmlDoc.LoadXml(decodedXml);

                if (!IsSuccessStatus(xmlDoc))
                {
                    _logger.LogWarning("SAML auth failed (Status not Success)");
                    return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("Authentication failed"));
                }

                var attributes = ExtractDynamicAttributes(xmlDoc);

                var response = new AuthenticationResponse
                {
                    Success = true,
                    AuthenticationMethod = "SAML",
                    Claims = attributes,
                    ExpiresAt = _dateTimeProvider.UtcNow.AddHours(1),
                };

                // Extract OrgId if present, though ideally it should be confirmed via RelayState or Issuer
                if (attributes.TryGetValue("organizationid", out var orgIdValue) // Check for common variations if needed
                    && Guid.TryParse(orgIdValue?.ToString(), out var organizationId))
                {
                    response.OrganizationId = organizationId;
                }

                return Task.FromResult(ServiceResult<AuthenticationResponse>.Success(response));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SAML response processing failed");
                return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("Processing failed"));
            }
        }

        public async Task<ServiceResult<string>> CreateLogoutRequestAsync(Guid organizationId, Guid userId, CancellationToken cancellationToken = default)
        {
            try
            {
                var config = await GetConfigAsync(organizationId, cancellationToken);
                if (config == null || string.IsNullOrEmpty(config.SloUrl))
                    return ServiceResult<string>.Failure("SLO not configured or SAML not enabled");

                var requestId = $"LO_{Guid.NewGuid():N}";
                var samlLogout = $@"<samlp:LogoutRequest ID=""{requestId}"" Version=""2.0""
                        xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"">
                        <saml:NameID xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">{userId}</saml:NameID>
                </samlp:LogoutRequest>";

                return ServiceResult<string>.Success(Convert.ToBase64String(Encoding.UTF8.GetBytes(samlLogout)));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Logout request failed");
                return ServiceResult<string>.Failure("Logout failed");
            }
        }

        public Task<ServiceResult> ProcessLogoutResponseAsync(string samlResponse, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<SamlIdpMetadata>> ImportIdpMetadataAsync(string metadataUrl, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = GetCacheKey("idp_meta", metadataUrl.GetHashCode().ToString());
                var cached = await _cacheService.GetAsync<SamlIdpMetadata>(cacheKey, cancellationToken);
                if (cached != null)
                    return ServiceResult<SamlIdpMetadata>.Success(cached);

                using var httpClient = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };
                var xml = await httpClient.GetStringAsync(metadataUrl, cancellationToken);

                var metadata = ParseIdpMetadata(xml);

                await _cacheService.SetAsync(cacheKey, metadata, TimeSpan.FromHours(24), cancellationToken);

                return ServiceResult<SamlIdpMetadata>.Success(metadata);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Metadata import failed from {Url}", metadataUrl);
                return ServiceResult<SamlIdpMetadata>.Failure("Import failed");
            }
        }

        public async Task<ServiceResult> ConfigureAttributeMappingAsync(Guid organizationId, Dictionary<string, string> mappings, CancellationToken cancellationToken = default)
        {
            // ✅ [FIX CS1061] Use correct method name
            bool isFeatureEnabled = await _planRestrictionService.IsFeatureToggleEnabledAsync(organizationId, AuthConstants.SSO.SAML, cancellationToken);
            if (!isFeatureEnabled)
            {
                return ServiceResult.Failure($"Feature '{AuthConstants.SSO.SAML}' is not enabled for this organization's plan.", ServiceErrorReason.PlanRestriction);
            }

            var connectedId = _principalAccessor.ConnectedId;
            if (!connectedId.HasValue)
            {
                _logger.LogWarning("Attempted to configure SAML mappings for org {OrgId} without a valid connectedId.", organizationId);
                return ServiceResult.Failure("User context (ConnectedId) is required to configure SAML mappings.", ServiceErrorReason.Unauthorized);
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var configEntity = await _samlConfigRepository.FirstOrDefaultAsync(
                    c => c.OrganizationId == organizationId && c.Protocol == AuthConstants.SSO.SAML, cancellationToken);

                if (configEntity == null)
                {
                    return ServiceResult.Failure("SAML configuration not found. Please configure IdP first.", "SAML_NOT_CONFIGURED");
                }

                configEntity.AttributeMapping = JsonSerializer.Serialize(mappings);
                configEntity.UpdatedAt = _dateTimeProvider.UtcNow;
                configEntity.UpdatedByConnectedId = connectedId;

                await _samlConfigRepository.UpdateAsync(configEntity, cancellationToken);

                // ✅ [FIX CS1503] Pass arguments in the correct order for LogActionAsync
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Update,
                    action: "SAML_MAPPING_CONFIG",
                    connectedId: connectedId.Value,
                    success: true,
                    resourceType: nameof(SamlConfiguration),
                    resourceId: configEntity.Id.ToString(),
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                var cacheKey = GetCacheKey("config", organizationId.ToString());
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);

                await _eventBus.PublishAsync(new SamlConfigurationUpdatedEvent(organizationId, connectedId), cancellationToken);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Mapping configuration failed");
                return ServiceResult.Failure("Configuration failed");
            }
        }

        public async Task<ServiceResult<bool>> ValidateConfigurationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var config = await GetConfigAsync(organizationId, cancellationToken);
            var isValid = config != null && config.IsEnabled && !string.IsNullOrEmpty(config.EntityId) && !string.IsNullOrEmpty(config.SsoUrl);
            return ServiceResult<bool>.Success(isValid);
        }

        #endregion

        #region Helper Methods
        // ... (GetConfigAsync, GetCacheKey, IsSuccessStatus, ExtractDynamicAttributes, ParseIdpMetadata remain the same) ...
        private async Task<SamlIdpConfiguration?> GetConfigAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var cacheKey = GetCacheKey("config", organizationId.ToString());
            var cachedConfig = await _cacheService.GetAsync<SamlIdpConfiguration>(cacheKey, cancellationToken);
            if (cachedConfig != null)
                return cachedConfig;

            var configEntity = await _samlConfigRepository.FirstOrDefaultAsync(
                c => c.OrganizationId == organizationId && c.Protocol == AuthConstants.SSO.SAML && c.IsEnabled,
                cancellationToken);

            if (configEntity == null)
                return null;

            var configModel = new SamlIdpConfiguration
            {
                ProviderName = configEntity.Provider,
                DisplayName = configEntity.DisplayName,
                EntityId = configEntity.EntityId,
                SsoUrl = configEntity.SsoUrl,
                SloUrl = configEntity.SloUrl,
                Certificate = configEntity.Certificate,
                MetadataUrl = configEntity.MetadataUrl,
                IsEnabled = configEntity.IsEnabled,
                EnableJitProvisioning = configEntity.EnableJitProvisioning,
                AttributeMappings = JsonSerializer.Deserialize<Dictionary<string, string>>(configEntity.AttributeMapping ?? "{}") ?? new(),
                AllowedDomains = JsonSerializer.Deserialize<List<string>>(configEntity.AllowedDomains ?? "[]") ?? new()
            };

            await _cacheService.SetAsync(cacheKey, configModel, TimeSpan.FromHours(CONFIG_CACHE_HOURS), cancellationToken);
            return configModel;
        }

        private string GetCacheKey(string type, string identifier) => $"{CACHE_KEY_PREFIX}:{type}:{identifier}";
        private bool IsSuccessStatus(XmlDocument xmlDoc)
        {
            var ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            var statusNode = xmlDoc.SelectSingleNode("//samlp:StatusCode", ns);
            return statusNode?.Attributes?["Value"]?.Value?.EndsWith("Success") == true;
        }
        private Dictionary<string, object> ExtractDynamicAttributes(XmlDocument xmlDoc)
        {
            var attributes = new Dictionary<string, object>();
            var ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            var nameIdNode = xmlDoc.SelectSingleNode("//saml:NameID", ns);
            if (nameIdNode != null) attributes["nameId"] = nameIdNode.InnerText;
            var attributeNodes = xmlDoc.SelectNodes("//saml:Attribute", ns);
            if (attributeNodes != null)
            {
                foreach (XmlNode node in attributeNodes)
                {
                    var name = node.Attributes?["Name"]?.Value;
                    var value = node.SelectSingleNode(".//saml:AttributeValue", ns)?.InnerText;
                    if (!string.IsNullOrEmpty(name) && value != null)
                    {
                        var key = name.ToLowerInvariant().Replace(":", "_").Replace("/", "_"); // Use InvariantCulture
                        attributes[key] = value;
                    }
                }
            }
            return attributes;
        }
        private SamlIdpMetadata ParseIdpMetadata(string xml)
        {
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(xml);
            var ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
            ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            return new SamlIdpMetadata
            {
                EntityId = xmlDoc.SelectSingleNode("//@entityID")?.Value ?? "",
                SsoUrl = xmlDoc.SelectSingleNode("//md:SingleSignOnService/@Location", ns)?.Value ?? "",
                SloUrl = xmlDoc.SelectSingleNode("//md:SingleLogoutService/@Location", ns)?.Value,
                Certificate = xmlDoc.SelectSingleNode("//ds:X509Certificate", ns)?.InnerText ?? "",
                SupportedBindings = new List<SamlBinding> { SamlBinding.HttpPost }
            };
        }
        #endregion

        #region IExternalService Implementation
        public async Task<ServiceHealthStatus> CheckHealthAsync(CancellationToken cancellationToken = default)
        {
            var isHealthy = await IsHealthyAsync(cancellationToken);
            return new ServiceHealthStatus
            {
                IsHealthy = isHealthy,
                ErrorMessage = isHealthy ? "Operational" : "Degraded",
                CheckedAt = _dateTimeProvider.UtcNow
            };
        }
        public async Task<ServiceResult> TestConnectionAsync(CancellationToken cancellationToken = default)
        {
            return await _cacheService.IsHealthyAsync(cancellationToken) ? ServiceResult.Success() : ServiceResult.Failure("Cache unavailable");
        }
        public async Task<ServiceResult> ValidateConfigurationAsync(CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask; return ServiceResult.Success();
        }
        public async Task<ServiceResult<ExternalServiceUsage>> GetUsageAsync(DateTime startDate, DateTime endDate, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask; return ServiceResult<ExternalServiceUsage>.Success(new ExternalServiceUsage { ServiceName = ServiceName, PeriodStart = startDate, PeriodEnd = endDate });
        }
        public async Task RecordMetricsAsync(ExternalServiceMetrics metrics, CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
        }
        #endregion
    }
}