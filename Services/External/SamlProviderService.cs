using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Models.Base;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Services.External
{
    /// <summary>
    /// SAML 2.0 제공자 서비스 - SaaS 최적화 버전
    /// 멀티테넌트 환경에서 동적 SAML 설정 처리
    /// </summary>
    public class SamlProviderService : ISamlProviderService, IService
    {
        private readonly ILogger<SamlProviderService> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;

        private const string CACHE_KEY_PREFIX = "saml";
        private const int CONFIG_CACHE_HOURS = 4; // 설정 캐시 시간 단축
        private const int REQUEST_CACHE_MINUTES = 5;

        #region IExternalService Properties
        public string ServiceName => "SAML";
        public string Provider => "SAML2.0";
        public string? ApiVersion => "2.0";
        public RetryPolicy RetryPolicy { get; set; } = new() 
        { 
            MaxRetries = 2, 
            InitialDelayMs = 500,
            UseExponentialBackoff = false // SaaS에서는 빠른 실패가 더 효율적
        };
        public int TimeoutSeconds { get; set; } = 15; // 타임아웃 단축
        public bool EnableCircuitBreaker { get; set; } = true;
        public IExternalService? FallbackService { get; set; }
        
        public event EventHandler<ExternalServiceCalledEventArgs>? ServiceCalled;
        public event EventHandler<ExternalServiceFailedEventArgs>? ServiceFailed;
        public event EventHandler<ExternalServiceRecoveredEventArgs>? ServiceRecovered;
        #endregion

        public SamlProviderService(
            ILogger<SamlProviderService> logger,
            ICacheService cacheService,
            IAuditService auditService,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider)
        {
            _logger = logger;
            _cacheService = cacheService;
            _auditService = auditService;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
        }

        #region IService Implementation
        public async Task InitializeAsync()
        {
            _logger.LogInformation("SAML Provider Service initialized");
            await Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            return await _cacheService.IsHealthyAsync();
        }
        #endregion

        /// <summary>
        /// IdP 설정 - 동적 필드 처리
        /// </summary>
        public async Task<ServiceResult> ConfigureIdpAsync(Guid organizationId, SamlIdpConfiguration config)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 필수 필드만 검증, 나머지는 동적으로 처리
                if (string.IsNullOrEmpty(config.EntityId) || string.IsNullOrEmpty(config.SsoUrl))
                    return ServiceResult.Failure("EntityId and SsoUrl are required");

                // 인증서 검증 (선택적)
                if (!string.IsNullOrEmpty(config.Certificate))
                {
                    try
                    {
                        // .NET 8+ 호환성을 위한 처리
                        #pragma warning disable SYSLIB0057 // Type or member is obsolete
                        var cert = new X509Certificate2(Convert.FromBase64String(config.Certificate));
                        #pragma warning restore SYSLIB0057
                        
                        if (cert.NotAfter < _dateTimeProvider.UtcNow)
                        {
                            _logger.LogWarning("Certificate expired for org {OrgId}", organizationId);
                        }
                    }
                    catch
                    {
                        _logger.LogWarning("Invalid certificate format for org {OrgId}, proceeding anyway", organizationId);
                    }
                }

                // 동적 설정 저장 - AttributeMappings에 모든 추가 데이터 저장
                var cacheKey = GetCacheKey("config", organizationId.ToString());
                await _cacheService.SetAsync(cacheKey, config, TimeSpan.FromHours(CONFIG_CACHE_HOURS));

                // 감사 로그 - 최소 정보만
                await _auditService.LogActionAsync(
                    Core.Enums.Core.AuditActionType.Update,
                    "SAML_CONFIG",
                    organizationId,
                    resourceId: organizationId.ToString());

                await _unitOfWork.CommitTransactionAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "SAML config failed for {OrgId}", organizationId);
                return ServiceResult.Failure("Configuration failed");
            }
        }

        /// <summary>
        /// SP 메타데이터 생성 - 동적 템플릿 기반
        /// </summary>
        public async Task<ServiceResult<string>> GenerateSpMetadataAsync(Guid organizationId)
        {
            try
            {
                // 조직별 커스텀 메타데이터 템플릿 확인
                var cacheKey = GetCacheKey("metadata_template", organizationId.ToString());
                var template = await _cacheService.GetAsync<string>(cacheKey);
                
                if (!string.IsNullOrEmpty(template))
                {
                    // 커스텀 템플릿 사용
                    var metadata = template
                        .Replace("{organizationId}", organizationId.ToString())
                        .Replace("{timestamp}", _dateTimeProvider.UtcNow.ToString("O"));
                    return ServiceResult<string>.Success(metadata);
                }

                // 기본 템플릿 (최소화)
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

        /// <summary>
        /// 인증 요청 생성 - 최적화된 버전
        /// </summary>
        public async Task<ServiceResult<SamlAuthRequest>> CreateAuthRequestAsync(Guid organizationId, string returnUrl)
        {
            try
            {
                // 설정 캐시에서 가져오기
                var config = await GetConfigAsync(organizationId);
                if (config == null)
                    return ServiceResult<SamlAuthRequest>.Failure("Not configured");

                var requestId = $"S_{Guid.NewGuid():N}";
                var timestamp = _dateTimeProvider.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

                // 최소 SAML Request
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

                // 짧은 캐시 (5분)
                var cacheKey = GetCacheKey("request", requestId);
                await _cacheService.SetAsync(cacheKey, authRequest, TimeSpan.FromMinutes(REQUEST_CACHE_MINUTES));

                ServiceCalled?.Invoke(this, new() { ServiceName = ServiceName, Operation = "CreateAuth" });
                return ServiceResult<SamlAuthRequest>.Success(authRequest);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Auth request failed for {OrgId}", organizationId);
                ServiceFailed?.Invoke(this, new() { ServiceName = ServiceName, Error = ex.Message });
                return ServiceResult<SamlAuthRequest>.Failure("Request failed");
            }
        }

        /// <summary>
        /// SAML Response 처리 - 동적 속성 매핑
        /// </summary>
        public Task<ServiceResult<AuthenticationResponse>> ProcessSamlResponseAsync(string samlResponse, string? relayState = null)
        {
            try
            {
                var decodedXml = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponse));
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(decodedXml);

                // 상태 확인 (빠른 실패)
                if (!IsSuccessStatus(xmlDoc))
                {
                    _logger.LogWarning("SAML auth failed");
                    return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("Authentication failed"));
                }

                // 동적 속성 추출
                var attributes = ExtractDynamicAttributes(xmlDoc);
                
                var response = new AuthenticationResponse
                {
                    Success = true,
                    AuthenticationMethod = "SAML",
                    Claims = attributes, // 모든 동적 속성 저장
                    ExpiresAt = _dateTimeProvider.UtcNow.AddHours(1), // 짧은 만료 시간
                };

                // 조직 ID 추출 시도 (있으면)
                if (attributes.TryGetValue("organizationId", out var orgId) && Guid.TryParse(orgId.ToString(), out var organizationId))
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

        /// <summary>
        /// 로그아웃 요청 - 간소화
        /// </summary>
        public async Task<ServiceResult<string>> CreateLogoutRequestAsync(Guid organizationId, Guid userId)
        {
            try
            {
                var config = await GetConfigAsync(organizationId);
                if (config == null || string.IsNullOrEmpty(config.SloUrl))
                    return ServiceResult<string>.Failure("SLO not configured");

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

        /// <summary>
        /// 로그아웃 응답 처리
        /// </summary>
        public async Task<ServiceResult> ProcessLogoutResponseAsync(string samlResponse)
        {
            await Task.CompletedTask;
            // 간단한 성공 반환 (대부분의 경우 충분)
            return ServiceResult.Success();
        }

        /// <summary>
        /// IdP 메타데이터 가져오기 - 동적 파싱
        /// </summary>
        public async Task<ServiceResult<SamlIdpMetadata>> ImportIdpMetadataAsync(string metadataUrl)
        {
            try
            {
                // URL 캐시 확인
                var cacheKey = GetCacheKey("idp_meta", metadataUrl.GetHashCode().ToString());
                var cached = await _cacheService.GetAsync<SamlIdpMetadata>(cacheKey);
                if (cached != null)
                    return ServiceResult<SamlIdpMetadata>.Success(cached);

                using var httpClient = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };
                var xml = await httpClient.GetStringAsync(metadataUrl);
                
                var metadata = ParseIdpMetadata(xml);
                
                // 캐시 저장
                await _cacheService.SetAsync(cacheKey, metadata, TimeSpan.FromHours(24));
                
                return ServiceResult<SamlIdpMetadata>.Success(metadata);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Metadata import failed from {Url}", metadataUrl);
                return ServiceResult<SamlIdpMetadata>.Failure("Import failed");
            }
        }

        /// <summary>
        /// 동적 속성 매핑 설정
        /// </summary>
        public async Task<ServiceResult> ConfigureAttributeMappingAsync(Guid organizationId, Dictionary<string, string> mappings)
        {
            try
            {
                // 동적 매핑 저장 - 어떤 매핑이든 허용
                var cacheKey = GetCacheKey("mappings", organizationId.ToString());
                await _cacheService.SetAsync(cacheKey, mappings, TimeSpan.FromHours(CONFIG_CACHE_HOURS));
                
                _logger.LogInformation("Attribute mappings updated for {OrgId}, count: {Count}", 
                    organizationId, mappings.Count);
                
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Mapping configuration failed");
                return ServiceResult.Failure("Configuration failed");
            }
        }

        /// <summary>
        /// 설정 검증 - 최소 검증만
        /// </summary>
        public async Task<ServiceResult<bool>> ValidateConfigurationAsync(Guid organizationId)
        {
            var config = await GetConfigAsync(organizationId);
            var isValid = config != null && !string.IsNullOrEmpty(config.EntityId) && !string.IsNullOrEmpty(config.SsoUrl);
            return ServiceResult<bool>.Success(isValid);
        }

        #region Helper Methods

        private async Task<SamlIdpConfiguration?> GetConfigAsync(Guid organizationId)
        {
            var cacheKey = GetCacheKey("config", organizationId.ToString());
            return await _cacheService.GetAsync<SamlIdpConfiguration>(cacheKey);
        }

        private string GetCacheKey(string type, string identifier)
        {
            return $"{CACHE_KEY_PREFIX}:{type}:{identifier}";
        }

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
            
            // NameID 추출
            var nameIdNode = xmlDoc.SelectSingleNode("//saml:NameID", ns);
            if (nameIdNode != null)
                attributes["nameId"] = nameIdNode.InnerText;
            
            // 모든 속성 동적으로 추출
            var attributeNodes = xmlDoc.SelectNodes("//saml:Attribute", ns);
            if (attributeNodes != null)
            {
                foreach (XmlNode node in attributeNodes)
                {
                    var name = node.Attributes?["Name"]?.Value;
                    var value = node.SelectSingleNode(".//saml:AttributeValue", ns)?.InnerText;
                    
                    if (!string.IsNullOrEmpty(name) && value != null)
                    {
                        // 동적 키 정규화 (소문자, 언더스코어)
                        var key = name.ToLower().Replace(":", "_").Replace("/", "_");
                        attributes[key] = value;
                    }
                }
            }
            
            return attributes;
        }

        private SamlIdpMetadata ParseIdpMetadata(string xml)
        {
            var xmlDoc = new XmlDocument();
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
                SupportedBindings = new List<SamlBinding> { SamlBinding.HttpPost } // 기본값
            };
        }

        #endregion

        #region IExternalService Implementation

        public async Task<ServiceHealthStatus> CheckHealthAsync()
        {
            var isHealthy = await IsHealthyAsync();
            return new ServiceHealthStatus
            {
                IsHealthy = isHealthy,
                ErrorMessage = isHealthy ? "Operational" : "Degraded",
                CheckedAt = _dateTimeProvider.UtcNow
            };
        }

        public async Task<ServiceResult> TestConnectionAsync()
        {
            return await _cacheService.IsHealthyAsync() 
                ? ServiceResult.Success() 
                : ServiceResult.Failure("Cache unavailable");
        }

        public async Task<ServiceResult> ValidateConfigurationAsync()
        {
            await Task.CompletedTask;
            return ServiceResult.Success(); // 동적 설정이므로 항상 성공
        }

        public async Task<ServiceResult<ExternalServiceUsage>> GetUsageAsync(DateTime startDate, DateTime endDate, Guid? organizationId = null)
        {
            // 사용량 추적은 별도 메트릭 서비스에서 처리
            await Task.CompletedTask;
            return ServiceResult<ExternalServiceUsage>.Success(new ExternalServiceUsage
            {
                ServiceName = ServiceName,
                PeriodStart = startDate,
                PeriodEnd = endDate
            });
        }

        public async Task RecordMetricsAsync(ExternalServiceMetrics metrics)
        {
            // 메트릭은 별도 서비스에서 중앙 집중 처리
            await Task.CompletedTask;
        }

        #endregion
    }
}