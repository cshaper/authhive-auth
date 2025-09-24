using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Organization.Handler;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Organization.Events;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;

namespace AuthHive.Auth.Organization.Handlers
{
    /// <summary>
    /// 조직 도메인 이벤트 핸들러 - 도메인 관련 이벤트를 처리하고 후속 작업을 수행합니다.
    /// </summary>
    public class OrganizationDomainEventHandler : IOrganizationDomainEventHandler, IService
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationDomainRepository _domainRepository;
        private readonly IDnsVerificationHelper _dnsVerificationHelper;
        private readonly ISslCertificateHelper _sslCertificateHelper;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<OrganizationDomainEventHandler> _logger;
        private readonly IEventBus _eventBus;

        // 캐시 키 접두사 상수
        private const string DOMAIN_CACHE_PREFIX = "org:domain";
        private const string DOMAIN_LIST_CACHE_PREFIX = "org:domains";
        private const string PRIMARY_DOMAIN_CACHE_PREFIX = "org:primary-domain";
        private const string SSL_CACHE_PREFIX = "org:domain:ssl";
        private const string VERIFICATION_CACHE_PREFIX = "org:domain:verification";
        
        // 감사 액션 상수
        private const string DOMAIN_ADDED = "ORGANIZATION_DOMAIN_ADDED";
        private const string DOMAIN_UPDATED = "ORGANIZATION_DOMAIN_UPDATED";
        private const string DOMAIN_REMOVED = "ORGANIZATION_DOMAIN_REMOVED";
        private const string DOMAIN_VERIFIED = "ORGANIZATION_DOMAIN_VERIFIED";
        private const string DOMAIN_VERIFICATION_FAILED = "ORGANIZATION_DOMAIN_VERIFICATION_FAILED";
        private const string DOMAIN_ACTIVATED = "ORGANIZATION_DOMAIN_ACTIVATED";
        private const string DOMAIN_DEACTIVATED = "ORGANIZATION_DOMAIN_DEACTIVATED";
        private const string PRIMARY_DOMAIN_CHANGED = "ORGANIZATION_PRIMARY_DOMAIN_CHANGED";
        private const string SSL_RENEWED = "ORGANIZATION_DOMAIN_SSL_RENEWED";
        private const string SSL_EXPIRING = "ORGANIZATION_DOMAIN_SSL_EXPIRING";

        // SSL 만료 경고 기준일
        private const int SSL_WARNING_DAYS = 30;
        private const int SSL_CRITICAL_DAYS = 7;

        public OrganizationDomainEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IOrganizationRepository organizationRepository,
            IOrganizationDomainRepository domainRepository,
            IDnsVerificationHelper dnsVerificationHelper,
            ISslCertificateHelper sslCertificateHelper,
            IDateTimeProvider dateTimeProvider,
            ILogger<OrganizationDomainEventHandler> logger,
            IEventBus eventBus)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _organizationRepository = organizationRepository;
            _domainRepository = domainRepository;
            _dnsVerificationHelper = dnsVerificationHelper;
            _sslCertificateHelper = sslCertificateHelper;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
            _eventBus = eventBus;
        }

        #region IService Implementation
        
        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationDomainEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            return await _cacheService.IsHealthyAsync() && await _auditService.IsHealthyAsync();
        }
        
        #endregion

        #region Domain CRUD Events

        public async Task HandleDomainAddedAsync(DomainAddedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing domain added event: Domain={Domain}, Organization={OrganizationId}, Type={DomainType}",
                    @event.Domain, @event.OrganizationId, @event.DomainType);

                // 1. 감사 로그 기록
                await LogDomainEventAsync(
                    DOMAIN_ADDED,
                    AuditActionType.Create,
                    @event.CreatedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain,
                        DomainType = @event.DomainType.ToString(),
                        VerificationToken = !string.IsNullOrEmpty(@event.VerificationToken) ? "[REDACTED]" : null,
                        VerificationMethod = @event.VerificationMethod
                    }
                );

                // 2. 도메인 목록 캐시 무효화
                await InvalidateDomainListCacheAsync(@event.OrganizationId);

                // 3. DNS 검증 토큰 설정
                if (!string.IsNullOrEmpty(@event.VerificationToken))
                {
                    await SetupDnsVerificationAsync(@event.DomainId, @event.Domain, @event.VerificationToken);
                }

                // 4. 도메인 중복 체크
                await CheckForDomainDuplicationAsync(@event.Domain);

                // 5. SSL 인증서 상태 초기 확인
                if (@event.DomainType == DomainType.Production)
                {
                    await InitializeSslMonitoringAsync(@event.DomainId, @event.Domain);
                }

                _logger.LogInformation("Successfully processed domain added event for Domain={Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain added event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        public async Task HandleDomainUpdatedAsync(DomainUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing domain updated event: DomainId={DomainId}, Organization={OrganizationId}",
                    @event.DomainId, @event.OrganizationId);

                // 1. 감사 로그 기록
                await LogDomainEventAsync(
                    DOMAIN_UPDATED,
                    AuditActionType.Update,
                    @event.UpdatedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain,
                        ChangedProperties = @event.ChangedProperties
                    }
                );

                // 2. 도메인 캐시 무효화
                await InvalidateDomainCacheAsync(@event.OrganizationId, @event.DomainId);

                // 3. 도메인 변경 시 리다이렉션 설정
                if (@event.ChangedProperties.ContainsKey("Domain"))
                {
                    await SetupDomainRedirectionAsync(@event.DomainId, 
                        @event.ChangedProperties["Domain"]?.ToString() ?? @event.Domain,
                        @event.Domain);
                }

                _logger.LogInformation("Successfully processed domain updated event for DomainId={DomainId}", @event.DomainId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain updated event for DomainId={DomainId}", @event.DomainId);
                throw;
            }
        }

        public async Task HandleDomainRemovedAsync(DomainRemovedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing domain removed event: Domain={Domain}, Organization={OrganizationId}",
                    @event.Domain, @event.OrganizationId);

                // 1. 감사 로그 기록 (Critical)
                await LogDomainEventAsync(
                    DOMAIN_REMOVED,
                    AuditActionType.Delete,
                    @event.DeletedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain,
                        DomainType = @event.DomainType.ToString()
                    },
                    AuditEventSeverity.Critical
                );

                // 2. 모든 관련 캐시 무효화
                await InvalidateDomainCacheAsync(@event.OrganizationId, @event.DomainId);
                await InvalidateDomainListCacheAsync(@event.OrganizationId);
                await InvalidateSslCacheAsync(@event.DomainId);

                // 3. DNS 레코드 정리 알림
                await NotifyDnsCleanupRequiredAsync(@event.Domain);

                // 4. SSL 모니터링 중지
                await StopSslMonitoringAsync(@event.DomainId);

                _logger.LogWarning("Successfully processed domain removed event for Domain={Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain removed event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        #endregion

        #region Domain Verification Events

        public async Task HandleDomainVerifiedAsync(DomainVerifiedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing domain verified event: Domain={Domain}, Method={Method}",
                    @event.Domain, @event.VerificationMethod);

                // 1. 감사 로그 기록
                await LogDomainEventAsync(
                    DOMAIN_VERIFIED,
                    AuditActionType.Update,
                    @event.VerifiedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain,
                        VerificationMethod = @event.VerificationMethod
                    },
                    AuditEventSeverity.Success
                );

                // 2. 검증 캐시 업데이트
                await UpdateVerificationCacheAsync(@event.DomainId, true);

                // 3. 도메인 자동 활성화
                await AutoActivateDomainAsync(@event.DomainId, @event.OrganizationId);

                // 4. SSL 인증서 자동 요청
                await RequestSslCertificateAsync(@event.DomainId, @event.Domain);

                // 5. 성공 알림 발송
                await NotifyDomainVerificationSuccessAsync(@event.OrganizationId, @event.Domain);

                _logger.LogInformation("Successfully processed domain verified event for Domain={Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain verified event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        public async Task HandleDomainVerificationFailedAsync(DomainVerificationFailedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing domain verification failed: Domain={Domain}, Reason={Reason}, Attempts={Attempts}",
                    @event.Domain, @event.FailureReason, @event.AttemptCount);

                // 1. 감사 로그 기록 (Warning)
                await LogDomainEventAsync(
                    DOMAIN_VERIFICATION_FAILED,
                    AuditActionType.FailedLogin, // 실패 시도로 분류
                    Guid.Empty, // 시스템 이벤트
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain,
                        FailureReason = @event.FailureReason,
                        AttemptCount = @event.AttemptCount
                    },
                    AuditEventSeverity.Warning
                );

                // 2. 검증 캐시 업데이트
                await UpdateVerificationCacheAsync(@event.DomainId, false);

                // 3. 재시도 로직
                if (@event.AttemptCount < 5)
                {
                    await ScheduleDomainVerificationRetryAsync(@event.DomainId, @event.AttemptCount + 1);
                }
                else
                {
                    // 최대 시도 횟수 도달
                    await HandleMaxVerificationAttemptsReachedAsync(@event.DomainId, @event.Domain);
                }

                // 4. 실패 알림
                await NotifyDomainVerificationFailureAsync(@event.OrganizationId, @event.Domain, @event.FailureReason);

                _logger.LogWarning("Processed domain verification failure for Domain={Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain verification failed event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        #endregion

        #region Domain State Events

        public async Task HandleDomainActivatedAsync(DomainActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing domain activated event: Domain={Domain}", @event.Domain);

                // 1. 감사 로그 기록
                await LogDomainEventAsync(
                    DOMAIN_ACTIVATED,
                    AuditActionType.Update,
                    @event.ChangedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain
                    }
                );

                // 2. 캐시 업데이트
                await InvalidateDomainCacheAsync(@event.OrganizationId, @event.DomainId);

                // 3. 라우팅 규칙 활성화
                await EnableDomainRoutingAsync(@event.DomainId, @event.Domain);

                // 4. 모니터링 시작
                await StartDomainMonitoringAsync(@event.DomainId, @event.Domain);

                _logger.LogInformation("Successfully activated domain: {Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain activated event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        public async Task HandleDomainDeactivatedAsync(DomainDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing domain deactivated event: Domain={Domain}", @event.Domain);

                // 1. 감사 로그 기록
                await LogDomainEventAsync(
                    DOMAIN_DEACTIVATED,
                    AuditActionType.Update,
                    @event.ChangedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain
                    },
                    AuditEventSeverity.Warning
                );

                // 2. 캐시 업데이트
                await InvalidateDomainCacheAsync(@event.OrganizationId, @event.DomainId);

                // 3. 라우팅 규칙 비활성화
                await DisableDomainRoutingAsync(@event.DomainId);

                // 4. 모니터링 중지
                await StopDomainMonitoringAsync(@event.DomainId);

                _logger.LogWarning("Successfully deactivated domain: {Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain deactivated event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        public async Task HandlePrimaryDomainChangedAsync(PrimaryDomainChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing primary domain change: Old={OldDomain}, New={NewDomain}",
                    @event.OldPrimaryDomain, @event.NewPrimaryDomain);

                // 1. 감사 로그 기록 (Critical - 주요 변경사항)
                await LogDomainEventAsync(
                    PRIMARY_DOMAIN_CHANGED,
                    AuditActionType.Update,
                    @event.SetByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        OldPrimaryDomainId = @event.OldPrimaryDomainId,
                        OldPrimaryDomain = @event.OldPrimaryDomain,
                        NewPrimaryDomainId = @event.NewPrimaryDomainId,
                        NewPrimaryDomain = @event.NewPrimaryDomain
                    },
                    AuditEventSeverity.Critical
                );

                // 2. Primary 도메인 캐시 무효화
                await InvalidatePrimaryDomainCacheAsync(@event.OrganizationId);

                // 3. 리다이렉션 규칙 업데이트
                if (@event.OldPrimaryDomainId.HasValue)
                {
                    await SetupPrimaryDomainRedirectionAsync(
                        @event.OldPrimaryDomain ?? string.Empty,
                        @event.NewPrimaryDomain
                    );
                }

                // 4. 이메일 발송 도메인 업데이트
                await UpdateEmailSendingDomainAsync(@event.OrganizationId, @event.NewPrimaryDomain);

                // 5. 웹훅 URL 업데이트 알림
                await NotifyWebhookUrlChangeRequiredAsync(@event.OrganizationId, @event.NewPrimaryDomain);

                _logger.LogWarning("Successfully changed primary domain to: {NewDomain}", @event.NewPrimaryDomain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing primary domain change for Organization={OrganizationId}", 
                    @event.OrganizationId);
                throw;
            }
        }

        #endregion

        #region SSL Certificate Events

        public async Task HandleSslCertificateRenewedAsync(SslCertificateRenewedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing SSL certificate renewed: Domain={Domain}, NewExpiry={NewExpiry}",
                    @event.Domain, @event.NewExpiryDate);

                // 1. 감사 로그 기록
                await LogDomainEventAsync(
                    SSL_RENEWED,
                    AuditActionType.Update,
                    @event.RenewedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain,
                        OldExpiryDate = @event.OldExpiryDate,
                        NewExpiryDate = @event.NewExpiryDate
                    },
                    AuditEventSeverity.Success
                );

                // 2. SSL 캐시 업데이트
                await UpdateSslCacheAsync(@event.DomainId, @event.NewExpiryDate);

                // 3. 모니터링 일정 재조정
                await RescheduleSslExpiryMonitoringAsync(@event.DomainId, @event.NewExpiryDate);

                // 4. 성공 알림
                await NotifySslRenewalSuccessAsync(@event.OrganizationId, @event.Domain, @event.NewExpiryDate);

                _logger.LogInformation("Successfully processed SSL renewal for Domain={Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SSL renewal event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        public async Task HandleSslCertificateExpiringAsync(SslCertificateExpiringEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var severity = @event.DaysUntilExpiry <= SSL_CRITICAL_DAYS 
                    ? AuditEventSeverity.Critical 
                    : AuditEventSeverity.Warning;

                _logger.LogWarning("Processing SSL certificate expiring: Domain={Domain}, DaysRemaining={Days}",
                    @event.Domain, @event.DaysUntilExpiry);

                // 1. 감사 로그 기록
                await LogDomainEventAsync(
                    SSL_EXPIRING,
                    AuditActionType.System,
                    Guid.Empty, // 시스템 생성 이벤트
                    @event.OrganizationId,
                    new
                    {
                        DomainId = @event.DomainId,
                        Domain = @event.Domain,
                        ExpiryDate = @event.ExpiryDate,
                        DaysUntilExpiry = @event.DaysUntilExpiry
                    },
                    severity
                );

                // 2. 자동 갱신 시도
                if (@event.DaysUntilExpiry <= SSL_WARNING_DAYS)
                {
                    await AttemptAutoSslRenewalAsync(@event.DomainId, @event.Domain);
                }

                // 3. 경고 알림 발송
                await NotifySslExpiringWarningAsync(@event.OrganizationId, @event.Domain, @event.DaysUntilExpiry);

                // 4. 임박한 경우 긴급 알림
                if (@event.DaysUntilExpiry <= SSL_CRITICAL_DAYS)
                {
                    await SendUrgentSslExpiryAlertAsync(@event.OrganizationId, @event.Domain, @event.ExpiryDate);
                }

                _logger.LogWarning("Processed SSL expiring warning for Domain={Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SSL expiring event for Domain={Domain}", @event.Domain);
                throw;
            }
        }

        #endregion

        #region Private Helper Methods

        private Task LogDomainEventAsync(
            string action,
            AuditActionType actionType,
            Guid performedBy,
            Guid orgId,
            object eventData,
            AuditEventSeverity severity = AuditEventSeverity.Info)
        {
            var auditLog = new AuditLog
            {
                Action = action,
                ActionType = actionType,
                PerformedByConnectedId = performedBy,
                TargetOrganizationId = orgId,
                Success = true,
                Timestamp = _dateTimeProvider.UtcNow,
                Severity = severity,
                Metadata = JsonSerializer.Serialize(eventData)
            };
            return _auditService.LogAsync(auditLog);
        }

        private async Task InvalidateDomainCacheAsync(Guid organizationId, Guid domainId)
        {
            var cacheKey = $"{DOMAIN_CACHE_PREFIX}:{organizationId}:{domainId}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated domain cache for Organization={OrganizationId}, DomainId={DomainId}",
                organizationId, domainId);
        }

        private async Task InvalidateDomainListCacheAsync(Guid organizationId)
        {
            var cacheKey = $"{DOMAIN_LIST_CACHE_PREFIX}:{organizationId}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated domain list cache for Organization={OrganizationId}", organizationId);
        }

        private async Task InvalidatePrimaryDomainCacheAsync(Guid organizationId)
        {
            var cacheKey = $"{PRIMARY_DOMAIN_CACHE_PREFIX}:{organizationId}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated primary domain cache for Organization={OrganizationId}", organizationId);
        }

        private async Task InvalidateSslCacheAsync(Guid domainId)
        {
            var cacheKey = $"{SSL_CACHE_PREFIX}:{domainId}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated SSL cache for DomainId={DomainId}", domainId);
        }

        private async Task UpdateVerificationCacheAsync(Guid domainId, bool isVerified)
        {
            var cacheKey = $"{VERIFICATION_CACHE_PREFIX}:{domainId}";
            // bool을 객체로 래핑하여 저장
            var verificationData = new { IsVerified = isVerified, VerifiedAt = _dateTimeProvider.UtcNow };
            await _cacheService.SetAsync(cacheKey, JsonSerializer.Serialize(verificationData), TimeSpan.FromDays(30));
        }

        private async Task UpdateSslCacheAsync(Guid domainId, DateTime expiryDate)
        {
            var cacheKey = $"{SSL_CACHE_PREFIX}:{domainId}";
            var sslInfo = new { ExpiryDate = expiryDate, LastChecked = _dateTimeProvider.UtcNow };
            await _cacheService.SetAsync(cacheKey, JsonSerializer.Serialize(sslInfo), TimeSpan.FromDays(7));
        }

        private async Task SetupDnsVerificationAsync(Guid domainId, string domain, string verificationToken)
        {
            _logger.LogInformation("Setting up DNS verification for Domain={Domain}", domain);
            // DNS TXT 레코드 검증 - 실제 설정은 외부에서 수행되어야 함
            var verificationResult = await _dnsVerificationHelper.VerifyDnsRecordAsync(
                domain, 
                verificationToken, 
                "TXT"
            );
            
            if (!verificationResult.IsMatch)
            {
                _logger.LogWarning("DNS verification record not found for Domain={Domain}. User needs to add TXT record.", domain);
            }
        }

        private async Task CheckForDomainDuplicationAsync(string domain)
        {
            // 도메인 중복 확인 로직
            _logger.LogDebug("Checking for domain duplication: {Domain}", domain);
            await Task.CompletedTask;
        }

        private async Task InitializeSslMonitoringAsync(Guid domainId, string domain)
        {
            _logger.LogInformation("Initializing SSL monitoring for Domain={Domain}", domain);
            // SSL 인증서 상태 확인
            var status = await _sslCertificateHelper.CheckCertificateStatusAsync(domain);
            if (status != null && status.IsValid && status.ExpiresAt.HasValue)
            {
                await UpdateSslCacheAsync(domainId, status.ExpiresAt.Value);
            }
        }

        private async Task SetupDomainRedirectionAsync(Guid domainId, string oldDomain, string newDomain)
        {
            _logger.LogInformation("Setting up redirection from {OldDomain} to {NewDomain}", oldDomain, newDomain);
            // 리다이렉션 설정 로직
            await Task.CompletedTask;
        }

        private async Task NotifyDnsCleanupRequiredAsync(string domain)
        {
            await _eventBus.PublishAsync(new DnsCleanupRequiredNotification
            {
                Domain = domain
            });
        }

        private async Task StopSslMonitoringAsync(Guid domainId)
        {
            _logger.LogInformation("Stopping SSL monitoring for DomainId={DomainId}", domainId);
            await InvalidateSslCacheAsync(domainId);
        }

        private async Task StopDomainMonitoringAsync(Guid domainId)
        {
            _logger.LogInformation("Stopping domain monitoring for DomainId={DomainId}", domainId);
            await Task.CompletedTask;
        }

        private async Task AutoActivateDomainAsync(Guid domainId, Guid organizationId)
        {
            _logger.LogInformation("Auto-activating domain: DomainId={DomainId}", domainId);
            await _eventBus.PublishAsync(new AutoActivateDomainCommand
            {
                DomainId = domainId,
                OrganizationId = organizationId
            });
        }

        private async Task RequestSslCertificateAsync(Guid domainId, string domain)
        {
            _logger.LogInformation("Checking SSL certificate status for Domain={Domain}", domain);
            // SSL 인증서 상태 확인 후 필요시 갱신
            var status = await _sslCertificateHelper.CheckCertificateStatusAsync(domain);
            
            if (!status.IsValid || status.ExpiresAt < _dateTimeProvider.UtcNow.AddDays(30))
            {
                _logger.LogInformation("SSL certificate needs renewal for Domain={Domain}", domain);
                await _sslCertificateHelper.RenewCertificateAsync(domain);
            }
        }

        private async Task NotifyDomainVerificationSuccessAsync(Guid organizationId, string domain)
        {
            await _eventBus.PublishAsync(new DomainVerificationSuccessNotification
            {
                OrganizationId = organizationId,
                Domain = domain
            });
        }

        private async Task NotifyDomainVerificationFailureAsync(Guid organizationId, string domain, string reason)
        {
            await _eventBus.PublishAsync(new DomainVerificationFailureNotification
            {
                OrganizationId = organizationId,
                Domain = domain,
                FailureReason = reason
            });
        }

        private async Task ScheduleDomainVerificationRetryAsync(Guid domainId, int attemptNumber)
        {
            var delay = TimeSpan.FromMinutes(Math.Pow(2, attemptNumber)); // Exponential backoff
            await _eventBus.PublishDelayedAsync(new RetryDomainVerificationCommand
            {
                DomainId = domainId,
                AttemptNumber = attemptNumber
            }, delay);
        }

        private async Task HandleMaxVerificationAttemptsReachedAsync(Guid domainId, string domain)
        {
            _logger.LogError("Max verification attempts reached for Domain={Domain}", domain);
            await _eventBus.PublishAsync(new MaxVerificationAttemptsReachedEvent
            {
                DomainId = domainId,
                Domain = domain
            });
        }

        private async Task EnableDomainRoutingAsync(Guid domainId, string domain)
        {
            _logger.LogInformation("Enabling routing for Domain={Domain}", domain);
            // 라우팅 규칙 활성화 로직
            await Task.CompletedTask;
        }

        private async Task DisableDomainRoutingAsync(Guid domainId)
        {
            _logger.LogInformation("Disabling routing for DomainId={DomainId}", domainId);
            // 라우팅 규칙 비활성화 로직
            await Task.CompletedTask;
        }

        private async Task StartDomainMonitoringAsync(Guid domainId, string domain)
        {
            _logger.LogInformation("Starting monitoring for Domain={Domain}", domain);
            // 모니터링 시작 로직
            await Task.CompletedTask;
        }

        private async Task SetupPrimaryDomainRedirectionAsync(string oldDomain, string newDomain)
        {
            _logger.LogInformation("Setting up primary domain redirection from {OldDomain} to {NewDomain}", 
                oldDomain, newDomain);
            // Primary 도메인 리다이렉션 설정
            await Task.CompletedTask;
        }

        private async Task UpdateEmailSendingDomainAsync(Guid organizationId, string newDomain)
        {
            _logger.LogInformation("Updating email sending domain to {Domain} for Organization={OrganizationId}",
                newDomain, organizationId);
            // 이메일 발송 도메인 업데이트
            await Task.CompletedTask;
        }

        private async Task NotifyWebhookUrlChangeRequiredAsync(Guid organizationId, string newDomain)
        {
            await _eventBus.PublishAsync(new WebhookUrlChangeRequiredNotification
            {
                OrganizationId = organizationId,
                NewPrimaryDomain = newDomain
            });
        }

        private async Task RescheduleSslExpiryMonitoringAsync(Guid domainId, DateTime newExpiryDate)
        {
            _logger.LogInformation("Rescheduling SSL monitoring for DomainId={DomainId}, NewExpiry={ExpiryDate}",
                domainId, newExpiryDate);
            // SSL 모니터링 일정 재조정
            await Task.CompletedTask;
        }

        private async Task NotifySslRenewalSuccessAsync(Guid organizationId, string domain, DateTime newExpiryDate)
        {
            await _eventBus.PublishAsync(new SslRenewalSuccessNotification
            {
                OrganizationId = organizationId,
                Domain = domain,
                NewExpiryDate = newExpiryDate
            });
        }

        private async Task AttemptAutoSslRenewalAsync(Guid domainId, string domain)
        {
            _logger.LogInformation("Attempting auto SSL renewal for Domain={Domain}", domain);
            await _sslCertificateHelper.RenewCertificateAsync(domain);
        }

        private async Task NotifySslExpiringWarningAsync(Guid organizationId, string domain, int daysUntilExpiry)
        {
            await _eventBus.PublishAsync(new SslExpiringWarningNotification
            {
                OrganizationId = organizationId,
                Domain = domain,
                DaysUntilExpiry = daysUntilExpiry
            });
        }

        private async Task SendUrgentSslExpiryAlertAsync(Guid organizationId, string domain, DateTime expiryDate)
        {
            await _eventBus.PublishAsync(new UrgentSslExpiryAlert
            {
                OrganizationId = organizationId,
                Domain = domain,
                ExpiryDate = expiryDate
            });
        }

        #endregion
    }

    #region Domain Event Classes

    internal class DnsCleanupRequiredNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public string Domain { get; set; } = string.Empty;
    }

    internal class AutoActivateDomainCommand : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid DomainId { get; set; }
        public Guid OrganizationId { get; set; }
    }

    internal class DomainVerificationSuccessNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string Domain { get; set; } = string.Empty;
    }

    internal class DomainVerificationFailureNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string Domain { get; set; } = string.Empty;
        public string FailureReason { get; set; } = string.Empty;
    }

    internal class RetryDomainVerificationCommand : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid DomainId { get; set; }
        public int AttemptNumber { get; set; }
    }

    internal class MaxVerificationAttemptsReachedEvent : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid DomainId { get; set; }
        public string Domain { get; set; } = string.Empty;
    }

    internal class WebhookUrlChangeRequiredNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string NewPrimaryDomain { get; set; } = string.Empty;
    }

    internal class SslRenewalSuccessNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string Domain { get; set; } = string.Empty;
        public DateTime NewExpiryDate { get; set; }
    }

    internal class SslExpiringWarningNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string Domain { get; set; } = string.Empty;
        public int DaysUntilExpiry { get; set; }
    }

    internal class UrgentSslExpiryAlert : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string Domain { get; set; } = string.Empty;
        public DateTime ExpiryDate { get; set; }
    }

    #endregion
}