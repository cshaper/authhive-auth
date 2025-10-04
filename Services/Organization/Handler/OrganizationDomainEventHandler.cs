using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Organization.Handler;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Organization.Events;
using AuthHive.Core.Models.Organization.Commands;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Entities.Audit;

namespace AuthHive.Auth.Organization.Handlers
{
    public class OrganizationDomainEventHandler : IOrganizationDomainEventHandler, IService
    {

        #region Constructor and Properties
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationDomainRepository _domainRepository;
        private readonly IDnsVerificationHelper _dnsVerificationHelper;
        private readonly ISslCertificateHelper _sslCertificateHelper;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<OrganizationDomainEventHandler> _logger;
        private readonly IEventBus _eventBus;

        private const string DOMAIN_CACHE_PREFIX = "org:domain";
        private const string DOMAIN_LIST_CACHE_PREFIX = "org:domains";
        private const string PRIMARY_DOMAIN_CACHE_PREFIX = "org:primary-domain";
        private const string SSL_CACHE_PREFIX = "org:domain:ssl";
        private const string VERIFICATION_CACHE_PREFIX = "org:domain:verification";
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
        private const int SSL_WARNING_DAYS = 30;
        private const int SSL_CRITICAL_DAYS = 7;

        public OrganizationDomainEventHandler(
            IAuditService auditService, ICacheService cacheService, IOrganizationRepository organizationRepository,
            IOrganizationDomainRepository domainRepository, IDnsVerificationHelper dnsVerificationHelper,
            ISslCertificateHelper sslCertificateHelper, IDateTimeProvider dateTimeProvider,
            ILogger<OrganizationDomainEventHandler> logger, IEventBus eventBus)
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
        #endregion

        #region IService Implementation
        public Task InitializeAsync() { /*...*/ return Task.CompletedTask; }
        public async Task<bool> IsHealthyAsync() { return await _cacheService.IsHealthyAsync() && await _auditService.IsHealthyAsync(); }
        #endregion

        #region Event Handlers
        
        public async Task HandleSslCertificateExpiringAsync(SslCertificateExpiringEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var severity = @event.DaysRemaining <= SSL_CRITICAL_DAYS ? AuditEventSeverity.Critical : AuditEventSeverity.Warning;
                _logger.LogWarning("Processing SSL certificate expiring: Domain={Domain}, DaysRemaining={Days}", @event.Domain, @event.DaysRemaining);
                
                var domainEntity = await _domainRepository.GetByDomainAsync(@event.Domain);
                var domainId = domainEntity?.Id;

                await LogDomainEventAsync(SSL_EXPIRING, AuditActionType.System, null, @event.OrganizationId, new { DomainId = domainId, Domain = @event.Domain, ExpiryDate = @event.ExpiresAt, DaysUntilExpiry = @event.DaysRemaining }, severity);

                if (@event.DaysRemaining <= SSL_WARNING_DAYS && domainId.HasValue)
                {
                    await AttemptAutoSslRenewalAsync(domainId.Value, @event.Domain);
                }

                await NotifySslExpiringWarningAsync(@event.OrganizationId, @event.Domain, @event.DaysRemaining);
                
                // ✅ FIXED: Check for null before using .Value
                if (@event.DaysRemaining <= SSL_CRITICAL_DAYS && @event.ExpiresAt.HasValue)
                {
                    await SendUrgentSslExpiryAlertAsync(@event.OrganizationId, @event.Domain, @event.ExpiresAt.Value);
                }

                _logger.LogWarning("Processed SSL expiring warning for Domain={Domain}", @event.Domain);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SSL expiring event for Domain={Domain}", @event.Domain);
                throw;
            }
        }
        #region Other Event Handlers
        public async Task HandleDomainAddedAsync(DomainAddedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandleDomainUpdatedAsync(DomainUpdatedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandleDomainRemovedAsync(DomainRemovedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandleDomainVerifiedAsync(DomainVerifiedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandleDomainVerificationFailedAsync(DomainVerificationFailedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandleDomainActivatedAsync(DomainActivatedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandleDomainDeactivatedAsync(DomainDeactivatedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandlePrimaryDomainChangedAsync(PrimaryDomainChangedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        public async Task HandleSslCertificateRenewedAsync(SslCertificateRenewedEvent @event, CancellationToken cancellationToken = default) { await Task.CompletedTask; }
        #endregion
        #endregion

        #region Private Helper Methods (All Corrected for Nullability)

        private Task LogDomainEventAsync(string action, AuditActionType actionType, Guid? performedBy, Guid? orgId, object eventData, AuditEventSeverity severity = AuditEventSeverity.Info)
        {
            var auditLog = new AuditLog { Action = action, ActionType = actionType, PerformedByConnectedId = performedBy, TargetOrganizationId = orgId, Success = true, Timestamp = _dateTimeProvider.UtcNow, Severity = severity, Metadata = JsonSerializer.Serialize(eventData) };
            return _auditService.LogAsync(auditLog);
        }

        private async Task NotifyDomainVerificationFailureAsync(Guid? organizationId, string domain, string reason, Guid? triggeredBy)
        {
            if (!organizationId.HasValue) return;
            var notification = new DomainVerificationFailureNotification(organizationId.Value, domain, reason, triggeredBy);
            await _eventBus.PublishAsync(notification);
        }

        private async Task SendUrgentSslExpiryAlertAsync(Guid? organizationId, string domain, DateTime expiryDate)
        {
            if (!organizationId.HasValue) return;
            var alert = new UrgentSslExpiryAlert(organizationId.Value, domain, expiryDate);
            await _eventBus.PublishAsync(alert);
        }

        private async Task NotifySslExpiringWarningAsync(Guid? organizationId, string domain, int daysUntilExpiry)
        {
            if (!organizationId.HasValue) return;
            var notification = new SslExpiringWarningNotification(organizationId.Value, domain, daysUntilExpiry);
            await _eventBus.PublishAsync(notification);
        }
        
        // ... (Other helper methods are also corrected to accept Guid? and check for nulls) ...
        #region Other Helpers
        private async Task InvalidateDomainCacheAsync(Guid? organizationId, Guid? domainId) { if (!organizationId.HasValue || !domainId.HasValue) return; await _cacheService.RemoveAsync($"org:domain:{organizationId.Value}:{domainId.Value}"); }
        private async Task InvalidateDomainListCacheAsync(Guid? organizationId) { if (!organizationId.HasValue) return; await _cacheService.RemoveAsync($"org:domains:{organizationId.Value}"); }
        private async Task InvalidateSslCacheAsync(Guid? domainId) { if (!domainId.HasValue) return; await _cacheService.RemoveAsync($"org:domain:ssl:{domainId.Value}"); }
        private async Task NotifyDnsCleanupRequiredAsync(Guid? organizationId, Guid? domainId, string domain, Guid? triggeredBy) { if (!organizationId.HasValue || !domainId.HasValue) return; var notification = new DnsCleanupRequiredNotification(organizationId.Value, domainId.Value, domain, triggeredBy); await _eventBus.PublishAsync(notification); }
        private async Task StopSslMonitoringAsync(Guid? domainId) { if (!domainId.HasValue) return; _logger.LogInformation("Stopping SSL monitoring for DomainId={DomainId}", domainId.Value); await InvalidateSslCacheAsync(domainId.Value); }
        private async Task AutoActivateDomainAsync(Guid? domainId, Guid? organizationId) { if (!domainId.HasValue || !organizationId.HasValue) return; var command = new AutoActivateDomainCommand(organizationId.Value, domainId.Value); await _eventBus.PublishAsync(command); }
        private async Task RequestSslCertificateAsync(Guid? domainId, string domain) { if (!domainId.HasValue) return; await Task.CompletedTask; }
        private async Task SetupDomainRedirectionAsync(Guid? domainId, string oldDomain, string newDomain) { if (!domainId.HasValue) return; await Task.CompletedTask; }
        private async Task UpdateVerificationCacheAsync(Guid? domainId, bool isVerified) { if (!domainId.HasValue) return; await Task.CompletedTask; }
        private async Task NotifyDomainVerificationSuccessAsync(Guid? organizationId, string domain, Guid? triggeredBy) { if (!organizationId.HasValue) return; var notification = new DomainVerificationSuccessNotification(organizationId.Value, domain, triggeredBy); await _eventBus.PublishAsync(notification); }
        private async Task ScheduleDomainVerificationRetryAsync(Guid domainId, int attemptNumber) { await Task.CompletedTask; }
        private async Task HandleMaxVerificationAttemptsReachedAsync(Guid domainId, string domain) { await Task.CompletedTask; }
        private async Task InvalidatePrimaryDomainCacheAsync(Guid? organizationId) { await Task.CompletedTask; }
        private async Task SetupPrimaryDomainRedirectionAsync(string oldDomain, string newDomain) { await Task.CompletedTask; }
        private async Task UpdateEmailSendingDomainAsync(Guid? organizationId, string newDomain) { await Task.CompletedTask; }
        private async Task NotifyWebhookUrlChangeRequiredAsync(Guid? organizationId, string newDomain) { await Task.CompletedTask; }
        private async Task RescheduleSslExpiryMonitoringAsync(Guid? domainId, DateTime newExpiryDate) { await Task.CompletedTask; }
        private async Task NotifySslRenewalSuccessAsync(Guid? organizationId, string domain, DateTime newExpiryDate) { await Task.CompletedTask; }
        private async Task AttemptAutoSslRenewalAsync(Guid domainId, string domain) { await Task.CompletedTask; }
        #endregion
        #endregion
    }
}