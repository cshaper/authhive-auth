using System;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Interfaces.Base; // IDomainEvent, IDomainEvent를 위해 추가
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.Infra.Security;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Events;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Validators
{
    public class OrganizationDomainValidator : IOrganizationDomainValidator
    {
        private readonly IOrganizationDomainRepository _domainRepository;
        private readonly IDnsVerificationHelper _dnsHelper;
        private readonly ISslCertificateHelper _sslHelper;
        private readonly IPlanService _planService;
        private readonly ICacheService _cache;
        private readonly IDomainEvent _eventBus; // [추가] 이벤트 버스 의존성
        private readonly ILogger<OrganizationDomainValidator> _logger;

        private static readonly Regex DomainFormatRegex = new Regex(
            @"^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private const string DOMAIN_EXISTS_CACHE_KEY = "domain_exists_{0}";
        private const int CACHE_DURATION_MINUTES = 10;

        public OrganizationDomainValidator(
            IOrganizationDomainRepository domainRepository,
            IDnsVerificationHelper dnsHelper,
            ISslCertificateHelper sslHelper,
            IPlanService planService,
            ICacheService cache,
            IDomainEvent eventBus, // [추가] 생성자에 IDomainEvent 주입
            ILogger<OrganizationDomainValidator> logger)
        {
            _domainRepository = domainRepository;
            _dnsHelper = dnsHelper;
            _sslHelper = sslHelper;
            _planService = planService;
            _cache = cache;
            _eventBus = eventBus; // [추가]
            _logger = logger;
        }

        public async Task<ValidationResult> ValidateDomainFormatAsync(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return new ValidationResult("Domain name cannot be empty.", new[] { "Domain" });

            if (!DomainFormatRegex.IsMatch(domain))
                return new ValidationResult("Invalid domain name format.", new[] { "Domain" });

            var cacheKey = string.Format(DOMAIN_EXISTS_CACHE_KEY, domain.ToLowerInvariant());
            var cachedResult = await _cache.GetAsync<CachedBoolValue>(cacheKey);
            bool exists;

            if (cachedResult == null)
            {
                exists = await _domainRepository.IsDomainExistsAsync(domain);
                await _cache.SetAsync(cacheKey, new CachedBoolValue { Value = exists }, TimeSpan.FromMinutes(CACHE_DURATION_MINUTES));
            }
            else
            {
                exists = cachedResult.Value;
            }

            if (exists)
                return new ValidationResult($"The domain '{domain}' is already in use.", new[] { "Domain" });

            return ValidationResult.Success!;
        }
        public async Task<ValidationResult> ValidateDnsRecordsAsync(string domain)
        {
            var domainEntity = await _domainRepository.GetByDomainAsync(domain);
            if (domainEntity?.VerificationToken == null || domainEntity.VerificationMethod == null)
            {
                _logger.LogWarning("Verification token for domain {Domain} is not available.", domain);
                // FIX #2: Changed from ValidationResult.Failure to constructor
                return new ValidationResult("Verification token for the domain is not available.", new[] { "Domain" });
            }

            var verificationResult = await _dnsHelper.VerifyDnsRecordAsync(domain, domainEntity.VerificationToken, domainEntity.VerificationMethod);

            if (!verificationResult.IsMatch)
            {
                _logger.LogWarning("DNS verification failed for domain {Domain}. Expected: {Expected}, Found: {Actual}", domain, verificationResult.ExpectedValue, verificationResult.ActualValue);

                // Since we cannot track attempts on the entity, we'll assume this is the first failure detection in this context.
                const int newAttemptCount = 1;

                var verificationFailedEvent = new DomainVerificationFailedEvent(
                    organizationId: domainEntity.OrganizationId,
                    domainId: domainEntity.Id,
                    domain: domain,
                    reason: $"Expected '{verificationResult.ExpectedValue}' but found '{verificationResult.ActualValue}'.",
                    attemptCount: newAttemptCount,
                    triggeredBy: null  // Since we removed the parameter, we pass null here
                );
                await _eventBus.PublishAsync(verificationFailedEvent);

                // FIX #3: Changed from ValidationResult.Failure to constructor
                return new ValidationResult($"DNS record verification failed: Expected '{verificationResult.ExpectedValue}' but found '{verificationResult.ActualValue}'.", new[] { "DnsRecord" });
            }

            _logger.LogInformation("DNS verification successful for domain {Domain}.", domain);
            return ValidationResult.Success!;
        }
        public async Task<ValidationResult> ValidateDnsRecordsAsync(string domain, Guid? triggeredBy)
        {
            var domainEntity = await _domainRepository.GetByDomainAsync(domain);
            if (domainEntity?.VerificationToken == null || domainEntity.VerificationMethod == null)
            {
                _logger.LogWarning("Verification token for domain {Domain} is not available.", domain);
                return new ValidationResult("Verification token for the domain is not available.", new[] { "Domain" });
            }

            var verificationResult = await _dnsHelper.VerifyDnsRecordAsync(domain, domainEntity.VerificationToken, domainEntity.VerificationMethod);

            if (!verificationResult.IsMatch)
            {
                _logger.LogWarning("DNS verification failed for domain {Domain}. Expected: {Expected}, Found: {Actual}", domain, verificationResult.ExpectedValue, verificationResult.ActualValue);

                // Since we cannot track attempts on the entity, we'll assume this is the first failure detection in this context.
                const int newAttemptCount = 1;

                var verificationFailedEvent = new DomainVerificationFailedEvent(
                    organizationId: domainEntity.OrganizationId,
                    domainId: domainEntity.Id,
                    domain: domain,
                    reason: $"Expected '{verificationResult.ExpectedValue}' but found '{verificationResult.ActualValue}'.",
                    attemptCount: newAttemptCount,
                    triggeredBy: triggeredBy
                );
                await _eventBus.PublishAsync(verificationFailedEvent);

                return new ValidationResult($"DNS record verification failed: Expected '{verificationResult.ExpectedValue}' but found '{verificationResult.ActualValue}'.", new[] { "DnsRecord" });
            }

            _logger.LogInformation("DNS verification successful for domain {Domain}.", domain);
            return ValidationResult.Success!;
        }

        public async Task<ValidationResult> ValidateSslCertificateAsync(string domain)
        {
            // First, get the domain entity to find out which organization it belongs to.
            var domainEntity = await _domainRepository.GetByDomainAsync(domain);
            if (domainEntity == null)
            {
                // If the domain isn't registered in our system, we can't validate it.
                return new ValidationResult("Domain not found in the system.", new[] { "Domain" });
            }

            var status = await _sslHelper.CheckCertificateStatusAsync(domain);

            if (!status.IsValid)
            {
                return new ValidationResult($"SSL certificate is invalid or missing. Reason: {status.Status}", new[] { "SslCertificate" });
            }

            // Check if the certificate is expiring soon.
            if (status.DaysRemaining.HasValue && status.DaysRemaining.Value <= 7)
            {
                // ✅ FIXED: Switched from object initializer to the correct constructor call.
                // We now provide all the required information.
                var expiringEvent = new SslCertificateExpiringEvent(
                    organizationId: domainEntity.OrganizationId,
                    domain: domain,
                    daysRemaining: status.DaysRemaining.Value,
                    expiresAt: status.ExpiresAt ?? DateTime.UtcNow.AddDays(status.DaysRemaining.Value) // Use the actual expiration date if available
                );
                await _eventBus.PublishAsync(expiringEvent);

                // Return a warning in the validation result.
                return new ValidationResult($"SSL certificate is expiring in {status.DaysRemaining} days. Please renew it.", new[] { "SslCertificate" });
            }

            return ValidationResult.Success!;
        }

        public async Task<ValidationResult> ValidatePrimaryDomainAsync(Guid organizationId, Guid domainId)
        {
            var domain = await _domainRepository.GetByIdAsync(domainId);

            if (domain == null || domain.OrganizationId != organizationId)
                return new ValidationResult("Domain not found or does not belong to the organization.", new[] { "Domain" });

            if (!domain.IsVerified)
                return new ValidationResult("Only a verified domain can be set as primary.", new[] { "Domain" });

            if (!domain.IsActive)
                return new ValidationResult("An inactive domain cannot be set as primary.", new[] { "Domain" });

            return ValidationResult.Success!;
        }

        public async Task<ValidationResult> ValidateDomainCountLimitAsync(Guid organizationId, int currentCount)
        {
            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(organizationId);
            if (subscription == null)
                return new ValidationResult("Active subscription not found to verify domain limits.", new[] { "Plan" });

            if (PricingConstants.SubscriptionPlans.DomainLimits.TryGetValue(subscription.PlanKey, out var limit))
            {
                if (limit != -1 && currentCount >= limit)
                {
                    // ✅ FIXED: Switched from object initializer to the correct constructor call.
                    var limitEvent = new DomainCountLimitReachedEvent(
                        organizationId: organizationId,
                        currentPlan: subscription.PlanKey, // Use PlanKey for consistency
                        limit: limit,
                        triggeredBy: null // Pass the user's ConnectedId if available
                    );
                    await _eventBus.PublishAsync(limitEvent);

                    return new ValidationResult($"You have reached the maximum of {limit} domains for your current plan.", new[] { "DomainLimit" });
                }
            }

            return ValidationResult.Success!;
        }

        private class CachedBoolValue { public bool Value { get; set; } }

    }
}