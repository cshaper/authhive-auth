using System;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Interfaces.Base; // IEventBus, IDomainEvent를 위해 추가
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Infra.Security;
using AuthHive.Core.Models.Organization.Common;
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
        private readonly IEventBus _eventBus; // [추가] 이벤트 버스 의존성
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
            IEventBus eventBus, // [추가] 생성자에 IEventBus 주입
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
                return new ValidationResult("Verification token for the domain is not available.", new[] { "Domain" });

            var verificationResult = await _dnsHelper.VerifyDnsRecordAsync(domain, domainEntity.VerificationToken, domainEntity.VerificationMethod);

            if (!verificationResult.IsMatch)
            {
                // [추가] DNS 검증 실패 이벤트 발행
                await _eventBus.PublishAsync(new DomainVerificationFailedEvent
                {
                    OrganizationId = domainEntity.OrganizationId,
                    Domain = domain,
                    Reason = $"Expected '{verificationResult.ExpectedValue}' but found '{verificationResult.ActualValue}'."
                });

                return new ValidationResult($"DNS record verification failed: Expected '{verificationResult.ExpectedValue}' but found '{verificationResult.ActualValue}'.", new[] { "DnsRecord" });
            }

            return ValidationResult.Success!;
        }

        public async Task<ValidationResult> ValidateSslCertificateAsync(string domain)
        {
            var status = await _sslHelper.CheckCertificateStatusAsync(domain);

            if (!status.IsValid)
                return new ValidationResult($"SSL certificate is invalid or missing. Reason: {status.Status}", new[] { "SslCertificate" });

            if (status.DaysRemaining <= 7)
            {
                // [추가] SSL 인증서 만료 임박 이벤트 발행
                await _eventBus.PublishAsync(new SslCertificateExpiringEvent
                {
                    Domain = domain,
                    DaysRemaining = status.DaysRemaining.Value
                });
                
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
                    // [추가] 도메인 개수 한도 초과 이벤트 발행
                    await _eventBus.PublishAsync(new DomainCountLimitReachedEvent
                    {
                        OrganizationId = organizationId,
                        CurrentPlan = subscription.PlanName,
                        Limit = limit
                    });

                    return new ValidationResult($"You have reached the maximum of {limit} domains for your current plan.", new[] { "DomainLimit" });
                }
            }

            return ValidationResult.Success!;
        }
        
        private class CachedBoolValue { public bool Value { get; set; } }

        #region Domain Events (Should be moved to a dedicated Models/Events folder)

        public class DomainVerificationFailedEvent : IDomainEvent
        {
            public Guid EventId { get; set; } = Guid.NewGuid();
            public Guid OrganizationId { get; set; }
            public string Domain { get; set; } = string.Empty;
            public string Reason { get; set; } = string.Empty;
            public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        }

        public class SslCertificateExpiringEvent : IDomainEvent
        {
            public Guid EventId { get; set; } = Guid.NewGuid();
            public string Domain { get; set; } = string.Empty;
            public int DaysRemaining { get; set; }
            public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        }

        public class DomainCountLimitReachedEvent : IDomainEvent
        {
            public Guid EventId { get; set; } = Guid.NewGuid();
            public Guid OrganizationId { get; set; }
            public string CurrentPlan { get; set; } = string.Empty;
            public int Limit { get; set; }
            public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        }

        #endregion
    }
}