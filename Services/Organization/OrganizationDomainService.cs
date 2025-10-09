using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Core.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Security;
using Microsoft.EntityFrameworkCore;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 도메인 관리 서비스 구현체 - AuthHive v15
    /// 도메인 CRUD, 검증, SSL 관리 등 모든 도메인 관련 비즈니스 로직을 처리합니다.
    /// </summary>
    public class OrganizationDomainService : IOrganizationDomainService
    {
        private readonly IOrganizationDomainRepository _domainRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ILogger<OrganizationDomainService> _logger;
        private readonly IDnsVerificationHelper _dnsHelper;
        private readonly ISslCertificateHelper _sslHelper;

        // 비즈니스 규칙 상수
        private const int MAX_DOMAINS_PER_ORG = 10;
        private const int MAX_VERIFICATION_ATTEMPTS = 10;
        private const int VERIFICATION_TOKEN_LENGTH = 32;
        private const int SSL_EXPIRY_WARNING_DAYS = 30;

        public OrganizationDomainService(
            IOrganizationDomainRepository domainRepository,
            IOrganizationRepository organizationRepository,
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ILogger<OrganizationDomainService> logger,
            IDnsVerificationHelper dnsHelper,
            ISslCertificateHelper sslHelper)
        {
            _domainRepository = domainRepository ?? throw new ArgumentNullException(nameof(domainRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dnsHelper = dnsHelper ?? throw new ArgumentNullException(nameof(dnsHelper));
            _sslHelper = sslHelper ?? throw new ArgumentNullException(nameof(sslHelper));
        }

        #region IService 기본 구현

        // OrganizationDomainService.cs

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            try
            {
                // 🚨 CancellationToken을 CountAsync에 전달:
                // 대부분의 Repository CountAsync는 (predicate, token) 시그니처를 가집니다.
                // predicate 없이 토큰만 전달하려면 첫 번째 인수로 null을 명시해야 합니다.
                await _domainRepository.CountAsync(null, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationDomainService health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            // Method body is already optimized for a completed task.
            _logger.LogInformation("OrganizationDomainService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region 도메인 CRUD

        public async Task<ServiceResult<OrganizationDomainDto>> GetByIdAsync(Guid domainId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult<OrganizationDomainDto>.NotFound("Domain not found");
                }

                var dto = _mapper.Map<OrganizationDomainDto>(domain);
                return ServiceResult<OrganizationDomainDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving domain {DomainId}", domainId);
                return ServiceResult<OrganizationDomainDto>.Failure("Failed to retrieve domain", "DOMAIN_RETRIEVAL_ERROR");
            }
        }

        public async Task<ServiceResult<IEnumerable<OrganizationDomainDto>>> GetByOrganizationAsync(
            Guid organizationId,
            bool includeInactive = false)
        {
            try
            {
                var domains = includeInactive
                    ? await _domainRepository.GetByOrganizationIdAsync(organizationId)
                    : await _domainRepository.GetActiveDomainsAsync(organizationId);

                var dtos = _mapper.Map<IEnumerable<OrganizationDomainDto>>(domains);
                return ServiceResult<IEnumerable<OrganizationDomainDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving domains for organization {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<OrganizationDomainDto>>.Failure(
                    "Failed to retrieve organization domains",
                    "DOMAIN_LIST_ERROR");
            }
        }

        public async Task<ServiceResult<OrganizationDomainDto>> GetByDomainNameAsync(string domain)
        {
            try
            {
                // 도메인 이름 정규화
                domain = NormalizeDomain(domain);

                var domainEntity = await _domainRepository.GetByDomainAsync(domain);
                if (domainEntity == null)
                {
                    return ServiceResult<OrganizationDomainDto>.NotFound($"Domain '{domain}' not found");
                }

                var dto = _mapper.Map<OrganizationDomainDto>(domainEntity);
                return ServiceResult<OrganizationDomainDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving domain by name {Domain}", domain);
                return ServiceResult<OrganizationDomainDto>.Failure(
                    "Failed to retrieve domain",
                    "DOMAIN_RETRIEVAL_ERROR");
            }
        }

        public async Task<ServiceResult<OrganizationDomainDto>> CreateAsync(
            CreateOrganizationDomainRequest createDto,
            Guid createdByConnectedId)
        {
            try
            {
                // 입력 검증
                var validationResult = await ValidateCreateRequest(createDto);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<OrganizationDomainDto>.Failure(
                        validationResult.ErrorMessage ?? "Validation failed",
                        validationResult.ErrorCode);
                }

                // 도메인 이름 정규화
                var normalizedDomain = NormalizeDomain(createDto.DomainName);

                // 중복 확인
                if (await _domainRepository.IsDomainExistsAsync(normalizedDomain))
                {
                    return ServiceResult<OrganizationDomainDto>.Failure(
                        $"Domain '{normalizedDomain}' is already registered",
                        "DOMAIN_ALREADY_EXISTS");
                }

                // 조직의 도메인 수 제한 확인
                var existingDomains = await _domainRepository.FindAsync(
                    d => EF.Property<Guid>(d, "OrganizationId") == createDto.OrganizationId
                );
                if (existingDomains.Count() >= MAX_DOMAINS_PER_ORG)
                {
                    return ServiceResult<OrganizationDomainDto>.Failure(
                        $"Organization has reached maximum domain limit ({MAX_DOMAINS_PER_ORG})",
                        "DOMAIN_LIMIT_EXCEEDED");
                }

                // Primary 도메인 중복 확인
                if (createDto.DomainType == DomainType.Primary)
                {
                    var existingPrimary = await _domainRepository.GetPrimaryDomainAsync(createDto.OrganizationId);
                    if (existingPrimary != null)
                    {
                        return ServiceResult<OrganizationDomainDto>.Failure(
                            "Organization already has a primary domain",
                            "PRIMARY_DOMAIN_EXISTS");
                    }
                }

                // 엔티티 생성
                var domain = new OrganizationDomain
                {
                    OrganizationId = createDto.OrganizationId,
                    Domain = normalizedDomain,
                    DomainType = createDto.DomainType,
                    IsVerified = false,
                    VerificationToken = GenerateVerificationToken(),
                    SSLEnabled = createDto.EnableSsl,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = createdByConnectedId
                };

                await _domainRepository.AddAsync(domain);
                await _unitOfWork.SaveChangesAsync();

                var dto = _mapper.Map<OrganizationDomainDto>(domain);

                _logger.LogInformation(
                    "Domain {Domain} created for organization {OrganizationId} by {CreatedBy}",
                    normalizedDomain, createDto.OrganizationId, createdByConnectedId);

                return ServiceResult<OrganizationDomainDto>.Success(dto, "Domain created successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating domain");
                return ServiceResult<OrganizationDomainDto>.Failure(
                    "Failed to create domain",
                    "DOMAIN_CREATE_ERROR");
            }
        }

        public async Task<ServiceResult<OrganizationDomainDto>> UpdateAsync(
            Guid domainId,
            UpdateOrganizationDomainRequest updateDto,
            Guid updatedByConnectedId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult<OrganizationDomainDto>.NotFound("Domain not found");
                }

                // 검증된 도메인의 이름은 변경 불가
                if (domain.IsVerified && !string.IsNullOrEmpty(updateDto.Domain) &&
                    !domain.Domain.Equals(updateDto.Domain, StringComparison.OrdinalIgnoreCase))
                {
                    return ServiceResult<OrganizationDomainDto>.Failure(
                        "Cannot change domain name after verification",
                        "VERIFIED_DOMAIN_IMMUTABLE");
                }

                // 업데이트 적용
                if (!string.IsNullOrEmpty(updateDto.Domain))
                {
                    domain.Domain = NormalizeDomain(updateDto.Domain);
                }

                if (updateDto.DomainType.HasValue)
                {
                    // Primary 도메인 중복 확인
                    if (updateDto.DomainType == DomainType.Primary && domain.DomainType != DomainType.Primary)
                    {
                        var existingPrimary = await _domainRepository.GetPrimaryDomainAsync(domain.OrganizationId);
                        if (existingPrimary != null && existingPrimary.Id != domainId)
                        {
                            return ServiceResult<OrganizationDomainDto>.Failure(
                                "Organization already has a primary domain",
                                "PRIMARY_DOMAIN_EXISTS");
                        }
                    }
                    domain.DomainType = updateDto.DomainType.Value;
                }

                if (updateDto.EnableSsl.HasValue)
                {
                    domain.SSLEnabled = updateDto.EnableSsl.Value;
                }

                domain.UpdatedAt = DateTime.UtcNow;
                domain.UpdatedByConnectedId = updatedByConnectedId;

                await _domainRepository.UpdateAsync(domain);
                await _unitOfWork.SaveChangesAsync();

                var dto = _mapper.Map<OrganizationDomainDto>(domain);

                _logger.LogInformation(
                    "Domain {DomainId} updated by {UpdatedBy}",
                    domainId, updatedByConnectedId);

                return ServiceResult<OrganizationDomainDto>.Success(dto, "Domain updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating domain {DomainId}", domainId);
                return ServiceResult<OrganizationDomainDto>.Failure(
                    "Failed to update domain",
                    "DOMAIN_UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid domainId, Guid deletedByConnectedId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult.NotFound("Domain not found");
                }

                // Primary 도메인은 삭제 불가
                if (domain.DomainType == DomainType.Primary && domain.IsActive)
                {
                    return ServiceResult.Failure(
                        "Cannot delete active primary domain",
                        "PRIMARY_DOMAIN_DELETE_FORBIDDEN");
                }

                domain.IsDeleted = true;
                domain.DeletedAt = DateTime.UtcNow;
                domain.DeletedByConnectedId = deletedByConnectedId;

                await _domainRepository.UpdateAsync(domain);
                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation(
                    "Domain {DomainId} deleted by {DeletedBy}",
                    domainId, deletedByConnectedId);

                return ServiceResult.Success("Domain deleted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting domain {DomainId}", domainId);
                return ServiceResult.Failure("Failed to delete domain", "DOMAIN_DELETE_ERROR");
            }
        }

        #endregion

        #region 도메인 검증

        public async Task<ServiceResult<DomainVerificationResult>> VerifyOwnershipAsync(
            Guid domainId,
            Guid verifiedByConnectedId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult<DomainVerificationResult>.NotFound("Domain not found");
                }

                if (domain.IsVerified)
                {
                    return ServiceResult<DomainVerificationResult>.Success(
                        new DomainVerificationResult
                        {
                            IsVerified = true,
                            VerificationStatus = "Verified",
                            VerifiedAt = domain.VerifiedAt
                        },
                        "Domain is already verified");
                }

                // 검증 시도 횟수 확인
                if (domain.VerificationAttemptCount >= MAX_VERIFICATION_ATTEMPTS)
                {
                    return ServiceResult<DomainVerificationResult>.Failure(
                        "Maximum verification attempts exceeded",
                        "MAX_ATTEMPTS_EXCEEDED");
                }

                // 검증 시도 횟수 증가
                await _domainRepository.IncrementVerificationAttemptAsync(domainId);

                // DNS 검증 수행
                var dnsResult = await _dnsHelper.VerifyDnsRecordAsync(
                    domain.Domain,
                    domain.VerificationToken ?? string.Empty,
                    domain.VerificationMethod ?? "TXT");

                if (dnsResult.IsMatch)
                {
                    // 검증 성공
                    await _domainRepository.MarkDomainAsVerifiedAsync(
                        domainId,
                        verifiedByConnectedId,
                        DateTime.UtcNow);

                    await _unitOfWork.SaveChangesAsync();

                    _logger.LogInformation(
                        "Domain {Domain} verified successfully by {VerifiedBy}",
                        domain.Domain, verifiedByConnectedId);

                    return ServiceResult<DomainVerificationResult>.Success(
                        new DomainVerificationResult
                        {
                            IsVerified = true,
                            VerificationStatus = "Verified",
                            VerifiedAt = DateTime.UtcNow,
                            DnsResult = dnsResult
                        },
                        "Domain verified successfully");
                }
                else
                {
                    // 검증 실패
                    _logger.LogWarning(
                        "Domain verification failed for {Domain}. Expected: {Expected}, Found: {Found}",
                        domain.Domain, dnsResult.ExpectedValue, dnsResult.ActualValue);

                    return ServiceResult<DomainVerificationResult>.Success(
                        new DomainVerificationResult
                        {
                            IsVerified = false,
                            VerificationStatus = "Failed",
                            AttemptCount = domain.VerificationAttemptCount + 1,
                            LastAttemptAt = DateTime.UtcNow,
                            ErrorMessage = $"DNS record not found or mismatch. Expected: {dnsResult.ExpectedValue}",
                            DnsResult = dnsResult
                        },
                        "Domain verification failed");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying domain {DomainId}", domainId);
                return ServiceResult<DomainVerificationResult>.Failure(
                    "Failed to verify domain",
                    "VERIFICATION_ERROR");
            }
        }

        public async Task<ServiceResult<string>> GenerateVerificationTokenAsync(Guid domainId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult<string>.NotFound("Domain not found");
                }

                if (domain.IsVerified)
                {
                    return ServiceResult<string>.Failure(
                        "Domain is already verified",
                        "DOMAIN_ALREADY_VERIFIED");
                }

                // 새 토큰 생성
                var newToken = GenerateVerificationToken();
                domain.VerificationToken = newToken;
                domain.VerificationAttemptCount = 0; // 리셋
                domain.UpdatedAt = DateTime.UtcNow;

                await _domainRepository.UpdateAsync(domain);
                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation(
                    "New verification token generated for domain {DomainId}",
                    domainId);

                return ServiceResult<string>.Success(newToken, "Verification token generated");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating verification token for domain {DomainId}", domainId);
                return ServiceResult<string>.Failure(
                    "Failed to generate verification token",
                    "TOKEN_GENERATION_ERROR");
            }
        }

        public async Task<ServiceResult<DnsVerificationResult>> CheckDnsRecordsAsync(string domain)
        {
            try
            {
                domain = NormalizeDomain(domain);
                var result = await _dnsHelper.CheckDnsRecordsAsync(domain);
                return ServiceResult<DnsVerificationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking DNS records for {Domain}", domain);
                return ServiceResult<DnsVerificationResult>.Failure(
                    "Failed to check DNS records",
                    "DNS_CHECK_ERROR");
            }
        }

        public async Task<ServiceResult<bool>> IsDomainAvailableAsync(string domain)
        {
            try
            {
                domain = NormalizeDomain(domain);
                var exists = await _domainRepository.IsDomainExistsAsync(domain);
                return ServiceResult<bool>.Success(!exists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking domain availability for {Domain}", domain);
                return ServiceResult<bool>.Failure(
                    "Failed to check domain availability",
                    "AVAILABILITY_CHECK_ERROR");
            }
        }

        #endregion

        #region SSL 인증서 관리

        public async Task<ServiceResult<SslCertificateStatus>> CheckSslStatusAsync(Guid domainId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult<SslCertificateStatus>.NotFound("Domain not found");
                }

                if (!domain.SSLEnabled)
                {
                    return ServiceResult<SslCertificateStatus>.Success(
                        new SslCertificateStatus
                        {
                            IsEnabled = false,
                            Status = "Disabled"
                        });
                }

                // SSL 인증서 상태 확인
                var sslStatus = await _sslHelper.CheckCertificateStatusAsync(domain.Domain);

                // DB 업데이트
                if (sslStatus.ExpiresAt.HasValue && domain.CertificateExpiry != sslStatus.ExpiresAt)
                {
                    await _domainRepository.UpdateSslCertificateAsync(
                        domainId,
                        sslStatus.ExpiresAt.Value,
                        domain.SSLEnabled);
                    await _unitOfWork.SaveChangesAsync();
                }

                return ServiceResult<SslCertificateStatus>.Success(sslStatus);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking SSL status for domain {DomainId}", domainId);
                return ServiceResult<SslCertificateStatus>.Failure(
                    "Failed to check SSL status",
                    "SSL_CHECK_ERROR");
            }
        }

        public async Task<ServiceResult> RenewSslCertificateAsync(
            Guid domainId,
            Guid renewedByConnectedId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult.NotFound("Domain not found");
                }

                if (!domain.IsVerified)
                {
                    return ServiceResult.Failure(
                        "Domain must be verified before SSL renewal",
                        "DOMAIN_NOT_VERIFIED");
                }

                // SSL 인증서 갱신 (Let's Encrypt 또는 다른 제공자 사용)
                var renewalResult = await _sslHelper.RenewCertificateAsync(domain.Domain);

                if (renewalResult.IsSuccess && renewalResult.ExpiryDate.HasValue)
                {
                    await _domainRepository.UpdateSslCertificateAsync(
                        domainId,
                        renewalResult.ExpiryDate.Value,
                        true);

                    await _unitOfWork.SaveChangesAsync();

                    _logger.LogInformation(
                        "SSL certificate renewed for domain {Domain} by {RenewedBy}",
                        domain.Domain, renewedByConnectedId);

                    return ServiceResult.Success("SSL certificate renewed successfully");
                }
                else
                {
                    return ServiceResult.Failure(
                        renewalResult.ErrorMessage ?? "SSL renewal failed",
                        "SSL_RENEWAL_FAILED");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error renewing SSL certificate for domain {DomainId}", domainId);
                return ServiceResult.Failure(
                    "Failed to renew SSL certificate",
                    "SSL_RENEWAL_ERROR");
            }
        }

        public async Task<ServiceResult<IEnumerable<OrganizationDomainDto>>> GetExpiringCertificatesAsync(
            int daysBeforeExpiry = 30)
        {
            try
            {
                var expiringDomains = await _domainRepository.GetExpiringCertificatesAsync(daysBeforeExpiry);
                var dtos = _mapper.Map<IEnumerable<OrganizationDomainDto>>(expiringDomains);

                _logger.LogInformation(
                    "Found {Count} domains with expiring certificates (within {Days} days)",
                    expiringDomains.Count(), daysBeforeExpiry);

                return ServiceResult<IEnumerable<OrganizationDomainDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving expiring certificates");
                return ServiceResult<IEnumerable<OrganizationDomainDto>>.Failure(
                    "Failed to retrieve expiring certificates",
                    "EXPIRING_CERTS_ERROR");
            }
        }

        #endregion

        #region 도메인 활성화

        public async Task<ServiceResult<OrganizationDomainDto>> SetActiveStatusAsync(
            Guid domainId,
            bool isActive,
            Guid changedByConnectedId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult<OrganizationDomainDto>.NotFound("Domain not found");
                }

                // Primary 도메인 비활성화 시 경고
                if (!isActive && domain.DomainType == DomainType.Primary)
                {
                    _logger.LogWarning(
                        "Deactivating primary domain {Domain} for organization {OrganizationId}",
                        domain.Domain, domain.OrganizationId);
                }

                var result = await _domainRepository.UpdateDomainStatusAsync(
                    domainId,
                    isActive,
                    changedByConnectedId);

                if (result)
                {
                    await _unitOfWork.SaveChangesAsync();

                    // 업데이트된 도메인 다시 조회
                    domain = await _domainRepository.GetByIdAsync(domainId);
                    var dto = _mapper.Map<OrganizationDomainDto>(domain);

                    _logger.LogInformation(
                        "Domain {DomainId} status changed to {Status} by {ChangedBy}",
                        domainId, isActive ? "Active" : "Inactive", changedByConnectedId);

                    return ServiceResult<OrganizationDomainDto>.Success(
                        dto,
                        $"Domain {(isActive ? "activated" : "deactivated")} successfully");
                }
                else
                {
                    return ServiceResult<OrganizationDomainDto>.Failure(
                        "Failed to update domain status",
                        "STATUS_UPDATE_FAILED");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating domain {DomainId} status", domainId);
                return ServiceResult<OrganizationDomainDto>.Failure(
                    "Failed to update domain status",
                    "STATUS_UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult<OrganizationDomainDto>> SetAsPrimaryAsync(
            Guid domainId,
            Guid setByConnectedId)
        {
            try
            {
                var domain = await _domainRepository.GetByIdAsync(domainId);
                if (domain == null)
                {
                    return ServiceResult<OrganizationDomainDto>.NotFound("Domain not found");
                }

                if (!domain.IsVerified)
                {
                    return ServiceResult<OrganizationDomainDto>.Failure(
                        "Domain must be verified before setting as primary",
                        "DOMAIN_NOT_VERIFIED");
                }

                if (!domain.IsActive)
                {
                    return ServiceResult<OrganizationDomainDto>.Failure(
                        "Domain must be active to set as primary",
                        "DOMAIN_NOT_ACTIVE");
                }

                // 기존 Primary 도메인 해제
                var existingPrimary = await _domainRepository.GetPrimaryDomainAsync(domain.OrganizationId);
                if (existingPrimary != null && existingPrimary.Id != domainId)
                {
                    existingPrimary.DomainType = DomainType.CustomSubdomain;
                    existingPrimary.UpdatedAt = DateTime.UtcNow;
                    existingPrimary.UpdatedByConnectedId = setByConnectedId;
                    await _domainRepository.UpdateAsync(existingPrimary);
                }

                // 새 Primary 설정
                domain.DomainType = DomainType.Primary;
                domain.UpdatedAt = DateTime.UtcNow;
                domain.UpdatedByConnectedId = setByConnectedId;
                await _domainRepository.UpdateAsync(domain);

                await _unitOfWork.SaveChangesAsync();

                var dto = _mapper.Map<OrganizationDomainDto>(domain);

                _logger.LogInformation(
                    "Domain {Domain} set as primary for organization {OrganizationId} by {SetBy}",
                    domain.Domain, domain.OrganizationId, setByConnectedId);

                return ServiceResult<OrganizationDomainDto>.Success(
                    dto,
                    "Domain set as primary successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting domain {DomainId} as primary", domainId);
                return ServiceResult<OrganizationDomainDto>.Failure(
                    "Failed to set domain as primary",
                    "SET_PRIMARY_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 도메인 이름 정규화
        /// </summary>
        private string NormalizeDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentException("Domain cannot be empty", nameof(domain));
            }

            // 소문자 변환, 공백 제거
            domain = domain.Trim().ToLowerInvariant();

            // http://, https:// 제거
            domain = domain.Replace("https://", "").Replace("http://", "");

            // 마지막 슬래시 제거
            domain = domain.TrimEnd('/');

            // www. 제거는 선택적 (비즈니스 요구사항에 따라)
            // domain = domain.StartsWith("www.") ? domain.Substring(4) : domain;

            return domain;
        }

        /// <summary>
        /// 검증 토큰 생성
        /// </summary>
        private string GenerateVerificationToken()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[VERIFICATION_TOKEN_LENGTH];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes)
                .Replace("+", "")
                .Replace("/", "")
                .Replace("=", "")
                .Substring(0, VERIFICATION_TOKEN_LENGTH);
        }

        /// <summary>
        /// 도메인 생성 요청 검증
        /// </summary>
        private async Task<ServiceResult> ValidateCreateRequest(CreateOrganizationDomainRequest request)
        {
            // 조직 존재 확인
            var organization = await _organizationRepository.GetByIdAsync(request.OrganizationId);
            if (organization == null)
            {
                return ServiceResult.Failure("Organization not found", "ORGANIZATION_NOT_FOUND");
            }

            // 도메인 형식 검증
            if (!IsValidDomainFormat(request.DomainName))
            {
                return ServiceResult.Failure("Invalid domain format", "INVALID_DOMAIN_FORMAT");
            }

            // 예약된 도메인 확인 (예: localhost, example.com 등)
            if (IsReservedDomain(request.DomainName))
            {
                return ServiceResult.Failure("Domain is reserved and cannot be used", "RESERVED_DOMAIN");
            }

            return ServiceResult.Success();
        }

        /// <summary>
        /// 도메인 형식 검증
        /// </summary>
        private bool IsValidDomainFormat(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            // 기본적인 도메인 형식 검증
            var domainPattern = @"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$";
            return System.Text.RegularExpressions.Regex.IsMatch(
                domain.ToLowerInvariant(),
                domainPattern);
        }

        /// <summary>
        /// 예약된 도메인 확인
        /// </summary>
        private bool IsReservedDomain(string domain)
        {
            var reserved = new[]
            {
                "localhost",
                "example.com",
                "example.org",
                "example.net",
                "test.com",
                "authive.com"  // 자체 도메인
            };

            domain = domain.ToLowerInvariant();
            return reserved.Any(r => domain.Equals(r) || domain.EndsWith($".{r}"));
        }

        #endregion
    }
}