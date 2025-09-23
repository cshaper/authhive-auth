// Providers/Authentication/CertificateAuthenticationProvider.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Providers.Authentication
{
    /// <summary>
    /// 인증서 기반 인증 제공자 - AuthHive v15
    /// X.509 클라이언트 인증서를 사용한 강력한 인증
    /// </summary>
    public class CertificateAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IConfiguration _configuration;
        private readonly ICertificateValidationService _certificateValidationService;
        
        public override string ProviderName => "Certificate";
        public override string ProviderType => "Internal";

        public CertificateAuthenticationProvider(
            ILogger<CertificateAuthenticationProvider> logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context,
            ITokenProvider tokenProvider,
            IConfiguration configuration,
            ICertificateValidationService certificateValidationService)
            : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
        {
            _tokenProvider = tokenProvider;
            _configuration = configuration;
            _certificateValidationService = certificateValidationService;
        }

        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.ClientCertificate))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Client certificate is required");
                }

                // 인증서 파싱
                X509Certificate2 certificate;
                try
                {
                    var certBytes = Convert.FromBase64String(request.ClientCertificate);
                    certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(certBytes);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to parse client certificate");
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid certificate format");
                }

                // 인증서 검증
                var validationResult = await _certificateValidationService.ValidateCertificateAsync(certificate);
                if (!validationResult.IsSuccess || !validationResult.Data)
                {
                    _logger.LogWarning("Certificate validation failed for subject: {Subject}", certificate.Subject);
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        validationResult.ErrorMessage ?? "Certificate validation failed");
                }

                // 인증서로 ClientCertificate 엔티티 찾기
                var clientCert = await _context.ClientCertificates
                    .Include(cc => cc.ConnectedId)
                        .ThenInclude(ci => ci.User)
                    .FirstOrDefaultAsync(cc => 
                        cc.Thumbprint == certificate.Thumbprint &&
                        cc.SerialNumber == certificate.SerialNumber &&
                        cc.IsActive &&
                        !cc.IsRevoked);

                if (clientCert == null)
                {
                    // 인증서 자동 등록 (설정에 따라)
                    if (_configuration.GetValue<bool>("Certificate:AllowAutoRegistration"))
                    {
                        clientCert = await RegisterCertificateAsync(certificate, request.OrganizationId);
                        if (clientCert == null)
                        {
                            return ServiceResult<AuthenticationOutcome>.Failure("Failed to register certificate");
                        }
                    }
                    else
                    {
                        return ServiceResult<AuthenticationOutcome>.Failure("Certificate not registered");
                    }
                }

                // 인증서 만료 확인
                if (clientCert.NotAfter < DateTime.UtcNow)
                {
                    clientCert.IsActive = false;
                    await _context.SaveChangesAsync();
                    return ServiceResult<AuthenticationOutcome>.Failure("Certificate has expired");
                }

                // 사용 정보 업데이트
                clientCert.LastUsedAt = DateTime.UtcNow;
                clientCert.UseCount++;
                await _context.SaveChangesAsync();

                var connectedId = clientCert.ConnectedId;
                var user = connectedId.User;
                var organizationId = connectedId.OrganizationId;

                // 세션 생성
                var sessionResult = await _sessionService.CreateSessionAsync(
                    new Core.Models.Auth.Session.Requests.CreateSessionRequest
                    {
                        ConnectedId = connectedId.Id,
                        OrganizationId = organizationId,
                        SessionType = SessionType.Web,
                        IPAddress = request.IpAddress,
                        UserAgent = request.UserAgent,
                        DeviceInfo = request.DeviceInfo?.DeviceId,
                        OperatingSystem = request.DeviceInfo?.OperatingSystem,
                        Browser = request.DeviceInfo?.Browser,
                        Location = request.DeviceInfo?.Location,
                        ExpiresAt = DateTime.UtcNow.AddHours(24),
                        InitialStatus = SessionStatus.Active,
                        InitialRiskScore = 0,
                        Metadata = System.Text.Json.JsonSerializer.Serialize(new
                        {
                            AuthenticationMethod = AuthenticationMethod.Certificate.ToString(),
                            Provider = "Certificate",
                            ApplicationId = request.ApplicationId,
                            CertificateThumbprint = certificate.Thumbprint,
                            CertificateSubject = certificate.Subject,
                            SecurityLevel = "VeryHigh"
                        })
                    });

                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed");
                }

                // 토큰 생성
                var claims = new List<Claim>
                {
                    new Claim("user_id", user.Id.ToString()),
                    new Claim("connected_id", connectedId.Id.ToString()),
                    new Claim("org_id", organizationId.ToString()),
                    new Claim("auth_method", "certificate"),
                    new Claim("cert_thumbprint", certificate.Thumbprint),
                    new Claim("cert_subject", certificate.Subject),
                    new Claim("session_id", (sessionResult.Data?.SessionId.ToString()) ?? string.Empty)
                };

                var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                    user.Id,
                    connectedId.Id,
                    claims);

                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed");
                }

                var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedId.Id,
                    SessionId = sessionResult.Data?.SessionId ?? Guid.Empty,
                    AccessToken = tokenResult.Data?.AccessToken,
                    RefreshToken = refreshToken.Data,
                    ExpiresAt = tokenResult.Data?.ExpiresAt,
                    OrganizationId = organizationId,
                    ApplicationId = request.ApplicationId,
                    AuthenticationMethod = AuthenticationMethod.Certificate.ToString(),
                    AuthenticationStrength = AuthenticationStrength.VeryHigh
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate authentication failed");
                return ServiceResult<AuthenticationOutcome>.Failure("Authentication failed");
            }
        }

        private async Task<ClientCertificate?> RegisterCertificateAsync(
            X509Certificate2 certificate, 
            Guid? requestOrgId)
        {
            // 인증서에서 이메일 추출
            var email = ExtractEmailFromCertificate(certificate);
            var cn = ExtractCommonNameFromCertificate(certificate);

            if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(cn))
            {
                _logger.LogWarning("Certificate has no email or CN");
                return null;
            }

            // UserProfile로 사용자 찾기
            UserProfile? userProfile = null;
            if (!string.IsNullOrEmpty(email))
            {
                userProfile = await _context.UserProfiles
                    .Include(up => up.User)
                    .FirstOrDefaultAsync(up => up.User.Email == email);
            }

            if (userProfile == null && !string.IsNullOrEmpty(cn))
            {
                userProfile = await _context.UserProfiles
                    .Include(up => up.User)
                    .FirstOrDefaultAsync(up => up.User.Username == cn);
            }

            if (userProfile == null)
            {
                _logger.LogWarning("No user found for certificate");
                return null;
            }

            var user = userProfile.User;
            var organizationId = requestOrgId ?? 
                _configuration.GetValue<Guid>("Auth:GlobalOrganizationId", 
                    Guid.Parse("00000000-0000-0000-0000-000000000001"));

            // ConnectedId 찾기 또는 생성
            var connectedIdResponses = await _connectedIdService.GetByUserAsync(user.Id);
            Guid? connectedIdGuid = null;
            
            if (connectedIdResponses.IsSuccess && connectedIdResponses.Data != null)
            {
                var existingConnectedId = connectedIdResponses.Data
                    .FirstOrDefault(c => c.OrganizationId == organizationId);
                if (existingConnectedId != null)
                {
                    connectedIdGuid = existingConnectedId.Id;
                }
            }

            if (connectedIdGuid == null)
            {
                var createRequest = new CreateConnectedIdRequest
                {
                    UserId = user.Id,
                    OrganizationId = organizationId,
                    ApplicationId = null
                };

                var createResult = await _connectedIdService.CreateAsync(createRequest);
                if (!createResult.IsSuccess || createResult.Data == null)
                {
                    return null;
                }

                connectedIdGuid = createResult.Data.Id;
            }

            // ConnectedId 엔티티 조회 (ClientCertificate와 연결하기 위해)
            var connectedId = await _context.ConnectedIds
                .Include(ci => ci.User)
                .FirstOrDefaultAsync(ci => ci.Id == connectedIdGuid.Value);

            if (connectedId == null)
            {
                return null;
            }

            // ClientCertificate 엔티티 생성
            var clientCert = new ClientCertificate
            {
                Id = Guid.NewGuid(),
                ConnectedIdId = connectedId.Id,
                ConnectedId = connectedId,
                Subject = certificate.Subject,
                Issuer = certificate.Issuer,
                SerialNumber = certificate.SerialNumber,
                Thumbprint = certificate.Thumbprint,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                CertificateData = certificate.RawData,
                IsActive = true,
                Purpose = "ClientAuthentication",
                UseCount = 0
            };

            await _context.ClientCertificates.AddAsync(clientCert);
            await _context.SaveChangesAsync();

            return clientCert;
        }

        private string? ExtractEmailFromCertificate(X509Certificate2 certificate)
        {
            var subject = certificate.Subject;
            if (subject.Contains("E="))
            {
                var emailStart = subject.IndexOf("E=") + 2;
                var emailEnd = subject.IndexOf(",", emailStart);
                if (emailEnd == -1) emailEnd = subject.Length;
                return subject.Substring(emailStart, emailEnd - emailStart).Trim();
            }
            return null;
        }

        private string? ExtractCommonNameFromCertificate(X509Certificate2 certificate)
        {
            var subject = certificate.Subject;
            if (subject.Contains("CN="))
            {
                var cnStart = subject.IndexOf("CN=") + 3;
                var cnEnd = subject.IndexOf(",", cnStart);
                if (cnEnd == -1) cnEnd = subject.Length;
                return subject.Substring(cnStart, cnEnd - cnStart).Trim();
            }
            return null;
        }

        protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request)
        {
            // Certificate는 인증서로 인증하므로 이 메서드는 사용하지 않음
            return Task.FromResult<UserProfile?>(null);
        }

        public override async Task<ServiceResult<bool>> ValidateAsync(string token)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token);
            return ServiceResult<bool>.Success(result.IsSuccess);
        }

        public override async Task<ServiceResult> RevokeAsync(string tokenOrSessionId)
        {
            // Try to parse as GUID (session ID) first
            if (Guid.TryParse(tokenOrSessionId, out var sessionId))
            {
                var session = await _context.Sessions
                    .FirstOrDefaultAsync(s => s.Id == sessionId && s.Status == SessionStatus.Active);

                if (session != null)
                {
                    session.Status = SessionStatus.LoggedOut;
                    session.EndedAt = DateTime.UtcNow;
                    session.EndReason = SessionEndReason.UserLogout;
                    await _context.SaveChangesAsync();
                    return ServiceResult.Success();
                }
            }
            
            // Otherwise try as token
            var sessionByToken = await _context.Sessions
                .FirstOrDefaultAsync(s => s.TokenId == tokenOrSessionId && s.Status == SessionStatus.Active);

            if (sessionByToken != null)
            {
                sessionByToken.Status = SessionStatus.LoggedOut;
                sessionByToken.EndedAt = DateTime.UtcNow;
                sessionByToken.EndReason = SessionEndReason.UserLogout;
                await _context.SaveChangesAsync();
            }

            return ServiceResult.Success();
        }

        public override async Task<bool> IsEnabledAsync()
        {
            var isEnabled = _configuration.GetValue<bool>("Certificate:Enabled");
            return await Task.FromResult(isEnabled);
        }
    }
}

