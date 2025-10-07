// Providers/Authentication/PasetoAuthenticationProvider.cs
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Providers;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Providers.Authentication
{
    /// <summary>
    /// PASETO 기반 인증 제공자 - AuthHive v15
    /// 내부 인증(Password, API Key) 처리
    /// </summary>
    public class PasetoAuthenticationProvider : IAuthenticationProvider
    {
        private readonly PasetoTokenProvider _tokenProvider;
        private readonly IPasswordProvider _passwordProvider;
        private readonly ILogger<PasetoAuthenticationProvider> _logger;
        private readonly IDistributedCache _cache;
        private readonly AuthDbContext _context;
        private readonly IAuthenticationAttemptLogRepository _attemptLogRepository;
        private readonly IMfaService _mfaService;
        private readonly IApiKeyProvider _apiKeyProvider;

        public string ProviderName => "PASETO";
        public string ProviderType => "Internal";

        public PasetoAuthenticationProvider(
            PasetoTokenProvider tokenProvider,
            IPasswordProvider passwordProvider,
            ILogger<PasetoAuthenticationProvider> logger,
            IDistributedCache cache,
            AuthDbContext context,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            IMfaService mfaService,
            IApiKeyProvider apiKeyProvider)
        {
            _tokenProvider = tokenProvider;
            _passwordProvider = passwordProvider;
            _logger = logger;
            _cache = cache;
            _context = context;
            _attemptLogRepository = attemptLogRepository;
            _mfaService = mfaService;
            _apiKeyProvider = apiKeyProvider;
        }

        public async Task<ServiceResult<AuthenticationOutcome>> AuthenticateAsync(
            AuthenticationRequest request)
        {
            try
            {
                // Rate limiting
                if (!await CheckRateLimitAsync(request.IpAddress))
                {
                    await LogFailedAttemptAsync(request, AuthenticationResult.TooManyAttempts);
                    return ServiceResult<AuthenticationOutcome>.Failure("Too many attempts. Please try again later.");
                }

                // 인증 방식별 처리
                var result = request.Method switch
                {
                    AuthenticationMethod.Password => await AuthenticatePasswordAsync(request),
                    AuthenticationMethod.ApiKey => await AuthenticateApiKeyAsync(request),
                    _ => ServiceResult<AuthenticationOutcome>.Failure($"Unsupported authentication method: {request.Method}")
                };

                // 로깅
                await LogAuthenticationAttemptAsync(request, result);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed for {Method}", request.Method);
                return ServiceResult<AuthenticationOutcome>.Failure("Authentication error occurred");
            }
        }

        private async Task<ServiceResult<AuthenticationOutcome>> AuthenticatePasswordAsync(
            AuthenticationRequest request)
        {
            // UserProfile과 User 조회
            var userProfile = await _context.UserProfiles
                .Include(up => up.User)
                .ThenInclude(u => u.ConnectedIds)
                .FirstOrDefaultAsync(up =>
                    up.User.Username == request.Username ||
                    up.User.Email == request.Username);

            if (userProfile == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Invalid credentials");
            }

            var user = userProfile.User;

            // 비밀번호 검증
            var passwordHash = user.PasswordHash ?? string.Empty;
            if (!await _passwordProvider.VerifyPasswordAsync(request.Password ?? "", passwordHash))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Invalid credentials");
            }

            // MFA 확인
            if (user.TwoFactorEnabled && string.IsNullOrEmpty(request.MfaCode))
            {
                var mfaMethods = new List<string> { user.TwoFactorMethod?.ToString() ?? MfaMethod.Totp.ToString() };

                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = false,
                    RequiresMfa = true,
                    UserId = user.Id,
                    MfaMethods = mfaMethods,
                    Message = "MFA verification required"
                });
            }


            // MFA 코드 검증 부분 수정
            if (user.TwoFactorEnabled && !string.IsNullOrEmpty(request.MfaCode))
            {
                MfaMethod mfaMethod = MfaMethod.None;
                if (!string.IsNullOrEmpty(request.MfaMethod))
                {
                    Enum.TryParse<MfaMethod>(request.MfaMethod, out mfaMethod);
                }

                var verifyResult = await _mfaService.VerifyMfaCodeAsync(
                    user.Id,
                    request.MfaCode,
                    mfaMethod,
                    null);

                // null 체크 추가
                if (!verifyResult.IsSuccess || verifyResult.Data == null || !verifyResult.Data.Success)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid MFA code");
                }
            }

            // ConnectedId 처리
            ConnectedId? connectedId = null;
            if (request.OrganizationId.HasValue)
            {
                connectedId = user.ConnectedIds
                    .FirstOrDefault(c => c.OrganizationId == request.OrganizationId.Value);

                if (connectedId == null)
                {
                    connectedId = new ConnectedId
                    {
                        UserId = user.Id,
                        OrganizationId = request.OrganizationId.Value,
                        Status = ConnectedIdStatus.Active,
                        MembershipType = MembershipType.Member,
                        Provider = ProviderName,
                        JoinedAt = DateTime.UtcNow,
                        LastActiveAt = DateTime.UtcNow
                    };
                    await _context.ConnectedIds.AddAsync(connectedId);
                    await _context.SaveChangesAsync();
                }
            }

            // 세션 생성
            var session = new SessionEntity
            {
                UserId = user.Id,
                OrganizationId = request.OrganizationId,
                ApplicationId = request.ApplicationId,
                ConnectedId = connectedId?.Id,
                SessionToken = Guid.NewGuid().ToString(),
                SessionType = SessionType.Web,
                Level = request.OrganizationId.HasValue ? SessionLevel.Organization : SessionLevel.Global,
                Status = SessionStatus.Active,
                IpAddress = request.IpAddress,
                UserAgent = request.UserAgent,
                ExpiresAt = DateTime.UtcNow.AddHours(8),
                LastActivityAt = DateTime.UtcNow
            };

            await _context.Sessions.AddAsync(session);
            await _context.SaveChangesAsync();

            // 토큰 생성
            var claims = new List<Claim>
            {
                new Claim("session_id", session.Id.ToString()),
                new Claim("user_id", user.Id.ToString())
            };

            if (request.OrganizationId.HasValue)
            {
                claims.Add(new Claim("org_id", request.OrganizationId.Value.ToString()));
            }

            var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                user.Id,
                connectedId?.Id ?? Guid.Empty,
                claims);

            if (!tokenResult.IsSuccess || tokenResult.Data == null)
            {
                _context.Sessions.Remove(session);
                await _context.SaveChangesAsync();
                return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed");
            }

            var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

            // 세션에 토큰 정보 저장
            session.TokenId = tokenResult.Data.AccessToken;
            session.TokenExpiresAt = tokenResult.Data.ExpiresAt;
            await _context.SaveChangesAsync();

            return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
            {
                Success = true,
                UserId = user.Id,
                ConnectedId = connectedId?.Id,
                SessionId = session.Id,
                AccessToken = tokenResult.Data.AccessToken,
                RefreshToken = refreshToken.Data,
                ExpiresAt = tokenResult.Data.ExpiresAt,
                OrganizationId = request.OrganizationId,
                ApplicationId = request.ApplicationId,
                AuthenticationMethod = request.Method.ToString(),
                MfaVerified = user.TwoFactorEnabled && !string.IsNullOrEmpty(request.MfaCode)
            });
        }

        private async Task<ServiceResult<AuthenticationOutcome>> AuthenticateApiKeyAsync(
            AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.ApiKey))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("API key is required");
            }

            var validationResult = await _apiKeyProvider.ValidateApiKeyAsync(request.ApiKey);
            if (!validationResult.IsSuccess || validationResult.Data == null || !validationResult.Data.IsValid)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Invalid API key");
            }

            return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
            {
                Success = true,
                ApplicationId = validationResult.Data.ApplicationId,
                OrganizationId = validationResult.Data.OrganizationId,
                AuthenticationMethod = AuthenticationMethod.ApiKey.ToString()
            });
        }

        public async Task<ServiceResult<bool>> ValidateAsync(string token)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token);
            return ServiceResult<bool>.Success(result.IsSuccess);
        }

        public async Task<ServiceResult> RevokeAsync(string token)
        {
            var session = await _context.Sessions
                .FirstOrDefaultAsync(s => s.TokenId == token && s.Status == SessionStatus.Active);

            if (session != null)
            {
                session.Status = SessionStatus.LoggedOut;
                session.EndedAt = DateTime.UtcNow;
                session.EndReason = SessionEndReason.UserLogout;
                await _context.SaveChangesAsync();

                await _cache.RemoveAsync($"session:{session.Id}");
            }

            return ServiceResult.Success();
        }

        public Task<bool> IsEnabledAsync()
        {
            return Task.FromResult(true);
        }

        private async Task<bool> CheckRateLimitAsync(string? ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return true;

            var key = $"auth_rate:{ipAddress}";
            var count = await _cache.GetStringAsync(key);

            if (!string.IsNullOrEmpty(count) && int.Parse(count) >= 10)
                return false;

            await _cache.SetStringAsync(key,
                string.IsNullOrEmpty(count) ? "1" : (int.Parse(count) + 1).ToString(),
                new DistributedCacheEntryOptions { SlidingExpiration = TimeSpan.FromMinutes(15) });

            return true;
        }

        private async Task LogAuthenticationAttemptAsync(
            AuthenticationRequest request,
            ServiceResult<AuthenticationOutcome> result)
        {
            var attemptLog = new AuthenticationAttemptLog
            {
                Username = request.Username,
                UserId = result.Data?.UserId,
                Method = request.Method,
                Provider = ProviderName,
                IpAddress = request.IpAddress ?? "Unknown",
                UserAgent = request.UserAgent,
                IsSuccess = result.IsSuccess && result.Data?.Success == true,
                AttemptedAt = DateTime.UtcNow,
                ApplicationId = request.ApplicationId,
                SessionId = result.Data?.SessionId,
                FailureReason = !result.IsSuccess ?
                    (result.Data?.RequiresMfa == true ? AuthenticationResult.MfaRequired : AuthenticationResult.InvalidCredentials)
                    : null
            };

            // OrganizationId가 있는 경우에만 설정
            if (request.OrganizationId.HasValue)
            {
                attemptLog.OrganizationId = request.OrganizationId.Value;
            }

            await _attemptLogRepository.AddAsync(attemptLog);
        }
        private async Task LogFailedAttemptAsync(
            AuthenticationRequest request,
            AuthenticationResult reason)
        {
            var attemptLog = new AuthenticationAttemptLog
            {
                Username = request.Username,
                Method = request.Method,
                Provider = ProviderName,
                IpAddress = request.IpAddress ?? "Unknown",
                UserAgent = request.UserAgent,
                IsSuccess = false,
                FailureReason = reason,
                AttemptedAt = DateTime.UtcNow,
                ApplicationId = request.ApplicationId
            };

            // OrganizationId가 있는 경우에만 설정
            if (request.OrganizationId.HasValue)
            {
                attemptLog.OrganizationId = request.OrganizationId.Value;
            }

            await _attemptLogRepository.AddAsync(attemptLog);
        }
    }
}