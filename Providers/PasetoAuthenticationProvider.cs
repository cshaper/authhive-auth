using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.User.Repository; // AuthConstants 사용을 위해 추가

namespace AuthHive.Auth.Providers.Authentication
{
    /// <summary>
    /// PASETO 기반 인증 제공자 - AuthHive v16 Refactored
    /// IUnitOfWork, Repository, ICacheService를 사용하여 v16 아키텍처 원칙을 준수합니다.
    /// </summary>
    public class PasetoAuthenticationProvider : IAuthenticationProvider
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IPasswordProvider _passwordProvider;
        private readonly IApiKeyProvider _apiKeyProvider;
        private readonly IMfaService _mfaService;
        private readonly ILogger<PasetoAuthenticationProvider> _logger;

        // v16 아키텍처 의존성
        private readonly ICacheService _cacheService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IUserRepository _userRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IAuthenticationAttemptLogRepository _attemptLogRepository;

        public string ProviderName => "PASETO";
        public string ProviderType => "Internal";

        public PasetoAuthenticationProvider(
            // 기존 의존성
            ITokenProvider tokenProvider,
            IPasswordProvider passwordProvider,
            IApiKeyProvider apiKeyProvider,
            IMfaService mfaService,
            ILogger<PasetoAuthenticationProvider> logger,
            // v16 신규/변경 의존성
            ICacheService cacheService,
            IUnitOfWork unitOfWork,
            IUserRepository userRepository,
            ISessionRepository sessionRepository,
            IConnectedIdRepository connectedIdRepository,
            IAuthenticationAttemptLogRepository attemptLogRepository)
        {
            _tokenProvider = tokenProvider;
            _passwordProvider = passwordProvider;
            _apiKeyProvider = apiKeyProvider;
            _mfaService = mfaService;
            _logger = logger;
            _cacheService = cacheService;
            _unitOfWork = unitOfWork;
            _userRepository = userRepository;
            _sessionRepository = sessionRepository;
            _connectedIdRepository = connectedIdRepository;
            _attemptLogRepository = attemptLogRepository;
        }

        public async Task<ServiceResult<AuthenticationOutcome>> AuthenticateAsync(
            AuthenticationRequest request, CancellationToken cancellationToken = default)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!await CheckRateLimitAsync(request.IpAddress, cancellationToken))
                {
                    await LogFailedAttemptAsync(request, AuthenticationResult.TooManyAttempts, cancellationToken);
                    return ServiceResult<AuthenticationOutcome>.Failure("Too many attempts. Please try again later.");
                }

                var result = request.Method switch
                {
                    AuthenticationMethod.Password => await AuthenticatePasswordAsync(request, cancellationToken),
                    AuthenticationMethod.ApiKey => await AuthenticateApiKeyAsync(request, cancellationToken),
                    _ => ServiceResult<AuthenticationOutcome>.Failure($"Unsupported authentication method: {request.Method}")
                };

                await LogAuthenticationAttemptAsync(request, result, cancellationToken);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed for {Method}", request.Method);
                return ServiceResult<AuthenticationOutcome>.Failure("Authentication error occurred");
            }
        }

        private async Task<ServiceResult<AuthenticationOutcome>> AuthenticatePasswordAsync(
              AuthenticationRequest request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(request.Username))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Invalid credentials");
            }

            var user = await _userRepository.GetByUsernameAsync(request.Username, cancellationToken: cancellationToken);
            if (user == null)
            {
                user = await _userRepository.GetByEmailAsync(request.Username, cancellationToken: cancellationToken);
            }

            if (user == null)
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Invalid credentials");
            }

            var passwordHash = user.PasswordHash ?? string.Empty;
            if (!await _passwordProvider.VerifyPasswordAsync(request.Password ?? "", passwordHash, cancellationToken))
            {
                return ServiceResult<AuthenticationOutcome>.Failure("Invalid credentials");
            }

            // MFA 확인
            if (user.TwoFactorEnabled)
            {
                if (string.IsNullOrEmpty(request.MfaCode))
                {
                    return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                    {
                        Success = false,
                        RequiresMfa = true,
                        UserId = user.Id,
                        MfaMethods = new List<string> { user.TwoFactorMethod ?? MfaMethod.Totp.ToString() },
                        Message = "MFA verification required"
                    });
                }

                // 수정: user.TwoFactorMethod (string)를 MfaMethod (enum)으로 변환합니다.
                if (!Enum.TryParse<MfaMethod>(user.TwoFactorMethod, true, out var mfaMethodEnum))
                {
                    // 파싱 실패 시 기본값(Totp)으로 설정
                    mfaMethodEnum = MfaMethod.Totp;
                }

                var verifyResult = await _mfaService.VerifyMfaCodeAsync(user.Id, request.MfaCode, mfaMethodEnum, null, cancellationToken);
                if (!verifyResult.IsSuccess || verifyResult.Data == null || !verifyResult.Data.Success)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid MFA code");
                }
            }

            // ConnectedId 처리
            ConnectedId? connectedId = null;
            if (request.OrganizationId.HasValue)
            {
                connectedId = user.ConnectedIds.FirstOrDefault(c => c.OrganizationId == request.OrganizationId.Value);
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
                    await _connectedIdRepository.AddAsync(connectedId, cancellationToken);
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
            await _sessionRepository.AddAsync(session, cancellationToken);

            // 토큰 생성을 위한 클레임 구성
            var claims = new List<Claim> { new Claim(AuthConstants.ClaimTypes.SessionId, session.Id.ToString()) };
            if (request.OrganizationId.HasValue)
            {
                claims.Add(new Claim(AuthConstants.ClaimTypes.OrganizationId, request.OrganizationId.Value.ToString()));
            }

            var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, connectedId?.Id ?? Guid.Empty, claims, cancellationToken);
            if (!tokenResult.IsSuccess || tokenResult.Data == null)
            {
                _logger.LogError("Token generation failed for user {UserId}. Session will not be persisted.", user.Id);
                return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed");
            }

            var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(user.Id, cancellationToken);

            // 최종적으로 DB에 변경사항 저장
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
            {
                Success = true,
                UserId = user.Id,
                ConnectedId = connectedId?.Id,
                SessionId = session.Id,
                AccessToken = tokenResult.Data.AccessToken,
                RefreshToken = refreshTokenResult.Data,
                ExpiresAt = tokenResult.Data.ExpiresAt,
                OrganizationId = request.OrganizationId,
                ApplicationId = request.ApplicationId,
                AuthenticationMethod = request.Method.ToString(),
                MfaVerified = user.TwoFactorEnabled && !string.IsNullOrEmpty(request.MfaCode)
            });
        }
        private async Task<ServiceResult<AuthenticationOutcome>> AuthenticateApiKeyAsync(AuthenticationRequest request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(request.ApiKey))
                return ServiceResult<AuthenticationOutcome>.Failure("API key is required");

            // 수정: ValidateApiKeyAsync 메서드 시그니처에 맞게 IpAddress와 UserAgent를 전달합니다.
            var validationResult = await _apiKeyProvider.ValidateApiKeyAsync(
                request.ApiKey,
                request.IpAddress,
                request.UserAgent,
                cancellationToken);

            if (!validationResult.IsSuccess || validationResult.Data == null || !validationResult.Data.IsValid)
                return ServiceResult<AuthenticationOutcome>.Failure("Invalid API key");

            // API Key 인증 성공 시에는 토큰을 발급하지 않고, 인증 컨텍스트만 반환합니다.
            return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
            {
                Success = true,
                ApplicationId = validationResult.Data.ApplicationId,
                OrganizationId = validationResult.Data.OrganizationId,
                AuthenticationMethod = AuthenticationMethod.ApiKey.ToString()
            });
        }

        public async Task<ServiceResult<bool>> ValidateAsync(string token, CancellationToken cancellationToken = default)
        {
            var result = await _tokenProvider.ValidateAccessTokenAsync(token, cancellationToken);

            // 수정: result의 성공 여부에 따라 Success() 또는 Failure() 메서드를 호출합니다.
            if (result.IsSuccess)
            {
                return ServiceResult<bool>.Success(true);
            }
            else
            {
                return ServiceResult<bool>.Failure(result.ErrorMessage ?? "Token validation failed.", result.ErrorCode);
            }
        }

        public async Task<ServiceResult> RevokeAsync(string token, CancellationToken cancellationToken = default)
        {
            // 토큰 자체를 무효화하는 대신, 토큰과 연결된 세션을 무효화합니다.
            // PASETO는 상태 비저장 토큰이므로, 상태 저장이 필요한 폐기는 DB(세션)에서 처리해야 합니다.
            var principalResult = await _tokenProvider.ValidateAccessTokenAsync(token, cancellationToken);
            if (!principalResult.IsSuccess || principalResult.Data == null)
                return ServiceResult.Failure("Invalid token.");

            var sessionIdClaim = principalResult.Data.Claims.FirstOrDefault(c => c.Type == AuthConstants.ClaimTypes.SessionId);
            if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
                return ServiceResult.Failure("Session ID not found in token.");

            var session = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken);
            if (session != null && session.Status == SessionStatus.Active)
            {
                session.Status = SessionStatus.LoggedOut;
                session.EndedAt = DateTime.UtcNow;
                session.EndReason = SessionEndReason.UserLogout;

                await _sessionRepository.UpdateAsync(session, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 세션 관련 캐시 무효화
                await _cacheService.RemoveAsync($"session:{session.Id}", cancellationToken);
            }

            return ServiceResult.Success();
        }

        public Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true); // 이 제공자는 항상 활성화 상태입니다.
        }

        // --- Private Helper Methods ---

        private async Task<bool> CheckRateLimitAsync(string? ipAddress, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(ipAddress)) return true;

            var key = $"auth_rate:{ipAddress}";
            var countStr = await _cacheService.GetAsync<string>(key, cancellationToken);

            int.TryParse(countStr, out var count);
            if (count >= 10) // TODO: 설정에서 값 가져오기
                return false;

            await _cacheService.SetAsync(key, (count + 1).ToString(), TimeSpan.FromMinutes(15), cancellationToken);
            return true;
        }

        private async Task LogAuthenticationAttemptAsync(AuthenticationRequest request, ServiceResult<AuthenticationOutcome> result, CancellationToken cancellationToken)
        {
            var isSuccess = result.IsSuccess && (result.Data?.Success ?? false);
            var failureReason = !isSuccess
                ? (result.Data?.RequiresMfa == true ? AuthenticationResult.MfaRequired : AuthenticationResult.InvalidCredentials)
                : (AuthenticationResult?)null;

            await LogAttemptInternalAsync(request, isSuccess, failureReason, result.Data?.UserId, result.Data?.SessionId, cancellationToken);
        }

        private async Task LogFailedAttemptAsync(AuthenticationRequest request, AuthenticationResult reason, CancellationToken cancellationToken)
        {
            await LogAttemptInternalAsync(request, false, reason, null, null, cancellationToken);
        }

        private async Task LogAttemptInternalAsync(AuthenticationRequest request, bool isSuccess, AuthenticationResult? reason, Guid? userId, Guid? sessionId, CancellationToken cancellationToken)
        {
            try
            {
                var attemptLog = new AuthenticationAttemptLog
                {
                    Username = request.Username,
                    UserId = userId,
                    Method = request.Method,
                    Provider = ProviderName,
                    IpAddress = request.IpAddress ?? "Unknown",
                    UserAgent = request.UserAgent,
                    IsSuccess = isSuccess,
                    FailureReason = reason,
                    AttemptedAt = DateTime.UtcNow,
                    ApplicationId = request.ApplicationId,
                    OrganizationId = request.OrganizationId.GetValueOrDefault(),
                    SessionId = sessionId
                };
                await _attemptLogRepository.AddAsync(attemptLog, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log authentication attempt for user: {Username}", request.Username);
                // 로깅 실패가 전체 인증 흐름을 중단시켜서는 안 됩니다.
            }
        }
    }
}
