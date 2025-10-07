using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Auth.Providers;
using AuthHive.Auth.Providers.Authentication;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// 인증 관리자 구현 - AuthHive v15
    /// 모든 인증 프로바이더를 통합 관리하고 적절한 프로바이더로 라우팅합니다.
    /// </summary>
    public class AuthenticationManager : IAuthenticationManager
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<AuthenticationManager> _logger;
        private readonly ITokenProvider _tokenProvider;
        private readonly ISessionService _sessionService;
        private readonly Dictionary<AuthenticationMethod, Type> _providerMapping;
        private readonly IAuthenticationAttemptLogRepository _authAttemptRepository;
        private readonly ICacheService? _cacheService; // 선택적
        private readonly IAuditService _auditService; // 선택적

        public AuthenticationManager(
            IServiceProvider serviceProvider,
            ILogger<AuthenticationManager> logger,
            IAuditService auditService,
            ITokenProvider tokenProvider,
            ISessionService sessionService,
            IAuthenticationAttemptLogRepository authAttemptRepository)
        {
            _serviceProvider = serviceProvider;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _tokenProvider = tokenProvider;
            _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
            _authAttemptRepository = authAttemptRepository;
            // 인증 방법과 Provider 매핑
            _providerMapping = new Dictionary<AuthenticationMethod, Type>
            {
                [AuthenticationMethod.Password] = typeof(PasetoAuthenticationProvider),
                [AuthenticationMethod.ApiKey] = typeof(PasetoAuthenticationProvider),
                [AuthenticationMethod.OAuth] = typeof(OAuthAuthenticationProvider),
                [AuthenticationMethod.SocialLogin] = typeof(SocialAuthenticationProvider),
                [AuthenticationMethod.SSO] = typeof(SsoAuthenticationProvider),
                [AuthenticationMethod.JWT] = typeof(PasetoAuthenticationProvider),
                [AuthenticationMethod.MagicLink] = typeof(MagicLinkAuthenticationProvider),
                [AuthenticationMethod.Passkey] = typeof(PasskeyAuthenticationProvider),
                [AuthenticationMethod.Certificate] = typeof(CertificateAuthenticationProvider),
                [AuthenticationMethod.Biometric] = typeof(BiometricAuthenticationProvider)
            };
        }

        public async Task<ServiceResult<AuthenticationOutcome>> AuthenticateAsync(
            AuthenticationRequest request)
        {
            try
            {
                _logger.LogInformation(
                    "Processing authentication request for method: {Method}, Organization: {OrgId}",
                    request.Method, request.OrganizationId);

                // 적절한 Provider 선택
                var provider = GetProvider(request.Method);
                if (provider == null)
                {
                    _logger.LogWarning("No provider found for authentication method: {Method}", request.Method);
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        $"Authentication method {request.Method} is not supported");
                }

                // Provider가 활성화되어 있는지 확인
                if (!await provider.IsEnabledAsync())
                {
                    _logger.LogWarning("Provider {Provider} is not enabled", provider.ProviderName);
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        $"Authentication provider {provider.ProviderName} is not enabled");
                }

                // 인증 수행
                var result = await provider.AuthenticateAsync(request);

                if (result.IsSuccess && result.Data != null)
                {
                    _logger.LogInformation(
                        "Authentication successful for user {UserId} using {Method}",
                        result.Data.UserId, request.Method);

                    // 인증 성공 이벤트 발행
                    await PublishAuthenticationSuccessEvent(result.Data);
                }
                else
                {
                    _logger.LogWarning(
                        "Authentication failed for method {Method}: {Error}",
                        request.Method, result.ErrorMessage);

                    // 인증 실패 이벤트 발행
                    await PublishAuthenticationFailureEvent(request, result.ErrorMessage);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication error for method {Method}", request.Method);
                return ServiceResult<AuthenticationOutcome>.Failure(
                    "An error occurred during authentication");
            }
        }

        public async Task<ServiceResult<bool>> ValidateTokenAsync(string token)
        {
            try
            {
                // PASETO 토큰 검증
                var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token);
                return ServiceResult<bool>.Success(validationResult.IsSuccess);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                return ServiceResult<bool>.Failure("Token validation error");
            }
        }

        public async Task<ServiceResult> RevokeTokenAsync(string token)
        {
            try
            {
                // 세션 찾기 및 종료
                var sessionResult = await _sessionService.GetSessionByTokenAsync(token);
                if (sessionResult.IsSuccess && sessionResult.Data != null)
                {
                    await _sessionService.EndSessionAsync(
                        sessionResult.Data.Id,
                        SessionEnums.SessionEndReason.UserLogout);

                    return ServiceResult.Success("Token revoked successfully");
                }

                return ServiceResult.Failure("Token not found or could not be revoked");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking token");
                return ServiceResult.Failure("Token revocation error");
            }
        }

        public async Task<ServiceResult<AuthenticationOutcome>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                // Refresh Token으로 세션 찾기 - SessionResponse 반환
                var sessionResult = await _sessionService.GetSessionByTokenAsync(refreshToken);
                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid refresh token");
                }

                var session = sessionResult.Data; // SessionResponse (UserId 포함)

                // 세션 갱신
                var refreshResult = await _sessionService.RefreshSessionAsync(session.Id);
                if (!refreshResult.IsSuccess || refreshResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to refresh session");
                }

                var refreshedSession = refreshResult.Data; // 갱신된 SessionResponse

                // 클레임 생성
                var claims = new List<Claim>
                {
                    new Claim("user_id", session.UserId.ToString()),
                    new Claim("session_id", refreshedSession.Id.ToString())
                };

                // ConnectedId는 Guid.Empty가 아닐 때만 추가
                if (refreshedSession.ConnectedId != Guid.Empty)
                {
                    claims.Add(new System.Security.Claims.Claim("connected_id", refreshedSession.ConnectedId.ToString()));
                }

                // OrganizationId는 Guid.Empty가 아닐 때만 추가
                if (refreshedSession.OrganizationId != Guid.Empty)
                {
                    claims.Add(new Claim("org_id", refreshedSession.OrganizationId.ToString()));
                }

                // Access Token 생성
                var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                    session.UserId,
                    refreshedSession.ConnectedId,
                    claims);

                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to generate new token");
                }

                // Refresh Token 생성
                var newRefreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(session.UserId);

                if (!newRefreshTokenResult.IsSuccess || newRefreshTokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Failed to generate new refresh token");
                }

                // AuthenticationOutcome 생성
                return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
                {
                    Success = true,
                    UserId = session.UserId,
                    ConnectedId = refreshedSession.ConnectedId != Guid.Empty ? refreshedSession.ConnectedId : null,
                    SessionId = refreshedSession.Id,
                    AccessToken = tokenResult.Data.AccessToken,
                    RefreshToken = newRefreshTokenResult.Data,
                    ExpiresAt = tokenResult.Data.ExpiresAt,
                    OrganizationId = refreshedSession.OrganizationId != Guid.Empty ? refreshedSession.OrganizationId : null,
                    ApplicationId = null, // SessionResponse에 없음
                    AuthenticationMethod = "RefreshToken",
                    Provider = "AuthHive",
                    RequiresMfa = false,
                    MfaVerified = true,
                    AuthenticationStrength = AuthenticationStrength.Medium
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing token");
                return ServiceResult<AuthenticationOutcome>.Failure("Token refresh error");
            }
        }
        public async Task<ServiceResult<List<AuthenticationMethod>>> GetAvailableMethodsAsync(
         Guid? organizationId = null)
        {
            try
            {
                var availableMethods = new List<AuthenticationMethod>();

                foreach (var mapping in _providerMapping)
                {
                    var provider = GetProvider(mapping.Key);
                    if (provider != null && await provider.IsEnabledAsync())
                    {
                        // 조직별 설정 확인 (필요한 경우)
                        if (organizationId.HasValue)
                        {
                            // TODO: 조직별 인증 방법 설정 확인
                        }

                        availableMethods.Add(mapping.Key);
                    }
                }

                return ServiceResult<List<AuthenticationMethod>>.Success(availableMethods);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting available authentication methods");
                return ServiceResult<List<AuthenticationMethod>>.Failure(
                    "Failed to get available authentication methods");
            }
        }

        public async Task<ServiceResult<bool>> IsMethodEnabledAsync(
            AuthenticationMethod method,
            Guid? organizationId = null)
        {
            try
            {
                var provider = GetProvider(method);
                if (provider == null)
                {
                    return ServiceResult<bool>.Success(false);
                }

                var isEnabled = await provider.IsEnabledAsync();

                // 조직별 설정 확인
                if (isEnabled && organizationId.HasValue)
                {
                    // TODO: 조직별 인증 방법 설정 확인
                }

                return ServiceResult<bool>.Success(isEnabled);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking if method {Method} is enabled", method);
                return ServiceResult<bool>.Failure("Failed to check method status");
            }
        }

        public async Task<ServiceResult<AuthenticationMethodSettings>> GetMethodSettingsAsync(
            AuthenticationMethod method,
            Guid? organizationId = null)
        {
            try
            {
                var settings = new AuthenticationMethodSettings
                {
                    Method = method,
                    IsEnabled = await IsMethodEnabledAsync(method, organizationId).ContinueWith(t => t.Result.Data),
                    Priority = GetMethodPriority(method),
                    RequiresMfa = ShouldRequireMfa(method),
                    MaxAttempts = 5,
                    LockoutMinutes = 30
                };

                // 조직별 설정 오버라이드
                if (organizationId.HasValue)
                {
                    // TODO: 조직별 설정 로드
                }

                return ServiceResult<AuthenticationMethodSettings>.Success(settings);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting settings for method {Method}", method);
                return ServiceResult<AuthenticationMethodSettings>.Failure("Failed to get method settings");
            }
        }

        public Task<ServiceResult<string>> GenerateExternalLoginUrlAsync(
            string provider,
            string redirectUri,
            string? state = null,
            List<string>? scopes = null)
        {
            try
            {
                // OAuth/Social Provider에게 위임
                // TODO: OAuthProviderFactory를 통해 URL 생성

                var loginUrl = $"https://auth.provider.com/oauth/authorize?client_id=xxx&redirect_uri={redirectUri}&state={state ?? Guid.NewGuid().ToString()}";

                return Task.FromResult(ServiceResult<string>.Success(loginUrl));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating external login URL for {Provider}", provider);
                return Task.FromResult(ServiceResult<string>.Failure("Failed to generate login URL"));
            }
        }

        public async Task<ServiceResult<bool>> VerifyMfaAsync(
            Guid userId,
            string code,
            MfaMethod method)
        {
            try
            {
                // TODO: MFA 서비스 구현
                await Task.CompletedTask;
                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying MFA for user {UserId}", userId);
                return ServiceResult<bool>.Failure("MFA verification failed");
            }
        }
        public async Task<ServiceResult<List<AuthenticationAttemptSummary>>> GetAuthenticationHistoryAsync(
     Guid? userId = null,
     Guid? organizationId = null,
     int limit = 10)
        {
            try
            {
                List<AuthenticationAttemptLog> attempts;

                if (userId.HasValue)
                {
                    // userId가 있으면 GetHistoryForUserAsync 사용
                    var history = await _authAttemptRepository.GetHistoryForUserAsync(
                        userId.Value,
                        DateTime.UtcNow.AddDays(-30), // 최근 30일
                        DateTime.UtcNow);

                    attempts = history.Take(limit).ToList();
                }
                else if (organizationId.HasValue)
                {
                    // organizationId만 있으면 GetSuspiciousAttemptsAsync 활용
                    var suspicious = await _authAttemptRepository.GetSuspiciousAttemptsAsync(
                        organizationId,
                        DateTime.UtcNow.AddDays(-7),
                        null);

                    attempts = suspicious.Take(limit).ToList();
                }
                else
                {
                    // 둘 다 없으면 빈 리스트
                    attempts = new List<AuthenticationAttemptLog>();
                }

                // AuthenticationAttemptLog를 AuthenticationAttemptSummary로 변환
                var summaries = attempts.Select(a => new AuthenticationAttemptSummary
                {
                    AttemptId = a.Id,
                    UserId = a.UserId,
                    Method = a.Method,
                    IsSuccess = a.IsSuccess,
                    AttemptedAt = a.AttemptedAt,
                    IpAddress = a.IpAddress,
                    FailureReason = a.FailureReason?.ToString(),
                }).ToList();

                return ServiceResult<List<AuthenticationAttemptSummary>>.Success(summaries);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting authentication history");
                return ServiceResult<List<AuthenticationAttemptSummary>>.Failure("Failed to get authentication history");
            }
        }

        public async Task<ServiceResult<List<SessionSummary>>> GetActiveSessionsAsync(
            Guid userId,
            Guid? organizationId = null)
        {
            try
            {
                // SessionService를 통해 활성 세션 조회
                var sessionsResult = await _sessionService.GetUserActiveSessionsAsync(userId);

                if (!sessionsResult.IsSuccess || sessionsResult.Data == null)
                {
                    return ServiceResult<List<SessionSummary>>.Success(new List<SessionSummary>());
                }

                var sessions = sessionsResult.Data;

                // organizationId가 지정된 경우 해당 조직의 세션만 필터링
                if (organizationId.HasValue)
                {
                    sessions = sessions.Where(s => s.OrganizationId == organizationId.Value).ToList();
                }

                // SessionResponse를 SessionSummary로 변환
                var summaries = sessions.Select(s => new SessionSummary
                {
                    SessionId = s.Id,
                    UserId = s.UserId,
                    ConnectedId = s.ConnectedId != Guid.Empty ? s.ConnectedId : null,
                    OrganizationId = s.OrganizationId != Guid.Empty ? s.OrganizationId : null,
                    AuthenticationMethod = "Password", // SessionResponse에 없으므로 기본값 또는 별도 조회 필요
                    IpAddress = s.IpAddress,
                    DeviceInfo = !string.IsNullOrEmpty(s.Browser) && !string.IsNullOrEmpty(s.OperatingSystem)
                        ? $"{s.Browser} on {s.OperatingSystem}"
                        : null,
                    CreatedAt = s.CreatedAt,
                    LastActivityAt = s.LastActivityAt,
                    ExpiresAt = s.ExpiresAt
                }).ToList();

                return ServiceResult<List<SessionSummary>>.Success(summaries);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active sessions for user {UserId}", userId);
                return ServiceResult<List<SessionSummary>>.Failure("Failed to get active sessions");
            }
        }

        public async Task<ServiceResult<int>> RevokeAllSessionsAsync(
     Guid userId,
     string? exceptCurrentToken = null)
        {
            try
            {
                var revokedCount = 0;

                // 1. 사용자의 모든 활성 세션 조회
                var sessionsResult = await _sessionService.GetUserActiveSessionsAsync(userId);

                if (!sessionsResult.IsSuccess || sessionsResult.Data == null)
                {
                    _logger.LogWarning("No active sessions found for user {UserId}", userId);
                    return ServiceResult<int>.Success(0);
                }

                var sessions = sessionsResult.Data.ToList();

                // 2. 현재 토큰에 해당하는 세션 제외
                if (!string.IsNullOrEmpty(exceptCurrentToken))
                {
                    // 현재 토큰으로 세션 조회
                    var currentSessionResult = await _sessionService.GetSessionByTokenAsync(exceptCurrentToken);

                    if (currentSessionResult.IsSuccess && currentSessionResult.Data != null)
                    {
                        // 현재 세션 제외
                        sessions = sessions.Where(s => s.Id != currentSessionResult.Data.Id).ToList();
                    }
                }

                // 3. 각 세션 종료
                foreach (var session in sessions)
                {
                    var endResult = await _sessionService.EndSessionAsync(
                        session.Id,
                        SessionEndReason.UserLogout); // 또는 SessionEndReason.RevokedByUser

                    if (endResult.IsSuccess)
                    {
                        revokedCount++;
                        _logger.LogInformation("Session {SessionId} revoked for user {UserId}",
                            session.Id, userId);
                    }
                    else
                    {
                        _logger.LogWarning("Failed to revoke session {SessionId} for user {UserId}: {Error}",
                            session.Id, userId, endResult.ErrorMessage);
                    }
                }

                // 4. 감사 로그 기록 (옵션)
                if (revokedCount > 0)
                {
                    _logger.LogInformation("Revoked {Count} sessions for user {UserId}", revokedCount, userId);

                    // 선택적: 세션 이벤트 기록
                    // await _auditService.LogAsync(new AuditLog
                    // {
                    //     UserId = userId,
                    //     Action = "REVOKE_ALL_SESSIONS",
                    //     Details = $"Revoked {revokedCount} sessions",
                    //     Timestamp = DateTime.UtcNow
                    // });
                }

                return ServiceResult<int>.Success(revokedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking all sessions for user {UserId}", userId);
                return ServiceResult<int>.Failure("Failed to revoke sessions");
            }
        }
        public async Task<ServiceResult<AuthenticationStatistics>> GetStatisticsAsync(
            Guid? organizationId = null,
            DateTime? from = null,
            DateTime? to = null)
        {
            try
            {
                // 1. 기간 설정 (기본값: 최근 30일)
                var endDate = to ?? DateTime.UtcNow;
                var startDate = from ?? endDate.AddDays(-30);

                _logger.LogInformation(
                    "Getting authentication statistics for organization {OrganizationId} from {From} to {To}",
                    organizationId?.ToString() ?? "ALL",
                    startDate,
                    endDate);

                // 2. Repository를 통해 통계 데이터 조회
                // SaaS 환경에서는 organizationId로 데이터 격리가 필수
                var statistics = await _authAttemptRepository.GetStatisticsAsync(
                    startDate,
                    endDate,
                    organizationId);

                if (statistics == null)
                {
                    // 데이터가 없는 경우 빈 통계 반환
                    statistics = new AuthenticationStatistics
                    {
                        PeriodStart = startDate,
                        PeriodEnd = endDate,
                        TotalAttempts = 0,
                        SuccessfulAttempts = 0,
                        FailedAttempts = 0,
                        SuccessRate = 0,
                        UniqueUsers = 0,
                        AttemptsByMethod = new Dictionary<AuthenticationMethod, int>(),
                        FailureReasons = new Dictionary<AuthenticationResult, int>()
                    };
                }

                // 3. 추가 통계 데이터 수집 (병렬 처리로 성능 향상)
                var additionalStatsTasks = new List<Task>();

                // 3.1 시간대별 분포 (피크 시간 분석)
                Task<Dictionary<int, int>>? hourlyDistributionTask = null;
                if (organizationId.HasValue)
                {
                    // 특정 조직의 패턴 분석
                    hourlyDistributionTask = _authAttemptRepository.GetHourlyDistributionAsync(
                        startDate, organizationId);
                    additionalStatsTasks.Add(hourlyDistributionTask);
                }

                // 3.2 인증 방법별 성공률
                var successRateByMethodTask = _authAttemptRepository.GetSuccessRateByMethodAsync(
                    startDate, organizationId);
                additionalStatsTasks.Add(successRateByMethodTask);

                // 3.3 위험 IP 주소 (보안 분석)
                var riskyIpsTask = _authAttemptRepository.GetRiskyIpAddressesAsync(
                    failureThreshold: 5,
                    since: startDate);
                additionalStatsTasks.Add(riskyIpsTask);

                // 3.4 MFA 성공률
                var mfaSuccessRateTask = _authAttemptRepository.GetMfaSuccessRateAsync(
                    startDate, organizationId);
                additionalStatsTasks.Add(mfaSuccessRateTask);

                // 3.5 의심스러운 시도
                var suspiciousAttemptsTask = _authAttemptRepository.GetSuspiciousAttemptsAsync(
                    organizationId, startDate, minRiskScore: 50);
                additionalStatsTasks.Add(suspiciousAttemptsTask);

                // 3.6 실패 상위 사용자
                var topFailedUsersTask = _authAttemptRepository.GetTopFailedUsersAsync(
                    topCount: 10,
                    since: startDate);
                additionalStatsTasks.Add(topFailedUsersTask);

                // 모든 추가 통계 작업 대기
                await Task.WhenAll(additionalStatsTasks);

                // 4. 피크 시간 계산
                if (hourlyDistributionTask != null)
                {
                    var hourlyDist = await hourlyDistributionTask;
                    if (hourlyDist != null && hourlyDist.Any())
                    {
                        statistics.PeakHour = hourlyDist
                            .OrderByDescending(kv => kv.Value)
                            .First().Key;
                    }
                }

                // 5. 메소드별 성공률 데이터 보강
                var methodSuccessRates = await successRateByMethodTask;
                if (methodSuccessRates != null && methodSuccessRates.Any())
                {
                    // 성공률이 낮은 메소드 로깅 (모니터링용)
                    var lowSuccessMethods = methodSuccessRates
                        .Where(kv => kv.Value < 0.5) // 50% 미만
                        .ToList();

                    if (lowSuccessMethods.Any())
                    {
                        _logger.LogWarning(
                            "Low success rate authentication methods detected for organization {OrganizationId}: {@Methods}",
                            organizationId,
                            lowSuccessMethods);
                    }
                }

                // 6. 보안 위험 분석
                var riskyIps = await riskyIpsTask;
                var suspiciousAttempts = await suspiciousAttemptsTask;

                // 위험 IP 수가 임계값을 초과하면 경고
                if (riskyIps != null && riskyIps.Count() > 10)
                {
                    _logger.LogWarning(
                        "High number of risky IP addresses detected ({Count}) for organization {OrganizationId}",
                        riskyIps.Count(),
                        organizationId);

                    // 상위 위험 IP를 로깅 (분석용)
                    var topRiskyIps = riskyIps.Take(5).Select(ip => new
                    {
                        ip.IpAddress,
                        ip.FailureCount,
                        ip.RiskScore
                    });

                    _logger.LogInformation(
                        "Top risky IPs for organization {OrganizationId}: {@IPs}",
                        organizationId,
                        topRiskyIps);
                }

                // 7. 세션 관련 통계 추가
                if (_sessionService != null && organizationId.HasValue)
                {
                    try
                    {
                        // 활성 세션 수 조회
                        var activeSessionsResult = await _sessionService.GetOrganizationActiveSessionsAsync(
                            organizationId.Value,
                            includeInactive: false);

                        if (activeSessionsResult.IsSuccess && activeSessionsResult.Data != null)
                        {
                            var activeSessions = activeSessionsResult.Data.ToList();

                            // 세션 기반 추가 통계
                            var sessionStats = new
                            {
                                ActiveSessionCount = activeSessions.Count,
                                UniqueDevices = activeSessions
                                    .Where(s => !string.IsNullOrEmpty(s.DeviceInfo))
                                    .Select(s => s.DeviceInfo)
                                    .Distinct()
                                    .Count(),
                                UniqueBrowsers = activeSessions
                                    .Where(s => !string.IsNullOrEmpty(s.Browser))
                                    .Select(s => s.Browser)
                                    .Distinct()
                                    .Count(),
                                UniqueOperatingSystems = activeSessions
                                    .Where(s => !string.IsNullOrEmpty(s.OperatingSystem))
                                    .Select(s => s.OperatingSystem)
                                    .Distinct()
                                    .Count()
                            };

                            _logger.LogInformation(
                                "Session statistics for organization {OrganizationId}: {@SessionStats}",
                                organizationId,
                                sessionStats);
                        }

                        // 동시 세션 수
                        var concurrentResult = await _sessionService.GetConcurrentSessionCountAsync(
                            organizationId.Value);

                        if (concurrentResult.IsSuccess)
                        {
                            _logger.LogInformation(
                                "Concurrent sessions for organization {OrganizationId}: {Count}",
                                organizationId,
                                concurrentResult.Data);
                        }
                    }
                    catch (Exception ex)
                    {
                        // 세션 통계 실패는 전체 통계 조회 실패로 이어지지 않음
                        _logger.LogWarning(ex,
                            "Failed to get session statistics for organization {OrganizationId}",
                            organizationId);
                    }
                }

                // 8. 실패한 사용자 분석
                var topFailedUsers = await topFailedUsersTask;
                if (topFailedUsers != null && topFailedUsers.Any())
                {
                    var criticalUsers = topFailedUsers
                        .Where(u => u.FailureCount > 20) // 20회 이상 실패
                        .Take(3)
                        .ToList();

                    if (criticalUsers.Any())
                    {
                        _logger.LogWarning(
                            "Users with excessive login failures for organization {OrganizationId}: {@Users}",
                            organizationId,
                            criticalUsers.Select(u => new
                            {
                                u.UserId,
                                u.Username,
                                u.FailureCount,
                                u.ConsecutiveFailures,
                                u.LastAttempt,
                                u.LastFailure,
                                u.RiskScore,
                                u.RiskLevel,
                                u.IsAccountLocked,
                                u.ShouldLockAccount
                            }));
                    }

                    // 즉시 조치가 필요한 사용자
                    var urgentUsers = topFailedUsers
                        .Where(u => u.ShouldLockAccount || u.ShouldResetPassword)
                        .ToList();

                    if (urgentUsers.Any())
                    {
                        _logger.LogError(
                            "Users requiring immediate action for organization {OrganizationId}: {@Users}",
                            organizationId,
                            urgentUsers.Select(u => new
                            {
                                u.UserId,
                                u.Username,
                                u.FailureCount,
                                u.ConsecutiveFailures,
                                RequiresLock = u.ShouldLockAccount,
                                RequiresPasswordReset = u.ShouldResetPassword,
                                u.RiskLevel
                            }));
                    }
                }

                // 9. MFA 통계 보강
                var mfaSuccessRate = await mfaSuccessRateTask;
                if (mfaSuccessRate < 0.8) // MFA 성공률이 80% 미만
                {
                    _logger.LogWarning(
                        "Low MFA success rate ({Rate:P}) for organization {OrganizationId}",
                        mfaSuccessRate,
                        organizationId);
                }

                // 10. 의심스러운 활동 분석
                if (suspiciousAttempts != null && suspiciousAttempts.Any())
                {
                    var suspiciousCount = suspiciousAttempts.Count();
                    if (suspiciousCount > 0)
                    {
                        _logger.LogWarning(
                            "Detected {Count} suspicious authentication attempts for organization {OrganizationId}",
                            suspiciousCount,
                            organizationId);

                        // 의심스러운 활동 패턴 분석
                        var suspiciousPatterns = suspiciousAttempts
                            .GroupBy(s => s.FailureReason)
                            .Select(g => new { Reason = g.Key, Count = g.Count() })
                            .OrderByDescending(x => x.Count)
                            .Take(3);

                        _logger.LogInformation(
                            "Top suspicious patterns for organization {OrganizationId}: {@Patterns}",
                            organizationId,
                            suspiciousPatterns);
                    }
                }

                // 11. 성공률 재계산 (데이터 정합성 보장)
                if (statistics.TotalAttempts > 0)
                {
                    statistics.SuccessRate = (double)statistics.SuccessfulAttempts / statistics.TotalAttempts;
                }

                // 12. 캐싱 (선택적 - 자주 조회되는 통계는 캐시)
                if (_cacheService != null && organizationId.HasValue)
                {
                    var cacheKey = $"auth_stats:{organizationId}:{startDate:yyyyMMdd}:{endDate:yyyyMMdd}";
                    await _cacheService.SetAsync(
                        cacheKey,
                        statistics,
                        TimeSpan.FromMinutes(5)); // 5분 캐시
                }

                _logger.LogInformation(
                    "Successfully retrieved authentication statistics for organization {OrganizationId}: " +
                    "Total={Total}, Success={Success}, Failed={Failed}, Rate={Rate:P}",
                    organizationId,
                    statistics.TotalAttempts,
                    statistics.SuccessfulAttempts,
                    statistics.FailedAttempts,
                    statistics.SuccessRate);

                return ServiceResult<AuthenticationStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error getting authentication statistics for organization {OrganizationId}",
                    organizationId);

                // 에러 발생 시에도 빈 통계를 반환 (서비스 중단 방지)
                var emptyStats = new AuthenticationStatistics
                {
                    PeriodStart = from ?? DateTime.UtcNow.AddDays(-30),
                    PeriodEnd = to ?? DateTime.UtcNow,
                    TotalAttempts = 0,
                    SuccessfulAttempts = 0,
                    FailedAttempts = 0,
                    SuccessRate = 0,
                    UniqueUsers = 0,
                    AttemptsByMethod = new Dictionary<AuthenticationMethod, int>(),
                    FailureReasons = new Dictionary<AuthenticationResult, int>()
                };

                return ServiceResult<AuthenticationStatistics>.Success(emptyStats);
            }
        }

        // 헬퍼 메서드: 조직별 동적 데이터 처리 (SaaS 유연성)
        // ProcessAdditionalData 메서드 수정
        private Dictionary<string, object> ProcessAdditionalData(
            IEnumerable<AuthenticationAttemptLog> attempts)
        {
            var result = new Dictionary<string, object>();

            try
            {
                // AdditionalData JSON 필드에서 동적 메트릭 추출
                var additionalDataList = attempts
                    .Where(a => !string.IsNullOrEmpty(a.AdditionalData))
                    .Select(a => a.AdditionalData)
                    .Where(data => data != null)  // null 필터링 추가
                    .Cast<string>()  // null이 아닌 string으로 캐스팅
                    .ToList();

                if (!additionalDataList.Any())
                    return result;

                // JSON 데이터 집계 (각 조직이 저장한 커스텀 데이터)
                var aggregatedData = new Dictionary<string, List<string>>();

                foreach (var jsonData in additionalDataList)
                {
                    try
                    {
                        // 이제 jsonData는 확실히 null이 아님
                        var data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(jsonData);
                        if (data != null)
                        {
                            foreach (var kv in data)
                            {
                                if (!aggregatedData.ContainsKey(kv.Key))
                                    aggregatedData[kv.Key] = new List<string>();

                                aggregatedData[kv.Key].Add(kv.Value.ToString());
                            }
                        }
                    }
                    catch
                    {
                        // 개별 JSON 파싱 실패는 무시
                        continue;
                    }
                }

                // 집계 결과 생성
                foreach (var kv in aggregatedData)
                {
                    result[$"{kv.Key}_total"] = kv.Value.Count;
                    result[$"{kv.Key}_unique"] = kv.Value.Distinct().Count();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to process additional data");
            }

            return result;
        }
        // 헬퍼 메서드: 조직별 커스텀 메트릭 처리
        private async Task<Dictionary<string, object>> GetOrganizationCustomMetricsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            var customMetrics = new Dictionary<string, object>();

            try
            {
                var attempts = await _authAttemptRepository.GetHistoryForUserAsync(
                    Guid.Empty,
                    startDate,
                    endDate);

                var orgAttempts = attempts
                    .Where(a => a.OrganizationId == organizationId)
                    .ToList();

                foreach (var attempt in orgAttempts)
                {
                    // null이나 빈 문자열이면 건너뛰기
                    if (string.IsNullOrEmpty(attempt.AdditionalData))
                        continue;

                    try
                    {
                        // 이제 AdditionalData가 null이 아님이 보장됨
                        var additionalData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                            attempt.AdditionalData);

                        if (additionalData != null)
                        {
                            foreach (var kv in additionalData)
                            {
                                if (!customMetrics.ContainsKey(kv.Key))
                                {
                                    customMetrics[kv.Key] = new List<object>();
                                }

                                if (customMetrics[kv.Key] is List<object> list)
                                {
                                    list.Add(kv.Value.ToString());
                                }
                            }
                        }
                    }
                    catch
                    {
                        // JSON 파싱 실패는 무시
                        continue;
                    }
                }

                var processedMetrics = new Dictionary<string, object>();
                foreach (var kv in customMetrics)
                {
                    if (kv.Value is List<object> list)
                    {
                        processedMetrics[kv.Key + "_count"] = list.Count;
                        processedMetrics[kv.Key + "_unique"] = list.Distinct().Count();
                    }
                }

                return processedMetrics;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to get custom metrics for organization {OrganizationId}",
                    organizationId);
                return customMetrics;
            }
        }
        private IAuthenticationProvider? GetProvider(AuthenticationMethod method)
        {
            if (_providerMapping.TryGetValue(method, out var providerType))
            {
                return _serviceProvider.GetService(providerType) as IAuthenticationProvider;
            }

            return null;
        }

        private int GetMethodPriority(AuthenticationMethod method)
        {
            return method switch
            {
                AuthenticationMethod.Passkey => 1,
                AuthenticationMethod.Biometric => 2,
                AuthenticationMethod.SSO => 3,
                AuthenticationMethod.OAuth => 4,
                AuthenticationMethod.SocialLogin => 5,
                AuthenticationMethod.Password => 6,
                AuthenticationMethod.MagicLink => 7,
                AuthenticationMethod.ApiKey => 8,
                _ => 99
            };
        }

        private bool ShouldRequireMfa(AuthenticationMethod method)
        {
            return method switch
            {
                AuthenticationMethod.Password => true,
                AuthenticationMethod.MagicLink => false,
                AuthenticationMethod.Passkey => false,
                AuthenticationMethod.Biometric => false,
                AuthenticationMethod.Certificate => false,
                _ => false
            };
        }

        private async Task PublishAuthenticationSuccessEvent(AuthenticationOutcome outcome)
        {
            // 단순 성공 기록은 AuditService 사용

            await _auditService.LogActionAsync(
                performedByConnectedId: outcome.ConnectedId, // 파라미터 이름을 'performedByConnectedId'로 수정
                action: "AUTHENTICATION_SUCCESS",
                actionType: AuditActionType.Login, // 필수 파라미터 추가
                resourceType: "User",              // 필수 파라미터 추가
                resourceId: outcome.ConnectedId.ToString(), // 필수 파라미터 추가
                success: true,
                metadata: $"Authenticated via {outcome.AuthenticationMethod}"
            );
        }

        private async Task PublishAuthenticationFailureEvent(AuthenticationRequest request, string? errorMessage)
        {
            // 단순 실패 기록은 AuditService 사용
            await _auditService.LogActionAsync(
      performedByConnectedId: null, // 인증 실패로 아직 ConnectedId가 없음
      action: "AUTHENTICATION_FAILURE",
      actionType: AuditActionType.Login,
      resourceType: "User", // 인증 시도의 대상 리소스는 'User'
      resourceId: request.Username ?? "unknown", // 사용자 이름을 'resourceId'로 전달
      success: false,
      metadata: $"Authentication failed for method {request.Method}. Reason: {errorMessage}" // 'details'를 'metadata'로 수정
  );

            // 특정 조건(예: 실패 횟수 임계값 초과)에서는 IEventBus로 보안 이벤트 발행
            // if (isSuspicious) {
            //     await _eventBus.PublishAsync(new SuspiciousLoginActivityEvent(...));
            // }
        }
    }
}