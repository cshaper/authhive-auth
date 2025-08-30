// Path: AuthHive.Auth/Services/Authentication/AuthenticationOrchestrationService.cs
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Constants.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 인증 오케스트레이션 서비스 - AuthHive v15
    /// 모든 인증 관련 서비스들을 조율하는 Facade 패턴 구현
    /// 
    /// 역할:
    /// 1. 인증 방식에 따른 적절한 서비스 선택 및 위임
    /// 2. MFA 플로우 조율 (1차 인증 → MFA 필요성 판단 → 2차 인증)
    /// 3. 보안 정책 적용 (계정 잠금, 위험도 평가 등)
    /// 4. 세션 생성 및 토큰 발급 조율
    /// 5. 인증 시도 기록 및 감사
    /// </summary>
    public class AuthenticationOrchestrationService : IAuthenticationOrchestrationService
    {
        private readonly IPasswordService _passwordService;
        private readonly ISocialAuthenticationService _socialAuthService;
        private readonly IMfaAuthenticationService _mfaService;
        private readonly IAccountSecurityService _securityService;
        private readonly IAuthenticationAttemptService _attemptService;
        private readonly ITokenService _tokenService;
        private readonly ISessionService _sessionService;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IMemoryCache _cache;
        private readonly ILogger<AuthenticationOrchestrationService> _logger;

        // 캐시 키 상수
        private const string RISK_ASSESSMENT_PREFIX = "risk_assessment:";
        private const string MFA_CHALLENGE_PREFIX = "mfa_challenge:";

        public AuthenticationOrchestrationService(
            IPasswordService passwordService,
            ISocialAuthenticationService socialAuthService,
            IMfaAuthenticationService mfaService,
            IAccountSecurityService securityService,
            IAuthenticationAttemptService attemptService,
            ITokenService tokenService,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            IMemoryCache cache,
            ILogger<AuthenticationOrchestrationService> logger)
        {
            _passwordService = passwordService;
            _socialAuthService = socialAuthService;
            _mfaService = mfaService;
            _securityService = securityService;
            _attemptService = attemptService;
            _tokenService = tokenService;
            _sessionService = sessionService;
            _connectedIdService = connectedIdService;
            _cache = cache;
            _logger = logger;
        }

        #region IService Implementation
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // 핵심 의존 서비스들의 상태 확인
                var passwordHealthy = await _passwordService.IsHealthyAsync();
                var securityHealthy = await _securityService.IsHealthyAsync();
                var tokenHealthy = await _tokenService.IsHealthyAsync();
                
                return passwordHealthy && securityHealthy && tokenHealthy;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AuthenticationOrchestrationService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("AuthenticationOrchestrationService initialized");
            return Task.CompletedTask;
        }
        #endregion

        #region 캐시 전략 구현
        /// <summary>
        /// 위험도 평가 결과 캐싱
        /// </summary>
        private async Task<ServiceResult<RiskAssessment>> GetCachedRiskAssessmentAsync(string ipAddress)
        {
            var cacheKey = $"{RISK_ASSESSMENT_PREFIX}{ipAddress}";
            
            // 캐시에서 먼저 확인
            if (_cache.TryGetValue<RiskAssessment>(cacheKey, out var cachedAssessment) && cachedAssessment != null)
            {
                _logger.LogDebug("Risk assessment cache hit for IP {IpAddress}", ipAddress);
                return ServiceResult<RiskAssessment>.Success(cachedAssessment);
            }

            // 캐시 미스 - 실제 평가 수행
            var assessmentResult = await _attemptService.AssessIpRiskAsync(ipAddress);
            
            if (assessmentResult.IsSuccess && assessmentResult.Data != null)
            {
                // 결과를 캐시에 저장 (위험도가 높을수록 짧은 TTL)
                var ttl = assessmentResult.Data.RiskScore >= 0.7 
                    ? TimeSpan.FromMinutes(5)   // 고위험 IP - 5분
                    : TimeSpan.FromMinutes(15); // 저위험 IP - 15분
                
                _cache.Set(cacheKey, assessmentResult.Data, ttl);
                _logger.LogDebug("Risk assessment cached for IP {IpAddress} with TTL {TTL}", ipAddress, ttl);
            }
            
            return assessmentResult;
        }

        /// <summary>
        /// MFA 설정 캐싱
        /// </summary>
        private async Task<ServiceResult<MfaSettingsResponse>> GetCachedMfaSettingsAsync(Guid userId)
        {
            var cacheKey = $"mfa_settings_{userId}";
            
            // 캐시에서 먼저 확인
            if (_cache.TryGetValue<MfaSettingsResponse>(cacheKey, out var cachedSettings) && cachedSettings != null)
            {
                _logger.LogDebug("MFA settings cache hit for user {UserId}", userId);
                return ServiceResult<MfaSettingsResponse>.Success(cachedSettings);
            }

            // 캐시 미스 - 실제 MFA 설정 조회
            var settingsResult = await _mfaService.GetMfaSettingsAsync(userId);
            
            if (settingsResult.IsSuccess && settingsResult.Data != null)
            {
                // MFA 설정은 비교적 안정적이므로 30분 캐싱
                _cache.Set(cacheKey, settingsResult.Data, TimeSpan.FromMinutes(30));
                _logger.LogDebug("MFA settings cached for user {UserId}", userId);
            }
            
            return settingsResult;
        }

        /// <summary>
        /// MFA 필요성 판단 결과 캐싱
        /// </summary>
        private async Task<ServiceResult<MfaRequirement>> GetCachedMfaRequirementAsync(
            Guid userId, 
            Guid? organizationId)
        {
            var cacheKey = $"mfa_requirement_{userId}_{organizationId}";
            
            // 캐시에서 먼저 확인
            if (_cache.TryGetValue<MfaRequirement>(cacheKey, out var cachedRequirement) && cachedRequirement != null)
            {
                _logger.LogDebug("MFA requirement cache hit for user {UserId}", userId);
                return ServiceResult<MfaRequirement>.Success(cachedRequirement);
            }

            // 캐시 미스 - 실제 MFA 필요성 판단
            var requirementResult = await _mfaService.CheckMfaRequirementAsync(userId, organizationId);
            
            if (requirementResult.IsSuccess && requirementResult.Data != null)
            {
                // MFA 필요성은 조직 정책에 따라 달라질 수 있으므로 10분 캐싱
                _cache.Set(cacheKey, requirementResult.Data, TimeSpan.FromMinutes(10));
                _logger.LogDebug("MFA requirement cached for user {UserId}", userId);
            }
            
            return requirementResult;
        }

        /// <summary>
        /// ConnectedId별 캐시 정리 (AuthHive v15 철학 적용)
        /// </summary>
        private Task ClearSessionCacheAsync(Guid? connectedId, Guid? sessionId = null)
        {
            if (!connectedId.HasValue) 
                return Task.CompletedTask;

            try
            {
                var keysToRemove = new List<string>
                {
                    $"connected_id_permissions_{connectedId.Value}",
                    $"connected_id_roles_{connectedId.Value}",
                    $"connected_id_context_{connectedId.Value}"
                };

                if (sessionId.HasValue)
                {
                    keysToRemove.Add($"session_cache_{sessionId.Value}");
                }

                foreach (var key in keysToRemove)
                {
                    _cache.Remove(key);
                }

                _logger.LogDebug("Cache cleared for ConnectedId {ConnectedId}", connectedId.Value);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clear cache for ConnectedId {ConnectedId}", connectedId.Value);
            }
            
            return Task.CompletedTask;
        }

        /// <summary>
        /// 사용자별 캐시 정리 (하위 호환성 유지)
        /// </summary>
        private Task ClearUserCacheAsync(Guid? userId, Guid? sessionId = null)
        {
            if (!userId.HasValue) 
                return Task.CompletedTask;

            try
            {
                var keysToRemove = new List<string>
                {
                    $"mfa_settings_{userId.Value}",
                    $"mfa_requirement_{userId.Value}_*", // 조직별로 여러 키가 있을 수 있음
                    $"user_permissions_{userId.Value}",
                    $"user_roles_{userId.Value}"
                };

                if (sessionId.HasValue)
                {
                    keysToRemove.Add($"session_cache_{sessionId.Value}");
                }

                foreach (var key in keysToRemove)
                {
                    if (key.Contains('*'))
                    {
                        // 와일드카드 패턴 - 실제 구현에서는 더 정교한 방식 필요
                        // Redis를 사용한다면 KEYS 명령어 사용 가능
                        var baseKey = key.Replace("_*", "");
                        _cache.Remove($"{baseKey}_{Guid.Empty}"); // 기본 조직
                    }
                    else
                    {
                        _cache.Remove(key);
                    }
                }

                _logger.LogDebug("Cache cleared for user {UserId}", userId.Value);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clear cache for user {UserId}", userId.Value);
            }
            
            return Task.CompletedTask;
        }

        /// <summary>
        /// 모든 사용자 관련 캐시 정리 (하위 호환성 유지)
        /// </summary>
        private Task ClearAllUserCacheAsync(Guid userId)
        {
            try
            {
                // 사용자와 관련된 모든 캐시 패턴
                var patterns = new[]
                {
                    $"mfa_settings_{userId}",
                    $"mfa_requirement_{userId}_",
                    $"user_permissions_{userId}",
                    $"user_roles_{userId}",
                    $"session_cache_", // 해당 사용자의 모든 세션
                    $"risk_assessment_" // IP 기반이지만 사용자와 연관될 수 있음
                };

                foreach (var pattern in patterns)
                {
                    _cache.Remove(pattern);
                }

                _logger.LogDebug("All cache cleared for user {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clear all cache for user {UserId}", userId);
            }
            
            return Task.CompletedTask;
        }

        /// <summary>
        /// 캐시 통계 조회 (모니터링용)
        /// </summary>
        public async Task<ServiceResult<Dictionary<string, object>>> GetCacheStatisticsAsync()
        {
            try
            {
                var stats = new Dictionary<string, object>();
                
                // 캐시 히트/미스 통계는 실제 캐시 구현체(Redis 등)에서 제공하는 메트릭 사용
                // 현재는 기본적인 정보만 제공
                stats["cache_provider"] = "MemoryCache";
                stats["risk_assessment_ttl_minutes"] = "5-15";
                stats["mfa_settings_ttl_minutes"] = "30";
                stats["mfa_requirement_ttl_minutes"] = "10";
                
                return await Task.FromResult(ServiceResult<Dictionary<string, object>>.Success(stats));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get cache statistics");
                return ServiceResult<Dictionary<string, object>>.Failure("Failed to get cache statistics");
            }
        }

        /// <summary>
        /// 캐시 워밍업 (자주 사용되는 데이터 미리 로드)
        /// </summary>
        public async Task<ServiceResult> WarmupCacheAsync(Guid userId, Guid? organizationId = null)
        {
            try
            {
                _logger.LogInformation("Starting cache warmup for user {UserId}", userId);

                var warmupTasks = new List<Task>
                {
                    // MFA 설정 미리 로드
                    GetCachedMfaSettingsAsync(userId),
                    
                    // MFA 필요성 미리 확인
                    GetCachedMfaRequirementAsync(userId, organizationId)
                };

                // 동시에 실행하여 성능 최적화
                await Task.WhenAll(warmupTasks);
                
                _logger.LogInformation("Cache warmup completed for user {UserId}", userId);
                return ServiceResult.Success("Cache warmup completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Cache warmup failed for user {UserId}", userId);
                return ServiceResult.Failure("Cache warmup failed");
            }
        }
        #endregion

        #region 통합 인증 처리
        /// <summary>
        /// 통합 인증 처리 - 모든 인증 방식의 진입점
        /// </summary>
        public async Task<ServiceResult<AuthenticationResponse>> AuthenticateAsync(
            AuthenticationRequest request)
        {
            try
            {
                _logger.LogInformation("Authentication attempt started for method {Method}", request.Method);

                // 1. 사전 보안 검사
                var securityCheckResult = await PreAuthenticationSecurityCheckAsync(request);
                if (!securityCheckResult.IsSuccess)
                {
                    return ServiceResult<AuthenticationResponse>.Failure(securityCheckResult.ErrorMessage ?? "Security check failed");
                }

                // 2. 인증 방식에 따른 1차 인증 처리
                var primaryAuthResult = await PerformPrimaryAuthenticationAsync(request);
                if (!primaryAuthResult.IsSuccess || primaryAuthResult.Data == null)
                {
                    await LogFailedAuthenticationAsync(request, primaryAuthResult.ErrorMessage ?? "Primary authentication failed");
                    return primaryAuthResult;
                }

                var authResponse = primaryAuthResult.Data;
                
                // 3. MFA 필요성 판단 및 처리
                if (authResponse.UserId.HasValue)
                {
                    var mfaResult = await HandleMfaFlowAsync(request, authResponse);
                    if (!mfaResult.IsSuccess)
                    {
                        return mfaResult;
                    }
                    authResponse = mfaResult.Data ?? authResponse;
                }

                // 4. 인증 성공 후 처리
                if (authResponse.Success && authResponse.UserId.HasValue)
                {
                    await PostAuthenticationProcessingAsync(request, authResponse);
                }

                _logger.LogInformation("Authentication completed successfully for user {UserId}", authResponse.UserId);
                return ServiceResult<AuthenticationResponse>.Success(authResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication orchestration failed for method {Method}", request.Method);
                return ServiceResult<AuthenticationResponse>.Failure("Authentication failed");
            }
        }
        #endregion

        #region 사전 보안 검사
        /// <summary>
        /// 사전 보안 검사 - IP 차단, Rate Limiting 등
        /// </summary>
        private async Task<ServiceResult> PreAuthenticationSecurityCheckAsync(AuthenticationRequest request)
        {
            try
            {
                // IP 기반 위험도 평가 (캐싱 적용)
                if (!string.IsNullOrEmpty(request.IpAddress))
                {
                    var riskAssessment = await GetCachedRiskAssessmentAsync(request.IpAddress);
                    if (riskAssessment.IsSuccess && riskAssessment.Data?.RiskScore >= 0.8)
                    {
                        _logger.LogWarning("High risk IP detected: {IpAddress}, Risk: {RiskScore}", 
                            request.IpAddress, riskAssessment.Data.RiskScore);
                        return ServiceResult.Failure("Access denied due to security policy");
                    }
                }

                // 무차별 대입 공격 탐지
                if (!string.IsNullOrEmpty(request.Username) && !string.IsNullOrEmpty(request.IpAddress))
                {
                    var bruteForceCheck = await _attemptService.DetectBruteForceAttackAsync(
                        request.Username, request.IpAddress);
                    
                    if (bruteForceCheck.IsSuccess && bruteForceCheck.Data == true)
                    {
                        return ServiceResult.Failure("Too many failed attempts. Please try again later.");
                    }
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pre-authentication security check failed");
                return ServiceResult.Success(); // 보안 검사 실패 시 인증 진행 (Fail-open)
            }
        }
        #endregion

        #region 1차 인증 처리
        /// <summary>
        /// 인증 방식에 따른 1차 인증 처리
        /// </summary>
        private async Task<ServiceResult<AuthenticationResponse>> PerformPrimaryAuthenticationAsync(
            AuthenticationRequest request)
        {
            return request.Method switch
            {
                AuthenticationMethod.Password => await HandlePasswordAuthenticationAsync(request),
                AuthenticationMethod.OAuth => await HandleOAuthAuthenticationAsync(request),
                AuthenticationMethod.SSO => await HandleSocialAuthenticationAsync(request),
                AuthenticationMethod.ApiKey => await HandleApiKeyAuthenticationAsync(request),
                AuthenticationMethod.TwoFactor => await HandleDirectMfaAuthenticationAsync(request),
                _ => ServiceResult<AuthenticationResponse>.Failure($"Unsupported authentication method: {request.Method}")
            };
        }

        /// <summary>
        /// 패스워드 인증 처리
        /// </summary>
        private async Task<ServiceResult<AuthenticationResponse>> HandlePasswordAuthenticationAsync(
            AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return ServiceResult<AuthenticationResponse>.Failure("Username and password are required");
            }

            return await _passwordService.AuthenticateWithPasswordAsync(
                request.Username, 
                request.Password, 
                request.OrganizationId);
        }

        /// <summary>
        /// OAuth 인증 처리
        /// </summary>
        private async Task<ServiceResult<AuthenticationResponse>> HandleOAuthAuthenticationAsync(
            AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.RedirectUri))
            {
                return ServiceResult<AuthenticationResponse>.Failure("OAuth code and redirect URI are required");
            }

            return await _socialAuthService.AuthenticateWithOAuthAsync(
                request.Provider ?? "oauth",
                request.Code,
                request.RedirectUri,
                request.State);
        }

        /// <summary>
        /// 소셜 인증 처리
        /// </summary>
        private async Task<ServiceResult<AuthenticationResponse>> HandleSocialAuthenticationAsync(
            AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.SocialToken) || string.IsNullOrEmpty(request.SocialProvider))
            {
                return ServiceResult<AuthenticationResponse>.Failure("Social token and provider are required");
            }

            return await _socialAuthService.AuthenticateWithSocialAsync(
                request.SocialProvider,
                request.SocialToken,
                request.OrganizationId);
        }

        /// <summary>
        /// API 키 인증 처리
        /// </summary>
        private Task<ServiceResult<AuthenticationResponse>> HandleApiKeyAuthenticationAsync(
            AuthenticationRequest request)
        {
            // TODO: API 키 인증 구현 필요
            return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("API key authentication not yet implemented"));
        }

        /// <summary>
        /// 직접 MFA 인증 처리 (2차 인증만 수행)
        /// </summary>
        private Task<ServiceResult<AuthenticationResponse>> HandleDirectMfaAuthenticationAsync(
            AuthenticationRequest request)
        {
            // AuthHive v15 철학: ConnectedId가 활동의 주체
            // UserId 대신 ConnectedId를 사용하거나, Username으로 사용자를 찾아야 함
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.MfaCode))
            {
                return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("Username and MFA code are required for direct MFA authentication"));
            }

            // Username으로 사용자 찾기 (실제로는 ConnectedId를 통해 처리해야 함)
            // TODO: ConnectedId 기반으로 MFA 처리 로직 구현
            return Task.FromResult(ServiceResult<AuthenticationResponse>.Failure("Direct MFA authentication requires ConnectedId-based implementation"));
        }
        #endregion

        #region MFA 플로우 처리
        /// <summary>
        /// MFA 플로우 조율 - MFA 필요성 판단 및 처리 (캐싱 적용)
        /// </summary>
        private async Task<ServiceResult<AuthenticationResponse>> HandleMfaFlowAsync(
            AuthenticationRequest request, 
            AuthenticationResponse primaryResponse)
        {
            try
            {
                if (!primaryResponse.UserId.HasValue)
                {
                    return ServiceResult<AuthenticationResponse>.Success(primaryResponse);
                }

                // MFA 필요성 판단 (캐싱 적용)
                var mfaRequirement = await GetCachedMfaRequirementAsync(
                    primaryResponse.UserId.Value,
                    request.OrganizationId);

                if (!mfaRequirement.IsSuccess || mfaRequirement.Data?.IsRequired != true)
                {
                    // MFA 불필요 - 1차 인증 결과 그대로 반환
                    return ServiceResult<AuthenticationResponse>.Success(primaryResponse);
                }

                // MFA 코드가 제공된 경우 - 2차 인증 수행
                if (!string.IsNullOrEmpty(request.MfaCode))
                {
                    var mfaResult = await _mfaService.CompleteMfaAuthenticationAsync(
                        primaryResponse.UserId.Value,
                        request.MfaCode,
                        request.MfaMethod ?? "totp");

                    if (mfaResult.IsSuccess && mfaResult.Data != null)
                    {
                        // MFA 성공 - 원래 응답에 MFA 정보 업데이트
                        primaryResponse.RequiresMfa = false;
                        primaryResponse.MfaVerified = true;
                        return ServiceResult<AuthenticationResponse>.Success(primaryResponse);
                    }
                    else
                    {
                        return ServiceResult<AuthenticationResponse>.Failure(
                            mfaResult.ErrorMessage ?? "MFA verification failed");
                    }
                }
                else
                {
                    // MFA 코드 미제공 - MFA Challenge 시작
                    var availableMethods = await GetAvailableMfaMethodsAsync(primaryResponse.UserId.Value);
                    
                    primaryResponse.RequiresMfa = true;
                    primaryResponse.MfaMethods = availableMethods;
                    primaryResponse.MfaVerified = false;
                    
                    // 첫 번째 가능한 방법으로 챌린지 시작
                    if (availableMethods.Count > 0)
                    {
                        var challengeResult = await _mfaService.InitiateMfaAsync(
                            primaryResponse.UserId.Value, 
                            availableMethods[0]);
                        
                        if (challengeResult.IsSuccess)
                        {
                            _logger.LogInformation("MFA challenge initiated for user {UserId}", primaryResponse.UserId.Value);
                        }
                    }
                    
                    return ServiceResult<AuthenticationResponse>.Success(primaryResponse);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MFA flow handling failed for user {UserId}", primaryResponse.UserId);
                return ServiceResult<AuthenticationResponse>.Failure("MFA processing failed");
            }
        }

        /// <summary>
        /// 사용 가능한 MFA 방법 조회 (캐싱 적용)
        /// </summary>
        private async Task<List<string>> GetAvailableMfaMethodsAsync(Guid userId)
        {
            try
            {
                var settings = await GetCachedMfaSettingsAsync(userId);
                if (settings.IsSuccess && settings.Data != null)
                {
                    return settings.Data.EnabledMethods?.ToList() ?? new List<string> { "totp" };
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get MFA methods for user {UserId}", userId);
            }
            
            return new List<string> { "totp" }; // 기본값
        }
        #endregion

        #region 인증 후 처리
        /// <summary>
        /// 인증 성공 후 처리 - 세션 갱신, 보안 이벤트 로깅 등
        /// </summary>
        private async Task PostAuthenticationProcessingAsync(
            AuthenticationRequest request, 
            AuthenticationResponse response)
        {
            try
            {
                if (!response.UserId.HasValue)
                    return;

                // 성공한 인증 시도 기록
                await _attemptService.LogSuccessfulAuthenticationAsync(
                    response.UserId.Value,
                    response.ConnectedId,
                    request.Method,
                    request.IpAddress ?? CommonDefaults.DefaultLocalIpV4,
                    request.UserAgent);

                // 신뢰할 수 있는 장치 확인 및 알림
                if (!string.IsNullOrEmpty(request.DeviceInfo?.DeviceId))
                {
                    var isTrusted = await _securityService.IsTrustedDeviceAsync(
                        response.UserId.Value, 
                        request.DeviceInfo.DeviceId);

                    if (isTrusted.IsSuccess && !isTrusted.Data)
                    {
                        // 새로운 디바이스에서의 로그인 - 알림 발송
                        await _attemptService.NotifyNewDeviceLoginAsync(
                            response.UserId.Value,
                            request.DeviceInfo.DeviceId,
                            request.DeviceInfo.Location ?? "Unknown");
                    }
                }

                // ConnectedId 활동 업데이트
                if (response.ConnectedId.HasValue)
                {
                    await _connectedIdService.UpdateLastActivityAsync(response.ConnectedId.Value);
                }

                _logger.LogInformation("Post-authentication processing completed for user {UserId}", response.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Post-authentication processing failed for user {UserId}", response.UserId);
                // 후처리 실패는 인증 성공을 무효화하지 않음
            }
        }
        #endregion

        #region 실패 처리
        /// <summary>
        /// 실패한 인증 시도 기록
        /// </summary>
        private async Task LogFailedAuthenticationAsync(AuthenticationRequest request, string reason)
        {
            try
            {
                var result = AuthenticationResult.InvalidCredentials; // 기본값
                
                // 실패 원인에 따른 결과 코드 매핑
                if (reason.Contains("locked", StringComparison.OrdinalIgnoreCase))
                    result = AuthenticationResult.AccountLocked;
                else if (reason.Contains("disabled", StringComparison.OrdinalIgnoreCase))
                    result = AuthenticationResult.AccountDisabled;
                else if (reason.Contains("mfa", StringComparison.OrdinalIgnoreCase))
                    result = AuthenticationResult.TwoFactorRequired;

                await _attemptService.LogFailedAuthenticationAsync(
                    request.Username ?? "unknown",
                    request.Method,
                    result,
                    request.IpAddress ?? CommonDefaults.DefaultLocalIpV4,
                    request.UserAgent);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log authentication failure");
            }
        }
        #endregion

        #region 사용자 등록
        /// <summary>
        /// 사용자 등록 - PasswordService로 위임
        /// </summary>
        public async Task<ServiceResult<AuthenticationResponse>> RegisterAsync(
            string email, 
            string password, 
            string displayName, 
            Guid? organizationId = null)
        {
            try
            {
                _logger.LogInformation("User registration attempt for email {Email}", email);
                
                var result = await _passwordService.RegisterAsync(email, password, displayName, organizationId);
                
                if (result.IsSuccess)
                {
                    _logger.LogInformation("User registration successful for email {Email}", email);
                }
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "User registration failed for email {Email}", email);
                return ServiceResult<AuthenticationResponse>.Failure("Registration failed");
            }
        }
        #endregion

        #region 로그아웃 처리
        /// <summary>
        /// 로그아웃 처리 - 세션과 토큰 정리
        /// </summary>
        public async Task<ServiceResult> LogoutAsync(Guid sessionId, bool revokeAllTokens = false)
        {
            try
            {
                _logger.LogInformation("Logout initiated for session {SessionId}", sessionId);

                // 세션 정보 먼저 조회 (ConnectedId 확인용)
                Guid? connectedId = null;
                if (revokeAllTokens)
                {
                    var sessionResult = await _sessionService.GetSessionAsync(sessionId);
                    if (sessionResult.IsSuccess && sessionResult.Data != null)
                    {
                        // AuthHive v15 철학: ConnectedId가 활동의 주체
                        connectedId = sessionResult.Data.ConnectedId;
                    }
                }

                // 세션 종료
                var endResult = await _sessionService.EndSessionAsync(sessionId, SessionEndReason.UserLogout);
                if (!endResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to end session {SessionId}: {Error}", sessionId, endResult.ErrorMessage);
                }

                // 모든 토큰 해지인 경우 - ConnectedId 기반으로 처리
                if (revokeAllTokens && connectedId.HasValue)
                {
                    // TODO: ConnectedId 기반 토큰 해지 로직 구현 필요
                    // AuthHive v15에서는 UserId 대신 ConnectedId로 토큰을 관리해야 함
                    _logger.LogInformation("Token revocation requested for ConnectedId {ConnectedId}", connectedId.Value);
                }

                // 캐시 정리 - ConnectedId 기반으로 수정 필요
                await ClearSessionCacheAsync(connectedId, sessionId);

                _logger.LogInformation("Logout completed for session {SessionId}", sessionId);
                return ServiceResult.Success("Logged out successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Logout failed for session {SessionId}", sessionId);
                return ServiceResult.Failure("Logout failed");
            }
        }

        /// <summary>
        /// 모든 세션에서 로그아웃
        /// </summary>
        public async Task<ServiceResult<int>> LogoutAllSessionsAsync(Guid userId, Guid? exceptSessionId = null)
        {
            try
            {
                _logger.LogInformation("Logout all sessions initiated for user {UserId}", userId);

                // ConnectedId를 통한 세션 조회 필요 - userId로 직접 조회는 불가능
                // 대신 사용자의 모든 ConnectedId를 찾아서 각각의 활성 세션을 조회해야 함
                
                int loggedOutCount = 0;
                
                // 모든 토큰 해지
                var revokeResult = await _tokenService.RevokeAllTokensForUserAsync(userId);
                if (revokeResult.IsSuccess && revokeResult.Data > 0)
                {
                    loggedOutCount = revokeResult.Data;
                    _logger.LogInformation("Revoked {Count} tokens for user {UserId}", loggedOutCount, userId);
                }

                // 사용자 관련 캐시 정리
                await ClearAllUserCacheAsync(userId);

                _logger.LogInformation("Logout all sessions completed for user {UserId}", userId);
                return ServiceResult<int>.Success(loggedOutCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Logout all sessions failed for user {UserId}", userId);
                return ServiceResult<int>.Failure("Failed to logout from all sessions");
            }
        }
        #endregion

        #region 패스워드 관리
        /// <summary>
        /// 패스워드 재설정 요청 - PasswordService로 위임
        /// </summary>
        public async Task<ServiceResult<PasswordResetToken>> RequestPasswordResetAsync(
            string email, 
            Guid? organizationId = null)
        {
            return await _passwordService.RequestPasswordResetAsync(email, organizationId);
        }

        /// <summary>
        /// 패스워드 재설정 완료 - PasswordService로 위임
        /// </summary>
        public async Task<ServiceResult> ResetPasswordAsync(string token, string newPassword)
        {
            return await _passwordService.ResetPasswordAsync(token, newPassword);
        }

        /// <summary>
        /// 패스워드 변경 - PasswordService로 위임
        /// </summary>
        public async Task<ServiceResult> ChangePasswordAsync(
            Guid userId, 
            string currentPassword, 
            string newPassword)
        {
            return await _passwordService.ChangePasswordAsync(userId, currentPassword, newPassword);
        }
        #endregion
    }
}