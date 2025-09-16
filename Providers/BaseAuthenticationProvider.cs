// Providers/Authentication/BaseAuthenticationProvider.cs
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AuthHive.Auth.Providers.Authentication
{
    public abstract class BaseAuthenticationProvider : IAuthenticationProvider
    {
        protected readonly ILogger _logger;
        protected readonly IDistributedCache _cache;
        protected readonly IAuthenticationAttemptLogRepository _attemptLogRepository;
        protected readonly ISessionService _sessionService;
        protected readonly IConnectedIdService _connectedIdService;
        protected readonly AuthDbContext _context;
        
        public abstract string ProviderName { get; }
        public abstract string ProviderType { get; }
        
        protected BaseAuthenticationProvider(
            ILogger logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context)
        {
            _logger = logger;
            _cache = cache;
            _attemptLogRepository = attemptLogRepository;
            _sessionService = sessionService;
            _connectedIdService = connectedIdService;
            _context = context;
        }
        
        public async Task<ServiceResult<AuthenticationOutcome>> AuthenticateAsync(
            AuthenticationRequest request)
        {
            // 1. Rate limiting 체크
            var rateLimitResult = await CheckRateLimitAsync(request);
            if (!rateLimitResult)
            {
                await LogFailedAttemptAsync(request, AuthenticationResult.TooManyAttempts);
                return ServiceResult<AuthenticationOutcome>.Failure("Too many attempts. Please try again later.");
            }
            
            // 2. 계정 잠금 확인
            var lockStatus = await CheckAccountLockAsync(request);
            if (lockStatus.IsLocked)
            {
                await LogFailedAttemptAsync(request, AuthenticationResult.AccountLocked);
                return ServiceResult<AuthenticationOutcome>.Failure($"Account is locked until {lockStatus.UnlockedAt}");
            }
            
            // 3. 실제 인증 수행
            var authResult = await PerformAuthenticationAsync(request);
            
            // 4. 인증 시도 로깅
            await LogAuthenticationAttemptAsync(request, authResult);
            
            // 5. 성공 시 후처리
            if (authResult.IsSuccess && authResult.Data != null)
            {
                // ConnectedId 업데이트
                if (authResult.Data.ConnectedId.HasValue)
                {
                    await UpdateConnectedIdLastActivityAsync(authResult.Data.ConnectedId.Value);
                }
                
                // 연속 실패 카운터 초기화
                if (authResult.Data.UserId.HasValue)
                {
                    await _attemptLogRepository.ResetConsecutiveFailuresAsync(authResult.Data.UserId.Value);
                }
            }
            
            return authResult;
        }
        
        protected abstract Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request);
        
        protected virtual async Task<bool> CheckRateLimitAsync(AuthenticationRequest request)
        {
            // IP 기반 rate limiting
            var key = $"rate_limit:{request.IpAddress}";
            var attempts = await _cache.GetStringAsync(key);
            
            if (int.TryParse(attempts, out var count) && count >= 10)
            {
                return false;
            }
            
            await _cache.SetStringAsync(key, (count + 1).ToString(), 
                new DistributedCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromMinutes(15)
                });
            
            return true;
        }
        
        protected virtual async Task<AccountLockStatus> CheckAccountLockAsync(
            AuthenticationRequest request)
        {
            // UserProfile로 사용자 찾기
            var userProfile = await FindUserProfileAsync(request);
            if (userProfile == null) return new AccountLockStatus { IsLocked = false };
            
            // 연속 실패 횟수 확인
            var failureCount = await _attemptLogRepository.GetConsecutiveFailureCountAsync(userProfile.User.Id);
            
            if (failureCount >= 5)
            {
                return new AccountLockStatus 
                { 
                    IsLocked = true,
                    UnlockedAt = DateTime.UtcNow.AddMinutes(30)
                };
            }
            
            return new AccountLockStatus { IsLocked = false };
        }
        
        protected async Task LogAuthenticationAttemptAsync(
            AuthenticationRequest request,
            ServiceResult<AuthenticationOutcome> result)
        {
            var userProfile = await FindUserProfileAsync(request);
            
            var attemptLog = new AuthenticationAttemptLog
            {
                UserId = userProfile?.User?.Id,
                Username = request.Username,  // Email 필드가 없으므로 Username만 사용
                ApplicationId = request.ApplicationId,
                Method = request.Method,
                Provider = ProviderName,
                IpAddress = request.IpAddress ?? "Unknown",
                UserAgent = request.UserAgent,
                // DeviceFingerprint 필드가 AuthenticationAttemptLog에 없으므로 제거
                IsSuccess = result.IsSuccess && result.Data?.Success == true,
                FailureReason = result.IsSuccess ? null : AuthenticationResult.InvalidCredentials,
                AttemptedAt = DateTime.UtcNow,
                RiskScore = CalculateRiskScore(request),
                IsSuspicious = await DetectSuspiciousActivityAsync(request)
            };
            
            // OrganizationId 설정
            if (request.OrganizationId.HasValue)
            {
                attemptLog.OrganizationId = request.OrganizationId.Value;
            }
            
            if (result.IsSuccess && result.Data?.SessionId != null)
            {
                attemptLog.SessionId = result.Data.SessionId;
            }
            
            if (result.Data?.RequiresMfa == true)
            {
                attemptLog.MfaRequired = true;
                // MfaMethod 필드가 AuthenticationAttemptLog에 없으므로 MfaCompleted 사용
                attemptLog.MfaCompleted = result.Data.MfaVerified;
            }
            
            await _attemptLogRepository.AddAsync(attemptLog);
        }
        
        protected abstract Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request);
        
        public abstract Task<ServiceResult<bool>> ValidateAsync(string token);
        public abstract Task<ServiceResult> RevokeAsync(string token);
        public abstract Task<bool> IsEnabledAsync();
        
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
            
            if (request.OrganizationId.HasValue)
            {
                attemptLog.OrganizationId = request.OrganizationId.Value;
            }
            
            await _attemptLogRepository.AddAsync(attemptLog);
        }
        
        private int CalculateRiskScore(AuthenticationRequest request)
        {
            // 간단한 리스크 점수 계산 로직
            int score = 0;
            
            // 새로운 IP/Device
            if (request.DeviceInfo == null || string.IsNullOrEmpty(request.DeviceInfo.DeviceId))
                score += 20;
            
            // 비정상 시간대 (새벽 2-5시)
            var hour = DateTime.UtcNow.Hour;
            if (hour >= 2 && hour <= 5)
                score += 30;
            
            return Math.Min(score, 100);
        }
        
        private async Task<bool> DetectSuspiciousActivityAsync(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.IpAddress))
                return false;
                
            // 최근 실패 시도 패턴 확인
            var recentFailures = await _attemptLogRepository.GetByIpAddressAsync(
                request.IpAddress,
                DateTime.UtcNow.AddMinutes(-30));
            
            return recentFailures.Count() > 5;
        }
        
        private async Task UpdateConnectedIdLastActivityAsync(Guid connectedId)
        {
            var entity = await _context.ConnectedIds.FindAsync(connectedId);
            if (entity != null)
            {
                entity.LastActiveAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
            }
        }
    }
    
    public class AccountLockStatus
    {
        public bool IsLocked { get; set; }
        public DateTime? UnlockedAt { get; set; }
    }
}