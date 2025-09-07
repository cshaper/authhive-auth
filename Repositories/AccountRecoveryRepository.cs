using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using System.Security.Cryptography;
using System.Text;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 계정 복구 요청 Repository 구현체 - AuthHive v15
    /// 비밀번호 재설정 등 계정 복구 프로세스를 관리합니다.
    /// </summary>
    public class AccountRecoveryRepository : BaseRepository<AccountRecoveryRequest>, IAccountRecoveryRepository
    {
        private const string CACHE_KEY_PREFIX = "account_recovery_";
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);

        public AccountRecoveryRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        /// <summary>
        /// 해시된 토큰 값으로 활성 복구 요청을 찾습니다.
        /// </summary>
        public async Task<AccountRecoveryRequest?> FindActiveByTokenHashAsync(
            string tokenHash, 
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(tokenHash))
                return null;

            // 캐시 확인
            var cacheKey = $"{CACHE_KEY_PREFIX}token_{tokenHash}";
            if (_cache != null && _cache.TryGetValue<AccountRecoveryRequest>(cacheKey, out var cached) && cached != null)
            {
                // 만료 및 완료 여부 재확인
                if (!cached.IsCompleted && cached.ExpiresAt > DateTime.UtcNow)
                    return cached;
                else
                {
                    _cache.Remove(cacheKey);
                    return null;
                }
            }

            // 데이터베이스에서 조회
            var request = await Query()
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => 
                    r.TokenHash == tokenHash && 
                    !r.IsCompleted && 
                    r.ExpiresAt > DateTime.UtcNow,
                    cancellationToken);

            // 캐시에 저장
            if (request != null && _cache != null)
            {
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = request.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(1)
                };
                _cache.Set(cacheKey, request, cacheOptions);
            }

            return request;
        }

        /// <summary>
        /// 특정 사용자의 모든 대기 중인 복구 요청을 무효화합니다.
        /// </summary>
        public async Task<int> InvalidatePendingRequestsForUserAsync(Guid userId)
        {
            var now = DateTime.UtcNow;
            
            // 활성 요청들 조회
            var pendingRequests = await Query()
                .Where(r => 
                    r.UserId == userId && 
                    !r.IsCompleted && 
                    r.ExpiresAt > now)
                .ToListAsync();

            if (!pendingRequests.Any())
                return 0;

            // 모든 요청을 완료 상태로 표시
            foreach (var request in pendingRequests)
            {
                request.IsCompleted = true;
                request.CompletedAt = now;
                request.UpdatedAt = now;
                
                // 캐시에서 제거
                if (_cache != null)
                {
                    var cacheKey = $"{CACHE_KEY_PREFIX}token_{request.TokenHash}";
                    _cache.Remove(cacheKey);
                }
            }

            await UpdateRangeAsync(pendingRequests);
            await _context.SaveChangesAsync();

            return pendingRequests.Count;
        }

        #region 추가 메서드

        /// <summary>
        /// 새 계정 복구 요청을 생성합니다.
        /// </summary>
        public async Task<(AccountRecoveryRequest request, string token)> CreateRecoveryRequestAsync(
            Guid userId,
            string requestIpAddress,
            int validityMinutes = 30,
            CancellationToken cancellationToken = default)
        {
            // 기존 대기 중인 요청 무효화
            await InvalidatePendingRequestsForUserAsync(userId);

            // 랜덤 토큰 생성
            var token = GenerateSecureToken();
            var tokenHash = HashToken(token);

            var user = await _context.Set<Core.Entities.User.User>()
                .FirstAsync(u => u.Id == userId, cancellationToken);

            var request = new AccountRecoveryRequest
            {
                UserId = userId,
                TokenHash = tokenHash,
                ExpiresAt = DateTime.UtcNow.AddMinutes(validityMinutes),
                IsCompleted = false,
                RequestIpAddress = requestIpAddress,
                User = user
            };

            await AddAsync(request);
            await _context.SaveChangesAsync(cancellationToken);

            return (request, token);
        }

        /// <summary>
        /// 복구 요청을 완료 처리합니다.
        /// </summary>
        public async Task<bool> CompleteRecoveryRequestAsync(
            Guid requestId,
            string completionIpAddress,
            CancellationToken cancellationToken = default)
        {
            var request = await GetByIdAsync(requestId);
            
            if (request == null || request.IsCompleted)
                return false;

            request.IsCompleted = true;
            request.CompletedAt = DateTime.UtcNow;
            request.CompletionIpAddress = completionIpAddress;
            request.UpdatedAt = DateTime.UtcNow;

            // 캐시에서 제거
            if (_cache != null)
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}token_{request.TokenHash}";
                _cache.Remove(cacheKey);
            }

            await UpdateAsync(request);
            await _context.SaveChangesAsync(cancellationToken);

            return true;
        }

        /// <summary>
        /// 사용자의 최근 복구 요청 이력을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<AccountRecoveryRequest>> GetRecentRequestsByUserAsync(
            Guid userId,
            int days = 30,
            CancellationToken cancellationToken = default)
        {
            var fromDate = DateTime.UtcNow.AddDays(-days);
            
            return await Query()
                .Where(r => r.UserId == userId && r.CreatedAt >= fromDate)
                .OrderByDescending(r => r.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료된 요청들을 정리합니다.
        /// </summary>
        public async Task<int> CleanupExpiredRequestsAsync(
            CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-7); // 7일 이상 지난 요청 삭제

            var expiredRequests = await Query()
                .Where(r => r.ExpiresAt < cutoffDate || 
                           (r.IsCompleted && r.CompletedAt < cutoffDate))
                .ToListAsync(cancellationToken);

            if (expiredRequests.Any())
            {
                await DeleteRangeAsync(expiredRequests);
                await _context.SaveChangesAsync(cancellationToken);
            }

            return expiredRequests.Count;
        }

        /// <summary>
        /// IP 주소별 복구 요청 빈도를 확인합니다. (브루트포스 방지)
        /// </summary>
        public async Task<int> GetRequestCountByIpAsync(
            string ipAddress,
            TimeSpan timeWindow,
            CancellationToken cancellationToken = default)
        {
            var fromDate = DateTime.UtcNow.Subtract(timeWindow);
            
            return await Query()
                .CountAsync(r => 
                    r.RequestIpAddress == ipAddress && 
                    r.CreatedAt >= fromDate,
                    cancellationToken);
        }

        /// <summary>
        /// 사용자별 복구 요청 빈도를 확인합니다. (남용 방지)
        /// </summary>
        public async Task<int> GetRequestCountByUserAsync(
            Guid userId,
            TimeSpan timeWindow,
            CancellationToken cancellationToken = default)
        {
            var fromDate = DateTime.UtcNow.Subtract(timeWindow);
            
            return await Query()
                .CountAsync(r => 
                    r.UserId == userId && 
                    r.CreatedAt >= fromDate,
                    cancellationToken);
        }

        /// <summary>
        /// 복구 요청 통계를 조회합니다.
        /// </summary>
        public async Task<RecoveryRequestStatistics> GetStatisticsAsync(
            DateTime? fromDate = null,
            DateTime? toDate = null,
            CancellationToken cancellationToken = default)
        {
            fromDate ??= DateTime.UtcNow.AddDays(-30);
            toDate ??= DateTime.UtcNow;

            var requests = await Query()
                .Where(r => r.CreatedAt >= fromDate && r.CreatedAt <= toDate)
                .ToListAsync(cancellationToken);

            return new RecoveryRequestStatistics
            {
                TotalRequests = requests.Count,
                CompletedRequests = requests.Count(r => r.IsCompleted),
                ExpiredRequests = requests.Count(r => !r.IsCompleted && r.ExpiresAt < DateTime.UtcNow),
                PendingRequests = requests.Count(r => !r.IsCompleted && r.ExpiresAt >= DateTime.UtcNow),
                AverageCompletionTimeMinutes = requests
                    .Where(r => r.IsCompleted && r.CompletedAt.HasValue)
                    .Select(r => (r.CompletedAt!.Value - r.CreatedAt).TotalMinutes)
                    .DefaultIfEmpty(0)
                    .Average(),
                FromDate = fromDate.Value,
                ToDate = toDate.Value
            };
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 토큰 값을 SHA256으로 해시합니다.
        /// </summary>
        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// 암호학적으로 안전한 랜덤 토큰을 생성합니다.
        /// </summary>
        private string GenerateSecureToken(int length = 32)
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[length];
            rng.GetBytes(bytes);
            
            // URL-safe Base64 인코딩
            return Convert.ToBase64String(bytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");
        }

        #endregion
    }

    /// <summary>
    /// 복구 요청 통계
    /// </summary>
    public class RecoveryRequestStatistics
    {
        public int TotalRequests { get; set; }
        public int CompletedRequests { get; set; }
        public int ExpiredRequests { get; set; }
        public int PendingRequests { get; set; }
        public double AverageCompletionTimeMinutes { get; set; }
        public DateTime FromDate { get; set; }
        public DateTime ToDate { get; set; }
        
        public double CompletionRate => 
            TotalRequests > 0 ? (double)CompletedRequests / TotalRequests * 100 : 0;
    }
}