using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Services.Context;
using System.Security.Cryptography;
using System.Text;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache;


namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 계정 복구 요청 Repository 구현체 - AuthHive v16
    /// 비밀번호 재설정 등 계정 복구 프로세스를 관리합니다. ICacheService를 사용하도록 리팩토링되었습니다.
    /// </summary>
    /// <summary>
    /// 계정 복구 요청 Repository 구현체 - AuthHive v16
    /// </summary>
    public class AccountRecoveryRepository : BaseRepository<AccountRecoveryRequest>, IAccountRecoveryRepository
    {
        
        private readonly IOrganizationContext _organizationContext; // Store the context locally

        public AccountRecoveryRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext)
            : base(context)
        {

            _organizationContext = organizationContext ?? throw new ArgumentNullException(nameof(organizationContext));
        }

        // ✅ FIX 1: Implement the missing abstract method from BaseRepository.
        /// <summary>
        /// AccountRecoveryRequest 엔티티는 특정 조직에 속하므로,
        /// 멀티테넌시 필터링을 적용하기 위해 true를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            return true;
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

           var cacheKey = GetCacheKey($"token_{tokenHash}"); 
            AccountRecoveryRequest? cached = null;

            // 1. ✅ 캐시 조회 - ICacheService 널 체크 추가
            if (_cacheService != null) // 👈 널 체크 추가
            {
                try
                {
                    // _cacheService가 널이 아님을 보장하므로 GetAsync 호출은 안전합니다.
                    cached = await _cacheService.GetAsync<AccountRecoveryRequest>(cacheKey, cancellationToken);
                }
                catch { /* 캐시 실패 시 로그 후 무시 */ }
            }


            if (cached is not null)
            {
                var requestFromCache = cached;

                // 만료 및 완료 여부 재확인
                if (!requestFromCache.IsCompleted && requestFromCache.ExpiresAt > DateTime.UtcNow)
                    return requestFromCache;
                else
                {
                    // 2. ✅ 만료되었거나 완료된 요청은 ICacheService를 사용하여 비동기로 캐시에서 제거
                    // 널 체크가 바깥에 있으므로, 여기서도 _cacheService에 대한 널 체크를 다시 해주는 것이 좋습니다.
                    if (_cacheService != null)
                    {
                        _ = Task.Run(() => _cacheService.RemoveAsync(cacheKey, CancellationToken.None));
                    }
                    return null;
                }
            }

            // 데이터베이스에서 조회 (이 부분은 이전과 동일하게 널 무시 연산자 유지)
            var request = await Query()
                .Include(r => r.User!)
                .FirstOrDefaultAsync(r =>
                    r.TokenHash == tokenHash &&
                    !r.IsCompleted &&
                    r.ExpiresAt > DateTime.UtcNow,
                    cancellationToken)!;

            // 3. ✅ 데이터베이스 조회 후, ICacheService를 사용하여 비동기로 캐시에 저장
            if (request != null && _cacheService != null) // 👈 널 체크 추가
            {
                // 토큰 만료 시간까지 캐시 유지
                var cacheDuration = request.ExpiresAt - DateTime.UtcNow;

                if (cacheDuration > TimeSpan.Zero)
                {
                    _ = Task.Run(() =>
                        _cacheService.SetAsync(key: cacheKey, value: request, expiration: cacheDuration, CancellationToken.None));
                }
            }

            return request;
        }
        /// <summary>
        /// 특정 사용자의 모든 대기 중인 복구 요청을 무효화합니다.
        /// </summary>
        public async Task<int> InvalidatePendingRequestsForUserAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            // 활성 요청들 조회 (cancellationToken 전달)
            var pendingRequests = await Query()
                .Where(r =>
                    r.UserId == userId &&
                    !r.IsCompleted &&
                    r.ExpiresAt > now)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            if (!pendingRequests.Any())
                return 0;

            // 모든 요청을 완료 상태로 표시
            foreach (var request in pendingRequests)
            {
                request.IsCompleted = true;
                request.CompletedAt = now;
                request.UpdatedAt = now;

                // 4. ✅ 캐시에서 제거 (ICacheService 사용)
                var cacheKey = GetCacheKey($"token_{request.TokenHash}"); 

                // 🚨 CS8602 해결: _cacheService가 null이 아닐 때만 RemoveAsync 호출
                if (_cacheService != null)
                {
                    await _cacheService.RemoveAsync(cacheKey, cancellationToken); // 👈 CancellationToken 전달
                }
            }

            // UpdateRangeAsync는 BaseRepository에 정의되어 있으므로, CancellationToken을 받는 시그니처를 가정합니다.
            await UpdateRangeAsync(pendingRequests, cancellationToken);

            // SaveChangesAsync에도 CancellationToken 전달
            await _context.SaveChangesAsync(cancellationToken);

            return pendingRequests.Count;
        }
        /// <summary>
        /// 복구 요청을 완료 처리합니다.
        /// </summary>
        public async Task<bool> CompleteRecoveryRequestAsync(
            Guid requestId,
            string completionIpAddress,
            CancellationToken cancellationToken = default)
        {
            // GetByIdAsync는 BaseRepository에 정의되어 있으며, AccountRecoveryRequest?를 반환한다고 가정
            var request = await GetByIdAsync(requestId, cancellationToken);

            // 널 체크
            if (request == null || request.IsCompleted)
                return false;

            // 널이 아님이 보장되었으므로, 속성 접근은 안전합니다.
            request.IsCompleted = true;
            request.CompletedAt = DateTime.UtcNow;
            request.CompletionIpAddress = completionIpAddress;
            request.UpdatedAt = DateTime.UtcNow;

            // 5. ✅ 캐시에서 제거 (ICacheService 사용)
            // 🚨 CS8602 해결 1: _cacheService 널 체크
            if (_cacheService != null)
            {
                // 🚨 CS8602 해결 2: request가 널이 아님을 보장하므로 TokenHash 접근은 안전합니다.
                var cacheKey = GetCacheKey($"token_{request.TokenHash}");

                // request.TokenHash가 required string이므로 널일 가능성이 없지만, 
                // _cacheService가 널이 아닐 때만 호출해야 합니다.
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }

            await UpdateAsync(request, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            return true;
        }
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
            await InvalidatePendingRequestsForUserAsync(userId); // 내부적으로 캐시 제거 로직 포함

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

            // 참고: AddAsync가 호출되지만, FindActiveByTokenHashAsync에서만 캐시를 사용하므로 여기서 SetAsync를 호출할 필요는 없습니다.

            return (request, token);
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
        // RecoveryRequestStatistics 클래스 정의는 생략됨.

        // --- Helper Methods는 그대로 유지합니다 ---

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

        // #endregion
    }

}