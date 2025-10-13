using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // 💡 ICacheService 네임스페이스 추가
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Security;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Auth.Events;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 인증 시도 로그 저장소 구현 - AuthHive v15 (보안 감사 및 분석에 사용)
    /// </summary>
    public class AuthenticationAttemptLogRepository : BaseRepository<AuthenticationAttemptLog>,
        IAuthenticationAttemptLogRepository
    {
        private readonly ILogger<AuthenticationAttemptLogRepository> _logger;
        private readonly IOrganizationContext _organizationContext;
        private readonly IEventBus _eventBus;
        /// <summary>
        /// Repository 생성자. BaseRepository의 규칙에 따라 DbContext와 ICacheService를 주입받습니다.
        /// </summary>
        public AuthenticationAttemptLogRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<AuthenticationAttemptLogRepository> logger,
            IEventBus eventBus,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _organizationContext = organizationContext ?? throw new ArgumentNullException(nameof(organizationContext));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
        }

        /// <summary>
        /// BaseRepository<TEntity>의 추상 멤버 구현.
        /// 인증 시도 로그(AuthenticationAttemptLog)는 특정 조직의 보안 로그이므로 true를 반환하여 
        /// 멀티테넌시 필터링(조직 스코핑)을 강제합니다. (CS0534 에러 해결)
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            return true;
        }

        #region 조회 메서드 - BaseRepository 활용

        /// <summary>
        /// 사용자의 최근 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetRecentAttemptsAsync(
            Guid userId, int count = 10, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(x => x.UserId == userId)
                .OrderByDescending(x => x.AttemptedAt)
                .Take(Math.Min(count, 100)) // DOS 방지
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 특정 사용자의 인증 기록을 기간별로 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetHistoryForUserAsync(
            Guid userId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.UserId == userId);

            // startDate가 null이 아닐 때만 기간 필터링을 추가
            if (startDate.HasValue)
            {
                query = query.Where(log => log.AttemptedAt >= startDate.Value);
            }

            // endDate가 null이 아닐 때만 기간 필터링을 추가
            if (endDate.HasValue)
            {
                query = query.Where(log => log.AttemptedAt <= endDate.Value);
            }

            return await query
                .OrderByDescending(log => log.AttemptedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 사용자명으로 인증 시도 조회 - 캐시 가능한 조회 (주로 로그인 실패 횟수 계산용)
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByUsernameAsync(
            string username,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username))
                return Enumerable.Empty<AuthenticationAttemptLog>();

            // 캐시 키 생성 (since가 null이거나 최근 1시간 이내인 경우만 캐시)
            bool canCache = since == null || (since.HasValue && since.Value > DateTime.UtcNow.AddHours(-1));
            string? cacheKey = canCache ? $"Username_{username}_{since?.Ticks ?? 0}" : null;

            if (canCache && cacheKey != null && _cacheService != null)
            {
                var cached = await _cacheService.GetAsync<IEnumerable<AuthenticationAttemptLog>>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    return cached;
                }
            }

            var query = Query().Where(x => x.Username == username);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var result = await query
                         .OrderByDescending(x => x.AttemptedAt)
                         .Take(1000) // 대량 데이터 방지
                         .ToListAsync(cancellationToken);

            // 캐시 저장 (5분간)
            if (canCache && cacheKey != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(5));
            }

            return result;
        }
        /// <summary>
        /// 지정된 날짜 이전의 오래된 인증 시도 로그를 비활성화(Soft Delete)합니다.
        /// </summary>
        /// <param name="before">이 날짜/시간 이전에 발생한 로그를 정리합니다.</param>
        /// <param name="cancellationToken">작업 취소 토큰입니다.</param>
        /// <returns>정리된 로그의 개수입니다.</returns>
        public async Task<int> CleanupOldLogsAsync(DateTime before, CancellationToken cancellationToken = default)
        {
            // 💡 EF Core 7.0의 ExecuteUpdateAsync를 사용하여 데이터베이스에서 직접 대량 업데이트를 수행합니다.
            // 이는 엔티티를 메모리로 로드하지 않으므로 매우 효율적입니다.

            int totalDeleted = await Query()
                .Where(log => log.AttemptedAt < before && !log.IsDeleted) // 'before' 이전의 삭제되지 않은 로그를 대상으로 지정
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(log => log.IsDeleted, true)      // IsDeleted 플래그를 true로 설정
                    .SetProperty(log => log.DeletedAt, DateTime.UtcNow), // 삭제 시간을 현재 UTC로 기록
                cancellationToken);

            if (totalDeleted > 0)
            {
                // 정리 작업이 성공적으로 수행되었을 때 정보 로그를 남깁니다.
                _logger.LogInformation("Completed soft cleanup: {Count} logs marked as deleted that occurred before {Date}",
                    totalDeleted, before);
            }

            return totalDeleted;
        }
        /// <summary>
        /// 조직별 인증 시도 조회 - BaseRepository의 조직 스코핑 활용
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByOrganizationAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 조직별 조회 활용 (BaseRepository 내부의 QueryForOrganization을 사용한다고 가정)
            var query = QueryForOrganization(organizationId);

            if (startDate.HasValue)
                query = query.Where(x => x.AttemptedAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(x => x.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 애플리케이션별 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByApplicationAsync(
            Guid applicationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.ApplicationId == applicationId);

            if (startDate.HasValue)
                query = query.Where(x => x.AttemptedAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(x => x.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// IP 주소별 인증 시도 조회 - 보안상 중요하므로 캐시 적용
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return Enumerable.Empty<AuthenticationAttemptLog>();

            // 최근 1시간 데이터는 캐시 (보안 분석용)
            bool canCache = since == null || (since.HasValue && since.Value > DateTime.UtcNow.AddHours(-1));
            string? cacheKey = canCache ? $"IpAddress_{ipAddress}_{since?.Ticks ?? 0}" : null;

            // ✅ _cacheService.GetAsync<T> 사용
            if (canCache && cacheKey != null && _cacheService != null)
            {
                var cached = await _cacheService.GetAsync<IEnumerable<AuthenticationAttemptLog>>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    return cached;
                }
            }
            var query = Query().Where(x => x.IpAddress == ipAddress);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var result = await query
                           .OrderByDescending(x => x.AttemptedAt)
                           .Take(1000) // 보안상 제한
                           .ToListAsync(cancellationToken);

            if (canCache && cacheKey != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(10));
            }

            return result;
        }

        /// <summary>
        /// 인증 방법별 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByMethodAsync(
            AuthenticationMethod method,
            DateTime? since = null,
            bool? successOnly = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.Method == method);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            if (successOnly.HasValue)
                query = query.Where(x => x.IsSuccess == successOnly.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region 실패 분석 - 최적화된 쿼리

        /// <summary>
        /// 실패한 인증 시도 횟수 조회 - 단순 카운트로 최적화
        /// </summary>
        public async Task<int> GetFailedAttemptCountAsync(Guid userId, DateTime since, CancellationToken cancellationToken = default)
        {
            // BaseRepository의 CountAsync를 사용한다고 가정
            // (BaseRepository에 해당 메서드가 정의되어 있어야 함)
            return await CountAsync(x =>
                x.UserId == userId &&
                !x.IsSuccess &&
                x.AttemptedAt >= since, cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 연속 실패 횟수 조회 - 최적화된 로직 (로그인 잠금 정책 판단에 사용)
        /// </summary>
        public async Task<int> GetConsecutiveFailureCountAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            // 캐시 확인 (자주 호출되는 메서드)
            string cacheKey = $"ConsecutiveFailure_{userId}";

            if (_cacheService != null)
            {
                // ✅ ICacheService.GetStringAsync을 사용하여 string으로 가져온 후 int로 변환 (참조 타입 제약 CS0452 우회)
                var cachedString = await _cacheService.GetStringAsync(cacheKey, cancellationToken);

                if (!string.IsNullOrEmpty(cachedString) && int.TryParse(cachedString, out int cachedCount))
                {
                    if (cachedCount > 0)
                    {
                        return cachedCount;
                    }
                }
            }


            // 마지막 성공 이후의 실패만 조회하도록 최적화 (DB 쿼리 1)
            var lastSuccess = await Query()
                .Where(x => x.UserId == userId && x.IsSuccess)
                .OrderByDescending(x => x.AttemptedAt)
                .Select(x => x.AttemptedAt)
                .FirstOrDefaultAsync(cancellationToken); // 👈 CancellationToken 전달

            var failureQuery = Query().Where(x => x.UserId == userId && !x.IsSuccess);

            if (lastSuccess != default)
            {
                failureQuery = failureQuery.Where(x => x.AttemptedAt > lastSuccess);
            }

            // 실패 횟수 카운트 (DB 쿼리 2)
            var count = await failureQuery.CountAsync(cancellationToken);

            // 5분간 캐시
            // 💡 CS0103 및 동기 Set 호출 에러 해결: _cacheService.SetStringAsync 사용
            if (count > 0 && _cacheService != null)
            {
                // int 값을 string으로 변환하여 SetStringAsync로 저장
                await _cacheService.SetStringAsync(cacheKey, count.ToString(), TimeSpan.FromMinutes(5), cancellationToken);
            }

            return count;
        }

        /// <summary>
        /// 실패한 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            query = query.OrderByDescending(x => x.AttemptedAt);

            // 안전한 제한값 설정
            int safeLimit = Math.Min(limit ?? 100, 1000);
            query = query.Take(safeLimit);

            return await query.ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 실패 사유별 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByFailureReasonAsync(
            AuthenticationResult reason,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.FailureReason == reason && !x.IsSuccess);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000) // 제한
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 계정 잠금을 트리거한 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetLockTriggerAttemptsAsync(
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.TriggeredAccountLock);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region 보안 분석 - 캐시 최적화

        /// <summary>
        /// 의심스러운 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetSuspiciousAttemptsAsync(
            Guid? organizationId = null,
            DateTime? since = null,
            int? minRiskScore = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.IsSuspicious);

            if (organizationId.HasValue)
                query = query.Where(x => x.OrganizationId == organizationId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            if (minRiskScore.HasValue)
                query = query.Where(x => x.RiskScore >= minRiskScore.Value);

            return await query
                .OrderByDescending(x => x.RiskScore)
                .ThenByDescending(x => x.AttemptedAt)
                .Take(500) // 분석 데이터 제한
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 브루트포스 공격 패턴 감지 - 최적화된 그룹화 쿼리 (보안 분석에 사용)
        /// </summary>
        public async Task<IEnumerable<BruteForcePattern>> DetectBruteForceAttacksAsync(
            DateTime since,
            int threshold = 5,
            CancellationToken cancellationToken = default)
        {
            // 캐시 확인 (10분간 캐시)
            string cacheKey = $"BruteForce_{since.Ticks}_{threshold}";

            // ✅ _cacheService와 GetAsync를 사용하여 CS0103 및 CS1929 에러 해결
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<IEnumerable<BruteForcePattern>>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    return cached;
                }
            }

            var patterns = await Query()
                .Where(x => x.AttemptedAt >= since && !x.IsSuccess)
                .GroupBy(x => new { x.IpAddress, x.Username })
                .Where(g => g.Count() >= threshold)
                .Select(g => new BruteForcePattern
                {
                    IpAddress = g.Key.IpAddress ?? string.Empty, // Null 방지
                    Username = g.Key.Username,
                    AttemptCount = g.Count(),
                    FirstAttempt = g.Min(x => x.AttemptedAt),
                    LastAttempt = g.Max(x => x.AttemptedAt)
                })
                .OrderByDescending(x => x.AttemptCount)
                .Take(100) // 상위 100개만
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            // 캐시 저장
            if (_cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, patterns, TimeSpan.FromMinutes(10));
            }

            return patterns;
        }

        /// <summary>
        /// 이상 접근 패턴 감지 - 모듈화된 접근 (내부 헬퍼 메서드 활용)
        /// </summary>
        public async Task<IEnumerable<AnomalyPattern>> DetectAnomaliesAsync(
            Guid? userId = null,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var tasks = new List<Task<IEnumerable<AnomalyPattern>>>
            {
                // 헬퍼 메서드에 CancellationToken 전달 필요
                DetectMultipleIpAccessAsync(userId, since, cancellationToken),
                DetectUnusualTimeAccessAsync(userId, since, cancellationToken),
                DetectGeographicalAnomaliesAsync(userId, since, cancellationToken)
            };

            var results = await Task.WhenAll(tasks); // 👈 Task.WhenAll을 통한 병렬 실행
            var allAnomalies = results.SelectMany(x => x).ToList();

            return allAnomalies.OrderByDescending(x => x.RiskScore);
        }

        /// <summary>
        /// 위험 IP 주소 목록 조회 - 최적화된 그룹화 (반복적인 실패를 야기한 IP 목록)
        /// </summary>
        public async Task<IEnumerable<RiskyIpAddress>> GetRiskyIpAddressesAsync(
            int failureThreshold = 10,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .GroupBy(x => x.IpAddress)
                .Where(g => g.Count() >= failureThreshold)
                .Select(g => new RiskyIpAddress
                {
                    IpAddress = g.Key ?? string.Empty, // Null 방지
                    FailureCount = g.Count(),
                    // Null UserId 필터링 후 고유 사용자 수 카운트
                    UniqueUserCount = g.Where(x => x.UserId != null).Select(x => x.UserId).Distinct().Count(),
                    FirstSeen = g.Min(x => x.AttemptedAt),
                    LastSeen = g.Max(x => x.AttemptedAt)
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(100)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region 통계 - BaseRepository의 통계 기능 활용

        /// <summary>
        /// 인증 시도 통계 조회
        /// </summary>
        public async Task<AuthenticationStatistics> GetStatisticsAsync(
            DateTime from,
            DateTime to,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Where(x => x.AttemptedAt >= from && x.AttemptedAt <= to);

            var attempts = await query.ToListAsync(cancellationToken); // 👈 CancellationToken 전달

            // BaseRepository의 GetGroupCountAsync 활용 가능
            // (BaseRepository에 해당 메서드가 정의되어 있다고 가정)
            var methodStats = await GetGroupCountAsync(
                x => x.Method,
                x => x.AttemptedAt >= from && x.AttemptedAt <= to &&
                      (!organizationId.HasValue || x.OrganizationId == organizationId.Value),
                cancellationToken); // 👈 CancellationToken 전달

            var failureReasons = attempts
                .Where(x => !x.IsSuccess && x.FailureReason.HasValue)
                .GroupBy(x => x.FailureReason!.Value)
                .ToDictionary(g => g.Key, g => g.Count());

            return new AuthenticationStatistics
            {
                TotalAttempts = attempts.Count,
                SuccessfulAttempts = attempts.Count(x => x.IsSuccess),
                FailedAttempts = attempts.Count(x => !x.IsSuccess),
                SuccessRate = attempts.Any() ? (double)attempts.Count(x => x.IsSuccess) / attempts.Count : 0,
                AttemptsByMethod = methodStats,
                FailureReasons = failureReasons
            };
        }

        /// <summary>
        /// 시간대별 인증 시도 분포
        /// </summary>
        public async Task<Dictionary<int, int>> GetHourlyDistributionAsync(
            DateTime date,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var startDate = date.Date;
            var endDate = startDate.AddDays(1);

            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            var distribution = await query
                .Where(x => x.AttemptedAt >= startDate && x.AttemptedAt < endDate)
                .GroupBy(x => x.AttemptedAt.Hour)
                .Select(g => new { Hour = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Hour, x => x.Count, cancellationToken); // 👈 CancellationToken 전달

            // 모든 시간대 포함
            var result = new Dictionary<int, int>();
            for (int i = 0; i < 24; i++)
            {
                result[i] = distribution.TryGetValue(i, out int count) ? count : 0;
            }

            return result;
        }

        /// <summary>
        /// 인증 방법별 성공률
        /// </summary>
        public async Task<Dictionary<AuthenticationMethod, double>> GetSuccessRateByMethodAsync(
            DateTime? since = null,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .GroupBy(x => x.Method)
                .Select(g => new
                {
                    Method = g.Key,
                    Total = g.Count(),
                    Success = g.Count(x => x.IsSuccess)
                })
                .ToDictionaryAsync(
                    x => x.Method,
                    x => x.Total > 0 ? (double)x.Success / x.Total : 0,
                    cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 상위 실패 사용자 조회
        /// </summary>
        public async Task<IEnumerable<UserFailureStatistics>> GetTopFailedUsersAsync(
            int topCount = 10,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess && x.UserId != null);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .GroupBy(x => new { x.UserId, x.Username })
                .Where(g => g.Key.UserId.HasValue) // 추가 null 체크
                .Select(g => new UserFailureStatistics
                {
                    UserId = g.Key.UserId!.Value,
                    Username = g.Key.Username ?? string.Empty,
                    FailureCount = g.Count(),
                    LastFailure = g.Max(x => x.AttemptedAt),
                    IsAccountLocked = false // 외부 정보이므로, 여기서는 기본값 사용
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(Math.Min(topCount, 50)) // 안전한 제한
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region MFA 관련

        /// <summary>
        /// MFA 요구된 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetMfaRequiredAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.MfaRequired);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// MFA 성공률 조회
        /// </summary>
        public async Task<double> GetMfaSuccessRateAsync(
            DateTime? since = null,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Where(x => x.MfaRequired);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var total = await query.CountAsync(cancellationToken); // 👈 CancellationToken 전달
            if (total == 0) return 0;

            var successful = await query.CountAsync(x => x.MfaCompleted == true, cancellationToken); // 👈 CancellationToken 전달
            return (double)successful / total;
        }

        #endregion

        #region 정리 작업 - 개선된 배치 처리 (영구 삭제 대신 Soft Delete 또는 아카이빙)

        /// <summary>
        /// 오래된 로그 정리 - 배치 크기 제한으로 메모리 최적화 (Soft Delete 방식)
        /// </summary>


        /// <summary>
        /// 성공한 오래된 로그 아카이브 - ExecuteUpdateAsync 활용 (IsArchived 플래그 사용)
        /// </summary>
        public async Task<int> ArchiveSuccessfulLogsAsync(
            DateTime before,
            string archiveLocation,
            CancellationToken cancellationToken = default)
        {
            // 💡 실제 아카이브(외부 시스템 전송 후 DB 삭제) 로직은 서비스 레이어에서 처리되어야 합니다.
            // Repository는 단순히 '아카이브 대상'으로 마크하는 역할만 수행하는 것이 SRP 원칙에 맞습니다.

            // ExecuteUpdateAsync를 사용하여 IsArchived 플래그를 설정합니다.
            var totalMarked = await Query()
                .Where(x => x.IsSuccess && x.AttemptedAt < before && !x.IsArchived)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(x => x.IsArchived, true),
                    cancellationToken); // 👈 CancellationToken 전달

            if (totalMarked > 0)
            {
                _logger.LogInformation("Completed marking for archive: {Count} logs marked IsArchived before {Date}",
                    totalMarked, before);

                // TODO: 아카이브 서비스 호출 및 영구 삭제는 서비스 레이어에서 수행되어야 함.
            }

            return totalMarked;
        }

        #endregion

        #region Private Helper Methods - 병렬 처리 최적화 (Anomaly Detection)

        // 🚨 이 헬퍼 메서드들은 이제 DetectAnomaliesAsync에서 CancellationToken을 받도록 수정해야 합니다.

        private async Task<IEnumerable<AnomalyPattern>> DetectMultipleIpAccessAsync(
            Guid? userId,
            DateTime? since,
            CancellationToken cancellationToken)
        {
            var query = Query();

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .Where(x => x.UserId != null) // Null UserId 필터링
                .GroupBy(x => x.UserId)
                .Where(g => g.Select(x => x.IpAddress).Distinct().Count() > 3)
                .Select(g => new AnomalyPattern
                {
                    UserId = g.Key,
                    AnomalyType = "MultipleIpAccess",
                    Description = $"User accessed from {g.Select(x => x.IpAddress).Distinct().Count()} different IPs",
                    RiskScore = Math.Min(g.Select(x => x.IpAddress).Distinct().Count() * 20, 100),
                    DetectedAt = DateTime.UtcNow
                })
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectUnusualTimeAccessAsync(
            Guid? userId,
            DateTime? since,
            CancellationToken cancellationToken)
        {
            // UTC 기준으로 새벽 2시부터 5시 사이를 비정상적인 시간으로 임시 정의
            var query = Query().Where(x => x.AttemptedAt.Hour >= 2 && x.AttemptedAt.Hour <= 5);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .Where(x => x.UserId != null) // Null UserId 필터링
                .GroupBy(x => x.UserId)
                .Where(g => g.Count() > 5)
                .Select(g => new AnomalyPattern
                {
                    UserId = g.Key,
                    AnomalyType = "UnusualTimeAccess",
                    Description = $"User accessed {g.Count()} times during unusual hours (2-5 AM UTC)",
                    RiskScore = Math.Min(g.Count() * 15, 100),
                    DetectedAt = DateTime.UtcNow
                })
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectGeographicalAnomaliesAsync(
            Guid? userId,
            DateTime? since,
            CancellationToken cancellationToken)
        {
            // 지리적 이상 감지는 IP 주소의 빈번한 변경(IP 수 > 10)을 기준으로 임시 정의
            var query = Query();

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .Where(x => x.UserId != null) // Null UserId 필터링
                .GroupBy(x => x.UserId)
                // 10개 이상의 고유 IP에서 접근이 있었다면 이상 징후로 간주
                .Where(g => g.Select(x => x.IpAddress).Distinct().Count() > 10)
                .Select(g => new AnomalyPattern
                {
                    UserId = g.Key,
                    AnomalyType = "FrequentLocationChange",
                    Description = $"User changed location {g.Select(x => x.IpAddress).Distinct().Count()} times",
                    RiskScore = 70, // 고정 위험 점수
                    DetectedAt = DateTime.UtcNow
                })
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

        #region 추가 구현 (인터페이스 동기화)

        // 🚨 IAuthenticationAttemptLogRepository에 CancellationToken이 추가되었을 것으로 가정하고 시그니처를 수정합니다.

        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsFromIpAsync(string ipAddress, DateTime since, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(x => !x.IsSuccess && x.IpAddress == ipAddress && x.AttemptedAt >= since)
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsForUsernameAsync(string username, DateTime since, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(x => !x.IsSuccess && x.Username == username && x.AttemptedAt >= since)
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync(cancellationToken); // 👈 CancellationToken 전달
        }

        /// <summary>
        /// 연속 실패 횟수 초기화 (주로 성공적인 로그인 또는 관리자 조작 시 호출됨)
        /// </summary>
        public async Task ResetConsecutiveFailuresAsync(Guid userId, CancellationToken cancellationToken = default) // ✅ CS4032 해결: 'async' 키워드 추가
        {
            // 캐시 초기화
            string cacheKey = $"ConsecutiveFailure_{userId}";

            if (_cacheService != null)
            {
                // RemoveAsync는 비동기 호출이므로 await가 필요합니다.
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }

            // ⭐️ 이벤트 발행: 연속 실패 횟수 초기화 이벤트를 발행
            await _eventBus.PublishAsync(
                new ConsecutiveFailureResetEvent(userId, DateTime.UtcNow),
                cancellationToken); // ✅ CancellationToken 전달

            _logger.LogInformation("Consecutive failure cache cleared for UserId: {UserId}", userId);

            // Task를 반환하는 async 메서드이므로 Task.CompletedTask를 명시적으로 반환할 필요가 없습니다.
            // 컴파일러가 자동으로 Task를 반환합니다.
        }

        /// <summary>
        /// 특정 기간의 로그를 아카이브 상태로 마킹합니다.
        /// </summary>
        /// <remarks>
        /// **사용 플로우:** 관리자가 특정 기간의 데이터를 일괄적으로 아카이브 대상으로 지정할 때 사용됩니다. 
        /// ArchiveSuccessfulLogsAsync의 일반화된 버전입니다.
        /// </remarks>
        /// <param name="from">시작 시각.</param>
        /// <param name="to">종료 시각.</param>
        /// <param name="cancellationToken">비동기 작업 취소 토큰.</param>
        /// <returns>아카이브 대상으로 마킹된 로그의 총 개수.</returns>
        public async Task<int> MarkAsArchivedAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(l => l.AttemptedAt >= from &&
                            l.AttemptedAt <= to &&
                            !l.IsArchived)
                .ExecuteUpdateAsync(updates => updates.SetProperty(l => l.IsArchived, true),
                    cancellationToken); // 👈 CancellationToken 전달
        }

        #endregion

    }
}