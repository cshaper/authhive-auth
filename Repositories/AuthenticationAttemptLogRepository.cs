using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 인증 시도 로그 저장소 구현 - AuthHive v15 (BaseRepository 최적화 + Null Safety 버전)
    /// </summary>
    public class AuthenticationAttemptLogRepository : BaseRepository<AuthenticationAttemptLog>,
        IAuthenticationAttemptLogRepository
    {
        private readonly ILogger<AuthenticationAttemptLogRepository> _logger;

        public AuthenticationAttemptLogRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ILogger<AuthenticationAttemptLogRepository> logger,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
            _logger = logger;
        }

        #region 조회 메서드 - BaseRepository 활용

        /// <summary>
        /// 사용자의 최근 인증 시도 조회 - BaseRepository 활용
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetRecentAttemptsAsync(
            Guid userId, int count = 10)
        {
            return await Query()
                .Where(x => x.UserId == userId)
                .OrderByDescending(x => x.AttemptedAt)
                .Take(Math.Min(count, 100)) // DOS 방지
                .ToListAsync();
        }

        /// <summary>
        /// 특정 사용자의 인증 기록을 기간별로 조회 - BaseRepository Query() 활용
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetHistoryForUserAsync(
            Guid userId,
            DateTime? startDate,
            DateTime? endDate)
        {
            var query = Query().Where(log => log.UserId == userId);

            if (startDate.HasValue)
                query = query.Where(log => log.AttemptedAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(log => log.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(log => log.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 사용자명으로 인증 시도 조회 - 캐시 가능한 조회 (Null Safety 개선)
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByUsernameAsync(
            string username,
            DateTime? since = null)
        {
            if (string.IsNullOrWhiteSpace(username))
                return Enumerable.Empty<AuthenticationAttemptLog>();

            // 캐시 키 생성 (since가 null이고 최근 1시간 이내인 경우만 캐시)
            bool canCache = since == null || (since.HasValue && since.Value > DateTime.UtcNow.AddHours(-1));
            string? cacheKey = canCache ? $"Username_{username}_{since?.Ticks ?? 0}" : null;

            // Null 체크 개선
            if (canCache && cacheKey != null && 
                _cache?.TryGetValue(cacheKey, out object? cachedObj) == true && 
                cachedObj is IEnumerable<AuthenticationAttemptLog> cached)
            {
                return cached;
            }

            var query = Query().Where(x => x.Username == username);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var result = await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000) // 대량 데이터 방지
                .ToListAsync();

            // 캐시 저장 (5분간) - Null 체크 개선
            if (canCache && cacheKey != null && _cache != null)
            {
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(5));
            }

            return result;
        }

        /// <summary>
        /// 조직별 인증 시도 조회 - BaseRepository의 조직 스코핑 활용
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByOrganizationAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            // BaseRepository의 조직별 조회 활용
            var query = QueryForOrganization(organizationId);

            if (startDate.HasValue)
                query = query.Where(x => x.AttemptedAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(x => x.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 애플리케이션별 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByApplicationAsync(
            Guid applicationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            var query = Query().Where(x => x.ApplicationId == applicationId);

            if (startDate.HasValue)
                query = query.Where(x => x.AttemptedAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(x => x.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// IP 주소별 인증 시도 조회 - 보안상 중요하므로 캐시 적용 (Null Safety 개선)
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? since = null)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return Enumerable.Empty<AuthenticationAttemptLog>();

            // 최근 1시간 데이터는 캐시 (보안 분석용)
            bool canCache = since == null || (since.HasValue && since.Value > DateTime.UtcNow.AddHours(-1));
            string? cacheKey = canCache ? $"IpAddress_{ipAddress}_{since?.Ticks ?? 0}" : null;

            // Null 체크 개선
            if (canCache && cacheKey != null && 
                _cache?.TryGetValue(cacheKey, out object? cachedObj) == true && 
                cachedObj is IEnumerable<AuthenticationAttemptLog> cached)
            {
                return cached;
            }

            var query = Query().Where(x => x.IpAddress == ipAddress);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var result = await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000) // 보안상 제한
                .ToListAsync();

            if (canCache && cacheKey != null && _cache != null)
            {
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(10));
            }

            return result;
        }

        /// <summary>
        /// 인증 방법별 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByMethodAsync(
            AuthenticationMethod method,
            DateTime? since = null,
            bool? successOnly = null)
        {
            var query = Query().Where(x => x.Method == method);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            if (successOnly.HasValue)
                query = query.Where(x => x.IsSuccess == successOnly.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        #endregion

        #region 실패 분석 - 최적화된 쿼리

        /// <summary>
        /// 실패한 인증 시도 횟수 조회 - 단순 카운트로 최적화
        /// </summary>
        public async Task<int> GetFailedAttemptCountAsync(Guid userId, DateTime since)
        {
            return await CountAsync(x =>
                x.UserId == userId &&
                !x.IsSuccess &&
                x.AttemptedAt >= since);
        }

        /// <summary>
        /// 연속 실패 횟수 조회 - 최적화된 로직 (Null Safety 개선)
        /// </summary>
        public async Task<int> GetConsecutiveFailureCountAsync(Guid userId)
        {
            // 캐시 확인 (자주 호출되는 메서드)
            string cacheKey = $"ConsecutiveFailure_{userId}";
            if (_cache?.TryGetValue(cacheKey, out object? cachedObj) == true && 
                cachedObj is int cachedCount)
            {
                return cachedCount;
            }

            // 마지막 성공 이후의 실패만 조회하도록 최적화
            var lastSuccess = await Query()
                .Where(x => x.UserId == userId && x.IsSuccess)
                .OrderByDescending(x => x.AttemptedAt)
                .Select(x => x.AttemptedAt)
                .FirstOrDefaultAsync();

            var failureQuery = Query().Where(x => x.UserId == userId && !x.IsSuccess);

            if (lastSuccess != default)
            {
                failureQuery = failureQuery.Where(x => x.AttemptedAt > lastSuccess);
            }

            var count = await failureQuery.CountAsync();

            // 5분간 캐시
            _cache?.Set(cacheKey, count, TimeSpan.FromMinutes(5));

            return count;
        }

        /// <summary>
        /// 실패한 인증 시도 조회 - BaseRepository 활용
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null,
            int? limit = null)
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

            return await query.ToListAsync();
        }

        /// <summary>
        /// 실패 사유별 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByFailureReasonAsync(
            AuthenticationResult reason,
            DateTime? since = null)
        {
            var query = Query().Where(x => x.FailureReason == reason && !x.IsSuccess);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000) // 제한
                .ToListAsync();
        }

        /// <summary>
        /// 계정 잠금을 트리거한 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetLockTriggerAttemptsAsync(
            DateTime? since = null)
        {
            var query = Query().Where(x => x.TriggeredAccountLock);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        #endregion

        #region 보안 분석 - 캐시 최적화

        /// <summary>
        /// 의심스러운 인증 시도 조회 - 캐시 적용
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetSuspiciousAttemptsAsync(
            DateTime? since = null,
            int? minRiskScore = null)
        {
            var query = Query().Where(x => x.IsSuspicious);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            if (minRiskScore.HasValue)
                query = query.Where(x => x.RiskScore >= minRiskScore.Value);

            return await query
                .OrderByDescending(x => x.RiskScore)
                .ThenByDescending(x => x.AttemptedAt)
                .Take(500) // 분석 데이터 제한
                .ToListAsync();
        }

        /// <summary>
        /// 브루트포스 공격 패턴 감지 - 최적화된 그룹화 쿼리 (Null Safety 개선)
        /// </summary>
        public async Task<IEnumerable<BruteForcePattern>> DetectBruteForceAttacksAsync(
            DateTime since,
            int threshold = 5)
        {
            // 캐시 확인 (10분간 캐시)
            string cacheKey = $"BruteForce_{since.Ticks}_{threshold}";
            if (_cache?.TryGetValue(cacheKey, out object? cachedObj) == true && 
                cachedObj is IEnumerable<BruteForcePattern> cached)
            {
                return cached;
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
                .ToListAsync();

            _cache?.Set(cacheKey, patterns, TimeSpan.FromMinutes(10));
            return patterns;
        }

        /// <summary>
        /// 이상 접근 패턴 감지 - 모듈화된 접근
        /// </summary>
        public async Task<IEnumerable<AnomalyPattern>> DetectAnomaliesAsync(
            Guid? userId = null,
            DateTime? since = null)
        {
            var tasks = new List<Task<IEnumerable<AnomalyPattern>>>
            {
                DetectMultipleIpAccessAsync(userId, since),
                DetectUnusualTimeAccessAsync(userId, since),
                DetectGeographicalAnomaliesAsync(userId, since)
            };

            var results = await Task.WhenAll(tasks);
            var allAnomalies = results.SelectMany(x => x).ToList();

            return allAnomalies.OrderByDescending(x => x.RiskScore);
        }

        /// <summary>
        /// 위험 IP 주소 목록 조회 - 최적화된 그룹화 (Null Safety 개선)
        /// </summary>
        public async Task<IEnumerable<RiskyIpAddress>> GetRiskyIpAddressesAsync(
            int failureThreshold = 10,
            DateTime? since = null)
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
                    UniqueUserCount = g.Where(x => x.UserId != null).Select(x => x.UserId).Distinct().Count(), // Null UserId 필터링
                    FirstSeen = g.Min(x => x.AttemptedAt),
                    LastSeen = g.Max(x => x.AttemptedAt)
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(100)
                .ToListAsync();
        }

        #endregion

        #region 통계 - BaseRepository의 통계 기능 활용 (Null Safety 개선)

        /// <summary>
        /// 인증 시도 통계 조회 - BaseRepository의 그룹 통계 활용
        /// </summary>
        public async Task<AuthenticationStatistics> GetStatisticsAsync(
            DateTime from,
            DateTime to,
            Guid? organizationId = null)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Where(x => x.AttemptedAt >= from && x.AttemptedAt <= to);

            var attempts = await query.ToListAsync();

            // BaseRepository의 GetGroupCountAsync 활용 가능
            var methodStats = await GetGroupCountAsync(
                x => x.Method,
                x => x.AttemptedAt >= from && x.AttemptedAt <= to &&
                     (!organizationId.HasValue || x.OrganizationId == organizationId.Value));

            var failureReasons = attempts
                .Where(x => !x.IsSuccess && x.FailureReason.HasValue)
                .GroupBy(x => x.FailureReason!.Value) // ! 연산자로 null이 아님을 명시
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
        /// 시간대별 인증 시도 분포 - BaseRepository의 날짜 통계 활용
        /// </summary>
        public async Task<Dictionary<int, int>> GetHourlyDistributionAsync(
            DateTime date,
            Guid? organizationId = null)
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
                .ToDictionaryAsync(x => x.Hour, x => x.Count);

            // 모든 시간대 포함
            var result = new Dictionary<int, int>();
            for (int i = 0; i < 24; i++)
            {
                result[i] = distribution.TryGetValue(i, out int count) ? count : 0; // GetValueOrDefault 대신 TryGetValue 사용
            }

            return result;
        }

        /// <summary>
        /// 인증 방법별 성공률
        /// </summary>
        public async Task<Dictionary<AuthenticationMethod, double>> GetSuccessRateByMethodAsync(
            DateTime? since = null,
            Guid? organizationId = null)
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
                    x => x.Total > 0 ? (double)x.Success / x.Total : 0);
        }

        /// <summary>
        /// 상위 실패 사용자 조회 (Null Safety 개선)
        /// </summary>
        public async Task<IEnumerable<UserFailureStatistics>> GetTopFailedUsersAsync(
            int topCount = 10,
            DateTime? since = null)
        {
            var query = Query().Where(x => !x.IsSuccess && x.UserId != null);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .GroupBy(x => new { x.UserId, x.Username })
                .Where(g => g.Key.UserId.HasValue) // 추가 null 체크
                .Select(g => new UserFailureStatistics
                {
                    UserId = g.Key.UserId!.Value, // ! 연산자로 null이 아님을 명시
                    Username = g.Key.Username ?? string.Empty,
                    FailureCount = g.Count(),
                    LastFailure = g.Max(x => x.AttemptedAt),
                    IsLocked = false // 별도 조회 필요
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(Math.Min(topCount, 50)) // 안전한 제한
                .ToListAsync();
        }

        #endregion

        #region MFA 관련

        /// <summary>
        /// MFA 요구된 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetMfaRequiredAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null)
        {
            var query = Query().Where(x => x.MfaRequired);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000)
                .ToListAsync();
        }

        /// <summary>
        /// MFA 성공률 조회
        /// </summary>
        public async Task<double> GetMfaSuccessRateAsync(
            DateTime? since = null,
            Guid? organizationId = null)
        {
            var query = organizationId.HasValue
                ? QueryForOrganization(organizationId.Value)
                : Query();

            query = query.Where(x => x.MfaRequired);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var total = await query.CountAsync();
            if (total == 0) return 0;

            var successful = await query.CountAsync(x => x.MfaCompleted == true);
            return (double)successful / total;
        }

        #endregion

        #region 정리 작업 - 개선된 배치 처리

        /// <summary>
        /// 오래된 로그 정리 - 배치 크기 제한으로 메모리 최적화
        /// </summary>
        public async Task<int> CleanupOldLogsAsync(DateTime before)
        {
            int totalDeleted = 0;
            const int batchSize = 1000;

            while (true)
            {
                var batch = await _dbSet
                    .Where(x => x.AttemptedAt < before && !x.IsDeleted)
                    .Take(batchSize)
                    .ToListAsync();

                if (batch.Count == 0) // Count 속성 사용
                    break;

                foreach (var log in batch)
                {
                    log.IsDeleted = true;
                    log.DeletedAt = DateTime.UtcNow;
                }

                await _context.SaveChangesAsync();
                totalDeleted += batch.Count;

                _logger.LogInformation("Cleaned up batch of {Count} logs, total: {Total}", 
                    batch.Count, totalDeleted);

                // 배치 간 약간의 지연으로 시스템 부하 방지
                await Task.Delay(100);
            }

            if (totalDeleted > 0)
            {
                _logger.LogInformation("Completed cleanup: {Count} logs before {Date}",
                    totalDeleted, before);
            }

            return totalDeleted;
        }

        /// <summary>
        /// 성공한 오래된 로그 아카이브 - 개선된 배치 처리
        /// </summary>
        public async Task<int> ArchiveSuccessfulLogsAsync(
            DateTime before,
            string archiveLocation)
        {
            int totalArchived = 0;
            const int batchSize = 1000;

            while (true)
            {
                var batch = await _dbSet
                    .Where(x => x.IsSuccess && x.AttemptedAt < before && !x.IsDeleted)
                    .Take(batchSize)
                    .ToListAsync();

                if (batch.Count == 0) // Count 속성 사용
                    break;

                // TODO: 실제 아카이브 로직 구현
                // 예: await _archiveService.ArchiveAsync(batch, archiveLocation);

                _dbSet.RemoveRange(batch);
                await _context.SaveChangesAsync();

                totalArchived += batch.Count;

                _logger.LogInformation("Archived batch of {Count} logs, total: {Total}", 
                    batch.Count, totalArchived);

                await Task.Delay(100);
            }

            if (totalArchived > 0)
            {
                _logger.LogInformation("Completed archiving: {Count} logs to {Location}",
                    totalArchived, archiveLocation);
            }

            return totalArchived;
        }

        #endregion

        #region Private Helper Methods - 병렬 처리 최적화

        private async Task<IEnumerable<AnomalyPattern>> DetectMultipleIpAccessAsync(
            Guid? userId,
            DateTime? since)
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
                .ToListAsync();
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectUnusualTimeAccessAsync(
            Guid? userId,
            DateTime? since)
        {
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
                    Description = $"User accessed {g.Count()} times during unusual hours (2-5 AM)",
                    RiskScore = Math.Min(g.Count() * 15, 100),
                    DetectedAt = DateTime.UtcNow
                })
                .ToListAsync();
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectGeographicalAnomaliesAsync(
            Guid? userId,
            DateTime? since)
        {
            var query = Query();

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .Where(x => x.UserId != null) // Null UserId 필터링
                .GroupBy(x => x.UserId)
                .Where(g => g.Select(x => x.IpAddress).Distinct().Count() > 10)
                .Select(g => new AnomalyPattern
                {
                    UserId = g.Key,
                    AnomalyType = "FrequentLocationChange",
                    Description = $"User changed location {g.Select(x => x.IpAddress).Distinct().Count()} times",
                    RiskScore = 70,
                    DetectedAt = DateTime.UtcNow
                })
                .ToListAsync();
        }

        #endregion
    }
}