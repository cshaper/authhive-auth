using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Events;
using AuthHive.Core.Models.Auth.Authentication.ReadModels;
using AuthHive.Core.Models.Auth.Security;
using AuthHive.Core.Models.Auth.Security.Dtos;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 인증 시도 로그 저장소 구현 - AuthHive v16 (보안 감사 및 분석에 사용)
    /// </summary>
    public class AuthenticationAttemptLogRepository : BaseRepository<AuthenticationAttemptLog>,
        IAuthenticationAttemptLogRepository
    {
        private readonly ILogger<AuthenticationAttemptLogRepository> _logger;
        private readonly IEventBus _eventBus;

        /// <summary>
        /// Repository 생성자. 최신 아키텍처에 따라 DbContext, Logger, EventBus, CacheService를 주입받습니다.
        /// </summary>
        public AuthenticationAttemptLogRepository(
            AuthDbContext context,
            ILogger<AuthenticationAttemptLogRepository> logger,
            IEventBus eventBus,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티가 조직 범위인지 여부를 결정합니다.
        /// 인증 시도 로그는 조직의 보안 자산이므로 true를 반환하여 멀티테넌시 필터링을 강제합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region 조회 메서드

        /// <summary>
        /// 특정 사용자의 최근 인증 시도 기록을 지정된 개수만큼 조회합니다.
        /// 사용: 사용자 프로필 페이지의 '최근 활동' 섹션에 표시할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetRecentAttemptsAsync(
            Guid userId, int count = 10, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(x => x.UserId == userId)
                .OrderByDescending(x => x.AttemptedAt)
                .Take(Math.Min(count, 100)) // 과도한 요청 방지
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 사용자의 인증 기록을 지정된 기간별로 조회합니다.
        /// 사용: 관리자가 특정 사용자의 상세 활동 로그를 감사할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetHistoryForUserAsync(
            Guid userId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(log => log.UserId == userId);
            if (startDate.HasValue) query = query.Where(log => log.AttemptedAt >= startDate.Value);
            if (endDate.HasValue) query = query.Where(log => log.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(log => log.AttemptedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 사용자명으로 인증 시도를 조회합니다. 최근 1시간 내의 조회는 캐시될 수 있습니다.
        /// 사용: 로그인 실패 횟수를 계산하거나, 특정 계정에 대한 최근 접근 시도를 빠르게 확인할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByUsernameAsync(
            string username,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username)) return Enumerable.Empty<AuthenticationAttemptLog>();

            bool canCache = since == null || (since.HasValue && since.Value > DateTime.UtcNow.AddHours(-1));
            string? cacheKey = canCache ? $"AuthAttempt:Username_{username}_{since?.Ticks ?? 0}" : null;

            if (canCache && cacheKey != null && _cacheService != null)
            {
                var cached = await _cacheService.GetAsync<List<AuthenticationAttemptLog>>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var query = Query().Where(x => x.Username == username);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            var result = await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000) // 대량 데이터 조회 방지
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            if (canCache && cacheKey != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(5), cancellationToken);
            }
            return result;
        }

        /// <summary>
        /// IP 주소로 인증 시도를 조회합니다. 최근 1시간 내의 조회는 캐시될 수 있습니다.
        /// 사용: 특정 IP 주소에서 발생하는 비정상 로그인 시도를 탐지하는 등 보안 분석에 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress)) return Enumerable.Empty<AuthenticationAttemptLog>();

            bool canCache = since == null || (since.HasValue && since.Value > DateTime.UtcNow.AddHours(-1));
            string? cacheKey = canCache ? $"AuthAttempt:IP_{ipAddress}_{since?.Ticks ?? 0}" : null;

            if (canCache && cacheKey != null && _cacheService != null)
            {
                var cached = await _cacheService.GetAsync<List<AuthenticationAttemptLog>>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }
            var query = Query().Where(x => x.IpAddress == ipAddress);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            var result = await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000) // 보안 분석을 위한 데이터 제한
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            if (canCache && cacheKey != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(10), cancellationToken);
            }
            return result;
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
            var query = QueryForOrganization(organizationId);
            if (startDate.HasValue) query = query.Where(x => x.AttemptedAt >= startDate.Value);
            if (endDate.HasValue) query = query.Where(x => x.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
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
            if (startDate.HasValue) query = query.Where(x => x.AttemptedAt >= startDate.Value);
            if (endDate.HasValue) query = query.Where(x => x.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
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
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);
            if (successOnly.HasValue) query = query.Where(x => x.IsSuccess == successOnly.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 실패 분석

        /// <summary>
        /// 특정 기간 동안 사용자의 로그인 실패 횟수를 조회합니다.
        /// 사용: 계정 잠금 정책을 적용하기 위해 "최근 10분간 5회 이상 실패"와 같은 조건을 확인할 때 사용됩니다.
        /// </summary>
        public async Task<int> GetFailedAttemptCountAsync(Guid userId, DateTime since, CancellationToken cancellationToken = default)
        {
            return await CountAsync(x =>
                x.UserId == userId &&
                !x.IsSuccess &&
                x.AttemptedAt >= since, cancellationToken);
        }

        /// <summary>
        /// 사용자의 마지막 성공 로그인 이후 연속된 실패 횟수를 조회합니다. (캐시 활용)
        /// 사용: "연속 5회 실패 시 계정 잠금"과 같은 실시간 보안 정책을 적용하는 데 핵심적으로 사용됩니다.
        /// </summary>
        public async Task<int> GetConsecutiveFailureCountAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            string cacheKey = $"ConsecutiveFailure_{userId}";
            if (_cacheService != null)
            {
                var cachedString = await _cacheService.GetStringAsync(cacheKey, cancellationToken);
                if (!string.IsNullOrEmpty(cachedString) && int.TryParse(cachedString, out int cachedCount))
                {
                    if (cachedCount > 0) return cachedCount;
                }
            }

            var lastSuccess = await Query()
                .Where(x => x.UserId == userId && x.IsSuccess)
                .OrderByDescending(x => x.AttemptedAt)
                .Select(x => (DateTime?)x.AttemptedAt)
                .FirstOrDefaultAsync(cancellationToken);

            var failureQuery = Query().Where(x => x.UserId == userId && !x.IsSuccess);
            if (lastSuccess.HasValue)
            {
                failureQuery = failureQuery.Where(x => x.AttemptedAt > lastSuccess.Value);
            }

            var count = await failureQuery.CountAsync(cancellationToken);
            if (count > 0 && _cacheService != null)
            {
                await _cacheService.SetStringAsync(cacheKey, count.ToString(), TimeSpan.FromMinutes(5), cancellationToken);
            }
            return count;
        }

        /// <summary>
        /// 사용자의 연속 로그인 실패 기록을 초기화하고, 관련 이벤트를 발행합니다.
        /// 사용: 사용자가 성공적으로 로그인했거나 비밀번호를 재설정했을 때 호출되어, 실패 횟수 카운트를 0으로 되돌립니다.
        /// </summary>
        public async Task ResetConsecutiveFailuresAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            string cacheKey = $"ConsecutiveFailure_{userId}";
            int previousFailureCount = 0;

            if (_cacheService != null)
            {
                var countStr = await _cacheService.GetStringAsync(cacheKey, cancellationToken);
                if (int.TryParse(countStr, out int count))
                {
                    previousFailureCount = count;
                }
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }

            var organizationId = await _context.ConnectedIds
                .Where(c => c.Id == userId)
                .Select(c => (Guid?)c.OrganizationId)
                .FirstOrDefaultAsync(cancellationToken);

            await _eventBus.PublishAsync(
                new ConsecutiveFailureResetEvent(
                    userId,
                    organizationId,
                    "SuccessfulLogin",
                    previousFailureCount,
                    userId
                ),
                cancellationToken);

            _logger.LogInformation("Consecutive failure count reset for UserId: {UserId}", userId);
        }
        
        /// <summary>
        /// 실패한 인증 시도 기록을 조회합니다.
        /// 사용: 보안 관리자가 실패한 로그인 시도만을 필터링하여 감사할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess);
            if (userId.HasValue) query = query.Where(x => x.UserId == userId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            query = query.OrderByDescending(x => x.AttemptedAt);
            int safeLimit = Math.Min(limit ?? 100, 1000);
            query = query.Take(safeLimit);

            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 실패 사유(예: '잘못된 비밀번호')에 해당하는 인증 시도 기록을 조회합니다.
        /// 사용: 특정 유형의 로그인 실패가 급증하는지 패턴을 분석할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByFailureReasonAsync(
            AuthenticationResult reason,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.FailureReason == reason && !x.IsSuccess);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 계정 잠금을 유발한 인증 시도 기록을 조회합니다.
        /// 사용: 어떤 로그인 시도가 계정 잠금으로 이어졌는지 추적하고 감사하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetLockTriggerAttemptsAsync(
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.TriggeredAccountLock);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 IP에서 발생한 실패한 인증 시도 기록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsFromIpAsync(string ipAddress, DateTime since, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(x => !x.IsSuccess && x.IpAddress == ipAddress && x.AttemptedAt >= since)
                .OrderByDescending(x => x.AttemptedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 사용자명으로 발생한 실패한 인증 시도 기록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsForUsernameAsync(string username, DateTime since, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(x => !x.IsSuccess && x.Username == username && x.AttemptedAt >= since)
                .OrderByDescending(x => x.AttemptedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 보안 분석

        /// <summary>
        /// 의심스러운 활동으로 플래그된 인증 시도 기록을 조회합니다.
        /// 사용: 보안 대시보드에서 고위험 활동을 우선적으로 검토할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetSuspiciousAttemptsAsync(
            Guid? organizationId = null,
            DateTime? since = null,
            int? minRiskScore = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.IsSuspicious);
            if (organizationId.HasValue) query = query.Where(x => x.OrganizationId == organizationId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);
            if (minRiskScore.HasValue) query = query.Where(x => x.RiskScore >= minRiskScore.Value);

            return await query
                .OrderByDescending(x => x.RiskScore)
                .ThenByDescending(x => x.AttemptedAt)
                .Take(500)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 브루트포스 공격 패턴(동일 IP/사용자명으로 단기간 내 여러 번 실패)을 감지합니다. (캐시 활용)
        /// 사용: 실시간 보안 모니터링 시스템에서 무차별 대입 공격을 탐지하고 해당 IP를 차단하는 등의 조치를 취할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<BruteForcePatternDto>> DetectBruteForceAttacksAsync(
            DateTime since,
            int threshold = 5,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"BruteForce_{since.Ticks}_{threshold}";
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<List<BruteForcePatternDto>>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var patterns = await Query()
                .Where(x => x.AttemptedAt >= since && !x.IsSuccess)
                .GroupBy(x => new { x.IpAddress, x.Username })
                .Where(g => g.Count() >= threshold)
                .Select(g => new BruteForcePatternDto
                {
                    IpAddress = g.Key.IpAddress ?? string.Empty,
                    Username = g.Key.Username,
                    AttemptCount = g.Count(),
                    FirstAttempt = g.Min(x => x.AttemptedAt),
                    LastAttempt = g.Max(x => x.AttemptedAt)
                })
                .OrderByDescending(x => x.AttemptCount)
                .Take(100)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            if (_cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, patterns, TimeSpan.FromMinutes(10), cancellationToken);
            }
            return patterns;
        }

        /// <summary>
        /// 여러 유형의 이상 접근 패턴(다수 IP 접근, 비정상 시간 접근 등)을 종합적으로 감지합니다.
        /// 사용: 사용자 행동 분석(UBA) 시스템의 기초 데이터로 사용되어, 단일 규칙으로는 탐지하기 어려운 복합적인 위협을 식별합니다.
        /// </summary>
        public async Task<IEnumerable<AnomalyPattern>> DetectAnomaliesAsync(
            Guid? userId = null,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var tasks = new List<Task<IEnumerable<AnomalyPattern>>>
            {
                DetectMultipleIpAccessAsync(userId, since, cancellationToken),
                DetectUnusualTimeAccessAsync(userId, since, cancellationToken),
                DetectGeographicalAnomaliesAsync(userId, since, cancellationToken)
            };

            var results = await Task.WhenAll(tasks);
            var allAnomalies = results.SelectMany(x => x).ToList();
            return allAnomalies.OrderByDescending(x => x.RiskScore);
        }

        /// <summary>
        /// 다수의 로그인 실패를 유발한 IP 주소 목록을 조회합니다.
        /// 사용: 방화벽이나 웹 방화벽(WAF)에 차단 목록으로 등록할 악성 IP를 식별하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<RiskyIpAddress>> GetRiskyIpAddressesAsync(
            int failureThreshold = 10,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess && x.IpAddress != null);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .GroupBy(x => x.IpAddress)
                .Where(g => g.Count() >= failureThreshold)
                .Select(g => new RiskyIpAddress
                {
                    IpAddress = g.Key!,
                    FailureCount = g.Count(),
                    UniqueUserCount = g.Select(x => x.UserId).Distinct().Count(),
                    FirstSeen = g.Min(x => x.AttemptedAt),
                    LastSeen = g.Max(x => x.AttemptedAt)
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(100)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 통계

        /// <summary>
        /// 지정된 기간 및 조직에 대한 인증 통계를 집계합니다.
        /// 사용: 관리자 대시보드에서 전반적인 로그인 성공률, 방법별 시도 횟수 등을 시각화하는 데 사용됩니다.
        /// </summary>
        public async Task<AuthenticationStatisticsReadModel> GetStatisticsAsync(
            DateTime from,
            DateTime to,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();
            query = query.Where(x => x.AttemptedAt >= from && x.AttemptedAt <= to);

            var attempts = await query.AsNoTracking().ToListAsync(cancellationToken);
            if (!attempts.Any()) return new AuthenticationStatisticsReadModel();

            var methodStats = attempts.GroupBy(x => x.Method).ToDictionary(g => g.Key, g => g.Count());
            var failureReasons = attempts.Where(x => !x.IsSuccess && x.FailureReason.HasValue)
                .GroupBy(x => x.FailureReason!.Value)
                .ToDictionary(g => g.Key, g => g.Count());

            return new AuthenticationStatisticsReadModel
            {
                TotalAttempts = attempts.Count,
                SuccessfulAttempts = attempts.Count(x => x.IsSuccess),
                FailedAttempts = attempts.Count(x => !x.IsSuccess),
                SuccessRate = (double)attempts.Count(x => x.IsSuccess) / attempts.Count,
                AttemptsByMethod = methodStats,
                FailureReasons = failureReasons
            };
        }

        /// <summary>
        /// 특정 날짜의 시간대별 인증 시도 분포를 조회합니다.
        /// 사용: 서버 부하가 가장 많은 시간을 파악하거나, 특정 시간대에 비정상적인 활동이 증가하는지 모니터링하는 데 사용됩니다.
        /// </summary>
        public async Task<Dictionary<int, int>> GetHourlyDistributionAsync(
            DateTime date,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var startDate = date.Date;
            var endDate = startDate.AddDays(1);
            var query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();

            var distribution = await query
                .Where(x => x.AttemptedAt >= startDate && x.AttemptedAt < endDate)
                .GroupBy(x => x.AttemptedAt.Hour)
                .Select(g => new { Hour = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Hour, x => x.Count, cancellationToken);

            var result = new Dictionary<int, int>();
            for (int i = 0; i < 24; i++)
            {
                result[i] = distribution.TryGetValue(i, out int count) ? count : 0;
            }
            return result;
        }

        /// <summary>
        /// 인증 방법별 성공률을 계산합니다.
        /// 사용: '비밀번호 로그인'보다 'MFA 로그인'의 성공률이 비정상적으로 낮은지 등을 분석하여 사용자 경험 문제를 파악하는 데 사용됩니다.
        /// </summary>
        public async Task<Dictionary<AuthenticationMethod, double>> GetSuccessRateByMethodAsync(
            DateTime? since = null,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .GroupBy(x => x.Method)
                .Select(g => new { Method = g.Key, Total = g.Count(), Success = g.Count(x => x.IsSuccess) })
                .ToDictionaryAsync(x => x.Method, x => x.Total > 0 ? (double)x.Success / x.Total : 0, cancellationToken);
        }

        /// <summary>
        /// 로그인 실패 횟수가 가장 많은 상위 사용자 목록을 조회합니다.
        /// 사용: 반복적인 로그인 실패로 계정 탈취 공격의 대상이 되고 있을 가능성이 있는 사용자를 식별하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<UserFailureStatistics>> GetTopFailedUsersAsync(
            int topCount = 10,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess && x.UserId != null);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .GroupBy(x => new { x.UserId, x.Username })
                .Where(g => g.Key.UserId.HasValue)
                .Select(g => new UserFailureStatistics
                {
                    UserId = g.Key.UserId!.Value,
                    Username = g.Key.Username ?? string.Empty,
                    FailureCount = g.Count(),
                    LastFailure = g.Max(x => x.AttemptedAt),
                    IsAccountLocked = false // 실제 잠금 상태는 다른 서비스에서 확인 필요
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(Math.Min(topCount, 50))
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region MFA 관련

        /// <summary>
        /// MFA 인증이 요구되었던 시도 기록을 조회합니다.
        /// 사용: MFA 정책이 올바르게 적용되고 있는지 감사하거나, MFA 관련 사용자 문제를 분석할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetMfaRequiredAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.MfaRequired);
            if (userId.HasValue) query = query.Where(x => x.UserId == userId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .Take(1000)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// MFA 인증 시도의 성공률을 계산합니다.
        /// 사용: MFA 시스템 자체의 안정성이나 사용자 편의성을 측정하는 지표로 사용될 수 있습니다.
        /// </summary>
        public async Task<double> GetMfaSuccessRateAsync(
            DateTime? since = null,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = organizationId.HasValue ? QueryForOrganization(organizationId.Value) : Query();
            query = query.Where(x => x.MfaRequired);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            var total = await query.CountAsync(cancellationToken);
            if (total == 0) return 0;

            var successful = await query.CountAsync(x => x.MfaCompleted == true, cancellationToken);
            return (double)successful / total;
        }

        #endregion

        #region 정리 작업

        /// <summary>
        /// 오래된 로그를 정리(Soft Delete)합니다.
        /// 사용: 데이터베이스 용량을 관리하기 위해 주기적인 배치 작업으로 실행됩니다.
        /// </summary>
        public async Task<int> CleanupOldLogsAsync(DateTime before, CancellationToken cancellationToken = default)
        {
            int totalDeleted = await Query()
                .Where(log => log.AttemptedAt < before && !log.IsDeleted)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(log => log.IsDeleted, true)
                    .SetProperty(log => log.DeletedAt, DateTime.UtcNow),
                    cancellationToken);

            if (totalDeleted > 0)
            {
                _logger.LogInformation("Soft-deleted {Count} old authentication logs before {Date}", totalDeleted, before);
            }
            return totalDeleted;
        }

        /// <summary>
        /// 오래된 '성공' 로그를 '아카이브' 상태로 표시합니다.
        /// 사용: DB 성능을 위해 오래된 로그를 별도의 스토리지로 옮기기 전, 대상을 마킹하는 배치 작업에서 사용됩니다.
        /// </summary>
        public async Task<int> ArchiveSuccessfulLogsAsync(
            DateTime before,
            string archiveLocation, // 실제 아카이브 로직은 서비스 계층에서 이 정보를 사용
            CancellationToken cancellationToken = default)
        {
            var totalMarked = await Query()
                .Where(x => x.IsSuccess && x.AttemptedAt < before && !x.IsArchived)
                .ExecuteUpdateAsync(updates => updates.SetProperty(x => x.IsArchived, true), cancellationToken);

            if (totalMarked > 0)
            {
                _logger.LogInformation("Marked {Count} successful logs for archival before {Date}", totalMarked, before);
            }
            return totalMarked;
        }
        
        /// <summary>
        /// 특정 기간의 로그를 '아카이브' 상태로 표시합니다.
        /// 사용: 관리자가 수동으로 특정 기간의 로그를 아카이브 처리할 때 사용됩니다.
        /// </summary>
        public async Task<int> MarkAsArchivedAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(l => l.AttemptedAt >= from && l.AttemptedAt <= to && !l.IsArchived)
                .ExecuteUpdateAsync(updates => updates.SetProperty(l => l.IsArchived, true), cancellationToken);
        }

        #endregion

        #region Private Helper Methods - Anomaly Detection

        private async Task<IEnumerable<AnomalyPattern>> DetectMultipleIpAccessAsync(Guid? userId, DateTime? since, CancellationToken cancellationToken)
        {
            var query = Query().Where(x => x.UserId != null);
            if (userId.HasValue) query = query.Where(x => x.UserId == userId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
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
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectUnusualTimeAccessAsync(Guid? userId, DateTime? since, CancellationToken cancellationToken)
        {
            var query = Query().Where(x => x.UserId != null && x.AttemptedAt.Hour >= 2 && x.AttemptedAt.Hour <= 5);
            if (userId.HasValue) query = query.Where(x => x.UserId == userId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
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
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectGeographicalAnomaliesAsync(Guid? userId, DateTime? since, CancellationToken cancellationToken)
        {
            var query = Query().Where(x => x.UserId != null);
            if (userId.HasValue) query = query.Where(x => x.UserId == userId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
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
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion
    }
}

