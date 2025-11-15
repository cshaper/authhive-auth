// 📍 위치: AuthHive.Auth/Repositories/AuthenticationAttemptLogRepository.cs
// (v17 최종본: 순수 조회 기능 및 CS0535 오류 해결)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth.Authentication;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.ReadModels;
using AuthHive.Core.Models.Auth.Security.ReadModels;
using AuthHive.Core.Interfaces.Base;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 인증 시도 로그 저장소 구현 - v17 (순수 데이터 접근 계층)
    /// </summary>
    public class AuthenticationAttemptLogRepository : BaseRepository<AuthenticationAttemptLog>,
        IAuthenticationAttemptLogRepository
    {
        private readonly ILogger<AuthenticationAttemptLogRepository> _logger;

        public AuthenticationAttemptLogRepository(
            AuthDbContext context,
            ILogger<AuthenticationAttemptLogRepository> logger,
            IEventBus eventBus,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        protected override bool IsOrganizationScopedEntity() => true;

        #region 조회 메서드 (Pure Query)

        /// <summary>
        /// 특정 사용자의 인증 기록을 지정된 기간별로 조회합니다.
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
                .Take(1000)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 실패 분석 (Pure Query)

        /// <summary>
        /// 특정 기간 동안 사용자의 로그인 실패 횟수를 조회합니다.
        /// </summary>
        public async Task<int> GetFailedAttemptCountAsync(Guid userId, DateTime since, CancellationToken cancellationToken = default)
        {
            return await CountAsync(x =>
                x.UserId == userId &&
                !x.IsSuccess &&
                x.AttemptedAt >= since, cancellationToken);
        }

        /// <summary>
        /// 실패한 인증 시도 기록을 조회합니다.
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
        /// 특정 실패 사유에 해당하는 인증 시도 기록을 조회합니다.
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

        #region 통계 및 분석 (ReadModel Retrieval) - CS0535 구현부

        /// <summary>
        /// 지정된 기간 및 조직에 대한 인증 통계를 집계합니다. (CS0535 구현)
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
            if (!attempts.Any()) return new AuthenticationStatisticsReadModel(0, from, to, 0, 0, 0, 0, null, null); // [FIX] 생성자 인자가 없으므로 기본값 0으로 초기화

            var methodStats = attempts.GroupBy(x => x.Method).ToDictionary(g => g.Key, g => g.Count());
            var failureReasons = attempts.Where(x => !x.IsSuccess && x.FailureReason.HasValue)
                .GroupBy(x => x.FailureReason!.Value)
                .ToDictionary(g => g.Key, g => g.Count());

            int totalAttempts = attempts.Count;
            int successfulAttempts = attempts.Count(x => x.IsSuccess);
            int failedAttempts = attempts.Count(x => !x.IsSuccess);

            // CS0500/CS7036 FIX: 객체 초기화 대신 생성자 호출
            return new AuthenticationStatisticsReadModel(
                totalAttempts: totalAttempts,
                periodStart: from,
                periodEnd: to,
                uniqueUsers: attempts.Select(x => x.UserId).Where(u => u.HasValue).Distinct().Count(),
                peakHour: attempts.GroupBy(x => x.AttemptedAt.Hour).OrderByDescending(g => g.Count()).FirstOrDefault()?.Key ?? 0,
                successfulAttempts: successfulAttempts,
                failedAttempts: failedAttempts,
                attemptsByMethod: methodStats,
                failureReasons: failureReasons
            );
        }

        /// <summary>
        /// 로그인 실패 횟수가 가장 많은 상위 사용자 목록을 조회합니다. (CS0535 구현)
        /// </summary>
       
        public async Task<IEnumerable<RiskyIpAddressReadModel>> GetRiskyIpAddressesAsync(
            int failureThreshold = 10,
            DateTime? since = null,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess && x.IpAddress != null);
            if (organizationId.HasValue) query = query.Where(x => x.OrganizationId == organizationId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            // --- Step 1: 데이터베이스 쿼리 실행 (익명 객체로 원시 데이터만 가져옴) ---
            var rawData = await query
                .GroupBy(x => x.IpAddress)
                .Where(g => g.Count() >= failureThreshold)
                .Select(g => new // 👈 익명 객체로 프로젝트 (CS0854 해결)
                {
                    IpAddress = g.Key!,
                    FailureCount = g.Count(),
                    UniqueUserCount = g.Select(x => x.UserId).Distinct().Count(),
                    SuccessCount = g.Count(x => x.IsSuccess),
                    FirstSeen = g.Min(x => x.AttemptedAt),
                    LastSeen = g.Max(x => x.AttemptedAt),
                    AccountLockTriggeredCount = g.Count(x => x.TriggeredAccountLock),
                    // CountryCode는 DB에서 직접 가져오지 않습니다.
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(100)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
            // ----------------------------------------------------

            // --- Step 2: C# 메모리에서 ReadModel 생성 (CS0500/CS7036 해결) ---
            // 여기서는 DTO의 Optional Arguments를 안전하게 사용합니다.
            return rawData.Select(r => new RiskyIpAddressReadModel(
                ipAddress: r.IpAddress,
                failureCount: r.FailureCount,
                uniqueUserCount: r.UniqueUserCount,
                successCount: r.SuccessCount,
                firstSeen: r.FirstSeen,
                lastSeen: r.LastSeen,
                suspiciousActivityDetected: true, // DTO 요구사항
                bruteForcePatternDetected: true, // DTO 요구사항
                accountLockTriggeredCount: r.AccountLockTriggeredCount
            )).ToList();
        }
        /// <summary>
        /// 로그인 실패 횟수가 가장 많은 상위 사용자 목록을 조회합니다. (CS0854 해결)
        /// </summary>
        public async Task<IEnumerable<UserFailureStatisticsReadModel>> GetTopFailedUsersAsync(
            int topCount = 10,
            DateTime? since = null,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => !x.IsSuccess && x.UserId.HasValue);
            if (organizationId.HasValue) query = query.Where(x => x.OrganizationId == organizationId.Value);
            if (since.HasValue) query = query.Where(x => x.AttemptedAt >= since.Value);

            // --- Step 1: 데이터베이스 쿼리 실행 (익명 객체로 원시 데이터만 가져옴) ---
            var rawData = await query
                .GroupBy(x => new { x.UserId, x.Username })
                .Where(g => g.Key.UserId.HasValue)
                .Select(g => new // 👈 익명 객체 생성 (CS0854 해결)
                {
                    UserId = g.Key.UserId!.Value,
                    Username = g.Key.Username,
                    FailureCount = g.Count(),
                    UniqueIpCount = g.Select(x => x.IpAddress).Distinct().Count(),
                    FirstFailure = g.Min(x => x.AttemptedAt),
                    LastAttempt = g.Max(x => x.AttemptedAt),
                    LockCount = g.Count(x => x.TriggeredAccountLock),
                    SuccessCount = g.Count(x => x.IsSuccess)
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(Math.Min(topCount, 50))
                .AsNoTracking()
                .ToListAsync(cancellationToken);
            // ------------------------------------------------------------------

            // --- Step 2: C# 메모리에서 ReadModel 생성자로 매핑 (CS7036/CS0500 해결) ---
            return rawData.Select(r => new UserFailureStatisticsReadModel(
                userId: r.UserId,
                failureCount: r.FailureCount,
                consecutiveFailures: 0,
                successCount: r.SuccessCount,
                isAccountLocked: false,
                lockCount: r.LockCount,
                uniqueIpCount: r.UniqueIpCount,
                username: r.Username,
                displayName: null,
                organizationId: organizationId,
                firstFailure: r.FirstFailure,
                lastAttempt: r.LastAttempt,
                lastSuccess: null,
                lastFailure: r.LastAttempt
            )).ToList();
        }

        /// <summary>
        /// 다수의 로그인 실패를 유발한 IP 주소 목록을 조회합니다. (CS0535 구현)
        /// </summary>


        #endregion

        #region MFA 관련

        /// <summary>
        /// MFA 인증이 요구되었던 시도 기록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetMfaRequiredAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(x => x.MfaRequired);
            if (organizationId.HasValue) query = query.Where(x => x.OrganizationId == organizationId.Value);
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

        #region 정리 작업 (Repository Level Maintenance)

        /// <summary>
        /// 오래된 로그를 정리(Soft Delete)합니다.
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
        /// </summary>
        public async Task<int> ArchiveSuccessfulLogsAsync(
            DateTime before,
            string archiveLocation,
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
        /// </summary>
        public async Task<int> MarkAsArchivedAsync(DateTime from, DateTime to, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(l => l.AttemptedAt >= from && l.AttemptedAt <= to && !l.IsArchived)
                .ExecuteUpdateAsync(updates => updates.SetProperty(l => l.IsArchived, true), cancellationToken);
        }

        #endregion
    }
}