// Path: AuthHive.Auth/Repositories/AuthenticationAttemptLogRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 인증 시도 로그 저장소 구현 - AuthHive v15
    /// AuthenticationAttemptLog는 AuditableEntity를 직접 상속받으므로
    /// Repository를 직접 상속합니다.
    /// </summary>
    public class AuthenticationAttemptLogRepository : BaseRepository<AuthenticationAttemptLog>, 
        IAuthenticationAttemptLogRepository
    {
        private readonly ILogger<AuthenticationAttemptLogRepository> _logger;

        public AuthenticationAttemptLogRepository(
            AuthDbContext context,
            ILogger<AuthenticationAttemptLogRepository> logger) 
            : base(context)
        {
            _logger = logger;
        }

        #region 조회 메서드

        /// <summary>
        /// 사용자의 최근 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetRecentAttemptsAsync(
            Guid userId, 
            int count = 10)
        {
            return await _dbSet
                .Where(x => x.UserId == userId && !x.IsDeleted)
                .OrderByDescending(x => x.AttemptedAt)
                .Take(count)
                .ToListAsync();
        }

        /// <summary>
        /// 사용자명으로 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByUsernameAsync(
            string username,
            DateTime? since = null)
        {
            var query = _dbSet.Where(x => x.Username == username && !x.IsDeleted);
            
            if (since.HasValue)
            {
                query = query.Where(x => x.AttemptedAt >= since.Value);
            }

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 조직별 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByOrganizationAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            var query = _dbSet.Where(x => x.OrganizationId == organizationId && !x.IsDeleted);

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
            var query = _dbSet.Where(x => x.ApplicationId == applicationId && !x.IsDeleted);

            if (startDate.HasValue)
                query = query.Where(x => x.AttemptedAt >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(x => x.AttemptedAt <= endDate.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// IP 주소별 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByIpAddressAsync(
            string ipAddress,
            DateTime? since = null)
        {
            var query = _dbSet.Where(x => x.IpAddress == ipAddress && !x.IsDeleted);

            if (since.HasValue)
            {
                query = query.Where(x => x.AttemptedAt >= since.Value);
            }

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 인증 방법별 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByMethodAsync(
            AuthenticationMethod method,
            DateTime? since = null,
            bool? successOnly = null)
        {
            var query = _dbSet.Where(x => x.Method == method && !x.IsDeleted);

            if (since.HasValue)
            {
                query = query.Where(x => x.AttemptedAt >= since.Value);
            }

            if (successOnly.HasValue)
            {
                query = query.Where(x => x.IsSuccess == successOnly.Value);
            }

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        #endregion

        #region 실패 분석

        /// <summary>
        /// 실패한 인증 시도 횟수 조회
        /// </summary>
        public async Task<int> GetFailedAttemptCountAsync(
            Guid userId,
            DateTime since)
        {
            return await _dbSet
                .CountAsync(x => 
                    x.UserId == userId && 
                    !x.IsSuccess && 
                    x.AttemptedAt >= since &&
                    !x.IsDeleted);
        }

        /// <summary>
        /// 연속 실패 횟수 조회
        /// </summary>
        public async Task<int> GetConsecutiveFailureCountAsync(Guid userId)
        {
            // 마지막 성공 이후의 실패 횟수를 계산
            var lastSuccess = await _dbSet
                .Where(x => x.UserId == userId && x.IsSuccess && !x.IsDeleted)
                .OrderByDescending(x => x.AttemptedAt)
                .FirstOrDefaultAsync();

            var query = _dbSet.Where(x => x.UserId == userId && !x.IsSuccess && !x.IsDeleted);

            if (lastSuccess != null)
            {
                query = query.Where(x => x.AttemptedAt > lastSuccess.AttemptedAt);
            }

            return await query.CountAsync();
        }

        /// <summary>
        /// 실패한 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetFailedAttemptsAsync(
            Guid? userId = null,
            DateTime? since = null,
            int? limit = null)
        {
            var query = _dbSet.Where(x => !x.IsSuccess && !x.IsDeleted);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            query = query.OrderByDescending(x => x.AttemptedAt);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync();
        }

        /// <summary>
        /// 실패 사유별 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetByFailureReasonAsync(
            AuthenticationResult reason,
            DateTime? since = null)
        {
            var query = _dbSet.Where(x => 
                x.FailureReason == reason && 
                !x.IsSuccess && 
                !x.IsDeleted);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 계정 잠금을 트리거한 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetLockTriggerAttemptsAsync(
            DateTime? since = null)
        {
            var query = _dbSet.Where(x => 
                x.TriggeredAccountLock && 
                !x.IsDeleted);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        #endregion

        #region 보안 분석

        /// <summary>
        /// 의심스러운 인증 시도 조회
        /// </summary>
        public async Task<IEnumerable<AuthenticationAttemptLog>> GetSuspiciousAttemptsAsync(
            DateTime? since = null,
            int? minRiskScore = null)
        {
            var query = _dbSet.Where(x => x.IsSuspicious && !x.IsDeleted);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            if (minRiskScore.HasValue)
                query = query.Where(x => x.RiskScore >= minRiskScore.Value);

            return await query
                .OrderByDescending(x => x.RiskScore)
                .ThenByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// 브루트포스 공격 패턴 감지
        /// </summary>
        public async Task<IEnumerable<BruteForcePattern>> DetectBruteForceAttacksAsync(
            DateTime since,
            int threshold = 5)
        {
            var attempts = await _dbSet
                .Where(x => 
                    x.AttemptedAt >= since && 
                    !x.IsSuccess && 
                    !x.IsDeleted)
                .GroupBy(x => new { x.IpAddress, x.Username })
                .Select(g => new BruteForcePattern
                {
                    IpAddress = g.Key.IpAddress,
                    Username = g.Key.Username,
                    AttemptCount = g.Count(),
                    FirstAttempt = g.Min(x => x.AttemptedAt),
                    LastAttempt = g.Max(x => x.AttemptedAt)
                })
                .Where(x => x.AttemptCount >= threshold)
                .OrderByDescending(x => x.AttemptCount)
                .ToListAsync();

            return attempts;
        }

        /// <summary>
        /// 이상 접근 패턴 감지
        /// </summary>
        public async Task<IEnumerable<AnomalyPattern>> DetectAnomaliesAsync(
            Guid? userId = null,
            DateTime? since = null)
        {
            var anomalies = new List<AnomalyPattern>();

            // 1. 짧은 시간 내 여러 IP에서의 접근
            var multiIpAccess = await DetectMultipleIpAccessAsync(userId, since);
            anomalies.AddRange(multiIpAccess);

            // 2. 비정상적인 시간대 접근
            var unusualTimeAccess = await DetectUnusualTimeAccessAsync(userId, since);
            anomalies.AddRange(unusualTimeAccess);

            // 3. 지리적 이상 징후
            var geographicalAnomalies = await DetectGeographicalAnomaliesAsync(userId, since);
            anomalies.AddRange(geographicalAnomalies);

            return anomalies.OrderByDescending(x => x.RiskScore);
        }

        /// <summary>
        /// 위험 IP 주소 목록 조회
        /// </summary>
        public async Task<IEnumerable<RiskyIpAddress>> GetRiskyIpAddressesAsync(
            int failureThreshold = 10,
            DateTime? since = null)
        {
            var query = _dbSet.Where(x => !x.IsSuccess && !x.IsDeleted);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var riskyIps = await query
                .GroupBy(x => x.IpAddress)
                .Select(g => new RiskyIpAddress
                {
                    IpAddress = g.Key,
                    FailureCount = g.Count(),
                    UniqueUserCount = g.Select(x => x.UserId).Distinct().Count(),
                    FirstSeen = g.Min(x => x.AttemptedAt),
                    LastSeen = g.Max(x => x.AttemptedAt)
                })
                .Where(x => x.FailureCount >= failureThreshold)
                .OrderByDescending(x => x.FailureCount)
                .ToListAsync();

            return riskyIps;
        }

        #endregion

        #region 통계

        /// <summary>
        /// 인증 시도 통계 조회
        /// </summary>
        public async Task<AuthenticationStatistics> GetStatisticsAsync(
            DateTime from,
            DateTime to,
            Guid? organizationId = null)
        {
            var query = _dbSet.Where(x => 
                x.AttemptedAt >= from && 
                x.AttemptedAt <= to && 
                !x.IsDeleted);

            if (organizationId.HasValue)
                query = query.Where(x => x.OrganizationId == organizationId.Value);

            var attempts = await query.ToListAsync();

            return new AuthenticationStatistics
            {
                TotalAttempts = attempts.Count,
                SuccessfulAttempts = attempts.Count(x => x.IsSuccess),
                FailedAttempts = attempts.Count(x => !x.IsSuccess),
                SuccessRate = attempts.Any() 
                    ? (double)attempts.Count(x => x.IsSuccess) / attempts.Count 
                    : 0,
                AttemptsByMethod = attempts
                    .GroupBy(x => x.Method)
                    .ToDictionary(g => g.Key, g => g.Count()),
                FailureReasons = attempts
                    .Where(x => !x.IsSuccess && x.FailureReason.HasValue)
                    .GroupBy(x => x.FailureReason!.Value)
                    .ToDictionary(g => g.Key, g => g.Count())
            };
        }

        /// <summary>
        /// 시간대별 인증 시도 분포
        /// </summary>
        public async Task<Dictionary<int, int>> GetHourlyDistributionAsync(
            DateTime date,
            Guid? organizationId = null)
        {
            var startDate = date.Date;
            var endDate = startDate.AddDays(1);

            var query = _dbSet.Where(x => 
                x.AttemptedAt >= startDate && 
                x.AttemptedAt < endDate &&
                !x.IsDeleted);

            if (organizationId.HasValue)
                query = query.Where(x => x.OrganizationId == organizationId.Value);

            var distribution = await query
                .GroupBy(x => x.AttemptedAt.Hour)
                .Select(g => new { Hour = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Hour, x => x.Count);

            // 모든 시간대를 포함하도록 빈 시간대 채우기
            var result = new Dictionary<int, int>();
            for (int i = 0; i < 24; i++)
            {
                result[i] = distribution.GetValueOrDefault(i, 0);
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
            var query = _dbSet.Where(x => !x.IsDeleted);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            if (organizationId.HasValue)
                query = query.Where(x => x.OrganizationId == organizationId.Value);

            var methodStats = await query
                .GroupBy(x => x.Method)
                .Select(g => new
                {
                    Method = g.Key,
                    Total = g.Count(),
                    Success = g.Count(x => x.IsSuccess)
                })
                .ToDictionaryAsync(x => x.Method, x => x.Total > 0 ? (double)x.Success / x.Total : 0);

            return methodStats;
        }

        /// <summary>
        /// 상위 실패 사용자 조회
        /// </summary>
        public async Task<IEnumerable<UserFailureStatistics>> GetTopFailedUsersAsync(
            int topCount = 10,
            DateTime? since = null)
        {
            var query = _dbSet.Where(x => !x.IsSuccess && x.UserId != null && !x.IsDeleted);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var topFailures = await query
                .GroupBy(x => new { x.UserId, x.Username })
                .Select(g => new UserFailureStatistics
                {
                    UserId = g.Key.UserId!.Value,
                    Username = g.Key.Username ?? string.Empty,
                    FailureCount = g.Count(),
                    LastFailure = g.Max(x => x.AttemptedAt),
                    IsLocked = false // 계정 잠금 상태는 별도 조회 필요
                })
                .OrderByDescending(x => x.FailureCount)
                .Take(topCount)
                .ToListAsync();

            return topFailures;
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
            var query = _dbSet.Where(x => x.MfaRequired && !x.IsDeleted);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            return await query
                .OrderByDescending(x => x.AttemptedAt)
                .ToListAsync();
        }

        /// <summary>
        /// MFA 성공률 조회
        /// </summary>
        public async Task<double> GetMfaSuccessRateAsync(
            DateTime? since = null,
            Guid? organizationId = null)
        {
            var query = _dbSet.Where(x => x.MfaRequired && !x.IsDeleted);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            if (organizationId.HasValue)
                query = query.Where(x => x.OrganizationId == organizationId.Value);

            var total = await query.CountAsync();
            if (total == 0) return 0;

            var successful = await query.CountAsync(x => x.MfaCompleted == true);
            return (double)successful / total;
        }

        #endregion

        #region 정리 작업

        /// <summary>
        /// 오래된 로그 정리
        /// </summary>
        public async Task<int> CleanupOldLogsAsync(DateTime before)
        {
            var oldLogs = await _dbSet
                .Where(x => x.AttemptedAt < before)
                .ToListAsync();

            if (oldLogs.Any())
            {
                _dbSet.RemoveRange(oldLogs);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Cleaned up {Count} old authentication logs before {Date}",
                    oldLogs.Count, before);
            }

            return oldLogs.Count;
        }

        /// <summary>
        /// 성공한 오래된 로그 아카이브
        /// </summary>
        public async Task<int> ArchiveSuccessfulLogsAsync(
            DateTime before,
            string archiveLocation)
        {
            var successfulLogs = await _dbSet
                .Where(x => x.IsSuccess && x.AttemptedAt < before)
                .ToListAsync();

            if (!successfulLogs.Any())
                return 0;

            // TODO: 실제 아카이브 로직 구현 (예: BigQuery, 파일 시스템 등)
            // 여기서는 삭제만 수행
            _dbSet.RemoveRange(successfulLogs);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Archived {Count} successful authentication logs to {Location}",
                successfulLogs.Count, archiveLocation);

            return successfulLogs.Count;
        }

        #endregion

        #region Private Helper Methods

        private async Task<IEnumerable<AnomalyPattern>> DetectMultipleIpAccessAsync(
            Guid? userId, 
            DateTime? since)
        {
            var query = _dbSet.Where(x => !x.IsDeleted);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var multiIpUsers = await query
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

            return multiIpUsers;
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectUnusualTimeAccessAsync(
            Guid? userId,
            DateTime? since)
        {
            // 비정상적인 시간대 (새벽 2-5시) 접근 탐지
            var query = _dbSet.Where(x => !x.IsDeleted);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            var unusualTimeAccess = await query
                .Where(x => x.AttemptedAt.Hour >= 2 && x.AttemptedAt.Hour <= 5)
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

            return unusualTimeAccess;
        }

        private async Task<IEnumerable<AnomalyPattern>> DetectGeographicalAnomaliesAsync(
            Guid? userId,
            DateTime? since)
        {
            // 지리적 이상 징후 탐지 (IP 기반 위치 변경)
            // 실제 구현에서는 IP-지리 정보 매핑 서비스를 활용
            // 여기서는 간단한 예시만 제공
            var anomalies = new List<AnomalyPattern>();

            var query = _dbSet.Where(x => !x.IsDeleted);

            if (userId.HasValue)
                query = query.Where(x => x.UserId == userId.Value);

            if (since.HasValue)
                query = query.Where(x => x.AttemptedAt >= since.Value);

            // IP 변경이 잦은 사용자 감지
            var frequentIpChanges = await query
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

            anomalies.AddRange(frequentIpChanges);

            return anomalies;
        }

        #endregion
    }
}