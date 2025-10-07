using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Models.Auth.Permissions.Common;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// PermissionValidationLog Repository - 권한 검증 로그 관리 Repository
    /// AuthHive v15 권한 검증 추적 및 분석 시스템의 핵심 저장소
    /// </summary>
    public class PermissionValidationLogRepository : BaseRepository<PermissionValidationLog>, IPermissionValidationLogRepository
    {
        public PermissionValidationLogRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }

        #region 기본 조회

        /// <summary>
        /// ConnectedId의 권한 검증 로그 조회
        /// </summary>
        public async Task<PagedResult<PermissionValidationLog>> GetByConnectedIdAsync(
            Guid connectedId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int pageNumber = 1,
            int pageSize = 50)
        {
            var query = Query().Where(log => log.ConnectedId == connectedId);

            if (startDate.HasValue)
            {
                query = query.Where(log => log.Timestamp >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(log => log.Timestamp <= endDate.Value);
            }

            var totalCount = await query.CountAsync();

            var items = await query
                .Include(log => log.ConnectedIdEntity)
                .Include(log => log.PlatformApplication)
                .OrderByDescending(log => log.Timestamp)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return PagedResult<PermissionValidationLog>.Create(items, totalCount, pageNumber, pageSize);
        }

        /// <summary>
        /// 애플리케이션별 권한 검증 로그 조회
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetByApplicationAsync(
            Guid applicationId,
            bool? isAllowed = null,
            int limit = 100)
        {
            var query = Query().Where(log => log.ApplicationId == applicationId);

            if (isAllowed.HasValue)
            {
                query = query.Where(log => log.IsAllowed == isAllowed.Value);
            }

            return await query
                .OrderByDescending(log => log.Timestamp)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .ToListAsync();
        }

        /// <summary>
        /// 스코프별 검증 로그 조회
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetByScopeAsync(
            string requestedScope,
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            var query = QueryForOrganization(organizationId)
                .Where(log => log.RequestedScope == requestedScope);

            if (startDate.HasValue)
            {
                query = query.Where(log => log.Timestamp >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(log => log.Timestamp <= endDate.Value);
            }

            return await query
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.ConnectedIdEntity)
                .ToListAsync();
        }

        /// <summary>
        /// 세션별 권한 검증 로그 조회
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetBySessionAsync(Guid sessionId)
        {
            return await Query()
                .Where(log => log.SessionId == sessionId)
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.Session)
                .ToListAsync();
        }

        /// <summary>
        /// 특정 권한에 대한 최근 검증 로그 조회
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetRecentByPermissionIdAsync(
            Guid permissionId,
            int days)
        {
            var startDate = DateTime.UtcNow.AddDays(-days);
            
            // Permission ID로 해당 권한의 Scope를 먼저 조회
            var permission = await _context.Set<Permission>()
                .FirstOrDefaultAsync(p => p.Id == permissionId);
            
            if (permission == null)
            {
                return Enumerable.Empty<PermissionValidationLog>();
            }

            // 해당 Scope로 검증된 로그들을 조회
            return await Query()
                .Where(log => log.RequestedScope == permission.Scope && 
                             log.Timestamp >= startDate)
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.ConnectedIdEntity)
                .ToListAsync();
        }

        /// <summary>
        /// 특정 권한에 대한 마지막 검증 로그 조회
        /// </summary>
        public async Task<PermissionValidationLog?> GetLastValidationAsync(Guid permissionId)
        {
            // Permission ID로 해당 권한의 Scope를 먼저 조회
            var permission = await _context.Set<Permission>()
                .FirstOrDefaultAsync(p => p.Id == permissionId);
            
            if (permission == null)
            {
                return null;
            }

            // 해당 Scope로 검증된 가장 최근 로그 조회
            return await Query()
                .Where(log => log.RequestedScope == permission.Scope)
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.ConnectedIdEntity)
                .FirstOrDefaultAsync();
        }

        /// <summary>
        /// 조직 및 권한별 검증 로그 수 조회
        /// </summary>
        public async Task<int> CountByOrganizationAsync(Guid organizationId, Guid permissionId)
        {
            // Permission ID로 해당 권한의 Scope를 먼저 조회
            var permission = await _context.Set<Permission>()
                .FirstOrDefaultAsync(p => p.Id == permissionId);
            
            if (permission == null)
            {
                return 0;
            }

            // 해당 조직과 Scope로 검증된 로그 수 카운트
            return await QueryForOrganization(organizationId)
                .Where(log => log.RequestedScope == permission.Scope)
                .CountAsync();
        }

        /// <summary>
        /// 애플리케이션 및 권한별 검증 로그 수 조회
        /// </summary>
        public async Task<int> CountByApplicationAsync(Guid applicationId, Guid permissionId)
        {
            // Permission ID로 해당 권한의 Scope를 먼저 조회
            var permission = await _context.Set<Permission>()
                .FirstOrDefaultAsync(p => p.Id == permissionId);
            
            if (permission == null)
            {
                return 0;
            }

            // 해당 애플리케이션과 Scope로 검증된 로그 수 카운트
            return await Query()
                .Where(log => log.ApplicationId == applicationId && 
                             log.RequestedScope == permission.Scope)
                .CountAsync();
        }

        #endregion

        #region 로그 기록

        /// <summary>
        /// 권한 검증 로그 기록
        /// </summary>
        public async Task<PermissionValidationLog> LogValidationAsync(PermissionValidationLog log)
        {
            log.Id = Guid.NewGuid();
            log.Timestamp = DateTime.UtcNow;
            log.CreatedAt = DateTime.UtcNow;

            return await AddAsync(log);
        }

        /// <summary>
        /// 성공한 권한 검증 기록
        /// </summary>
        public async Task<PermissionValidationLog> LogSuccessfulValidationAsync(
            Guid connectedId,
            string requestedScope,
            Guid? applicationId,
            int durationMs,
            PermissionCacheStatus cacheStatus)
        {
            // ConnectedId에서 OrganizationId 가져오기
            var connectedIdEntity = await _context.Set<ConnectedId>()
                .FirstOrDefaultAsync(c => c.Id == connectedId);

            if (connectedIdEntity == null)
            {
                throw new ArgumentException("ConnectedId not found", nameof(connectedId));
            }

            var log = new PermissionValidationLog
            {
                Id = Guid.NewGuid(),
                ConnectedId = connectedId,
                ApplicationId = applicationId,
                RequestedScope = requestedScope,
                IsAllowed = true,
                ValidationResult = PermissionValidationResult.Granted,
                ValidationDurationMs = durationMs,
                CacheStatus = cacheStatus,
                OrganizationId = connectedIdEntity.OrganizationId,
                Timestamp = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow
            };

            return await AddAsync(log);
        }

        /// <summary>
        /// 실패한 권한 검증 기록
        /// </summary>
        public async Task<PermissionValidationLog> LogFailedValidationAsync(
            Guid connectedId,
            string requestedScope,
            PermissionValidationResult validationResult,
            string denialReason,
            Guid? applicationId = null)
        {
            // ConnectedId에서 OrganizationId 가져오기
            var connectedIdEntity = await _context.Set<ConnectedId>()
                .FirstOrDefaultAsync(c => c.Id == connectedId);

            if (connectedIdEntity == null)
            {
                throw new ArgumentException("ConnectedId not found", nameof(connectedId));
            }

            var log = new PermissionValidationLog
            {
                Id = Guid.NewGuid(),
                ConnectedId = connectedId,
                ApplicationId = applicationId,
                RequestedScope = requestedScope,
                IsAllowed = false,
                ValidationResult = validationResult,
                DenialReason = denialReason,
                OrganizationId = connectedIdEntity.OrganizationId,
                Timestamp = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow
            };

            return await AddAsync(log);
        }

        /// <summary>
        /// 리소스 접근 검증 기록
        /// </summary>
        public async Task<PermissionValidationLog> LogResourceAccessAsync(
            Guid connectedId,
            ResourceType resourceType,
            Guid resourceId,
            string requestedScope,
            bool isAllowed)
        {
            // ConnectedId에서 OrganizationId 가져오기
            var connectedIdEntity = await _context.Set<ConnectedId>()
                .FirstOrDefaultAsync(c => c.Id == connectedId);

            if (connectedIdEntity == null)
            {
                throw new ArgumentException("ConnectedId not found", nameof(connectedId));
            }

            var log = new PermissionValidationLog
            {
                Id = Guid.NewGuid(),
                ConnectedId = connectedId,
                RequestedScope = requestedScope,
                IsAllowed = isAllowed,
                ResourceType = resourceType,
                ResourceId = resourceId,
                ValidationResult = isAllowed ? PermissionValidationResult.Granted : PermissionValidationResult.ResourceAccessDenied,
                OrganizationId = connectedIdEntity.OrganizationId,
                Timestamp = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow
            };

            return await AddAsync(log);
        }

        #endregion

        #region 거부 분석

        /// <summary>
        /// 거부된 권한 검증 조회
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetDeniedValidationsAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int limit = 100)
        {
            var query = QueryForOrganization(organizationId)
                .Where(log => !log.IsAllowed);

            if (startDate.HasValue)
            {
                query = query.Where(log => log.Timestamp >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(log => log.Timestamp <= endDate.Value);
            }

            return await query
                .OrderByDescending(log => log.Timestamp)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .ToListAsync();
        }

        /// <summary>
        /// 거부 사유별 통계
        /// </summary>
        public async Task<Dictionary<string, int>> GetDenialReasonStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await QueryForOrganization(organizationId)
                .Where(log => !log.IsAllowed &&
                             log.Timestamp >= startDate &&
                             !string.IsNullOrEmpty(log.DenialReason))
                .GroupBy(log => log.DenialReason)
                .ToDictionaryAsync(g => g.Key!, g => g.Count());
        }

        /// <summary>
        /// 가장 많이 거부된 스코프 조회
        /// </summary>
        public async Task<IEnumerable<(string Scope, int DenialCount)>> GetMostDeniedScopesAsync(
            Guid organizationId,
            int limit = 10)
        {
            return await QueryForOrganization(organizationId)
                .Where(log => !log.IsAllowed)
                .GroupBy(log => log.RequestedScope)
                .Select(g => new { Scope = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(limit)
                .Select(x => ValueTuple.Create(x.Scope, x.Count))
                .ToListAsync();
        }

        /// <summary>
        /// ConnectedId별 거부율 계산
        /// </summary>
        public async Task<double> CalculateDenialRateAsync(Guid connectedId, int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var totalValidations = await Query()
                .Where(log => log.ConnectedId == connectedId && log.Timestamp >= startDate)
                .CountAsync();

            if (totalValidations == 0) return 0;

            var deniedValidations = await Query()
                .Where(log => log.ConnectedId == connectedId && 
                             log.Timestamp >= startDate && 
                             !log.IsAllowed)
                .CountAsync();

            return Math.Round((double)deniedValidations / totalValidations * 100, 2);
        }

        #endregion

        #region 성능 분석

        /// <summary>
        /// 평균 검증 시간 계산
        /// </summary>
        public async Task<double> GetAverageValidationTimeAsync(Guid organizationId, int period = 7)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var avgTime = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.ValidationDurationMs.HasValue)
                .AverageAsync(log => (double?)log.ValidationDurationMs);

            return avgTime ?? 0;
        }

        /// <summary>
        /// 캐시 히트율 계산
        /// </summary>
        public async Task<double> CalculateCacheHitRateAsync(Guid organizationId, int period = 7)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var totalWithCache = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.CacheStatus.HasValue)
                .CountAsync();

            if (totalWithCache == 0) return 0;

            var cacheHits = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.CacheStatus == PermissionCacheStatus.Hit)
                .CountAsync();

            return Math.Round((double)cacheHits / totalWithCache * 100, 2);
        }

        /// <summary>
        /// 캐시 상태별 통계
        /// </summary>
        public async Task<Dictionary<PermissionCacheStatus, int>> GetCacheStatusStatisticsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            return await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.Timestamp <= endDate &&
                             log.CacheStatus.HasValue)
                .GroupBy(log => log.CacheStatus!.Value)
                .ToDictionaryAsync(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// 느린 검증 조회
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetSlowValidationsAsync(
            int thresholdMs,
            Guid organizationId,
            int limit = 50)
        {
            return await QueryForOrganization(organizationId)
                .Where(log => log.ValidationDurationMs.HasValue &&
                             log.ValidationDurationMs >= thresholdMs)
                .OrderByDescending(log => log.ValidationDurationMs)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .ToListAsync();
        }

        #endregion

        #region 검증 결과 분석

        /// <summary>
        /// 검증 결과별 통계
        /// </summary>
        public async Task<Dictionary<PermissionValidationResult, int>> GetValidationResultStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate)
                .GroupBy(log => log.ValidationResult)
                .ToDictionaryAsync(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// ConnectedId 검증 결과 통계
        /// </summary>
        public async Task<Dictionary<ConnectedIdValidationResult, int>> GetConnectedIdValidationStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.ConnectedIdValidationResult.HasValue)
                .GroupBy(log => log.ConnectedIdValidationResult!.Value)
                .ToDictionaryAsync(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// 검증 단계별 분석
        /// </summary>
        public async Task<Dictionary<string, (int Passed, int Failed)>> GetValidationStepAnalysisAsync(
            Guid organizationId)
        {
            var logs = await QueryForOrganization(organizationId)
                .Where(log => !string.IsNullOrEmpty(log.ValidationStep))
                .ToListAsync();

            return logs
                .GroupBy(log => log.ValidationStep!)
                .ToDictionary(
                    g => g.Key,
                    g => (
                        Passed: g.Count(log => log.IsAllowed),
                        Failed: g.Count(log => !log.IsAllowed)
                    )
                );
        }

        #endregion

        #region 리소스 접근 분석

        /// <summary>
        /// 리소스 타입별 접근 통계
        /// </summary>
        public async Task<Dictionary<ResourceType, int>> GetResourceAccessStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.ResourceType.HasValue)
                .GroupBy(log => log.ResourceType!.Value)
                .ToDictionaryAsync(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// 특정 리소스 접근 이력
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetResourceAccessHistoryAsync(
            ResourceType resourceType,
            Guid resourceId,
            int limit = 100)
        {
            return await Query()
                .Where(log => log.ResourceType == resourceType && log.ResourceId == resourceId)
                .OrderByDescending(log => log.Timestamp)
                .Take(limit)
                .Include(log => log.ConnectedIdEntity)
                .ToListAsync();
        }

        /// <summary>
        /// 가장 많이 접근된 리소스
        /// </summary>
        public async Task<IEnumerable<(Guid ResourceId, int AccessCount)>> GetMostAccessedResourcesAsync(
            Guid organizationId,
            ResourceType resourceType,
            int limit = 10)
        {
            return await QueryForOrganization(organizationId)
                .Where(log => log.ResourceType == resourceType &&
                             log.ResourceId.HasValue)
                .GroupBy(log => log.ResourceId!.Value)
                .Select(g => new { ResourceId = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(limit)
                .Select(x => ValueTuple.Create(x.ResourceId, x.Count))
                .ToListAsync();
        }

        #endregion

        #region 보안 분석

        /// <summary>
        /// 의심스러운 패턴 감지
        /// </summary>
        public async Task<bool> DetectSuspiciousPatternsAsync(
            Guid connectedId,
            int timeWindowMinutes = 5)
        {
            var windowStart = DateTime.UtcNow.AddMinutes(-timeWindowMinutes);
            
            var recentFailures = await Query()
                .Where(log => log.ConnectedId == connectedId &&
                             log.Timestamp >= windowStart &&
                             !log.IsAllowed)
                .CountAsync();

            return recentFailures >= 5;
        }

        /// <summary>
        /// 비정상적인 접근 시도 조회
        /// </summary>
        public async Task<IEnumerable<PermissionValidationLog>> GetAbnormalAccessAttemptsAsync(
            Guid organizationId,
            int threshold,
            int timeWindowMinutes)
        {
            var windowStart = DateTime.UtcNow.AddMinutes(-timeWindowMinutes);

            var suspiciousConnectedIds = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= windowStart &&
                             !log.IsAllowed)
                .GroupBy(log => log.ConnectedId)
                .Where(g => g.Count() >= threshold)
                .Select(g => g.Key)
                .ToListAsync();

            return await QueryForOrganization(organizationId)
                .Where(log => suspiciousConnectedIds.Contains(log.ConnectedId) &&
                             log.Timestamp >= windowStart)
                .OrderByDescending(log => log.Timestamp)
                .Include(log => log.ConnectedIdEntity)
                .ToListAsync();
        }

        /// <summary>
        /// IP별 검증 실패 분석
        /// </summary>
        public async Task<(int FailureCount, IEnumerable<string> FailedScopes)> AnalyzeIpFailuresAsync(
            string ipAddress,
            int period = 1)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var failures = await Query()
                .Where(log => log.IpAddress == ipAddress &&
                             log.Timestamp >= startDate &&
                             !log.IsAllowed)
                .ToListAsync();

            var failureCount = failures.Count;
            var failedScopes = failures.Select(log => log.RequestedScope).Distinct();

            return (failureCount, failedScopes);
        }

        #endregion

        #region 역할 및 권한 분석

        /// <summary>
        /// 역할별 검증 통계
        /// </summary>
        public async Task<Dictionary<string, (int Success, int Failure)>> GetRoleValidationStatisticsAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            var logs = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             !string.IsNullOrEmpty(log.RolesFound))
                .ToListAsync();

            var result = new Dictionary<string, (int Success, int Failure)>();
            
            foreach (var log in logs)
            {
                var roleKey = "general";
                if (!result.ContainsKey(roleKey))
                {
                    result[roleKey] = (0, 0);
                }

                if (log.IsAllowed)
                {
                    result[roleKey] = (result[roleKey].Success + 1, result[roleKey].Failure);
                }
                else
                {
                    result[roleKey] = (result[roleKey].Success, result[roleKey].Failure + 1);
                }
            }

            return result;
        }

        /// <summary>
        /// 권한별 사용 빈도
        /// </summary>
        public async Task<Dictionary<string, int>> GetPermissionUsageFrequencyAsync(
            Guid organizationId,
            int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);

            return await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate)
                .GroupBy(log => log.RequestedScope)
                .ToDictionaryAsync(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// 사용되지 않는 권한 찾기
        /// </summary>
        public async Task<IEnumerable<string>> FindUnusedPermissionsAsync(
            Guid organizationId,
            int inactiveDays = 90)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);

            var allScopes = await _context.Set<Permission>()
                .Select(p => p.Scope)
                .ToListAsync();

            var usedScopes = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= cutoffDate)
                .Select(log => log.RequestedScope)
                .Distinct()
                .ToListAsync();

            return allScopes.Except(usedScopes);
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 검증 로그 일괄 기록
        /// </summary>
        public async Task<int> BulkLogAsync(IEnumerable<PermissionValidationLog> logs)
        {
            var logList = logs.ToList();
            var timestamp = DateTime.UtcNow;

            foreach (var log in logList)
            {
                if (log.Id == Guid.Empty) log.Id = Guid.NewGuid();
                if (log.Timestamp == default) log.Timestamp = timestamp;
                if (log.CreatedAt == default) log.CreatedAt = timestamp;
            }

            await AddRangeAsync(logList);
            return logList.Count;
        }

        /// <summary>
        /// 오래된 로그 정리
        /// </summary>
        public async Task<int> CleanupOldLogsAsync(int olderThanDays, int batchSize = 1000)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-olderThanDays);

            var oldLogs = await Query()
                .Where(log => log.Timestamp < cutoffDate)
                .Take(batchSize)
                .ToListAsync();

            if (!oldLogs.Any()) return 0;

            await DeleteRangeAsync(oldLogs);
            return oldLogs.Count;
        }

        /// <summary>
        /// 로그 아카이빙
        /// </summary>
        public async Task<int> ArchiveLogsAsync(
            DateTime startDate,
            DateTime endDate,
            string targetLocation)
        {
            var logsToArchive = await Query()
                .Where(log => log.Timestamp >= startDate && log.Timestamp <= endDate)
                .ToListAsync();

            return logsToArchive.Count;
        }

        #endregion

        #region 리포팅

        /// <summary>
        /// 권한 검증 요약 보고서
        /// </summary>
        public async Task<PermissionValidationSummary> GetValidationSummaryAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate)
        {
            var logs = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.Timestamp <= endDate)
                .ToListAsync();

            var summary = new PermissionValidationSummary
            {
                OrganizationId = organizationId,
                StartDate = startDate,
                EndDate = endDate,
                TotalValidations = logs.Count,
                SuccessfulValidations = logs.Count(l => l.IsAllowed),
                FailedValidations = logs.Count(l => !l.IsAllowed),
                UniqueUsers = logs.Select(l => l.ConnectedId).Distinct().Count(),
                UniqueApplications = logs.Where(l => l.ApplicationId.HasValue)
                                       .Select(l => l.ApplicationId!.Value)
                                       .Distinct()
                                       .Count()
            };

            var cacheStats = logs.Where(l => l.CacheStatus.HasValue).ToList();
            if (cacheStats.Any())
            {
                summary.CacheHits = cacheStats.Count(l => l.CacheStatus == PermissionCacheStatus.Hit);
                summary.CacheMisses = cacheStats.Count - summary.CacheHits;
            }

            var timeLogs = logs.Where(l => l.ValidationDurationMs.HasValue).ToList();
            if (timeLogs.Any())
            {
                summary.AverageValidationTimeMs = timeLogs.Average(l => l.ValidationDurationMs!.Value);
            }

            summary.TopDenialReasons = logs
                .Where(l => !l.IsAllowed && !string.IsNullOrEmpty(l.DenialReason))
                .GroupBy(l => l.DenialReason!)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => g.Key)
                .ToList();

            return summary;
        }

        /// <summary>
        /// 시간대별 검증 패턴
        /// </summary>
        public async Task<Dictionary<int, int>> GetHourlyValidationPatternAsync(
            Guid organizationId,
            DateTime date)
        {
            var startDate = date.Date;
            var endDate = startDate.AddDays(1);

            var hourlyData = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.Timestamp < endDate)
                .GroupBy(log => log.Timestamp.Hour)
                .ToDictionaryAsync(g => g.Key, g => g.Count());

            var result = new Dictionary<int, int>();
            for (int hour = 0; hour < 24; hour++)
            {
                result[hour] = hourlyData.GetValueOrDefault(hour, 0);
            }

            return result;
        }

        /// <summary>
        /// 주간 트렌드 분석
        /// </summary>
        public async Task<IEnumerable<WeeklyValidationTrend>> GetWeeklyTrendsAsync(
            Guid organizationId,
            int weeks = 4)
        {
            var endDate = DateTime.UtcNow.Date;
            var startDate = endDate.AddDays(-weeks * 7);

            var logs = await QueryForOrganization(organizationId)
                .Where(log => log.Timestamp >= startDate &&
                             log.Timestamp <= endDate)
                .ToListAsync();

            var trends = new List<WeeklyValidationTrend>();

            for (int week = 0; week < weeks; week++)
            {
                var weekStart = startDate.AddDays(week * 7);
                var weekEnd = weekStart.AddDays(7);

                var weekLogs = logs.Where(l => l.Timestamp >= weekStart && l.Timestamp < weekEnd);

                trends.Add(new WeeklyValidationTrend
                {
                    WeekStartDate = weekStart,
                    WeekEndDate = weekEnd,
                    TotalValidations = weekLogs.Count(),
                    SuccessfulValidations = weekLogs.Count(l => l.IsAllowed),
                    FailedValidations = weekLogs.Count(l => !l.IsAllowed),
                    UniqueUsers = weekLogs.Select(l => l.ConnectedId).Distinct().Count()
                });
            }

            return trends;
        }

        #endregion
    }
}