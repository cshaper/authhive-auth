using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Interfaces.System.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Core.Audit;
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 감사 로그 저장소 구현 - AuthHive v15
    /// 시스템 전체의 모든 감사 추적을 관리하는 Read-Only Repository
    /// 
    /// 특징:
    /// - Read-Only: 감사 로그는 생성만 가능하고 수정/삭제 불가
    /// - 시스템 전역: 조직에 종속되지 않는 시스템 레벨 로그
    /// - 장기 보관: 컴플라이언스 요구사항에 따른 장기 데이터 보관
    /// </summary>
    public class AuditLogRepository : BaseRepository<AuditLog>, IAuditLogRepository
    {
        private readonly ILogger<AuditLogRepository> _logger;

        public AuditLogRepository(
            AuthDbContext context,
            ILogger<AuditLogRepository> logger) : base(context)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 기본 조회

        /// <summary>엔티티별 감사 로그 조회 (인터페이스 호환성)</summary>
        public async Task<IEnumerable<AuditLog>> GetByEntityAsync(
            string entityType, 
            Guid entityId, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            CancellationToken cancellationToken = default)
        {
            return await GetByResourceAsync(entityType, entityId.ToString(), fromDate, toDate, cancellationToken);
        }

        /// <summary>리소스별 감사 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByResourceAsync(
            string resourceType, 
            string resourceId, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            CancellationToken cancellationToken = default)
        {
            var query = GetActiveQuery()
                .Where(log => log.ResourceType == resourceType && log.ResourceId == resourceId);

            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            return await query
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>사용자별 감사 로그 조회 (인터페이스 호환성)</summary>
        public async Task<IEnumerable<AuditLog>> GetByUserAsync(
            Guid userId, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            int? limit = null, 
            CancellationToken cancellationToken = default)
        {
            return await GetByConnectedIdAsync(userId, fromDate, toDate, limit, cancellationToken);
        }

        /// <summary>ConnectedId별 감사 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByConnectedIdAsync(
            Guid connectedId, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            int? limit = null, 
            CancellationToken cancellationToken = default)
        {
            var query = GetActiveQuery().Where(log => log.PerformedByConnectedId == connectedId);

            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            query = query.OrderByDescending(log => log.Timestamp);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>조직별 감사 로그 조회 (인터페이스 호환성)</summary>
        public async Task<IEnumerable<AuditLog>> GetByOrganizationAsync(
            Guid organizationId, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            int? limit = null, 
            CancellationToken cancellationToken = default)
        {
            return await GetByApplicationAsync(organizationId, fromDate, toDate, limit, cancellationToken);
        }

        /// <summary>애플리케이션별 감사 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByApplicationAsync(
            Guid applicationId, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            int? limit = null, 
            CancellationToken cancellationToken = default)
        {
            var query = GetActiveQuery().Where(log => log.ApplicationId == applicationId);

            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            query = query.OrderByDescending(log => log.Timestamp);

            if (limit.HasValue)
                query = query.Take(limit.Value);

            return await query.ToListAsync(cancellationToken);
        }

        #endregion

        #region 액션 타입별 조회

        /// <summary>액션 타입별 로그 조회 (인터페이스 호환성)</summary>
        public async Task<IEnumerable<AuditLog>> GetByActionAsync(
            string actionType, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            CancellationToken cancellationToken = default)
        {
            var query = GetActiveQuery().Where(log => log.Action == actionType);

            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            return await query
                .OrderByDescending(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>중요 이벤트 로그 조회 (로그인, 권한 변경 등)</summary>
        public async Task<IEnumerable<AuditLog>> GetCriticalEventsAsync(
            Guid? organizationId = null, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            CancellationToken cancellationToken = default)
        {
            var criticalActions = new[]
            {
                "Login", "Logout", "PasswordChanged", "PermissionChanged", 
                "RoleAssigned", "RoleRevoked", "OrganizationCreated", 
                "OrganizationDeleted", "UserCreated", "UserDeleted",
                "SystemStartup", "SystemShutdown", "ConfigurationChanged"
            };

            var query = GetActiveQuery().Where(log => criticalActions.Contains(log.Action));

            if (organizationId.HasValue)
                query = query.Where(log => log.ApplicationId == organizationId.Value);

            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            return await query
                .OrderByDescending(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>보안 이벤트 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetSecurityEventsAsync(
            Guid? organizationId = null, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            CancellationToken cancellationToken = default)
        {
            var securityActions = new[]
            {
                "LoginFailed", "PasswordChanged", "AccountLocked", 
                "SuspiciousActivity", "UnauthorizedAccess", "SecurityBreach",
                "MfaEnabled", "MfaDisabled", "TokenRevoked"
            };

            var query = GetActiveQuery().Where(log => securityActions.Contains(log.Action));

            if (organizationId.HasValue)
                query = query.Where(log => log.ApplicationId == organizationId.Value);

            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            return await query
                .OrderByDescending(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 변경 추적

        /// <summary>엔티티 변경 이력 조회 (인터페이스 호환성)</summary>
        public async Task<IEnumerable<AuditLog>> GetEntityHistoryAsync(
            string entityType, 
            Guid entityId, 
            CancellationToken cancellationToken = default)
        {
            return await GetActiveQuery()
                .Where(log => log.ResourceType == entityType && log.ResourceId == entityId.ToString())
                .Include(log => log.AuditTrailDetails)
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>특정 필드 변경 이력 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetFieldChangesAsync(
            string entityType, 
            Guid entityId, 
            string fieldName, 
            CancellationToken cancellationToken = default)
        {
            return await GetActiveQuery()
                .Where(log => 
                    log.ResourceType == entityType && 
                    log.ResourceId == entityId.ToString() &&
                    log.AuditTrailDetails.Any(detail => detail.FieldName == fieldName))
                .Include(log => log.AuditTrailDetails.Where(detail => detail.FieldName == fieldName))
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region IP 및 세션 추적

        /// <summary>IP 주소별 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByIpAddressAsync(
            string ipAddress, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return new List<AuditLog>();

            var query = GetActiveQuery().Where(log => log.IPAddress == ipAddress);

            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            return await query
                .OrderByDescending(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>세션별 로그 조회 (인터페이스 호환성)</summary>
        public async Task<IEnumerable<AuditLog>> GetBySessionIdAsync(
            string sessionId, 
            CancellationToken cancellationToken = default)
        {
            return await GetByRequestIdAsync(sessionId, cancellationToken);
        }

        /// <summary>요청 ID별 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetByRequestIdAsync(
            string requestId, 
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(requestId))
                return new List<AuditLog>();

            return await GetActiveQuery()
                .Where(log => log.RequestId == requestId)
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>의심스러운 활동 감지</summary>
        public async Task<IEnumerable<SuspiciousActivity>> DetectSuspiciousActivitiesAsync(
            DateTime fromDate, 
            DateTime toDate, 
            CancellationToken cancellationToken = default)
        {
            var result = new List<SuspiciousActivity>();

            // 1. 동일 IP에서 여러 ConnectedId 로그인 시도
            var multipleAccountsPerIp = await GetActiveQuery()
                .Where(log => 
                    log.Timestamp >= fromDate && 
                    log.Timestamp <= toDate &&
                    log.Action == "Login" &&
                    !string.IsNullOrEmpty(log.IPAddress) &&
                    log.PerformedByConnectedId.HasValue)
                .GroupBy(log => log.IPAddress)
                .Where(g => g.Select(l => l.PerformedByConnectedId).Distinct().Count() > 5)
                .Select(g => new SuspiciousActivity
                {
                    Type = "MultipleAccountsFromSameIP",
                    IpAddress = g.Key,
                    Count = g.Count(),
                    FirstOccurrence = g.Min(l => l.Timestamp),
                    LastOccurrence = g.Max(l => l.Timestamp)
                })
                .ToListAsync(cancellationToken);

            // 2. 짧은 시간 내 다중 실패 로그인
            var failedLogins = await GetActiveQuery()
                .Where(log => 
                    log.Timestamp >= fromDate && 
                    log.Timestamp <= toDate &&
                    log.Action == "LoginFailed" &&
                    log.PerformedByConnectedId.HasValue)
                .GroupBy(log => new { log.PerformedByConnectedId, log.IPAddress })
                .Where(g => g.Count() > 10)
                .Select(g => new SuspiciousActivity
                {
                    Type = "BruteForceAttempt",
                    UserId = g.Key.PerformedByConnectedId,
                    IpAddress = g.Key.IPAddress,
                    Count = g.Count(),
                    FirstOccurrence = g.Min(l => l.Timestamp),
                    LastOccurrence = g.Max(l => l.Timestamp)
                })
                .ToListAsync(cancellationToken);

            result.AddRange(multipleAccountsPerIp);
            result.AddRange(failedLogins);

            return result.OrderByDescending(sa => sa.LastOccurrence);
        }

        #endregion

        #region 통계 및 분석

        /// <summary>감사 로그 통계</summary>
        public async Task<AuditLogStatistics> GetStatisticsAsync(
            Guid? organizationId, 
            DateTime fromDate, 
            DateTime toDate, 
            CancellationToken cancellationToken = default)
        {
            var query = GetActiveQuery().Where(log => log.Timestamp >= fromDate && log.Timestamp <= toDate);

            if (organizationId.HasValue)
                query = query.Where(log => log.ApplicationId == organizationId.Value);

            var totalLogs = await query.CountAsync(cancellationToken);
            var uniqueUsers = await query.Where(log => log.PerformedByConnectedId.HasValue)
                                         .Select(log => log.PerformedByConnectedId!.Value)
                                         .Distinct()
                                         .CountAsync(cancellationToken);

            var actionStats = await query
                .GroupBy(log => log.Action)
                .Select(g => new { Action = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Action, x => x.Count, cancellationToken);

            var entityStats = await query
                .Where(log => log.ResourceType != null)
                .GroupBy(log => log.ResourceType!)
                .Select(g => new { EntityType = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.EntityType, x => x.Count, cancellationToken);

            var securityActions = new[] { "LoginFailed", "AccountLocked", "SuspiciousActivity", "UnauthorizedAccess", "SecurityBreach" };
            var securityEvents = await query.CountAsync(log => securityActions.Contains(log.Action), cancellationToken);

            var criticalActions = new[] { "Login", "Logout", "PasswordChanged", "PermissionChanged", "RoleAssigned", "RoleRevoked" };
            var criticalEvents = await query.CountAsync(log => criticalActions.Contains(log.Action), cancellationToken);

            return new AuditLogStatistics
            {
                TotalLogs = totalLogs,
                ByAction = actionStats,
                ByEntity = entityStats,
                UniqueUsers = uniqueUsers,
                SecurityEvents = securityEvents,
                CriticalEvents = criticalEvents,
                GeneratedAt = DateTime.UtcNow
            };
        }

        /// <summary>액션별 빈도 분석</summary>
        public async Task<Dictionary<string, int>> GetActionFrequencyAsync(
            DateTime fromDate, 
            DateTime toDate, 
            CancellationToken cancellationToken = default)
        {
            return await GetActiveQuery()
                .Where(log => log.Timestamp >= fromDate && log.Timestamp <= toDate)
                .GroupBy(log => log.Action)
                .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
        }

        /// <summary>시간대별 활동 분석</summary>
        public async Task<Dictionary<int, int>> GetHourlyActivityAsync(
            DateTime date, 
            Guid? organizationId = null, 
            CancellationToken cancellationToken = default)
        {
            var startDate = date.Date;
            var endDate = startDate.AddDays(1);

            var query = GetActiveQuery().Where(log => log.Timestamp >= startDate && log.Timestamp < endDate);

            if (organizationId.HasValue)
                query = query.Where(log => log.ApplicationId == organizationId.Value);

            return await query
                .GroupBy(log => log.Timestamp.Hour)
                .ToDictionaryAsync(g => g.Key, g => g.Count(), cancellationToken);
        }

        #endregion

        #region 검색 및 필터

        /// <summary>감사 로그 검색</summary>
        public async Task<PagedResult<AuditLog>> SearchAsync(
            string? keyword = null, 
            string? entityType = null, 
            string? actionType = null, 
            Guid? userId = null, 
            Guid? organizationId = null, 
            DateTime? fromDate = null, 
            DateTime? toDate = null, 
            int pageNumber = 1, 
            int pageSize = 50, 
            CancellationToken cancellationToken = default)
        {
            var query = GetActiveQuery();

            // 키워드 검색
            if (!string.IsNullOrWhiteSpace(keyword))
            {
                query = query.Where(log => 
                    log.Action.Contains(keyword) ||
                    (log.ResourceType != null && log.ResourceType.Contains(keyword)) ||
                    (log.Metadata != null && log.Metadata.Contains(keyword)));
            }

            // 엔티티 타입 필터
            if (!string.IsNullOrWhiteSpace(entityType))
                query = query.Where(log => log.ResourceType == entityType);

            // 액션 타입 필터
            if (!string.IsNullOrWhiteSpace(actionType))
                query = query.Where(log => log.Action == actionType);

            // 사용자 필터
            if (userId.HasValue)
                query = query.Where(log => log.PerformedByConnectedId == userId.Value);

            // 조직 필터
            if (organizationId.HasValue)
                query = query.Where(log => log.ApplicationId == organizationId.Value);

            // 날짜 범위 필터
            if (fromDate.HasValue)
                query = query.Where(log => log.Timestamp >= fromDate.Value);

            if (toDate.HasValue)
                query = query.Where(log => log.Timestamp <= toDate.Value);

            // 정렬 (최신순)
            query = query.OrderByDescending(log => log.Timestamp);

            var totalCount = await query.CountAsync(cancellationToken);
            var logs = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(cancellationToken);

            return PagedResult<AuditLog>.Create(logs, totalCount, pageNumber, pageSize);
        }

        #endregion

        #region 컴플라이언스

        /// <summary>컴플라이언스 보고서용 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetForComplianceReportAsync(
            Guid organizationId, 
            DateTime fromDate, 
            DateTime toDate, 
            string[] requiredActions, 
            CancellationToken cancellationToken = default)
        {
            return await GetActiveQuery()
                .Where(log => 
                    log.ApplicationId == organizationId &&
                    log.Timestamp >= fromDate &&
                    log.Timestamp <= toDate &&
                    requiredActions.Contains(log.Action))
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        /// <summary>데이터 접근 로그 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetDataAccessLogsAsync(
            Guid organizationId, 
            string dataCategory, 
            DateTime fromDate, 
            DateTime toDate, 
            CancellationToken cancellationToken = default)
        {
            var dataAccessActions = new[] { "Read", "Export", "Download", "View", "Access" };

            return await GetActiveQuery()
                .Where(log => 
                    log.ApplicationId == organizationId &&
                    log.Timestamp >= fromDate &&
                    log.Timestamp <= toDate &&
                    dataAccessActions.Contains(log.Action) &&
                    (log.ResourceType != null && log.ResourceType.Contains(dataCategory)))
                .OrderBy(log => log.Timestamp)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 보관 및 정리

        /// <summary>오래된 로그 아카이빙 대상 조회</summary>
        public async Task<IEnumerable<AuditLog>> GetLogsForArchivingAsync(
            DateTime olderThan, 
            int batchSize = 1000, 
            CancellationToken cancellationToken = default)
        {
            return await GetActiveQuery()
                .Where(log => log.Timestamp < olderThan)
                .OrderBy(log => log.Timestamp)
                .Take(batchSize)
                .ToListAsync(cancellationToken);
        }

        /// <summary>아카이빙 완료 표시</summary>
        public async Task<bool> MarkAsArchivedAsync(
            IEnumerable<Guid> logIds, 
            string archiveLocation, 
            CancellationToken cancellationToken = default)
        {
            try
            {
                var logIdList = logIds.ToList();
                if (!logIdList.Any()) return true;

                var logs = await GetActiveQuery()
                    .Where(log => logIdList.Contains(log.Id))
                    .ToListAsync(cancellationToken);

                foreach (var log in logs)
                {
                    // Note: AuditLog 엔티티에 IsArchived, ArchiveLocation, ArchivedAt 속성 필요
                    // log.IsArchived = true;
                    // log.ArchiveLocation = archiveLocation;
                    // log.ArchivedAt = DateTime.UtcNow;
                }

                await _context.SaveChangesAsync(cancellationToken);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to mark logs as archived. LogIds: {LogIds}, Archive location: {Location}", 
                    string.Join(",", logIds), archiveLocation);
                return false;
            }
        }

        #endregion

        #region AuditTrailDetail 관리

        /// <summary>감사 로그에 상세 변경 내역 추가</summary>
        public async Task<AuditTrailDetail> AddTrailDetailAsync(
            Guid auditLogId, 
            string fieldName, 
            AuditFieldType fieldType,
            AuditActionType actionType,
            string? oldValue = null, 
            string? newValue = null,
            bool isSecureField = false,
            string? validationResult = null,
            CancellationToken cancellationToken = default)
        {
            var auditLog = await GetByIdAsync(auditLogId);
            if (auditLog == null)
                throw new ArgumentException($"AuditLog with ID {auditLogId} not found");

            var detail = new AuditTrailDetail
            {
                AuditLogId = auditLogId,
                FieldName = fieldName,
                FieldType = fieldType,
                ActionType = actionType,
                OldValue = oldValue,
                NewValue = newValue,
                IsSecureField = isSecureField,
                ValidationResult = validationResult
            };

            _context.AuditTrailDetails.Add(detail);
            await _context.SaveChangesAsync(cancellationToken);
            return detail;
        }

        /// <summary>벌크 상세 변경 내역 추가</summary>
        public async Task<List<AuditTrailDetail>> AddBulkTrailDetailsAsync(
            Guid auditLogId, 
            List<AuditTrailDetail> details,
            CancellationToken cancellationToken = default)
        {
            var auditLog = await GetByIdAsync(auditLogId);
            if (auditLog == null)
                throw new ArgumentException($"AuditLog with ID {auditLogId} not found");

            foreach (var detail in details)
            {
                detail.AuditLogId = auditLogId;
                // 필수 필드 검증
                if (detail.FieldType == 0) 
                    throw new ArgumentException("FieldType is required for AuditTrailDetail");
                if (detail.ActionType == 0) 
                    throw new ArgumentException("ActionType is required for AuditTrailDetail");
            }

            _context.AuditTrailDetails.AddRange(details);
            await _context.SaveChangesAsync(cancellationToken);
            return details;
        }

        #endregion

        #region Helper Methods

        /// <summary>활성화된 로그만 조회하는 기본 쿼리</summary>
        private IQueryable<AuditLog> GetActiveQuery()
        {
            return _context.AuditLogs.Where(log => !log.IsDeleted);
        }

        #endregion
    }
}