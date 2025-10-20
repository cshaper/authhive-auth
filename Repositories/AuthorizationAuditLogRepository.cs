using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Audit.Common;
using AuthHive.Core.Models.Audit.Requests;
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
    /// 권한 검증 감사 로그 Repository 구현체 - AuthHive v16
    /// 모든 권한 검증 요청과 결과를 추적하여 보안 감사 및 컴플라이언스에 활용합니다.
    /// </summary>
    public class AuthorizationAuditLogRepository : BaseRepository<AuthorizationAuditLog>, IAuthorizationAuditLogRepository
    {
        private readonly ILogger<AuthorizationAuditLogRepository> _logger;

        /// <summary>
        /// 생성자: 필요한 서비스(DbContext, CacheService, Logger)를 주입받습니다.
        /// </summary>
        public AuthorizationAuditLogRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<AuthorizationAuditLogRepository> logger)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티가 조직 범위에 속하는지 여부를 결정합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        /// <summary>
        /// 다양한 조건을 사용하여 권한 검증 감사 로그를 검색하고, 페이지 단위로 결과를 반환합니다.
        /// 사용: 감사 로그 조회 페이지에서 관리자가 필터링, 정렬, 페이징을 사용하여 로그를 탐색할 때 사용됩니다.
        /// </summary>
        public async Task<(IEnumerable<AuthorizationAuditLog> Items, int TotalCount)> SearchAsync(
            SearchAuthorizationAuditLogsRequest request,
            CancellationToken cancellationToken = default)
        {
            var query = Query(); // BaseRepository의 Query()는 IsDeleted = false를 기본으로 포함

            // 조직 ID 필터링
            if (request.OrganizationId.HasValue)
            {
                query = query.Where(log => log.OrganizationId == request.OrganizationId.Value);
            }
            // 기간 필터링
            if (request.StartDate.HasValue)
            {
                query = query.Where(log => log.Timestamp >= request.StartDate.Value);
            }
            if (request.EndDate.HasValue)
            {
                query = query.Where(log => log.Timestamp <= request.EndDate.Value);
            }
            // ConnectedId 필터링
            if (request.ConnectedId.HasValue)
            {
                query = query.Where(log => log.ConnectedId == request.ConnectedId.Value);
            }
            // IpAddress 필터링
            if (!string.IsNullOrWhiteSpace(request.IpAddress))
            {
                query = query.Where(log => log.IpAddress == request.IpAddress);
            }
            // IsAllowed 필터링
            if (request.IsAllowed.HasValue)
            {
                query = query.Where(log => log.IsAllowed == request.IsAllowed.Value);
            }
            // Resource 필터링
            if (!string.IsNullOrWhiteSpace(request.Resource))
            {
                // EF.Functions.ILike는 PostgreSQL에서 대소문자 무시 검색을 위해 사용됩니다.
                query = query.Where(log => EF.Functions.ILike(log.Resource, $"%{request.Resource}%"));
            }
            // Action 필터링
            if (!string.IsNullOrWhiteSpace(request.Action))
            {
                query = query.Where(log => EF.Functions.ILike(log.Action, $"%{request.Action}%"));
            }
            // DenialReason 필터링
            if (request.DenialReason.HasValue)
            {
                query = query.Where(log => log.DenialReason == request.DenialReason.Value);
            }
            // MinRiskScore 필터링
            if (request.MinRiskScore.HasValue)
            {
                query = query.Where(log => log.RiskScore >= request.MinRiskScore.Value);
            }

            // 전체 개수 조회 (페이징 전)
            var totalCount = await query.CountAsync(cancellationToken);

            // 정렬
            // TODO: request 객체에 SortBy, SortDirection 프로퍼티를 추가하여 동적 정렬 구현 가능
            query = query.OrderByDescending(log => log.Timestamp);

            // 페이징
            var items = await query
                .Skip(request.Skip)
                .Take(request.Take)
                .AsNoTracking()
                .ToListAsync(cancellationToken);

            return (items, totalCount);
        }


        #region 데이터 생명주기 관리

        /// <summary>
        /// 지정된 날짜 이전의 오래된 감사 로그를 영구적으로 삭제합니다.
        /// 사용: 시스템의 데이터 보존 정책에 따라 주기적인 배치 작업으로 실행되어, 오래된 데이터를 정리하고 DB 용량을 관리합니다.
        /// </summary>
        public async Task<int> CleanupOldLogsAsync(
            DateTimeOffset before,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // ExecuteDeleteAsync를 사용하여 DB에서 직접 대량 삭제 (매우 효율적)
                var deletedCount = await _dbSet
                    .Where(log => log.Timestamp < before)
                    .ExecuteDeleteAsync(cancellationToken);

                if (deletedCount > 0)
                {
                    _logger.LogInformation("{Count} authorization audit logs before {Date} were permanently deleted.", deletedCount, before);
                }
                return deletedCount;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during authorization audit log cleanup.");
                return 0;
            }
        }


        /// <summary>
        /// 지정된 날짜 이전의 오래된 감사 로그를 '아카이브' 상태로 표시합니다.
        /// 실제 아카이브(데이터 이동/백업) 로직은 이 메서드를 호출하는 상위 서비스에서 처리해야 합니다.
        /// 사용: 장기 보관이 필요한 로그를 DB에서 삭제하기 전에, 별도의 스토리지로 백업할 대상을 식별하는 배치 작업에서 사용됩니다.
        /// </summary>
        public async Task<int> ArchiveLogsAsync(
            DateTimeOffset before,
            string archiveLocation, // 아카이브 위치 정보는 로그 메타데이터에 기록
            CancellationToken cancellationToken = default)
        {
            try
            {
                // ExecuteUpdateAsync를 사용하여 DB에서 직접 대량 업데이트
                var archivedCount = await _dbSet
                    .Where(log => log.Timestamp < before && !log.IsArchived) // IsArchived 속성 사용
                    .ExecuteUpdateAsync(updates => updates
                        .SetProperty(log => log.IsArchived, true)
                        .SetProperty(log => log.Context, $"Archived to {archiveLocation} at {DateTime.UtcNow}"), // 간단한 컨텍스트 기록
                    cancellationToken);

                if (archivedCount > 0)
                {
                    _logger.LogInformation("{Count} authorization audit logs before {Date} were marked as archived.", archivedCount, before);
                }
                return archivedCount;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during authorization audit log archival.");
                return 0;
            }
        }

        #endregion
    }
}

