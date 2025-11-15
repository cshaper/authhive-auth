// 📍 위치: AuthHive.Auth/Repositories/AuthorizationAuditLogRepository.cs
// (CS1501 오류 해결 및 v17 최종 구현체)

using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth.Authorization;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
// [CS1501 해결] Expression Tree 확장 메서드를 위해 필수적인 using 추가
using AuthHive.Core.Extensions; 
using AuthHive.Core.Models.Auth.Authorization.Queries; 

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 권한 검증 감사 로그 저장소 구현 - v17 (순수 데이터 접근 계층)
    /// </summary>
    public class AuthorizationAuditLogRepository : BaseRepository<AuthorizationAuditLog>, 
        IAuthorizationAuditLogRepository
    {
        public AuthorizationAuditLogRepository(AuthDbContext context) 
            : base(context)
        {
        }

        protected override bool IsOrganizationScopedEntity() => true;

        #region SearchAsync 구현

        /// <summary>
        /// 다양한 조건을 사용하여 권한 검증 감사 로그를 검색하고, 페이지 단위로 결과를 반환합니다.
        /// </summary>
        public async Task<(IEnumerable<AuthorizationAuditLog> Items, int TotalCount)> SearchAsync(
            SearchAuthorizationAuditLogsQuery query,
            CancellationToken cancellationToken = default)
        {
            // --- CS1501 FIX: PredicateBuilder를 사용하여 쿼리 구성 ---
            
            // 1. 기본 쿼리 시작
            var queryable = Query().AsNoTracking();

            // 2. Expression Predicate 조합
            // Base filter: log.OrganizationId == query.OrganizationId
            Expression<Func<AuthorizationAuditLog, bool>> predicate = log => 
                log.OrganizationId == query.OrganizationId; 

            // Optional 필터 추가 (CS1501 해결: .And() 메서드 사용)
            if (query.ConnectedId.HasValue)
                predicate = predicate.And(log => log.ConnectedId == query.ConnectedId.Value);

            if (query.IsAllowed.HasValue)
                predicate = predicate.And(log => log.IsAllowed == query.IsAllowed.Value);

            if (!string.IsNullOrWhiteSpace(query.Resource))
                predicate = predicate.And(log => log.Resource == query.Resource);
            
            if (!string.IsNullOrWhiteSpace(query.Action))
                predicate = predicate.And(log => log.Action == query.Action);

            if (query.StartDate.HasValue)
                predicate = predicate.And(log => log.Timestamp >= query.StartDate.Value);

            if (query.EndDate.HasValue)
                predicate = predicate.And(log => log.Timestamp <= query.EndDate.Value);

            // 3. BaseRepository의 GetPagedAsync를 호출하여 페이징 및 정렬 위임
            // [CS1061 해결] SortByExpression 대신 BaseQuery에서 상속받은 SortBy 속성을 사용
            return await GetPagedAsync(
                query.PageNumber,
                query.PageSize,
                predicate,
                log => log.Timestamp, 
                query.SortDescending,
                cancellationToken);
        }
        
        #endregion

        #region 데이터 생명주기 관리 (Cleanup Methods)

        /// <summary>
        /// 지정된 날짜 이전의 오래된 감사 로그를 영구적으로 삭제합니다.
        /// </summary>
        public async Task<int> CleanupOldLogsAsync(
            DateTimeOffset before, 
            CancellationToken cancellationToken = default)
        {
            // ExecuteDeleteAsync (EF Core 7+)를 사용한 효율적인 삭제 로직이 구현된다고 가정합니다.
            return await _context.Set<AuthorizationAuditLog>()
                .Where(log => log.CreatedAt < before)
                .ExecuteDeleteAsync(cancellationToken);
        }

        /// <summary>
        /// 지정된 날짜 이전의 오래된 감사 로그를 외부 스토리지로 아카이브합니다.
        /// </summary>
        public async Task<int> ArchiveLogsAsync(
            DateTimeOffset before,
            string archiveLocation,
            CancellationToken cancellationToken = default)
        {
            // ArchiveLocation은 서비스 레이어 로직에서 사용되지만, 리포지토리는 DB 플래그만 업데이트합니다.
            return await _context.Set<AuthorizationAuditLog>()
                .Where(log => log.CreatedAt < before && !log.IsArchived)
                .ExecuteUpdateAsync(
                    updates => updates.SetProperty(log => log.IsArchived, true),
                    cancellationToken);
        }

        #endregion
    }
}