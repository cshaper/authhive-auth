using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Base;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Role;
using AuthHive.Core.Models.Business.Platform.Common;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// ConnectedId와 Role 매핑 관리 리포지토리 (v17 - 리팩토링)
    /// </summary>
    public class ConnectedIdRoleRepository : BaseRepository<ConnectedIdRole>, IConnectedIdRoleRepository
    {
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<ConnectedIdRoleRepository> _logger;

        public ConnectedIdRoleRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            IDateTimeProvider dateTimeProvider,
            ILogger<ConnectedIdRoleRepository> logger)
            : base(context, cacheService)
        {
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        protected override bool IsOrganizationScopedEntity() => true;

        #region 기본 조회 (IConnectedIdRoleRepository 구현)

        public async Task<IEnumerable<ConnectedIdRole>> GetActiveRolesAsync(
            Guid connectedId,
            Guid? applicationId = null,
            bool includeInherited = true,
            CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            var query = Query()
                .Where(cr => cr.ConnectedId == connectedId &&
                             cr.IsActive &&
                             (!cr.ExpiresAt.HasValue || cr.ExpiresAt > now));

            if (applicationId.HasValue)
            {
                query = query.Where(cr => cr.Role.ApplicationId == applicationId);
            }

            if (!includeInherited)
            {
                query = query.Where(cr => !cr.InheritedFromId.HasValue);
            }

            return await query
                .Include(cr => cr.Role)
                .OrderBy(cr => cr.Priority ?? cr.Role.Priority)
                .ThenBy(cr => cr.Role.Name)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<ConnectedIdRole>> GetByRoleAsync(
            Guid roleId,
            Guid? organizationId = null,
            bool activeOnly = true,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(cr => cr.RoleId == roleId);

            if (organizationId.HasValue)
            {
                query = query.Where(cr => cr.OrganizationId == organizationId);
            }

            if (activeOnly)
            {
                var now = _dateTimeProvider.UtcNow;
                query = query.Where(cr => cr.IsActive && (!cr.ExpiresAt.HasValue || cr.ExpiresAt > now));
            }

            // [수정] 'ConnectedUser'는 존재하지 않는 속성이므로 'User'로 변경해야 합니다. (엔티티 정의에 따라 달라질 수 있음)
            return await query
                .Include(cr => cr.ConnectedId) 
                .OrderBy(cr => cr.AssignedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<ConnectedIdRole>> GetByApplicationAsync(
            Guid applicationId,
            Guid? connectedId = null,
            CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            var query = Query()
                .Where(cr => cr.Role.ApplicationId == applicationId &&
                             cr.IsActive &&
                             (!cr.ExpiresAt.HasValue || cr.ExpiresAt > now));

            if (connectedId.HasValue)
            {
                query = query.Where(cr => cr.ConnectedId == connectedId);
            }

            return await query
                .Include(cr => cr.Role)
                .OrderBy(cr => cr.AssignedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> ExistsAsync(
            Guid connectedId,
            Guid roleId,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            var query = Query()
                .Where(cr => cr.ConnectedId == connectedId &&
                             cr.RoleId == roleId &&
                             cr.IsActive &&
                             (!cr.ExpiresAt.HasValue || cr.ExpiresAt > now));

            if (applicationId.HasValue)
            {
                query = query.Where(cr => cr.Role.ApplicationId == applicationId);
            }

            return await query.AnyAsync(cancellationToken);
        }

        public async Task<IEnumerable<ConnectedIdRole>> GetAssignmentHistoryAsync(
            Guid connectedId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(cr => cr.ConnectedId == connectedId);

            if (startDate.HasValue)
            {
                query = query.Where(cr => cr.AssignedAt >= startDate);
            }

            if (endDate.HasValue)
            {
                query = query.Where(cr => cr.AssignedAt <= endDate);
            }

            return await query
                .Include(cr => cr.Role)
                .OrderByDescending(cr => cr.AssignedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 역할 할당 관리

        public async Task<ConnectedIdRole> AssignRoleAsync(
            Guid connectedId,
            Guid roleId,
            Guid assignedBy,
            Guid? applicationId = null,
            DateTime? expiresAt = null,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            var role = await _context.Set<Role>().FindAsync(new object[] { roleId }, cancellationToken);
            if (role == null)
            {
                throw new ArgumentException("Role not found", nameof(roleId));
            }

            var assignment = new ConnectedIdRole
            {
                ConnectedId = connectedId,
                RoleId = roleId,
                OrganizationId = role.OrganizationId,
                AssignedByConnectedId = assignedBy,
                AssignedAt = _dateTimeProvider.UtcNow,
                ApplicationId = applicationId,
                ExpiresAt = expiresAt,
                Reason = reason,
                IsActive = true
            };

            return await AddAsync(assignment, cancellationToken);
        }

        public async Task<bool> RevokeRoleAsync(
            Guid connectedId,
            Guid roleId,
            Guid? applicationId = null,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(cr => cr.ConnectedId == connectedId && cr.RoleId == roleId);
            if (applicationId.HasValue)
            {
                 query = query.Where(cr => cr.ApplicationId == applicationId);
            }

            var assignment = await query.FirstOrDefaultAsync(cancellationToken);
            if (assignment == null) return false;

            await DeleteAsync(assignment, cancellationToken);
            return true;
        }

        public async Task<bool> SetActiveStatusAsync(
            Guid roleAssignmentId,
            bool isActive,
            CancellationToken cancellationToken = default)
        {
            var assignment = await GetByIdAsync(roleAssignmentId, cancellationToken);
            if (assignment == null) return false;

            assignment.IsActive = isActive;
            await UpdateAsync(assignment, cancellationToken);
            return true;
        }

        #endregion

        #region 일괄 작업

        public async Task<int> BulkAssignRoleAsync(
            IEnumerable<Guid> connectedIds,
            Guid roleId,
            Guid assignedBy,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default)
        {
            var role = await _context.Set<Role>().FindAsync(new object[] { roleId }, cancellationToken);
            if (role == null) return 0;

            var assignments = new List<ConnectedIdRole>();
            var connectedIdList = connectedIds.ToList();

            var existingAssignments = await Query()
                .Where(cr => cr.RoleId == roleId && connectedIdList.Contains(cr.ConnectedId))
                .Select(cr => cr.ConnectedId)
                .ToListAsync(cancellationToken);

            var newAssignments = connectedIdList.Except(existingAssignments);

            foreach (var connectedId in newAssignments)
            {
                assignments.Add(new ConnectedIdRole
                {
                    ConnectedId = connectedId,
                    RoleId = roleId,
                    OrganizationId = role.OrganizationId,
                    AssignedByConnectedId = assignedBy,
                    AssignedAt = _dateTimeProvider.UtcNow,
                    ApplicationId = applicationId,
                    IsActive = true
                });
            }

            if (assignments.Any())
            {
                await AddRangeAsync(assignments, cancellationToken);
                return assignments.Count;
            }

            return 0;
        }

        public async Task<int> BulkRevokeRoleAsync(
            IEnumerable<Guid> connectedIds,
            Guid roleId,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(cr => connectedIds.Contains(cr.ConnectedId) && cr.RoleId == roleId);
            if(applicationId.HasValue)
            {
                query = query.Where(cr => cr.ApplicationId == applicationId);
            }
            
            var assignments = await query.ToListAsync(cancellationToken);

            if (assignments.Any())
            {
                await DeleteRangeAsync(assignments, cancellationToken);
                return assignments.Count;
            }

            return 0;
        }

        public async Task<int> RemoveAllRolesAsync(
            Guid connectedId,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(cr => cr.ConnectedId == connectedId);

            if (applicationId.HasValue)
            {
                query = query.Where(cr => cr.ApplicationId == applicationId);
            }

            var assignments = await query.ToListAsync(cancellationToken);

            if (assignments.Any())
            {
                await DeleteRangeAsync(assignments, cancellationToken);
                return assignments.Count;
            }

            return 0;
        }

        #endregion
        
        #region IOrganizationScopedRepository 구현

        public async Task<IEnumerable<ConnectedIdRole>> GetByOrganizationIdAsync(Guid organizationId, DateTime? startDate = null, DateTime? endDate = null, int? limit = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            if (startDate.HasValue)
            {
                query = query.Where(e => e.CreatedAt >= startDate.Value);
            }
            if (endDate.HasValue)
            {
                query = query.Where(e => e.CreatedAt <= endDate.Value);
            }
            if (limit.HasValue)
            {
                query = query.Take(limit.Value);
            }
            return await query.ToListAsync(cancellationToken);
        }

        public async Task<ConnectedIdRole?> GetByIdAndOrganizationAsync(Guid id, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).FirstOrDefaultAsync(e => e.Id == id, cancellationToken);
        }

        public async Task<IEnumerable<ConnectedIdRole>> FindByOrganizationAsync(Guid organizationId, Expression<Func<ConnectedIdRole, bool>> predicate, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).Where(predicate).ToListAsync(cancellationToken);
        }

        public async Task<(IEnumerable<ConnectedIdRole> Items, int TotalCount)> GetPagedByOrganizationAsync(Guid organizationId, int pageNumber, int pageSize, Expression<Func<ConnectedIdRole, bool>>? additionalPredicate = null, Expression<Func<ConnectedIdRole, object>>? orderBy = null, bool isDescending = false, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            if (additionalPredicate != null)
            {
                query = query.Where(additionalPredicate);
            }
            return await GetPagedAsync(pageNumber, pageSize, query, orderBy, isDescending, cancellationToken);
        }

        public async Task<bool> ExistsInOrganizationAsync(Guid id, Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId).AnyAsync(e => e.Id == id, cancellationToken);
        }

        public async Task<int> CountByOrganizationAsync(Guid organizationId, Expression<Func<ConnectedIdRole, bool>>? predicate = null, CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId);
            if (predicate != null)
            {
                query = query.Where(predicate);
            }
            return await query.CountAsync(cancellationToken);
        }

        public async Task DeleteAllByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var entitiesToDelete = await QueryForOrganization(organizationId).ToListAsync(cancellationToken);
            if(entitiesToDelete.Any())
            {
                await DeleteRangeAsync(entitiesToDelete, cancellationToken);
            }
        }

        // BaseRepository에 페이징을 위한 새로운 private helper 추가가 필요할 수 있습니다.
        private async Task<(IEnumerable<T> Items, int TotalCount)> GetPagedAsync<T>(int pageNumber, int pageSize, IQueryable<T> query, Expression<Func<T, object>>? orderBy, bool isDescending, CancellationToken cancellationToken) where T : BaseEntity
        {
            var totalCount = await query.CountAsync(cancellationToken);
            IQueryable<T> orderedQuery;
            if (orderBy != null)
            {
                orderedQuery = isDescending ? query.OrderByDescending(orderBy) : query.OrderBy(orderBy);
            }
            else
            {
                orderedQuery = query.OrderByDescending(e => e.Id);
            }
            var items = await orderedQuery.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
            return (items, totalCount);
        }

        #endregion
        
        #region 통계 (IStatisticsRepository 구현)

        public async Task<RoleAssignmentStatistics?> GetStatisticsAsync(StatisticsQuery query)
        {
            if (query.OrganizationId == null)
            {
                throw new ArgumentNullException(nameof(query.OrganizationId), "OrganizationId is required for Role Assignment statistics.");
            }

            var dbQuery = QueryForOrganization(query.OrganizationId.Value);

            dbQuery = dbQuery.Where(cr => cr.AssignedAt >= query.StartDate && cr.AssignedAt < query.EndDate);

            if (query.ApplicationId.HasValue)
            {
                dbQuery = dbQuery.Where(cr => cr.Role.ApplicationId == query.ApplicationId.Value);
            }

            if (query.ConnectedId.HasValue)
            {
                dbQuery = dbQuery.Where(cr => cr.ConnectedId == query.ConnectedId.Value);
            }

            var assignments = await dbQuery.ToListAsync();

            if (!assignments.Any())
            {
                return null;
            }

            var now = _dateTimeProvider.UtcNow;
            var activeAssignments = assignments.Where(cr => cr.IsActive && (cr.ExpiresAt == null || cr.ExpiresAt > now)).ToList();
            var uniqueUserCount = activeAssignments.Select(cr => cr.ConnectedId).Distinct().Count();

            return new RoleAssignmentStatistics
            {
                GeneratedAt = now,
                CountByRoleId = activeAssignments
                    .GroupBy(cr => cr.RoleId)
                    .ToDictionary(g => g.Key, g => g.Count()),
                ActiveAssignments = activeAssignments.Count,
                ExpiredAssignments = assignments.Count(cr => cr.ExpiresAt.HasValue && cr.ExpiresAt <= now),
                UniqueConnectedIds = uniqueUserCount,
                RecentAssignmentCount = assignments.Count(cr => cr.AssignedAt >= now.AddDays(-7))
            };
        }
        
        #endregion
    }
}

