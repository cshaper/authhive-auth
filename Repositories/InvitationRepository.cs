using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 통합 초대 리포지토리 구현 - AuthHive v15
    /// PricingConstants 기반 제한 및 SaaS 멀티테넌시 원칙 준수
    /// </summary>
    public class InvitationRepository : BaseRepository<Invitation>, IInvitationRepository
    {
        private readonly ILogger<InvitationRepository> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUnitOfWork _unitOfWork;
        
        // 캐시 키 패턴
        private const string CACHE_KEY_INVITATION = "invitation:{0}";
        private const string CACHE_KEY_ORG_INVITATIONS = "org:invitations:{0}:{1}";
        private const string CACHE_KEY_INVITATION_COUNT = "invitation:count:{0}:{1}";
        private const int CACHE_DURATION_SECONDS = 300;

        public InvitationRepository(
            AuthDbContext context,
            ILogger<InvitationRepository> logger,
            ICacheService cacheService,
            IAuditService auditService,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork,
            IOrganizationContext organizationContext)
            : base(context, organizationContext, null)
        {
            _logger = logger;
            _cacheService = cacheService;
            _auditService = auditService;
            _dateTimeProvider = dateTimeProvider;
            _unitOfWork = unitOfWork;
        }

        #region 기본 조회

        public async Task<Invitation?> GetByCodeAsync(string inviteCode)
        {
            var cacheKey = string.Format(CACHE_KEY_INVITATION, inviteCode);
            var cached = await _cacheService.GetAsync<Invitation>(cacheKey);
            
            if (cached != null)
                return cached;

            var invitation = await _dbSet
                .Where(i => i.InviteCode == inviteCode && !i.IsDeleted)
                .FirstOrDefaultAsync();

            if (invitation != null)
            {
                await _cacheService.SetAsync(cacheKey, invitation, TimeSpan.FromSeconds(CACHE_DURATION_SECONDS));
            }

            return invitation;
        }

        public async Task<Invitation?> GetWithDetailsAsync(Guid invitationId)
        {
            return await _dbSet
                .Include(i => i.Organization)
                .Include(i => i.Application)
                .Include(i => i.InvitedBy)
                .Include(i => i.ProposedRole)
                .Where(i => i.Id == invitationId && !i.IsDeleted)
                .FirstOrDefaultAsync();
        }

        public async Task<bool> ExistsAsync(string inviteCode)
        {
            return await _dbSet.AnyAsync(i => i.InviteCode == inviteCode && !i.IsDeleted);
        }

        #endregion

        #region 조직 기반 조회

        public async Task<IEnumerable<Invitation>> GetByOrganizationAsync(
            Guid organizationId,
            bool includeSubOrganizations = false,
            InvitationType? type = null)
        {
            var query = _dbSet.Where(i => !i.IsDeleted);

            if (includeSubOrganizations)
            {
                query = query.Where(i => 
                    i.OrganizationId == organizationId ||
                    i.ParentOrganizationId == organizationId);
            }
            else
            {
                query = query.Where(i => i.OrganizationId == organizationId);
            }

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            return await query.ToListAsync();
        }

        public async Task<IEnumerable<Invitation>> GetByOrganizationPathAsync(
            string organizationPath,
            InvitationType? type = null)
        {
            var query = _dbSet.Where(i => 
                !i.IsDeleted &&
                i.OrganizationPath != null &&
                i.OrganizationPath.StartsWith(organizationPath));

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            return await query.ToListAsync();
        }

        public async Task<int> CountActiveByOrganizationAsync(
            Guid organizationId,
            InvitationType type)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            return await _dbSet.CountAsync(i => 
                i.OrganizationId == organizationId &&
                i.Type == type &&
                i.Status == InvitationStatus.Sent &&
                i.ExpiresAt > currentUtc &&
                !i.IsDeleted);
        }

        #endregion

        #region 사용자 기반 조회

        public async Task<IEnumerable<Invitation>> GetByInviterAsync(
            Guid invitedByConnectedId,
            DateTime? since = null)
        {
            var query = _dbSet.Where(i => 
                i.InvitedByConnectedId == invitedByConnectedId && 
                !i.IsDeleted);

            if (since.HasValue)
            {
                query = query.Where(i => i.CreatedAt >= since.Value);
            }

            return await query.OrderByDescending(i => i.CreatedAt).ToListAsync();
        }

        public async Task<IEnumerable<Invitation>> GetPendingByEmailAsync(
            string email,
            InvitationType? type = null)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            var query = _dbSet.Where(i => 
                i.InviteeEmail == email &&
                i.Status == InvitationStatus.Sent &&
                i.ExpiresAt > currentUtc &&
                !i.IsDeleted);

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            return await query.ToListAsync();
        }

        public async Task<bool> HasPendingInvitationAsync(
            string email,
            Guid organizationId,
            InvitationType type)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            return await _dbSet.AnyAsync(i =>
                i.InviteeEmail == email &&
                i.OrganizationId == organizationId &&
                i.Type == type &&
                i.Status == InvitationStatus.Sent &&
                i.ExpiresAt > currentUtc &&
                !i.IsDeleted);
        }

        #endregion

        #region 애플리케이션/프로젝트 조회

        public async Task<IEnumerable<Invitation>> GetByApplicationAsync(
            Guid applicationId,
            InvitationStatus? status = null)
        {
            var query = _dbSet.Where(i => 
                i.ApplicationId == applicationId && 
                !i.IsDeleted);

            if (status.HasValue)
            {
                query = query.Where(i => i.Status == status.Value);
            }

            return await query.ToListAsync();
        }

        public async Task<IEnumerable<Invitation>> GetByProjectAsync(
            Guid projectId,
            InvitationStatus? status = null)
        {
            var query = _dbSet.Where(i => 
                i.ProjectId == projectId && 
                !i.IsDeleted);

            if (status.HasValue)
            {
                query = query.Where(i => i.Status == status.Value);
            }

            return await query.ToListAsync();
        }

        #endregion

        #region 상태 관리

        public async Task<IEnumerable<Invitation>> GetActiveAsync(
            Guid organizationId,
            InvitationType? type = null,
            DateTime? expiringBefore = null)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            var query = _dbSet.Where(i => 
                i.OrganizationId == organizationId &&
                i.Status == InvitationStatus.Sent &&
                i.ExpiresAt > currentUtc &&
                !i.IsDeleted);

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            if (expiringBefore.HasValue)
            {
                query = query.Where(i => i.ExpiresAt <= expiringBefore.Value);
            }

            return await query.ToListAsync();
        }

        public async Task<IEnumerable<Invitation>> GetByStatusAsync(
            InvitationStatus status,
            Guid? organizationId = null)
        {
            var query = _dbSet.Where(i => i.Status == status && !i.IsDeleted);

            if (organizationId.HasValue)
            {
                query = query.Where(i => i.OrganizationId == organizationId.Value);
            }

            return await query.ToListAsync();
        }

        public async Task<bool> UpdateStatusAsync(
            Guid invitationId,
            InvitationStatus newStatus,
            Guid? updatedByConnectedId = null)
        {
            var invitation = await _dbSet.FindAsync(invitationId);
            if (invitation == null)
                return false;

            invitation.Status = newStatus;
            invitation.UpdatedAt = _dateTimeProvider.UtcNow;
            
            if (updatedByConnectedId.HasValue)
            {
                invitation.UpdatedByConnectedId = updatedByConnectedId.Value;
            }

            await _context.SaveChangesAsync();
            
            // 캐시 무효화
            var cacheKey = string.Format(CACHE_KEY_INVITATION, invitation.InviteCode);
            await _cacheService.RemoveAsync(cacheKey);
            
            return true;
        }

        #endregion

        #region 비율 제한 및 분석

        public async Task<int> CountInvitationsByUserAsync(
            Guid invitedByConnectedId,
            DateTime since,
            InvitationType? type = null)
        {
            var query = _dbSet.Where(i => 
                i.InvitedByConnectedId == invitedByConnectedId &&
                i.CreatedAt >= since &&
                !i.IsDeleted);

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            return await query.CountAsync();
        }

        public async Task<InvitationStatistics> GetStatisticsAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            var query = _dbSet.Where(i => i.OrganizationId == organizationId && !i.IsDeleted);

            if (startDate.HasValue)
                query = query.Where(i => i.CreatedAt >= startDate.Value);
            
            if (endDate.HasValue)
                query = query.Where(i => i.CreatedAt <= endDate.Value);

            var invitations = await query.ToListAsync();

            var stats = new InvitationStatistics
            {
                TotalSent = invitations.Count,
                TotalAccepted = invitations.Count(i => i.Status == InvitationStatus.Accepted),
                TotalDeclined = invitations.Count(i => i.Status == InvitationStatus.Declined),
                TotalExpired = invitations.Count(i => i.Status == InvitationStatus.Expired),
                TotalCancelled = invitations.Count(i => i.Status == InvitationStatus.Cancelled),
                TotalBounced = invitations.Count(i => i.Status == InvitationStatus.Bounced),
                CurrentlyPending = invitations.Count(i => i.Status == InvitationStatus.Sent && i.ExpiresAt > _dateTimeProvider.UtcNow)
            };

            stats.AcceptanceRate = stats.TotalSent > 0 
                ? (double)stats.TotalAccepted / stats.TotalSent * 100 
                : 0;

            stats.ByType = invitations
                .GroupBy(i => i.Type)
                .ToDictionary(g => g.Key, g => g.Count());

            // 평균 수락 시간 계산
            var acceptedInvitations = invitations
                .Where(i => i.Status == InvitationStatus.Accepted && i.AcceptedAt.HasValue)
                .ToList();

            if (acceptedInvitations.Any())
            {
                var totalAcceptTime = acceptedInvitations
                    .Select(i => i.AcceptedAt!.Value - i.CreatedAt)
                    .Aggregate((a, b) => a + b);
                
                stats.AverageTimeToAccept = TimeSpan.FromTicks(totalAcceptTime.Ticks / acceptedInvitations.Count);
            }

            return stats;
        }

        public async Task<Dictionary<InvitationType, int>> GetInvitationCountByTypeAsync(
            Guid organizationId,
            DateTime since)
        {
            return await _dbSet
                .Where(i => 
                    i.OrganizationId == organizationId &&
                    i.CreatedAt >= since &&
                    !i.IsDeleted)
                .GroupBy(i => i.Type)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Type, x => x.Count);
        }

        #endregion

        #region 유지보수 작업

        public async Task<int> MarkExpiredInvitationsAsync(DateTime currentUtc)
        {
            var expiredInvitations = await _dbSet
                .Where(i => 
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt <= currentUtc &&
                    !i.IsDeleted)
                .ToListAsync();

            foreach (var invitation in expiredInvitations)
            {
                invitation.Status = InvitationStatus.Expired;
                invitation.UpdatedAt = currentUtc;
            }

            return await _context.SaveChangesAsync();
        }

        public async Task<int> CleanupOldInvitationsAsync(
            DateTime olderThan,
            bool hardDelete = false)
        {
            var oldInvitations = await _dbSet
                .Where(i => i.CreatedAt < olderThan)
                .ToListAsync();

            if (hardDelete)
            {
                _dbSet.RemoveRange(oldInvitations);
            }
            else
            {
                foreach (var invitation in oldInvitations)
                {
                    invitation.IsDeleted = true;
                    invitation.DeletedAt = _dateTimeProvider.UtcNow;
                }
            }

            return await _context.SaveChangesAsync();
        }

        public async Task<IEnumerable<Invitation>> GetInvitationsNeedingReminderAsync(
            DateTime currentUtc,
            int minimumHoursBetweenReminders = 24)
        {
            return await _dbSet
                .Where(i => 
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc &&
                    i.ReminderCount < i.MaxReminders &&
                    !i.IsDeleted &&
                    (i.LastReminderAt == null || 
                     EF.Functions.DateDiffHour(i.LastReminderAt.Value, currentUtc) >= minimumHoursBetweenReminders))
                .ToListAsync();
        }

        public async Task<bool> IncrementReminderCountAsync(
            Guid invitationId,
            DateTime reminderSentAt)
        {
            var invitation = await _dbSet.FindAsync(invitationId);
            if (invitation == null)
                return false;

            invitation.ReminderCount++;
            invitation.LastReminderAt = reminderSentAt;
            invitation.UpdatedAt = reminderSentAt;

            return await _context.SaveChangesAsync() > 0;
        }

        #endregion

        #region 일괄 작업

        public async Task<IEnumerable<Invitation>> BulkCreateAsync(
            IEnumerable<Invitation> invitations)
        {
            await _dbSet.AddRangeAsync(invitations);
            await _context.SaveChangesAsync();
            return invitations;
        }

        public async Task<int> BulkCancelAsync(
            IEnumerable<Guid> invitationIds,
            Guid cancelledByConnectedId)
        {
            var invitationsToCancel = await _dbSet
                .Where(i => invitationIds.Contains(i.Id) && !i.IsDeleted)
                .ToListAsync();

            var currentUtc = _dateTimeProvider.UtcNow;
            foreach (var invitation in invitationsToCancel)
            {
                invitation.Status = InvitationStatus.Cancelled;
                invitation.CancelledAt = currentUtc;
                invitation.UpdatedAt = currentUtc;
                invitation.UpdatedByConnectedId = cancelledByConnectedId;
            }

            return await _context.SaveChangesAsync();
        }

        #endregion

        #region 유효성 검사 헬퍼

        public async Task<bool> HasReachedInvitationLimitAsync(
            Guid organizationId,
            string planKey,
            InvitationType type)
        {
            // PricingConstants에서 MAU 제한을 초대 제한으로 사용
            if (!PricingConstants.SubscriptionPlans.MAULimits.TryGetValue(planKey, out var limit))
            {
                limit = PricingConstants.SubscriptionPlans.MAULimits[PricingConstants.SubscriptionPlans.BASIC_KEY];
            }

            // Enterprise는 무제한
            if (planKey == PricingConstants.SubscriptionPlans.ENTERPRISE_KEY)
                return false;

            // 월간 초대 수 계산
            var currentMonthStart = new DateTime(_dateTimeProvider.UtcNow.Year, _dateTimeProvider.UtcNow.Month, 1);
            var currentCount = await _dbSet.CountAsync(i =>
                i.OrganizationId == organizationId &&
                i.Type == type &&
                i.CreatedAt >= currentMonthStart &&
                !i.IsDeleted);

            // MAU 제한의 10%를 초대 제한으로 사용
            var invitationLimit = limit / 10;
            return currentCount >= invitationLimit;
        }

        public async Task<IEnumerable<Invitation>> GetRecentDuplicatesAsync(
            string email,
            Guid organizationId,
            TimeSpan within)
        {
            var since = _dateTimeProvider.UtcNow.Subtract(within);
            
            return await _dbSet
                .Where(i => 
                    i.InviteeEmail == email &&
                    i.OrganizationId == organizationId &&
                    i.CreatedAt >= since &&
                    !i.IsDeleted)
                .OrderByDescending(i => i.CreatedAt)
                .ToListAsync();
        }

        #endregion
    }
}