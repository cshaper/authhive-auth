using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Common;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Entities.Auth.Invitation;
using AuthHive.Core.Models.Auth.Invitation.ReadModels;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 통합 초대 리포지토리 구현 - AuthHive v16
    /// PricingConstants 기반 제한 및 SaaS 멀티테넌시 원칙 준수
    /// </summary>
    public class InvitationRepository : BaseRepository<Invitation>, IInvitationRepository
    {
        private readonly ILogger<InvitationRepository> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        /// <summary>
        /// 생성자: 최신 아키텍처에 따라 필요한 서비스들을 주입받습니다.
        /// </summary>
        public InvitationRepository(
            AuthDbContext context,
            ILogger<InvitationRepository> logger,
            ICacheService? cacheService,
            IDateTimeProvider dateTimeProvider)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티(Invitation)가 조직 범위인지 여부를 결정합니다.
        /// Invitation은 조직에 종속되므로 true를 반환하여 멀티테넌시 필터링을 강제합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;


        #region 기본 조회

        /// <summary>
        /// 고유한 초대 코드로 초대를 조회합니다. 캐시를 우선 확인합니다.
        /// 사용: 사용자가 초대 링크를 클릭했을 때, 해당 코드가 유효한지 확인하는 과정에서 호출됩니다.
        /// </summary>
        public async Task<Invitation?> GetByCodeAsync(string inviteCode, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"Invitation:Code:{inviteCode}";
            if (_cacheService != null)
            {
                var cached = await _cacheService.GetAsync<Invitation>(cacheKey, cancellationToken);
                if (cached != null) return cached;
            }

            var invitation = await Query()
                .AsNoTracking()
                .FirstOrDefaultAsync(i => i.InviteCode == inviteCode, cancellationToken);

            if (invitation != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, invitation, TimeSpan.FromMinutes(5), cancellationToken);
            }
            return invitation;
        }

        /// <summary>
        /// 특정 초대의 모든 상세 정보(조직, 초대자 등)를 함께 조회합니다. (Eager Loading)
        /// 사용: 초대 수락 페이지에서 초대의 상세 내용을 보여주거나, 관리자가 특정 초대의 세부 정보를 확인할 때 사용됩니다.
        /// </summary>
        public async Task<Invitation?> GetWithDetailsAsync(Guid invitationId, CancellationToken cancellationToken = default)
        {
            return await Query()
                .Include(i => i.Organization)
                .Include(i => i.Application)
                .Include(i => i.InvitedBy)
                .Include(i => i.ProposedRole)
                .AsNoTracking()
                .FirstOrDefaultAsync(i => i.Id == invitationId, cancellationToken);
        }

        /// <summary>
        /// 주어진 초대 코드가 시스템에 존재하는지 확인합니다.
        /// 사용: 초대 코드 생성 시 중복을 방지하기 위한 내부 검증 로직에서 사용될 수 있습니다.
        /// </summary>
        public async Task<bool> ExistsAsync(string inviteCode, CancellationToken cancellationToken = default)
        {
            return await Query().AnyAsync(i => i.InviteCode == inviteCode, cancellationToken);
        }

        #endregion

        #region 조직 기반 조회

        /// <summary>
        /// 특정 조직의 초대 목록을 조회합니다. 하위 조직의 초대를 포함할 수 있습니다.
        /// 사용: 조직 관리자가 자신의 조직 및 하위 조직에 전송된 초대 현황을 모니터링할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetByOrganizationAsync(
            Guid organizationId, bool includeSubOrganizations = false, InvitationType? type = null, CancellationToken cancellationToken = default)
        {
            var query = Query();
            if (includeSubOrganizations)
            {
                query = query.Where(i => i.OrganizationId == organizationId || i.ParentOrganizationId == organizationId);
            }
            else
            {
                query = query.Where(i => i.OrganizationId == organizationId);
            }
            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직 경로(예: "root/child/")로 시작하는 모든 하위 조직의 초대를 조회합니다.
        /// 사용: 특정 부서나 팀(계층 구조상의 노드)과 그 하위 조직 전체의 초대 현황을 분석할 때 유용합니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetByOrganizationPathAsync(
            string organizationPath, InvitationType? type = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(i => i.OrganizationPath != null && i.OrganizationPath.StartsWith(organizationPath));
            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직 내에서 아직 유효한 '전송(Sent)' 상태의 초대 개수를 조회합니다.
        /// 사용: 조직의 구독 플랜(Pricing Plan)에 따른 월별 초대 발송량 제한을 검사할 때 호출됩니다.
        /// </summary>
        public async Task<int> CountActiveByOrganizationAsync(
            Guid organizationId, InvitationType type, CancellationToken cancellationToken = default)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            return await Query().CountAsync(i =>
                    i.OrganizationId == organizationId &&
                    i.Type == type &&
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc,
                cancellationToken);
        }

        #endregion

        #region 사용자 기반 조회

        /// <summary>
        /// 특정 사용자가 보낸 모든 초대 목록을 조회합니다.
        /// 사용: 사용자가 자신의 '초대 보낸 내역' 페이지를 확인할 때 호출됩니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetByInviterAsync(
            Guid invitedByConnectedId, DateTime? since = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(i => i.InvitedByConnectedId == invitedByConnectedId);
            if (since.HasValue)
            {
                query = query.Where(i => i.CreatedAt >= since.Value);
            }
            return await query
                .OrderByDescending(i => i.CreatedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 이메일 주소로 전송된, 아직 수락/거절되지 않은 유효한 초대 목록을 조회합니다.
        /// 사용: 신규 회원이 가입할 때, 해당 이메일로 온 초대가 있는지 확인하여 자동으로 조직에 참여시키는 로직에서 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetPendingByEmailAsync(
            string email, InvitationType? type = null, CancellationToken cancellationToken = default)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            var query = Query()
                .Where(i =>
                    i.InviteeEmail == email &&
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc);

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 사용자에게 특정 조직/유형으로 이미 보낸 초대가 있는지 확인합니다. (중복 발송 방지용)
        /// 사용: 초대 이메일을 보내기 직전에 호출되어, 동일한 사용자에게 짧은 시간 내에 같은 초대를 여러 번 보내는 것을 방지합니다.
        /// </summary>
        public async Task<bool> HasPendingInvitationAsync(
            string email, Guid organizationId, InvitationType type, CancellationToken cancellationToken = default)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            return await Query().AnyAsync(i =>
                    i.InviteeEmail == email &&
                    i.OrganizationId == organizationId &&
                    i.Type == type &&
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc,
                cancellationToken);
        }

        #endregion

        #region 애플리케이션/프로젝트 조회

        /// <summary>
        /// 특정 애플리케이션(Application)에 속한 초대 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetByApplicationAsync(
            Guid applicationId, InvitationStatus? status = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(i => i.ApplicationId == applicationId);
            if (status.HasValue)
            {
                query = query.Where(i => i.Status == status.Value);
            }
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 프로젝트(Project)에 속한 초대 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetByProjectAsync(
            Guid projectId, InvitationStatus? status = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(i => i.ProjectId == projectId);
            if (status.HasValue)
            {
                query = query.Where(i => i.Status == status.Value);
            }
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        #endregion

        #region 상태 관리

        /// <summary>
        /// 특정 조직의 활성(만료되지 않고 대기중인) 초대 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetActiveAsync(
            Guid organizationId, InvitationType? type = null, DateTime? expiringBefore = null, CancellationToken cancellationToken = default)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            var query = Query().Where(i =>
                i.OrganizationId == organizationId &&
                i.Status == InvitationStatus.Sent &&
                i.ExpiresAt > currentUtc);

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }
            if (expiringBefore.HasValue)
            {
                query = query.Where(i => i.ExpiresAt <= expiringBefore.Value);
            }
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 상태(Status)를 기준으로 초대 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetByStatusAsync(
            InvitationStatus status, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(i => i.Status == status);
            if (organizationId.HasValue)
            {
                query = query.Where(i => i.OrganizationId == organizationId.Value);
            }
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 초대의 상태를 업데이트합니다. (예: Sent -> Accepted)
        /// 중요: 실제 DB 저장은 상위 서비스의 UnitOfWork에서 처리합니다.
        /// </summary>
        public async Task<bool> UpdateStatusAsync(
            Guid invitationId, InvitationStatus newStatus, Guid? updatedByConnectedId = null, CancellationToken cancellationToken = default)
        {
            var invitation = await Query().FirstOrDefaultAsync(i => i.Id == invitationId, cancellationToken);
            if (invitation == null) return false;

            invitation.Status = newStatus;
            invitation.UpdatedAt = _dateTimeProvider.UtcNow;
            if (updatedByConnectedId.HasValue)
            {
                invitation.UpdatedByConnectedId = updatedByConnectedId.Value;
            }

            await InvalidateInvitationCacheAsync(invitation, cancellationToken);
            return true;
        }

        #endregion

        #region 비율 제한 및 분석

        /// <summary>
        /// 특정 기간 내에 한 사용자가 보낸 초대 수를 계산합니다. (비율 제한용)
        /// </summary>
        public async Task<int> CountInvitationsByUserAsync(
            Guid invitedByConnectedId, DateTime since, InvitationType? type = null, CancellationToken cancellationToken = default)
        {
            var query = Query().Where(i => i.InvitedByConnectedId == invitedByConnectedId && i.CreatedAt >= since);
            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }
            return await query.CountAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직의 초대 관련 통계를 집계하여 조회합니다.
        /// </summary>
        public async Task<InvitationStatisticsReadModel> GetStatisticsAsync(
        Guid organizationId, DateTime? startDate = null, DateTime? endDate = null, CancellationToken cancellationToken = default)
        {
            // 💡 DTO의 StartDate/EndDate는 non-nullable이므로, 쿼리에 사용할 실제 날짜 범위를 정의합니다.
            // (이 코드는 _dateTimeProvider가 주입되어 있다고 가정합니다.)
            DateTime actualEndDate = endDate ?? _dateTimeProvider.UtcNow;
            DateTime actualStartDate = startDate ?? actualEndDate.AddDays(-30); // 기본값: 30일 전

            var baseQuery = Query().Where(i => i.OrganizationId == organizationId);

            // 💡 수정: non-nullable 날짜로 쿼리
            baseQuery = baseQuery.Where(i => i.CreatedAt >= actualStartDate);
            baseQuery = baseQuery.Where(i => i.CreatedAt <= actualEndDate);

            // 1. 상태별 통계 (변경 없음)
            var statusCounts = await baseQuery
        .GroupBy(i => i.Status)
        .Select(g => new { Status = g.Key, Count = g.Count() })
        .ToDictionaryAsync(x => x.Status, x => x.Count, cancellationToken);

            // 2. 💡 [CS0266 수정] 1단계: 먼저 'int' 타입의 기본 데이터를 가져옵니다.
            var simpleTypeCounts = await baseQuery
        .GroupBy(i => i.Type)
        .Select(g => new { Type = g.Key, Count = g.Count() })
        .ToDictionaryAsync(x => x.Type, x => x.Count, cancellationToken);

            // 3. 💡 [CS0266 수정] 2단계: 'int' 딕셔너리를 'TypeStatisticsReadModel' 딕셔너리로 변환합니다.
            // (TypeStatisticsReadModel에 TotalSent 속성이 있다고 가정합니다)
            var typeCounts = simpleTypeCounts.ToDictionary(
                kvp => kvp.Key, // 키는 동일 (InvitationType)
                kvp => new TypeStatisticsReadModel { TotalSent = kvp.Value } // 값을 'int'에서 'TypeStatisticsReadModel' 객체로 변환
                );

            var acceptedInvitationDates = await baseQuery
              .Where(i => i.Status == InvitationStatus.Accepted && i.AcceptedAt.HasValue)
              .Select(i => new { i.CreatedAt, AcceptedAt = i.AcceptedAt.HasValue ? i.AcceptedAt.Value : DateTime.MinValue })
              .ToListAsync(cancellationToken);

            // --- 💡 v17 DTO 구조에 맞게 데이터 재조립 ---

            int totalAccepted = statusCounts.GetValueOrDefault(InvitationStatus.Accepted);
            int totalSent = statusCounts.Values.Sum();
            int currentlyPending = await baseQuery.CountAsync(i => i.Status == InvitationStatus.Sent && i.ExpiresAt > _dateTimeProvider.UtcNow, cancellationToken);

            // (v16 'AcceptanceRate' -> v17 'ConversionRate')
            double conversionRate = totalSent > 0 ? (double)totalAccepted / totalSent * 100 : 0;

            // (v16 'AverageTimeToAccept' -> v17 'MedianTimeToAction')
            TimeSpan timeToAction = TimeSpan.Zero;
            if (acceptedInvitationDates.Any())
            {
                double averageTicks = acceptedInvitationDates.Average(t => (t.AcceptedAt - t.CreatedAt).Ticks);
                timeToAction = TimeSpan.FromTicks((long)averageTicks);
            }

            var overallStats = new OverallStatisticsReadModel
            {
                TotalSent = totalSent,
                TotalAccepted = totalAccepted,
                TotalDeclined = statusCounts.GetValueOrDefault(InvitationStatus.Declined),
                TotalExpired = statusCounts.GetValueOrDefault(InvitationStatus.Expired),
                TotalCancelled = statusCounts.GetValueOrDefault(InvitationStatus.Cancelled),
                TotalBounced = statusCounts.GetValueOrDefault(InvitationStatus.Bounced),
                CurrentlyPending = currentlyPending
            };

            var performanceStats = new PerformanceMetricsReadModel
            {
                ConversionRate = conversionRate,
                MedianTimeToAction = timeToAction,
            };

            var timeBasedStats = new TimeBasedStatisticsReadModel(); // 'required' 만족용

            // 4. 💡 [CS0266 해결] 이제 'typeCounts' 변수는 DTO가 요구하는 타입과 일치합니다.
                        var stats = new InvitationStatisticsReadModel
                        {
                            StartDate = actualStartDate,
                            EndDate = actualEndDate,
                            Overall = overallStats,
                            ByType = typeCounts, // 이제 타입이 일치합니다.
                            TimeBased = timeBasedStats,
                            Performance = performanceStats
                        };

            return stats;
        }
        #endregion

        #region 유지보수 작업

        /// <summary>
        /// 주기적인 리마인더 발송이 필요한 초대 목록을 조회합니다. (백그라운드 서비스용)
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetInvitationsNeedingReminderAsync(
            int minimumHoursBetweenReminders = 24, CancellationToken cancellationToken = default)
        {
            var currentUtc = _dateTimeProvider.UtcNow;
            return await Query()
                .Where(i =>
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc &&
                    i.ReminderCount < i.MaxReminders &&
                    (i.LastReminderAt == null ||
                     EF.Functions.DateDiffHour(i.LastReminderAt.Value, currentUtc) >= minimumHoursBetweenReminders))
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 초대의 리마인더 발송 횟수를 1 증가시키고, 마지막 발송 시간을 기록합니다.
        /// </summary>
        public async Task<bool> IncrementReminderCountAsync(
            Guid invitationId, DateTime reminderSentAt, CancellationToken cancellationToken = default)
        {
            var invitation = await Query().FirstOrDefaultAsync(i => i.Id == invitationId, cancellationToken);
            if (invitation == null) return false;

            invitation.ReminderCount++;
            invitation.LastReminderAt = reminderSentAt;
            invitation.UpdatedAt = reminderSentAt; // 업데이트 시간도 함께 기록

            await InvalidateInvitationCacheAsync(invitation, cancellationToken);
            return true;
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 여러 개의 초대 엔티티를 데이터베이스 컨텍스트에 한 번에 추가합니다. (대량 초대용)
        /// </summary>
        public async Task<IEnumerable<Invitation>> BulkCreateAsync(
            IEnumerable<Invitation> invitations, CancellationToken cancellationToken = default)
        {
            await _dbSet.AddRangeAsync(invitations, cancellationToken);
            return invitations;
        }

        /// <summary>
        /// 여러 개의 초대를 한 번에 '취소' 상태로 변경합니다.
        /// </summary>
        public async Task<int> BulkCancelAsync(
            IEnumerable<Guid> invitationIds, Guid cancelledByConnectedId, CancellationToken cancellationToken = default)
        {
            var now = _dateTimeProvider.UtcNow;
            // ExecuteUpdateAsync를 사용하여 DB에서 직접 업데이트 (효율적)
            var affectedRows = await Query()
                .Where(i => invitationIds.Contains(i.Id) && i.Status == InvitationStatus.Sent)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(i => i.Status, InvitationStatus.Cancelled)
                    .SetProperty(i => i.CancelledAt, now)
                    .SetProperty(i => i.UpdatedAt, now)
                    .SetProperty(i => i.UpdatedByConnectedId, cancelledByConnectedId),
                    cancellationToken);

            // TODO: 캐시 무효화. 변경된 엔티티를 다시 조회하거나, 더 넓은 범위의 캐시를 무효화해야 함.
            if (affectedRows > 0)
            {
                _logger.LogWarning("BulkCancelAsync executed. A broad cache invalidation strategy might be needed.");
            }

            return affectedRows;
        }

        #endregion

        #region 유효성 검사 헬퍼

        /// <summary>
        /// 특정 시점 이후에 조직에서 보낸 초대 수를 계산합니다. (서비스 계층의 정책 판단용)
        /// </summary>
        public async Task<int> CountInvitationsSinceAsync(
            Guid organizationId, InvitationType type, DateTime since, CancellationToken cancellationToken = default)
        {
            return await Query().CountAsync(i =>
                    i.OrganizationId == organizationId &&
                    i.Type == type &&
                    i.CreatedAt >= since,
                cancellationToken);
        }

        /// <summary>
        /// 특정 기간 내에 생성된 중복 초대를 조회합니다. (스팸 방지용)
        /// </summary>
        public async Task<IEnumerable<Invitation>> GetRecentDuplicatesAsync(
            string email, Guid organizationId, TimeSpan within, CancellationToken cancellationToken = default)
        {
            var since = _dateTimeProvider.UtcNow.Subtract(within);
            return await Query()
                .Where(i =>
                    i.InviteeEmail == email &&
                    i.OrganizationId == organizationId &&
                    i.CreatedAt >= since)
                .OrderByDescending(i => i.CreatedAt)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 특정 초대와 관련된 모든 캐시 항목을 무효화합니다.
        /// </summary>
        private async Task InvalidateInvitationCacheAsync(Invitation invitation, CancellationToken cancellationToken)
        {
            if (_cacheService == null) return;

            var tasks = new List<Task>
            {
                // ID 기반 캐시 (BaseRepository의 InvalidateCacheAsync 호출)
                InvalidateCacheAsync(invitation.Id, cancellationToken),
                // Code 기반 캐시
                _cacheService.RemoveAsync($"Invitation:Code:{invitation.InviteCode}", cancellationToken)
            };

            try
            {
                await Task.WhenAll(tasks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache for invitation {InvitationId}", invitation.Id);
            }
        }

        #endregion
    }
}

