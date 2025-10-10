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
        private readonly IDateTimeProvider _dateTimeProvider;

        // 캐시 키 패턴
        private const string CACHE_KEY_INVITATION = "invitation:{0}";
        private const string CACHE_KEY_ORG_INVITATIONS = "org:invitations:{0}:{1}";
        private const string CACHE_KEY_INVITATION_COUNT = "invitation:count:{0}:{1}";
        private const int CACHE_DURATION_SECONDS = 300;

        public InvitationRepository(
            AuthDbContext context,
            ILogger<InvitationRepository> logger,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IOrganizationContext organizationContext)
            : base(context, organizationContext, cacheService)
        {
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        #region 기본 조회

        /// <summary>
        /// 고유한 초대 코드를 사용하여 초대를 조회합니다. 캐시를 우선적으로 확인합니다.
        /// </summary>
        /// <param name="inviteCode">조회할 초대 코드입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>해당하는 초대 엔티티를 반환하며, 없으면 null을 반환합니다.</returns>
        public async Task<Invitation?> GetByCodeAsync(string inviteCode, CancellationToken cancellationToken = default)
        {
            // 1. 캐시에서 데이터를 찾기 위한 고유 키를 생성합니다.
            var cacheKey = string.Format(CACHE_KEY_INVITATION, inviteCode);

            // 캐시 서비스가 주입되었는지 확인합니다.
            if (_cacheService != null)
            {
                // 2. 캐시에서 먼저 조회를 시도합니다.
                var cached = await _cacheService.GetAsync<Invitation>(cacheKey, cancellationToken);
                if (cached != null)
                {
                    // 캐시에 데이터가 있으면 DB 조회 없이 바로 반환합니다. (Cache Hit)
                    return cached;
                }
            }

            // 3. 캐시에 데이터가 없으면(Cache Miss) 데이터베이스에서 조회합니다.
            var invitation = await _dbSet
                .Where(i => i.InviteCode == inviteCode && !i.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            // 4. 데이터베이스에서 데이터를 찾은 경우
            if (invitation != null)
            {
                // 5. 다음 조회를 위해 찾은 데이터를 캐시에 저장합니다.
                if (_cacheService != null)
                {
                    await _cacheService.SetAsync(
                        cacheKey,
                        invitation,
                        TimeSpan.FromSeconds(CACHE_DURATION_SECONDS),
                        cancellationToken);
                }
            }

            return invitation;
        }
        /// <summary>
        /// 특정 초대(Invitation)와 연관된 모든 상세 정보(Organization, Application, Inviter 등)를 함께 조회합니다.
        /// N+1 쿼리 문제를 방지하기 위해 Eager Loading을 사용합니다.
        /// </summary>
        /// <param name="invitationId">조회할 초대의 ID입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>연관 엔티티가 모두 포함된 초대 엔티티를 반환합니다.</returns>
        public async Task<Invitation?> GetWithDetailsAsync(
            Guid invitationId,
            CancellationToken cancellationToken = default) // 원칙 3: CancellationToken 추가
        {
            // 원칙 1: _dbSet 대신 Query() 메서드를 사용합니다.
            return await Query()
                .Include(i => i.Organization)
                .Include(i => i.Application)
                .Include(i => i.InvitedBy)
                .Include(i => i.ProposedRole)
                // 원칙 2: 성능 최적화를 위해 AsNoTracking() 추가
                .AsNoTracking()
                // Query()를 사용하므로 Id 조건만 남깁니다.
                .Where(i => i.Id == invitationId)
                // 원칙 3: CancellationToken 전달
                .FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// 주어진 초대 코드가 시스템에 존재하는지 확인합니다.
        /// </summary>
        /// <param name="inviteCode">존재 여부를 확인할 초대 코드입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>코드가 존재하면 true, 그렇지 않으면 false를 반환합니다.</returns>
        public async Task<bool> ExistsAsync(
            string inviteCode,
            CancellationToken cancellationToken = default) // 원칙 3: CancellationToken 추가
        {

            return await Query().AnyAsync(i => i.InviteCode == inviteCode, cancellationToken);
        }

        #endregion

        #region 조직 기반 조회

        /// <summary>
        /// 특정 조직 ID를 기준으로 초대 목록을 조회합니다. 하위 조직의 초대를 포함할 수 있습니다.
        /// </summary>
        /// <param name="organizationId">조회할 기준 조직의 ID입니다.</param>
        /// <param name="includeSubOrganizations">true일 경우, 하위 조직(ParentOrganizationId가 일치하는)의 초대도 함께 조회합니다.</param>
        /// <param name="type">필터링할 초대의 유형입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetByOrganizationAsync(
            Guid organizationId,
            bool includeSubOrganizations = false,
            InvitationType? type = null,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            var query = Query();

            // 하위 조직 포함 여부에 따라 필터링 조건을 동적으로 구성합니다.
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

            // 초대 유형(type) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            // AsNoTracking()으로 성능을 최적화하고, CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            return await query
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직 경로(Path)로 시작하는 모든 하위 조직의 초대를 조회합니다.
        /// 예: "root-org/child-org/" 경로를 제공하면 해당 조직 및 모든 하위 조직의 초대를 가져옵니다.
        /// </summary>
        /// <param name="organizationPath">조회할 기준 조직의 경로입니다.</param>
        /// <param name="type">필터링할 초대의 유형입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetByOrganizationPathAsync(
            string organizationPath,
            InvitationType? type = null,
            CancellationToken cancellationToken = default)
        {
            var query = Query().Where(i =>
                    i.OrganizationPath != null &&
                    i.OrganizationPath.StartsWith(organizationPath));

            // 초대 유형(type) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            // AsNoTracking()으로 성능을 최적화하고, CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            return await query
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직 내에서 아직 유효한(만료되지 않은) '전송' 상태의 초대 개수를 조회합니다.
        /// </summary>
        /// <param name="organizationId">조회할 조직의 ID입니다.</param>
        /// <param name="type">필터링할 초대의 유형입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 활성 초대 개수입니다.</returns>
        public async Task<int> CountActiveByOrganizationAsync(
            Guid organizationId,
            InvitationType type,
            CancellationToken cancellationToken = default)
        {
            var currentUtc = _dateTimeProvider.UtcNow;

            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            return await Query().CountAsync(i =>
                    i.OrganizationId == organizationId &&
                    i.Type == type &&
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc, // 직접 얻어온 시간을 기준으로 만료 여부 판단
                cancellationToken);
        }

        #endregion

        #region 사용자 기반 조회

        /// <summary>
        /// 특정 초대자(ConnectedId)가 보낸 모든 초대 목록을 조회합니다.
        /// 선택적으로 특정 날짜(since) 이후에 생성된 초대만 필터링할 수 있습니다.
        /// 결과는 최신순으로 정렬됩니다.
        /// </summary>
        /// <param name="invitedByConnectedId">초대자의 ConnectedId입니다.</param>
        /// <param name="since">조회를 시작할 날짜 (이 날짜 이후의 초대만 포함).</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetByInviterAsync(
            Guid invitedByConnectedId,
            DateTime? since = null,
            CancellationToken cancellationToken = default) // 원칙 3: CancellationToken 추가
        {
            // 원칙 1: _dbSet 대신 Query() 메서드 사용 (소프트 삭제 및 조직 필터링 자동 적용)
            var query = Query()
                .Where(i => i.InvitedByConnectedId == invitedByConnectedId);

            if (since.HasValue)
            {
                query = query.Where(i => i.CreatedAt >= since.Value);
            }

            return await query
                .OrderByDescending(i => i.CreatedAt)
                .AsNoTracking() // 원칙 2: 성능 최적화를 위해 AsNoTracking() 추가
                .ToListAsync(cancellationToken); // 원칙 3: ToListAsync에 CancellationToken 전달
        }
        /// <summary>
        /// 특정 이메일 주소로 전송된 유효한(만료되지 않은, 대기중인) 초대 목록을 조회합니다.
        /// 선택적으로 초대 유형(type)을 지정하여 추가로 필터링할 수 있습니다.
        /// </summary>
        /// <param name="email">초대받은 사람의 이메일 주소입니다.</param>
        /// <param name="type">필터링할 초대의 유형(예: 조직 가입, 프로젝트 참여 등).</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>유효한 대기 중인 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetPendingByEmailAsync(
            string email,
            InvitationType? type = null,
            CancellationToken cancellationToken = default) // 원칙 3: CancellationToken 추가
        {
            var currentUtc = _dateTimeProvider.UtcNow;

            // 원칙 1: _dbSet 대신 Query() 메서드 사용 (!i.IsDeleted 조건이 자동으로 처리됨)
            var query = Query()
                .Where(i =>
                    i.InviteeEmail == email &&
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc);

            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            return await query
                .AsNoTracking() // 원칙 2: 성능 최적화를 위해 AsNoTracking() 추가
                .ToListAsync(cancellationToken); // 원칙 3: ToListAsync에 CancellationToken 전달
        }

        /// <summary>
        /// 특정 이메일, 조직, 초대 유형에 대해 유효한(만료되지 않은) '대기 중'인 초대가 존재하는지 확인합니다.
        /// </summary>
        /// <param name="email">초대받은 사람의 이메일 주소입니다.</param>
        /// <param name="organizationId">초대가 속한 조직의 ID입니다.</param>
        /// <param name="type">확인할 초대의 유형입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>유효한 대기 중인 초대가 존재하면 true, 그렇지 않으면 false를 반환합니다.</returns>
        public async Task<bool> HasPendingInvitationAsync(
            string email,
            Guid organizationId,
            InvitationType type,
            CancellationToken cancellationToken = default)
        {
            // IDateTimeProvider를 통해 Repository가 직접 현재 시간을 얻어옵니다.
            var currentUtc = _dateTimeProvider.UtcNow;

            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            return await Query().AnyAsync(i =>
                    i.InviteeEmail == email &&
                    i.OrganizationId == organizationId &&
                    i.Type == type &&
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc,
                cancellationToken); // CancellationToken을 전달하여 비동기 일관성을 확보합니다.
        }

        #endregion

        #region 애플리케이션/프로젝트 조회

        /// <summary>
        /// 특정 애플리케이션(Application)에 속한 초대 목록을 조회합니다.
        /// 선택적으로 특정 상태(status)의 초대만 필터링할 수 있습니다.
        /// </summary>
        /// <param name="applicationId">조회할 애플리케이션의 ID입니다.</param>
        /// <param name="status">필터링할 초대의 상태입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetByApplicationAsync(
            Guid applicationId,
            InvitationStatus? status = null,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            var query = Query().Where(i => i.ApplicationId == applicationId);

            // 상태(status) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (status.HasValue)
            {
                query = query.Where(i => i.Status == status.Value);
            }

            // AsNoTracking()으로 성능을 최적화하고, CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            return await query
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 프로젝트(Project)에 속한 초대 목록을 조회합니다.
        /// 선택적으로 특정 상태(status)의 초대만 필터링할 수 있습니다.
        /// </summary>
        /// <param name="projectId">조회할 프로젝트의 ID입니다.</param>
        /// <param name="status">필터링할 초대의 상태입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetByProjectAsync(
            Guid projectId,
            InvitationStatus? status = null,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            var query = Query().Where(i => i.ProjectId == projectId);

            // 상태(status) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (status.HasValue)
            {
                query = query.Where(i => i.Status == status.Value);
            }

            // AsNoTracking()으로 성능을 최적화하고, CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            return await query
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 상태 관리

        /// <summary>
        /// 특정 조직의 유효한(활성 상태인) 초대 목록을 조회합니다.
        /// 선택적으로 초대 유형(type) 및 만료 예정 시점(expiringBefore)으로 추가 필터링이 가능합니다.
        /// </summary>
        /// <param name="organizationId">조회할 조직의 ID입니다.</param>
        /// <param name="type">필터링할 초대의 유형입니다.</param>
        /// <param name="expiringBefore">초대가 만료되어야 하는 특정 시점 이전으로 필터링합니다. (예: "24시간 내 만료되는 초대")</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 활성 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetActiveAsync(
            Guid organizationId,
            InvitationType? type = null,
            DateTime? expiringBefore = null,
            CancellationToken cancellationToken = default)
        {
            // IDateTimeProvider를 통해 Repository가 직접 현재 시간을 얻어옵니다.
            var currentUtc = _dateTimeProvider.UtcNow;

            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            var query = Query().Where(i =>
                    i.OrganizationId == organizationId &&
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc);

            // 초대 유형(type) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            // 만료 예정 시점(expiringBefore) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (expiringBefore.HasValue)
            {
                query = query.Where(i => i.ExpiresAt <= expiringBefore.Value);
            }

            // AsNoTracking()으로 성능을 최적화하고, CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            return await query
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 초대 상태(Status)를 기준으로 초대 목록을 조회합니다.
        /// 선택적으로 특정 조직(organizationId)에 속한 초대만 필터링할 수 있습니다.
        /// </summary>
        /// <param name="status">조회할 초대의 상태입니다.</param>
        /// <param name="organizationId">필터링할 조직의 ID (선택 사항)입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetByStatusAsync(
            InvitationStatus status,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            var query = Query().Where(i => i.Status == status);

            // 조직 ID(organizationId) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (organizationId.HasValue)
            {
                query = query.Where(i => i.OrganizationId == organizationId.Value);
            }

            // AsNoTracking()으로 성능을 최적화하고, CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            return await query
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 초대의 상태(Status)를 업데이트합니다.
        /// 중요: 이 메서드는 데이터베이스에 변경 사항을 '저장'하지 않고, 메모리(Context) 상의 상태만 변경합니다.
        /// 실제 저장은 이 메서드를 호출한 서비스 계층에서 UnitOfWork.SaveChangesAsync()를 통해 이루어져야 합니다.
        /// </summary>
        /// <param name="invitationId">수정할 초대의 ID입니다.</param>
        /// <param name="newStatus">새롭게 적용할 초대의 상태입니다.</param>
        /// <param name="updatedByConnectedId">상태를 변경한 사용자의 ConnectedId (선택 사항)입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>초대를 찾아 업데이트를 준비했다면 true, 초대를 찾지 못했다면 false를 반환합니다.</returns>
        public async Task<bool> UpdateStatusAsync(
            Guid invitationId,
            InvitationStatus newStatus,
            Guid? updatedByConnectedId = null,
            CancellationToken cancellationToken = default)
        {
            // FindAsync 대신 Query()를 사용하여 IsDeleted 같은 전역 필터를 일관되게 적용합니다.
            var invitation = await Query()
                .FirstOrDefaultAsync(i => i.Id == invitationId, cancellationToken);

            if (invitation == null)
            {
                return false;
            }

            // 엔티티의 상태를 변경합니다.
            invitation.Status = newStatus;
            invitation.UpdatedAt = _dateTimeProvider.UtcNow;

            if (updatedByConnectedId.HasValue)
            {
                invitation.UpdatedByConnectedId = updatedByConnectedId.Value;
            }

            // 중요: Repository는 SaveChanges를 호출하지 않습니다.
            // _context.Entry(invitation).State = EntityState.Modified; // FirstOrDefaultAsync가 추적을 하므로 이 줄은 불필요.

            // 캐시 무효화 로직은 유지합니다. GetByCodeAsync에서 사용된 캐시를 제거해야 합니다.
            // BaseRepository의 InvalidateCacheAsync는 ID 기반이므로, InviteCode 기반 키는 직접 처리합니다.
            if (_cacheService != null)
            {
                var cacheKey = GetCacheKey(nameof(GetByCodeAsync), invitation.InviteCode);
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }

            // 이 외에 ID 기반 캐시도 무효화 해주는 것이 안전합니다.
            await InvalidateCacheAsync(invitation.Id, cancellationToken);

            return true;
        }

        #endregion

        #region 비율 제한 및 분석

        /// <summary>
        /// 특정 기간 내에 한 사용자가 보낸 초대 수를 계산합니다. (비율 제한용)
        /// </summary>
        /// <param name="invitedByConnectedId">초대를 보낸 사용자의 ConnectedId입니다.</param>
        /// <param name="since">계산을 시작할 시점입니다. (이 시간 이후에 생성된 초대만 카운트)</param>
        /// <param name="type">필터링할 초대의 유형입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 초대 개수입니다.</returns>
        public async Task<int> CountInvitationsByUserAsync(
            Guid invitedByConnectedId,
            DateTime since,
            InvitationType? type = null,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            var query = Query().Where(i =>
                    i.InvitedByConnectedId == invitedByConnectedId &&
                    i.CreatedAt >= since);

            // 초대 유형(type) 파라미터가 제공된 경우, 추가로 필터링합니다.
            if (type.HasValue)
            {
                query = query.Where(i => i.Type == type.Value);
            }

            // CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            return await query.CountAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직의 초대 관련 통계를 집계하여 조회합니다.
        /// 모든 계산은 데이터베이스에서 직접 수행하여 성능을 최적화합니다.
        /// </summary>
        public async Task<InvitationStatistics> GetStatisticsAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            CancellationToken cancellationToken = default)
        {
            var baseQuery = Query().Where(i => i.OrganizationId == organizationId);

            if (startDate.HasValue)
                baseQuery = baseQuery.Where(i => i.CreatedAt >= startDate.Value);

            if (endDate.HasValue)
                baseQuery = baseQuery.Where(i => i.CreatedAt <= endDate.Value);

            var statusCounts = await baseQuery
                .GroupBy(i => i.Status)
                .Select(g => new { Status = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Status, x => x.Count, cancellationToken);

            var typeCounts = await baseQuery
                .GroupBy(i => i.Type)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.Type, x => x.Count, cancellationToken);

            // [최종 오류 수정] 1. DB에서는 Nullable<DateTime> 그대로 조회합니다.
            var acceptedInvitationDates = await baseQuery
                .Where(i => i.Status == InvitationStatus.Accepted)
                .Select(i => new { i.CreatedAt, i.AcceptedAt })
                .ToListAsync(cancellationToken);

            var stats = new InvitationStatistics
            {
                TotalAccepted = statusCounts.GetValueOrDefault(InvitationStatus.Accepted),
                TotalDeclined = statusCounts.GetValueOrDefault(InvitationStatus.Declined),
                TotalExpired = statusCounts.GetValueOrDefault(InvitationStatus.Expired),
                TotalCancelled = statusCounts.GetValueOrDefault(InvitationStatus.Cancelled),
                TotalBounced = statusCounts.GetValueOrDefault(InvitationStatus.Bounced),
                TotalSent = statusCounts.Values.Sum(),
                CurrentlyPending = await baseQuery.CountAsync(i => i.Status == InvitationStatus.Sent && i.ExpiresAt > _dateTimeProvider.UtcNow, cancellationToken),
                ByType = typeCounts
            };

            stats.AcceptanceRate = stats.TotalSent > 0
                ? (double)stats.TotalAccepted / stats.TotalSent * 100
                : 0;

            // 2. 메모리로 가져온 데이터 중에서 null이 아닌 것만 필터링하여 계산합니다.
            // 이 방식은 컴파일러가 혼동할 여지가 전혀 없습니다.
            var validAcceptedTimes = acceptedInvitationDates
                .Where(t => t.AcceptedAt.HasValue)
                .ToList();

            // [최종 오류 수정] t.AcceptedAt 뒤에 '!' 연산자를 추가하여
            // 컴파일러에게 이 값이 절대 null이 아님을 강제로 알려줍니다.
            var averageTicks = validAcceptedTimes
                .Average(t => (t.AcceptedAt!.Value - t.CreatedAt).Ticks);
            stats.AverageTimeToAccept = TimeSpan.FromTicks((long)averageTicks);

            return stats;
        }
        #endregion

        #region 유지보수 작업

        /// <summary>
        /// 주기적인 리마인더 발송이 필요한 초대 목록을 조회합니다. (백그라운드 서비스용)
        /// </summary>
        /// <param name="minimumHoursBetweenReminders">최소 리마인더 발송 간격 (시간)입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>리마인더 발송이 필요한 초대 엔티티의 컬렉션입니다.</returns>
        /// MaxReminders: 이 초대에 대해 보낼 수 있는 리마인더의 최대 횟수를 저장합니다 (예: 3). 이 값은 시스템 기본값이거나, 조직의 설정에 따라 달라질 수 있습니다.
        public async Task<IEnumerable<Invitation>> GetInvitationsNeedingReminderAsync(
            int minimumHoursBetweenReminders = 24,
            CancellationToken cancellationToken = default)
        {
            // IDateTimeProvider를 통해 Repository가 직접 현재 시간을 얻어옵니다.
            var currentUtc = _dateTimeProvider.UtcNow;

            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            return await Query()
                .Where(i =>
                    i.Status == InvitationStatus.Sent &&
                    i.ExpiresAt > currentUtc &&
                    i.ReminderCount < i.MaxReminders &&
                    (i.LastReminderAt == null ||
                     EF.Functions.DateDiffHour(i.LastReminderAt.Value, currentUtc) >= minimumHoursBetweenReminders))
                // 조회 전용이므로 AsNoTracking()으로 성능을 최적화합니다.
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }
        /// <summary>
        /// 특정 초대의 리마인더 발송 횟수를 1 증가시키고, 마지막 발송 시간을 기록합니다.
        /// 중요: 이 메서드는 데이터베이스에 변경 사항을 '저장'하지 않고, 메모리(Context) 상의 상태만 변경합니다.
        /// 실제 저장은 이 메서드를 호출한 백그라운드 서비스에서 UnitOfWork.SaveChangesAsync()를 통해 이루어져야 합니다.
        /// </summary>
        /// <param name="invitationId">수정할 초대의 ID입니다.</param>
        /// <param name="reminderSentAt">리마인더가 실제 발송된 시간입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>초대를 찾아 업데이트를 준비했다면 true, 초대를 찾지 못했다면 false를 반환합니다.</returns>
        public async Task<bool> IncrementReminderCountAsync(
            Guid invitationId,
            DateTime reminderSentAt,
            CancellationToken cancellationToken = default)
        {
            // FindAsync 대신 Query()를 사용하여 IsDeleted 같은 전역 필터를 일관되게 적용합니다.
            var invitation = await Query()
                .FirstOrDefaultAsync(i => i.Id == invitationId, cancellationToken);

            if (invitation == null)
            {
                return false;
            }

            // 엔티티의 상태를 변경합니다.
            invitation.ReminderCount++;
            invitation.LastReminderAt = reminderSentAt;
            invitation.UpdatedAt = reminderSentAt; // 업데이트 시간도 함께 기록

            // 중요: Repository는 SaveChanges를 호출하지 않습니다.
            // 백그라운드 서비스가 모든 리마인더 처리 후 한 번에 SaveChanges를 호출해야 합니다.

            // 이 작업은 캐시된 데이터를 변경시키므로, 캐시를 무효화하는 것이 안전합니다.
            await InvalidateCacheAsync(invitation.Id, cancellationToken);
            if (_cacheService != null)
            {
                var codeCacheKey = GetCacheKey(nameof(GetByCodeAsync), invitation.InviteCode);
                await _cacheService.RemoveAsync(codeCacheKey, cancellationToken);
            }

            return true;
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 여러 개의 초대 엔티티를 데이터베이스 컨텍스트에 한 번에 추가합니다. (대량 초대용)
        /// 중요: 이 메서드는 데이터베이스에 변경 사항을 '저장'하지 않고, 메모리(Context)에 추가만 합니다.
        /// 실제 저장은 이 메서드를 호출한 서비스 계층에서 UnitOfWork.SaveChangesAsync()를 통해 이루어져야 합니다.
        /// </summary>
        /// <param name="invitations">추가할 초대 엔티티의 컬렉션입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>데이터베이스 컨텍스트에 추가된 초대 엔티티의 컬렉션을 반환합니다.</returns>
        public async Task<IEnumerable<Invitation>> BulkCreateAsync(
            IEnumerable<Invitation> invitations,
            CancellationToken cancellationToken = default)
        {
            // AddRangeAsync는 여러 엔티티를 컨텍스트에 한 번에 추가하는 가장 효율적인 방법입니다.
            // CancellationToken을 전달하여 비동기 일관성을 확보합니다.
            await _dbSet.AddRangeAsync(invitations, cancellationToken);

            // 중요: Repository는 SaveChanges를 호출하지 않습니다.
            // 서비스 계층에서 모든 비즈니스 로직이 끝난 후 한 번만 호출해야
            // 트랜잭션이 올바르게 관리됩니다.

            return invitations;
        }

        /// <summary>
        /// 여러 개의 초대를 한 번에 '취소' 상태로 변경합니다.
        /// 중요: 이 메서드는 데이터베이스에 변경 사항을 '저장'하지 않고, 메모리(Context) 상의 상태만 변경합니다.
        /// 실제 저장은 이 메서드를 호출한 서비스 계층에서 UnitOfWork.SaveChangesAsync()를 통해 이루어져야 합니다.
        /// </summary>
        /// <param name="invitationIds">취소할 초대 ID의 컬렉션입니다.</param>
        /// <param name="cancelledByConnectedId">취소를 실행한 사용자의 ConnectedId입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>성공적으로 상태 변경을 준비한 초대 개수입니다.</returns>
        public async Task<int> BulkCancelAsync(
            IEnumerable<Guid> invitationIds,
            Guid cancelledByConnectedId,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            var invitationsToCancel = await Query()
                .Where(i => invitationIds.Contains(i.Id))
                .ToListAsync(cancellationToken);

            var currentUtc = _dateTimeProvider.UtcNow;
            foreach (var invitation in invitationsToCancel)
            {
                // 엔티티의 상태를 변경합니다.
                invitation.Status = InvitationStatus.Cancelled;
                invitation.CancelledAt = currentUtc;
                invitation.UpdatedAt = currentUtc;
                invitation.UpdatedByConnectedId = cancelledByConnectedId;

                // 이 작업은 캐시된 데이터를 변경시키므로, 관련된 모든 캐시를 무효화합니다.
                await InvalidateCacheAsync(invitation.Id, cancellationToken);
                if (_cacheService != null)
                {
                    var codeCacheKey = GetCacheKey(nameof(GetByCodeAsync), invitation.InviteCode);
                    await _cacheService.RemoveAsync(codeCacheKey, cancellationToken);
                }
            }

            return invitationsToCancel.Count;
        }

        #endregion

        #region 유효성 검사 헬퍼
        /// <summary>
        /// 특정 시점 이후에 조직에서 보낸 초대 수를 계산합니다. (서비스 계층의 정책 판단용)
        /// </summary>
        /// <param name="organizationId">조회할 조직의 ID입니다.</param>
        /// <param name="type">필터링할 초대의 유형입니다.</param>
        /// <param name="since">계산을 시작할 시점입니다.</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>조건에 맞는 초대 개수입니다.</returns>
        public async Task<int> CountInvitationsSinceAsync(
            Guid organizationId,
            InvitationType type,
            DateTime since,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            return await Query().CountAsync(i =>
                    i.OrganizationId == organizationId &&
                    i.Type == type &&
                    i.CreatedAt >= since,
                cancellationToken);
        }
        /// <summary>
        /// 특정 기간 내에 생성된 중복 초대를 조회합니다. (스팸 방지용)
        /// </summary>
        /// <param name="email">초대받은 사람의 이메일 주소입니다.</param>
        /// <param name="organizationId">초대가 속한 조직의 ID입니다.</param>
        /// <param name="within">중복으로 간주할 시간 범위입니다. (예: 지난 1시간)</param>
        /// <param name="cancellationToken">비동기 작업 취소를 위한 토큰입니다.</param>
        /// <returns>최근에 생성된 중복 초대 엔티티의 컬렉션입니다.</returns>
        public async Task<IEnumerable<Invitation>> GetRecentDuplicatesAsync(
            string email,
            Guid organizationId,
            TimeSpan within,
            CancellationToken cancellationToken = default)
        {
            // IDateTimeProvider를 통해 'since' 시간을 안전하게 계산합니다.
            var since = _dateTimeProvider.UtcNow.Subtract(within);

            // BaseRepository의 Query()를 사용하여 IsDeleted 필터링 등을 자동으로 처리합니다.
            return await Query()
                .Where(i =>
                    i.InviteeEmail == email &&
                    i.OrganizationId == organizationId &&
                    i.CreatedAt >= since)
                .OrderByDescending(i => i.CreatedAt)
                // AsNoTracking()으로 성능을 최적화하고, CancellationToken을 전달하여 비동기 일관성을 확보합니다.
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion
    }
}