using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
// 필요한 엔티티 및 Enum 네임스페이스 추가
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Interfaces.PlatformApplication.Repository; // 인터페이스
using AuthHive.Core.Entities.Auth; // Role, ConnectedId 등 참조 엔티티

namespace AuthHive.Auth.Repositories // 네임스페이스는 프로젝트 구조에 맞게 조정 가능
{
    /// <summary>
    /// 사용자-플랫폼 애플리케이션 접근 권한 저장소 구현 (v16.1)
    /// 역할: 사용자가 특정 조직의 플랫폼 애플리케이션에 접근할 수 있는 권한 정보를 관리합니다.
    ///       v16 아키텍처에서는 역할(Role) 할당도 이 엔티티를 통해 관리됩니다.
    ///
    /// [v16.1 변경 사항]
    /// - IOrganizationContext 의존성 제거
    /// - ICacheService 통합 (BaseRepository 활용)
    /// - UoW 원칙 준수 (SaveChangesAsync 제거)
    /// - 읽기 전용 쿼리에 AsNoTracking 적용
    /// - 모든 비동기 메서드에 CancellationToken 적용 및 전달
    /// - 상세 한글 주석 추가
    /// - IUserPlatformApplicationAccessRepository 인터페이스의 모든 메서드 구현
    /// </summary>
    public class UserPlatformApplicationAccessRepository
        : BaseRepository<UserPlatformApplicationAccess>, IUserPlatformApplicationAccessRepository
    {
        // BaseRepository<T> 가 AuthDbContext(_context)와 ICacheService?(_cacheService)를 가지고 있음

        /// <summary>
        /// 생성자: v16.1 원칙에 따라 AuthDbContext와 ICacheService만 주입받습니다.
        /// </summary>
        public UserPlatformApplicationAccessRepository(
            AuthDbContext context,
            ICacheService? cacheService = null)
            : base(context, cacheService) // BaseRepository로 전달
        {
        }

        /// <summary>
        /// UserPlatformApplicationAccess는 특정 조직의 애플리케이션 접근 권한을 나타내므로
        /// 'true'를 반환하여 BaseRepository의 조직 범위 필터링(RLS)을 활성화합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region 특화 조회 (IUserPlatformApplicationAccessRepository 구현)

        /// <summary>
        /// 단일 엔티티를 주어진 조건(predicate)에 맞게 조회합니다.
        /// 내부적으로 BaseRepository의 Query()를 사용하여 IsDeleted=false 필터가 적용됩니다.
        /// </summary>
        /// <param name="predicate">조회 조건 람다식</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>조건에 맞는 첫 번째 엔티티 또는 null</returns>
        /// <remarks>읽기 전용 작업이므로 AsNoTracking()을 적용합니다.</remarks>
        public async Task<UserPlatformApplicationAccess?> FindSingleAsync(
            Expression<Func<UserPlatformApplicationAccess, bool>> predicate,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 Query()는 IsDeleted=false 필터를 포함
            return await Query()
                .AsNoTracking() // 읽기 전용 최적화
                .FirstOrDefaultAsync(predicate, cancellationToken); // 조건에 맞는 첫 번째 항목 조회
        }

        /// <summary>
        /// ConnectedId와 ApplicationId의 고유 조합으로 단일 접근 권한 레코드를 조회합니다.
        /// Role 정보도 함께 로드합니다 (Eager Loading).
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 식별자</param>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 권한 엔티티 (Role 포함, 없으면 null)</returns>
        /// <remarks>
        /// 사용 예시: 사용자가 특정 앱에 접근 시, 권한 레코드와 연결된 Role 정보를 확인합니다.
        /// 이 메서드로 조회된 엔티티는 수정될 수 있으므로 AsNoTracking()을 적용하지 않습니다.
        /// </remarks>
        public async Task<UserPlatformApplicationAccess?> GetByConnectedIdAndApplicationAsync(
            Guid connectedId,
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            // Query() 사용, Role 정보 Eager Loading
            return await Query()
                .Include(a => a.Role) // Role 정보 포함
                .FirstOrDefaultAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId, cancellationToken);
        }

        /// <summary>
        /// 특정 ConnectedId에 부여된 모든 (삭제되지 않은) 애플리케이션 접근 권한 목록을 조회합니다.
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 권한 엔티티 목록 (PlatformApplication 정보 포함)</returns>
        /// <remarks>
        /// 사용 예시: 사용자 프로필 화면 등에서 해당 사용자가 접근 가능한 앱 목록을 표시할 때 사용합니다.
        /// </remarks>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(a => a.ConnectedId == connectedId)
                .Include(a => a.PlatformApplication) // 앱 이름 등 표시 위해 앱 정보 포함
                .OrderBy(a => a.PlatformApplication.Name) // 앱 이름순 정렬
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 플랫폼 애플리케이션에 접근 권한이 부여된 모든 (삭제되지 않은) 사용자 목록을 조회합니다.
        /// </summary>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 권한 엔티티 목록 (ConnectedId 정보 포함)</returns>
        /// <remarks>
        /// 사용 예시: 애플리케이션 관리 페이지에서 해당 앱 사용자 목록을 표시할 때 사용합니다.
        /// </remarks>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByApplicationIdAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(a => a.ApplicationId == applicationId)
                .Include(a => a.ConnectedIdNavigation) // 사용자 정보 접근 위해 ConnectedId 포함
                  .ThenInclude(c => c.User) // 필요 시 User 정보까지 포함
                .OrderBy(a => a.GrantedAt) // 부여된 시간순 정렬
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 애플리케이션에 대해 특정 접근 레벨(AccessLevel)을 가진 모든 (삭제되지 않은) 권한 레코드를 조회합니다.
        /// </summary>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="accessLevel">조회할 접근 레벨 (Enum)</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 권한 엔티티 목록</returns>
        /// <remarks>
        /// 사용 예시: 특정 앱의 'Admin' 레벨 사용자 목록을 조회하여 관리 작업을 수행합니다.
        /// </remarks>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByAccessLevelAsync(
            Guid applicationId,
            ApplicationAccessLevel accessLevel,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(a => a.ApplicationId == applicationId && a.AccessLevel == accessLevel)
                .Include(a => a.PlatformApplication) // 앱 정보
                .Include(a => a.ConnectedIdNavigation) // 사용자 정보
                .OrderBy(a => a.GrantedAt) // 부여 시간순
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 역할(Role)이 할당된 모든 (삭제되지 않은) 접근 권한 레코드를 조회합니다.
        /// </summary>
        /// <param name="roleId">역할(Role) 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 권한 엔티티 목록</returns>
        /// <remarks>
        /// 사용 예시: 특정 역할을 가진 모든 사용자의 목록을 조회하여 역할 권한 변경의 영향을 분석합니다.
        /// </remarks>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByRoleIdAsync(
            Guid roleId,
            CancellationToken cancellationToken = default)
        {
            // RoleId는 Nullable일 수 있으므로 .HasValue 및 .Value 사용
            return await Query()
                .Where(a => a.RoleId.HasValue && a.RoleId.Value == roleId)
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.GrantedAt)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 접근 템플릿(AccessTemplate)으로부터 생성(또는 연결)된 모든 (삭제되지 않은) 접근 권한 레코드를 조회합니다.
        /// </summary>
        /// <param name="templateId">접근 템플릿 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 권한 엔티티 목록</returns>
        /// <remarks>
        /// 사용 예시: 특정 템플릿이 적용된 사용자 목록을 조회하여 템플릿 변경 시 영향을 받는 범위를 파악합니다.
        /// </remarks>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByTemplateIdAsync(
            Guid templateId,
            CancellationToken cancellationToken = default)
        {
            // AccessTemplateId는 Nullable
            return await Query()
                .Where(a => a.AccessTemplateId.HasValue && a.AccessTemplateId.Value == templateId)
                .Include(a => a.PlatformApplication)
                .Include(a => a.ConnectedIdNavigation)
                .OrderBy(a => a.GrantedAt)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직(Organization)에 속한 모든 (삭제되지 않은) 접근 권한 레코드를 조회합니다.
        /// BaseRepository의 QueryForOrganization 헬퍼를 사용합니다.
        /// </summary>
        /// <param name="organizationId">조직 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 권한 엔티티 목록</returns>
        /// <remarks>
        /// 사용 예시: 조직 관리자가 해당 조직 내 모든 앱 접근 권한 현황을 조회할 때 사용합니다.
        /// </remarks>
        public async Task<IEnumerable<UserPlatformApplicationAccess>> GetByOrganizationIdAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 조직 필터링 헬퍼 사용
            return await QueryForOrganization(organizationId)
                .Include(a => a.PlatformApplication) // 앱 정보
                .Include(a => a.ConnectedIdNavigation) // 사용자 정보
                .OrderBy(a => a.PlatformApplication.Name) // 앱 이름, 부여 시간 순 정렬
                .ThenBy(a => a.GrantedAt)
                .AsNoTracking() // 읽기 전용
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 검증 (IUserPlatformApplicationAccessRepository 구현)

        /// <summary>
        /// 특정 사용자가 특정 애플리케이션에 대한 권한 레코드(삭제된 것 포함)를 가지고 있는지 확인합니다.
        /// (레코드가 생성된 적 있는지 여부)
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 식별자</param>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>존재 여부</returns>
        public async Task<bool> ExistsAsync(
            Guid connectedId,
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            // AnyAsync는 IsDeleted=false 필터를 사용하는 Query()를 사용해야 함
            return await Query()
                .AnyAsync(a => a.ConnectedId == connectedId && a.ApplicationId == applicationId, cancellationToken);
        }

        /// <summary>
        /// 특정 사용자가 특정 앱에 대해 최소 요구 접근 레벨(예: Admin 이상)을 만족하는 '활성' 권한을 가졌는지 확인합니다.
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 식별자</param>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="minLevel">요구되는 최소 접근 레벨</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>최소 레벨 만족 여부</returns>
        public async Task<bool> HasAccessLevelAsync(
            Guid connectedId,
            Guid applicationId,
            ApplicationAccessLevel minLevel,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .AnyAsync(a =>
                    a.ConnectedId == connectedId &&
                    a.ApplicationId == applicationId &&
                    a.AccessLevel >= minLevel && // 접근 레벨 비교 (크거나 같음)
                    a.IsActive && // 활성 상태 확인
                    (a.ExpiresAt == null || a.ExpiresAt > now), // 만료되지 않았는지 확인
                    cancellationToken);
        }

        /// <summary>
        /// 특정 사용자가 특정 앱에 대해 '활성화'된 접근 권한을 가지고 있는지 확인합니다.
        /// (IsActive 플래그 및 만료일자(ExpiresAt) 모두 고려)
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 식별자</param>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>활성 권한 보유 여부</returns>
        public async Task<bool> IsActiveAsync(
            Guid connectedId,
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .AnyAsync(a =>
                    a.ConnectedId == connectedId &&
                    a.ApplicationId == applicationId &&
                    a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > now),
                    cancellationToken);
        }

        #endregion

        #region 통계 (IUserPlatformApplicationAccessRepository 구현)

        /// <summary>
        /// 특정 애플리케이션에 할당된 총 (삭제되지 않은) 접근 권한 레코드 수를 계산합니다.
        /// </summary>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>총 권한 레코드 수</returns>
        public async Task<int> GetCountByApplicationAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
             // CountAsync는 AsNoTracking 불필요
            return await Query()
                .CountAsync(a => a.ApplicationId == applicationId, cancellationToken);
        }

        /// <summary>
        /// 특정 애플리케이션에 할당된 '활성' 접근 권한 수를 계산합니다.
        /// (IsActive 플래그 및 만료일자(ExpiresAt) 고려)
        /// </summary>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>활성 권한 레코드 수</returns>
        public async Task<int> GetActiveCountByApplicationAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .CountAsync(a =>
                    a.ApplicationId == applicationId &&
                    a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > now),
                    cancellationToken);
        }

        /// <summary>
        /// 특정 애플리케이션의 활성 사용자 수를 접근 레벨별로 그룹화하여 계산합니다.
        /// </summary>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>접근 레벨별 사용자 수를 담은 Dictionary</returns>
        public async Task<Dictionary<ApplicationAccessLevel, int>> GetCountByAccessLevelAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            // GroupBy + ToDictionaryAsync 사용 (AsNoTracking 불필요)
            return await Query()
                .Where(a => a.ApplicationId == applicationId &&
                            a.IsActive &&
                            (a.ExpiresAt == null || a.ExpiresAt > now)) // 활성 권한 필터
                .GroupBy(a => a.AccessLevel) // 접근 레벨로 그룹화
                .Select(g => new { AccessLevel = g.Key, Count = g.Count() }) // 레벨과 개수 선택
                .ToDictionaryAsync(x => x.AccessLevel, x => x.Count, cancellationToken); // Dictionary로 변환
        }

        /// <summary>
        /// (오버로드) 특정 애플리케이션의 특정 접근 레벨을 가진 활성 사용자 수를 계산합니다.
        /// </summary>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="accessLevel">조회할 특정 접근 레벨</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>해당 레벨의 활성 사용자 수</returns>
        public async Task<int> GetCountByAccessLevelAsync(
            Guid applicationId,
            ApplicationAccessLevel accessLevel,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            return await Query()
                .CountAsync(a =>
                    a.ApplicationId == applicationId &&
                    a.AccessLevel == accessLevel && // 특정 레벨 필터
                    a.IsActive &&
                    (a.ExpiresAt == null || a.ExpiresAt > now),
                    cancellationToken);
        }

        #endregion

        #region 일괄 작업 (IUserPlatformApplicationAccessRepository 구현, UoW 적용)

        /// <summary>
        /// 특정 애플리케이션과 관련된 모든 (삭제되지 않은) 접근 권한 레코드를 소프트 삭제합니다.
        /// BaseRepository의 DeleteRangeAsync를 사용하여 처리합니다.
        /// </summary>
        /// <param name="applicationId">플랫폼 애플리케이션 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>작업 성공 여부 (UoW 커밋 가정)</returns>
        public async Task<bool> RemoveAllByApplicationAsync(
            Guid applicationId,
            CancellationToken cancellationToken = default)
        {
            // 삭제 대상 엔티티 조회 (추적 필요 - AsNoTracking 없음)
            var entitiesToDelete = await Query()
                .Where(a => a.ApplicationId == applicationId)
                .ToListAsync(cancellationToken);

            if (!entitiesToDelete.Any()) return true; // 삭제할 대상이 없으면 성공

            // BaseRepository의 일괄 삭제 메서드 호출 (내부적으로 IsDeleted, DeletedAt 설정)
            await DeleteRangeAsync(entitiesToDelete, cancellationToken);
            // 실제 저장은 서비스 레이어의 SaveChangesAsync에서 처리됨

             // 관련된 복합 캐시 키 무효화는 서비스 레이어 또는 이벤트 핸들러에서 처리 권장
            // (예: application:{appId}:accesslist)

            return true;
        }

        /// <summary>
        /// 특정 사용자와 관련된 모든 (삭제되지 않은) 애플리케이션 접근 권한 레코드를 소프트 삭제합니다.
        /// BaseRepository의 DeleteRangeAsync를 사용하여 처리합니다.
        /// </summary>
        /// <param name="connectedId">조직 내 사용자 식별자</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>작업 성공 여부 (UoW 커밋 가정)</returns>
        public async Task<bool> RemoveAllByConnectedIdAsync(
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            var entitiesToDelete = await Query()
                .Where(a => a.ConnectedId == connectedId)
                .ToListAsync(cancellationToken);

            if (!entitiesToDelete.Any()) return true;

            await DeleteRangeAsync(entitiesToDelete, cancellationToken);
            
            // 관련된 ConnectedId 기반 캐시 무효화 필요 (서비스 레이어/이벤트 핸들러)
            // 예: user:{connectedId}:appaccess

            return true;
        }

        /// <summary>
        /// 단일 접근 권한 레코드를 ID를 기준으로 소프트 삭제합니다.
        /// BaseRepository의 SoftDeleteAsync를 사용하며, 추가적으로 감사 정보(DeletedBy)를 설정합니다.
        /// </summary>
        /// <param name="id">삭제할 접근 권한 레코드의 ID</param>
        /// <param name="deletedByConnectedId">삭제 작업을 수행한 사용자의 ConnectedId</param>
        /// <param name="cancellationToken">취소 토큰</param>
        /// <returns>삭제 성공 여부 (UoW 커밋 가정)</returns>
        public async Task<bool> SoftDeleteAsync(
            Guid id,
            Guid deletedByConnectedId,
            CancellationToken cancellationToken = default)
        {
             // BaseRepository의 SoftDeleteAsync는 ID로 엔티티를 찾아서 IsDeleted=true, DeletedAt=now 처리 후 UpdateAsync 호출
            var entity = await _dbSet.FindAsync(new object[] { id }, cancellationToken); // 추적 상태로 로드
            if(entity == null || entity.IsDeleted) return false;

            // 감사 정보 추가 설정
            entity.DeletedByConnectedId = deletedByConnectedId;
            entity.IsActive = false; // 비활성화

            // BaseRepository의 DeleteAsync 호출 (내부적으로 UpdateAsync + 캐시 무효화(Id 기반))
            await DeleteAsync(entity, cancellationToken);

             // 추가적인 복합 캐시 키 무효화 (서비스 레이어/이벤트 핸들러)
             // 예: cid={cid}:aid={aid}:oid={oid}

            return true;
        }

        #endregion

        #region QueryBuilder 지원 (IUserPlatformApplicationAccessRepository 구현)

        /// <summary>
        /// 서비스 레이어에서 복잡한 동적 쿼리를 구성할 수 있도록 IQueryable<UserPlatformApplicationAccess>을 반환합니다.
        /// BaseRepository의 Query() 메서드를 사용하여 IsDeleted=false 필터가 기본 적용됩니다.
        /// </summary>
        /// <returns>IQueryable 인터페이스 (IsDeleted=false 필터 적용됨)</returns>
        public IQueryable<UserPlatformApplicationAccess> GetQueryable()
        {
            // BaseRepository의 Query() 메서드를 그대로 반환
            return Query();
        }

        #endregion

        // 헬퍼 메서드 (예: 캐시 키 생성, 정렬 등) 필요 시 여기에 추가
        // private string GetCustomCacheKey(...) { ... }
        // private IOrderedQueryable<UserPlatformApplicationAccess> ApplySorting(...) { ... }
    }
}