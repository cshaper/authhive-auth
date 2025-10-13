using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Repositories.PlatformApplication
{
    /// <summary>
    /// 사용자-플랫폼 애플리케이션 접근 권한 저장소 구현 (UserPlatformApplicationAccessRepository).
    /// 사용자가 특정 조직의 플랫폼 애플리케이션에 접근할 수 있는 권한 정보를 관리합니다.
    /// </summary>
    public class UserPlatformApplicationAccessRepository : BaseRepository<UserPlatformApplicationAccess>
    {

        public UserPlatformApplicationAccessRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, // 현재 조직(테넌트) 정보를 제공
            ICacheService? cacheService = null) 
            : base(context, cacheService) 
        {
    
        }

        /// <summary>
        /// BaseRepository<TEntity>의 추상 멤버를 구현합니다.
        /// 이 메서드는 BaseRepository가 쿼리를 실행할 때, 해당 엔티티가 조직 스코프를 가져야 하는지 결정합니다.
        /// </summary>
        /// <returns>
        /// UserPlatformApplicationAccess는 특정 조직의 애플리케이션 접근 권한을 나타내므로 
        /// true를 반환하여 멀티테넌시 데이터 격리를 강제합니다. (CS0534 에러 해결)
        /// </returns>
        protected override bool IsOrganizationScopedEntity()
        {
            return true;
        }
        
        // 여기에 UserPlatformApplicationAccess 전용 비즈니스 메서드를 추가합니다.
    }
}