using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
// using Microsoft.Extensions.Caching.Memory; // 🚫 ICacheService를 사용하므로 이 using은 제거되거나 불필요해집니다.
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache; // 💡 ICacheService의 네임스페이스가 필요합니다.

namespace AuthHive.Auth.Repositories.PlatformApplication
{
    /// <summary>
    /// 플랫폼 애플리케이션 초대 저장소 구현 (ApplicationInviteRepository).
    /// ApplicationInvite 엔티티에 대한 데이터 접근을 담당합니다.
    /// </summary>
    public class ApplicationInviteRepository : BaseRepository<ApplicationInvite>
    {
        private readonly IOrganizationContext _organizationContext; 

        public ApplicationInviteRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            ICacheService? cacheService = null) 
            // BaseRepository는 DbContext와 ICacheService를 받도록 수정되었습니다.
            : base(context, cacheService) 
        {
            _organizationContext = organizationContext ?? throw new ArgumentNullException(nameof(organizationContext));
        }

        /// <summary>
        /// BaseRepository<TEntity>의 추상 멤버를 구현합니다.
        /// ApplicationInvite는 특정 조직의 플랫폼 애플리케이션에 대한 초대이므로 
        /// true를 반환하여 멀티테넌시 필터링을 강제합니다. 
        /// </summary>
        protected override bool IsOrganizationScopedEntity()
        {
            return true;
        }

        // 여기에 ApplicationInvite 전용 비즈니스 메서드를 추가합니다.
    }
}