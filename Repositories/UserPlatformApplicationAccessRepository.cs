using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;

namespace AuthHive.Auth.Repositories.PlatformApplication
{
    public class UserPlatformApplicationAccessRepository : BaseRepository<UserPlatformApplicationAccess>
    {
        public UserPlatformApplicationAccessRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }
    }
}