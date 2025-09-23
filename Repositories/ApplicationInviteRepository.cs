using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories.PlatformApplication
{
    public class ApplicationInviteRepository : BaseRepository<ApplicationInvite>
    {
        public ApplicationInviteRepository(
            AuthDbContext context, 
            IOrganizationContext organizationContext, 
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }
    }
}