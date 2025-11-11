// [AuthHive.Auth] GetUserCountByOrganizationQueryHandler.cs
// v17 CQRS "본보기": 'GetUserCountByOrganizationQuery'를 처리하여 조직의 사용자 수를 조회합니다.
// v16 UserService.CountAsync 로직을 이관합니다.

using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.User.Queries;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "조직별 사용자 수 조회" 유스케이스 핸들러 (SOP 1-Read-Q)
    /// </summary>
    public class GetUserCountByOrganizationQueryHandler : IRequestHandler<GetUserCountByOrganizationQuery, int>
    {
        private readonly IUserRepository _userRepository;
        private readonly ILogger<GetUserCountByOrganizationQueryHandler> _logger;

        public GetUserCountByOrganizationQueryHandler(
            IUserRepository userRepository,
            ILogger<GetUserCountByOrganizationQueryHandler> logger)
        {
            _userRepository = userRepository;
            _logger = logger;
        }

        public async Task<int> Handle(GetUserCountByOrganizationQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling GetUserCountByOrganizationQuery for Org {OrganizationId}", query.OrganizationId);

            // 1. Repository 호출 (v16 로직 이관)
            // [v17 로직 수정] v16 IUserRepository의 CountUsersInOrganizationAsync 사용
            var count = await _userRepository.CountUsersInOrganizationAsync(
                query.OrganizationId,
                query.ActiveOnly,
                cancellationToken
            );

            // 2. 응답 DTO 반환
            return count;
        }
    }
}