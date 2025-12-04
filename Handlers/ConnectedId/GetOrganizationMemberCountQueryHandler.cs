using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Auth.ConnectedId.Queries;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.ConnectedId.Queries
{
    /// <summary>
    /// [v18 Standard] 조직의 멤버(ConnectedId) 수 조회 핸들러
    /// 도메인: ConnectedId (Membership)
    /// 역할: 특정 조직에 연결된 활성 멤버의 수를 반환합니다.
    /// </summary>
    public class GetOrganizationMemberCountQueryHandler 
        : IRequestHandler<GetOrganizationMemberCountQuery, int>
    {
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly ILogger<GetOrganizationMemberCountQueryHandler> _logger;

        public GetOrganizationMemberCountQueryHandler(
            IConnectedIdRepository connectedIdRepository,
            ILogger<GetOrganizationMemberCountQueryHandler> logger)
        {
            _connectedIdRepository = connectedIdRepository;
            _logger = logger;
        }

        public async Task<int> Handle(GetOrganizationMemberCountQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Counting members for Org {OrganizationId}", query.OrganizationId);

            // [수정 완료] 
            // 아까 Repository에 구현한 메서드 이름인 'CountMembersByOrgIdAsync'로 호출해야 합니다.
            // 파라미터 순서: (Guid organizationId, bool isActiveOnly, CancellationToken cancellationToken)
            var count = await _connectedIdRepository.CountMembersByOrgIdAsync(
                query.OrganizationId,
                query.ActiveOnly, 
                cancellationToken
            );

            return count;
        }
    }
}