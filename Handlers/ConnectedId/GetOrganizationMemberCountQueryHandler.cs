// using AuthHive.Core.Interfaces.Auth.ConnectedId;
// using AuthHive.Core.Interfaces.Auth.Repositories; // [중요] Query Repository가 있는 네임스페이스
// using AuthHive.Core.Models.Auth.ConnectedId.Queries;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System.Threading;
// using System.Threading.Tasks;

// namespace AuthHive.Auth.Handlers.ConnectedId.Queries
// {
//     /// <summary>
//     /// [v18 Standard] 조직의 멤버(ConnectedId) 수 조회 핸들러
//     /// 도메인: ConnectedId (Membership)
//     /// 역할: 특정 조직에 연결된 활성 멤버의 수를 반환합니다.
//     /// </summary>
//     public class GetOrganizationMemberCountQueryHandler 
//         : IRequestHandler<GetOrganizationMemberCountQuery, int>
//     {
//         // [변경] Query 전용 리포지토리 주입
//         private readonly IConnectedIdQueryRepository _connectedIdQueryRepository;
//         private readonly ILogger<GetOrganizationMemberCountQueryHandler> _logger;

//         public GetOrganizationMemberCountQueryHandler(
//             IConnectedIdQueryRepository connectedIdQueryRepository, // 생성자 주입 변경
//             ILogger<GetOrganizationMemberCountQueryHandler> logger)
//         {
//             _connectedIdQueryRepository = connectedIdQueryRepository;
//             _logger = logger;
//         }

//         public async Task<int> Handle(GetOrganizationMemberCountQuery query, CancellationToken cancellationToken)
//         {
//             _logger.LogInformation("Counting members for Org {OrganizationId}", query.OrganizationId);

//             // [호출] Query Repository의 메서드 사용
//             // (IConnectedIdQueryRepository에 CountMembersByOrgIdAsync 메서드가 정의되어 있어야 합니다)
//             var count = await _connectedIdQueryRepository.CountMembersByOrgIdAsync(
//                 query.OrganizationId,
//                 query.ActiveOnly, 
//                 cancellationToken
//             );

//             return count;
//         }
//     }
// }