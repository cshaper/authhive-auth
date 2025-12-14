// using AuthHive.Core.Models.User.Commands.Lifecycle;
// using AuthHive.Core.Models.User.Commands.Security;
// using AuthHive.Core.Models.User.Queries.Security;
// using AuthHive.Core.Models.User.Responses.Profile;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.Collections.Generic;
// using System.Threading;
// using System.Threading.Tasks;
// using AuthHive.Core.Exceptions;

// namespace AuthHive.Auth.Handlers.User.Security;

// /// <summary>
// /// [v18] "JIT 프로비저닝 (Get or Create)" 유스케이스 핸들러 (Orchestrator)
// /// 오케스트레이터는 Repository 대신 Mediator를 사용하여 다른 Command/Query를 호출합니다.
// /// </summary>
// public class GetOrCreateUserByExternalIdCommandHandler : IRequestHandler<GetOrCreateUserByExternalIdCommand, UserDetailResponse>
// {
//     private readonly IMediator _mediator; // 오케스트레이터 역할 유지
//     private readonly ILogger<GetOrCreateUserByExternalIdCommandHandler> _logger;

//     public GetOrCreateUserByExternalIdCommandHandler(
//         IMediator mediator,
//         ILogger<GetOrCreateUserByExternalIdCommandHandler> logger)
//     {
//         _mediator = mediator;
//         _logger = logger;
//     }

//     public async Task<UserDetailResponse> Handle(GetOrCreateUserByExternalIdCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation(
//             "Handling GetOrCreateUserByExternalIdCommand for {ExternalSystemType}:{ExternalUserId}",
//             command.ExternalSystemType, command.ExternalUserId);

//         UserDetailResponse? existingUser = null;

//         // 1. Get (읽기): 사용자가 이미 존재하는지 확인
//         // [수정] try-catch 대신 null 반환/체크 로직을 사용합니다.
//         try
//         {
//             var query = new GetUserByExternalIdQuery(command.ExternalSystemType, command.ExternalUserId);
//             // GetUserByExternalIdQueryHandler가 KeyNotFoundException 대신 null을 반환하도록 가정합니다.
//             existingUser = await _mediator.Send(query, cancellationToken);
//         }
//         catch (KeyNotFoundException ex)
//         {
//             // 만약 QueryHandler가 KeyNotFoundException을 던지도록 되어 있다면, 여기서만 잡아 처리합니다.
//             // (권장 사항: 쿼리 핸들러는 없으면 null을 반환하는 것이 더 깔끔합니다.)
//             _logger.LogDebug("Query execution failed with KeyNotFoundException. Proceeding to create. {Message}", ex.Message);
//         }
//         catch (Exception ex) when (ex is not KeyNotFoundException)
//         {
//              _logger.LogError(ex, "Unexpected error during user lookup for {ExternalUserId}", command.ExternalUserId);
//              throw; // 다른 예외는 던집니다.
//         }

//         if (existingUser != null)
//         {
//             // 1.1. User Found
//             _logger.LogInformation("User found (JIT not required): {UserId}", existingUser.Id);
//             return existingUser; 
//         }
//         else
//         {
//             // 2. Create (쓰기): 사용자가 없으므로 생성을 명령합니다.
//             _logger.LogInformation("User not found. Executing JIT Provisioning...");

//             var createCommand = new CreateUserCommand
//             {
//                 Email = command.Email,
//                 Password = null, // 소셜 로그인이므로 null
//                 Username = command.Username,
//                 DisplayName = command.DisplayName,
//                 ExternalUserId = command.ExternalUserId,
//                 ExternalSystemType = command.ExternalSystemType,

//                 // Audit Context 매핑
//                 TriggeredBy = command.TriggeredBy, 
//                 OrganizationId = command.OrganizationId,
//                 CorrelationId = command.CorrelationId
//             };

//             // CreateUserCommand의 응답 DTO도 UserDetailResponse라고 가정합니다.
//             var newUserDetail = await _mediator.Send(createCommand, cancellationToken);

//             _logger.LogInformation("JIT Provisioning successful. New User created: {UserId}", newUserDetail.Id);
//             return newUserDetail; 
//         }
//     }
// }