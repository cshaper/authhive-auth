// [AuthHive.Auth] GetOrCreateUserByExternalIdCommandHandler.cs
// v17 CQRS "본보기": JIT 프로비저닝(소셜 로그인)을 위한 'GetOrCreate' Command를 처리합니다.
// v17 철학: 이 핸들러는 '읽기' 핸들러와 '쓰기' 핸들러를 '조립'합니다.

using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Queries; // GetUserByExternalIdQuery
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic; // KeyNotFoundException
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "JIT 프로비저닝 (Get or Create)" 유스케이스 핸들러 (SOP 1-Write-N)
    /// v16 UserService.CreateOrGetByExternalAsync 로직을 이관합니다.
    /// '읽기' 핸들러를 호출하고, 실패 시 '쓰기' 핸들러를 호출합니다.
    /// </summary>
    public class GetOrCreateUserByExternalIdCommandHandler : IRequestHandler<GetOrCreateUserByExternalIdCommand, UserDetailResponse>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<GetOrCreateUserByExternalIdCommandHandler> _logger;

        // [v17 철학] 이 핸들러는 Repository나 Validator가 필요 없습니다.
        // 오직 다른 핸들러를 호출하는 IMediator만 필요합니다.
        public GetOrCreateUserByExternalIdCommandHandler(
            IMediator mediator,
            ILogger<GetOrCreateUserByExternalIdCommandHandler> logger)
        {
            _mediator = mediator;
            _logger = logger;
        }

        public async Task<UserDetailResponse> Handle(GetOrCreateUserByExternalIdCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation(
                "Handling GetOrCreateUserByExternalIdCommand for {ExternalSystemType}:{ExternalUserId}",
                command.ExternalSystemType, command.ExternalUserId);

            // 1. Get (읽기): 사용자가 이미 존재하는지 '읽기' 핸들러에게 물어봅니다.
            try
            {
                var query = new GetUserByExternalIdQuery(command.ExternalSystemType, command.ExternalUserId);
                var existingUser = await _mediator.Send(query, cancellationToken);
                
                // [v17 로직] 사용자를 찾음 (JIT 아님)
                _logger.LogInformation("User found (JIT not required): {UserId}", existingUser.Id);
                return existingUser;
            }
            catch (KeyNotFoundException)
            {
                // [v17 로직] 사용자를 못 찾음 (JIT 프로비저닝 필요)
                _logger.LogInformation("User not found for {ExternalSystemType}. Executing JIT Provisioning...", command.ExternalSystemType);

                // 2. Create (쓰기): 사용자가 없으므로 '쓰기' 핸들러에게 생성을 명령합니다.
                // (v16 UserService.CreateOrGetByExternalAsync 로직 이관)
                var createCommand = new CreateUserCommand(
                    email: command.Email,
                    password: null, // [v17 정합성] 소셜 로그인은 비밀번호가 없음
                    username: command.Username,
                    displayName: command.DisplayName,
                    externalUserId: command.ExternalUserId,
                    externalSystemType: command.ExternalSystemType
                );
                
                // [v17 철학] 생성 로직은 CreateUserCommandHandler가 100% 담당
                var newUser = await _mediator.Send(createCommand, cancellationToken);
                
                _logger.LogInformation("JIT Provisioning successful. New User created: {UserId}", newUser.Id);
                return newUser;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during GetOrCreateUserByExternalId flow for {Email}", command.Email);
                throw; // 예측하지 못한 오류
            }
        }
    }
}