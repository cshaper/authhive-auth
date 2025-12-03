using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Commands.Security;
using AuthHive.Core.Models.User.Queries.Security;
using AuthHive.Core.Models.User.Responses.Profile;
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic; // KeyNotFoundException
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Exceptions;

namespace AuthHive.Auth.Handlers.User.Security; // Namespace 변경

/// <summary>
/// [v18] "JIT 프로비저닝 (Get or Create)" 유스케이스 핸들러 (Orchestrator)
/// </summary>
public class GetOrCreateUserByExternalIdCommandHandler : IRequestHandler<GetOrCreateUserByExternalIdCommand, UserDetailResponse>
{
    private readonly IMediator _mediator;
    private readonly ILogger<GetOrCreateUserByExternalIdCommandHandler> _logger;

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

        // 1. Get (읽기): 사용자가 이미 존재하는지 확인
        try
        {
            // [Fix] GetUserByExternalIdQuery의 반환 타입이 UserDetailResponse라고 가정
            var query = new GetUserByExternalIdQuery(command.ExternalSystemType, command.ExternalUserId);
            var existingUser = await _mediator.Send(query, cancellationToken);

            // 🚨 [Fix CS8602] GetUserByExternalIdQueryHandler가 KeyNotFoundException 대신 null을 반환할 경우 대비
            if (existingUser == null)
            {
                throw new KeyNotFoundException("User not found by external ID.");
            }

            _logger.LogInformation("User found (JIT not required): {UserId}", existingUser.Id);
            return existingUser; // UserDetailResponse 반환
        }
        catch (KeyNotFoundException)
        {
            // 2. Create (쓰기): 사용자가 없으므로 생성을 명령합니다.
            _logger.LogInformation("User not found. Executing JIT Provisioning...");

            // [Fix CS1739] Positional -> Object Initializer ({}) 방식으로 변경
            var createCommand = new CreateUserCommand
            {
                // ✅ 이름 기반으로 깔끔하게 매핑
                Email = command.Email,
                Password = null, // 소셜 로그인이므로 null
                Username = command.Username,
                DisplayName = command.DisplayName,
                ExternalUserId = command.ExternalUserId,
                ExternalSystemType = command.ExternalSystemType,

                // Audit Context 매핑
                TriggeredBy = command.TriggeredBy, // JIT 핸들러에서 채워짐
                OrganizationId = command.OrganizationId,
                CorrelationId = command.CorrelationId
            };

            // 🚨 [Fix CS0266] CreateUserCommand의 응답 DTO도 UserDetailResponse라고 가정
            var newUserDetail = await _mediator.Send(createCommand, cancellationToken);

            _logger.LogInformation("JIT Provisioning successful. New User created: {UserId}", newUserDetail.Id);
            return newUserDetail; // UserDetailResponse 반환
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during GetOrCreateUserByExternalId flow for {Email}", command.Email);
            throw;
        }
    }
}