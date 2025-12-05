using System;
using System.Linq; 
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core Interfaces]
// ✅ Infra(DbContext) 제거 -> Repository Interface 추가
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; 
using AuthHive.Core.Exceptions;

// [Models]
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Events.Lifecycle;

namespace AuthHive.Core.Handlers.User.Lifecycle;

/// <summary>
/// [v18] "사용자 삭제" 유스케이스 핸들러 (Refactored)
/// Repository 패턴을 적용하여 Soft Delete를 수행합니다.
/// </summary>
public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, Unit>
{
    // ❌ private readonly AuthDbContext _context;
    private readonly IUserRepository _repository; // ✅ Lifecycle은 IUserRepository 담당
    private readonly IValidator<DeleteUserCommand> _validator;
    private readonly IPublisher _publisher;
    private readonly ILogger<DeleteUserCommandHandler> _logger;

    public DeleteUserCommandHandler(
        IUserRepository repository, // ✅ 생성자 주입 변경
        IValidator<DeleteUserCommand> validator,
        IPublisher publisher,
        ILogger<DeleteUserCommandHandler> logger)
    {
        _repository = repository;
        _validator = validator;
        _publisher = publisher;
        _logger = logger;
    }

    public async Task<Unit> Handle(DeleteUserCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling DeleteUserCommand for User {UserId}", command.UserId);

        // 1. 유효성 검사
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Validation failed", errorMessages);
        }

        // 2. 엔티티 조회 (Repository 사용)
        // ✅ _context.Users.FirstOrDefaultAsync(...) 대체
        // BaseRepository에 보통 GetByIdAsync가 있으므로 그것을 사용합니다.
        var user = await _repository.GetByIdAsync(command.UserId, cancellationToken);
        
        if (user == null)
        {
            throw new KeyNotFoundException($"User not found: {command.UserId}");
        }
        
        // 3. [Domain Logic] 상태 변경 (Soft Delete)
        // User Entity 내부의 비즈니스 로직 호출
        user.SoftDelete(deletedBy: command.TriggeredBy); 

        // 4. [Persistence] 저장 (Repository Update)
        // ✅ Soft Delete는 DB 행을 지우는게 아니라 상태를 업데이트하는 것이므로 UpdateAsync 호출
        await _repository.UpdateAsync(user, cancellationToken);

        _logger.LogInformation("User soft-deleted successfully: {UserId}", user.Id);

        // 5. 이벤트 발행
        var now = DateTime.UtcNow;

        var userDeletedEvent = new UserAccountDeletedEvent
        {
            // BaseEvent Required
            AggregateId = user.Id,
            OccurredOn = now,
            
            // Context
            EventId = Guid.NewGuid(),
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,

            // Payload
            UserId = user.Id,
            Email = user.Email,
            DeletedByConnectedId = command.TriggeredBy,
            DeletedAt = now,
            IsSoftDelete = true,
            DataRetained = true,
            Reason = "Account deletion request"
        };

        await _publisher.Publish(userDeletedEvent, cancellationToken);
        
        return Unit.Value;
    }
}