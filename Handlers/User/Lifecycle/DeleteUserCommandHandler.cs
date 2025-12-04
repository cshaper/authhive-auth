using System;
using System.Linq; // Select 사용
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core & Infra]
using AuthHive.Infra.Persistence.Context; // [v18] AuthDbContext 직접 사용
using AuthHive.Core.Exceptions;

// [Models]
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Events.Lifecycle;

namespace AuthHive.Core.Handlers.User.Lifecycle;

/// <summary>
/// [v18] "사용자 삭제" 유스케이스 핸들러
/// Repository를 제거하고 DbContext와 Entity 메서드를 통해 Soft Delete를 수행합니다.
/// </summary>
public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, Unit>
{
    private readonly AuthDbContext _context;          // [변경] Repository -> DbContext
    private readonly IValidator<DeleteUserCommand> _validator;
    private readonly IPublisher _publisher;           // [변경] IMediator -> IPublisher
    private readonly ILogger<DeleteUserCommandHandler> _logger;

    public DeleteUserCommandHandler(
        AuthDbContext context,
        IValidator<DeleteUserCommand> validator,
        IPublisher publisher,
        ILogger<DeleteUserCommandHandler> logger)
    {
        _context = context;
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

        // 2. 엔티티 조회 (DbContext 직접 사용)
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == command.UserId, cancellationToken);
        
        if (user == null)
        {
            throw new KeyNotFoundException($"User not found: {command.UserId}");
        }
        
        // 3. [Domain Logic] 상태 변경 (Soft Delete)
        // Repository에 숨겨져 있던 로직을 Entity 메서드 호출로 변경 (또는 속성 직접 변경)
        // 예: User Entity에 SoftDelete 메서드가 있다고 가정
        user.SoftDelete(deletedBy: command.TriggeredBy); 
        
        // 만약 Entity에 메서드가 없다면 아래와 같이 직접 설정:
        // user.IsDeleted = true;
        // user.DeletedAt = DateTime.UtcNow;
        // user.Status = UserStatus.Deleted; 

        // 4. [Persistence] 저장 (Change Tracking)
        await _context.SaveChangesAsync(cancellationToken);

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