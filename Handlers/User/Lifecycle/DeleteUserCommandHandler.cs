using System;
using System.Linq; // [필수] Select 사용
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation; // [필수] 표준 Validator

// [Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserRepository 위치
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider

// [Models]
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Events.Lifecycle;

// [Exceptions]
using AuthHive.Core.Exceptions;

// [Alias]
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Handlers.User.Lifecycle;

/// <summary>
/// [v17] "사용자 삭제" 유스케이스 핸들러 (SOP 1-Write-E)
/// </summary>
public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, Unit>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IMediator _mediator;
    private readonly ILogger<DeleteUserCommandHandler> _logger;
    private readonly IDateTimeProvider _timeProvider;
    
    // [수정] 표준 Validator 사용
    private readonly IValidator<DeleteUserCommand> _validator;

    public DeleteUserCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IMediator mediator,
        ILogger<DeleteUserCommandHandler> logger,
        // [수정] 주입 타입 변경
        IValidator<DeleteUserCommand> validator,
        IDateTimeProvider timeProvider)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _mediator = mediator;
        _logger = logger;
        _validator = validator;
        _timeProvider = timeProvider;
    }

    public async Task<Unit> Handle(DeleteUserCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling DeleteUserCommand for User {UserId}", command.UserId);

        // 1. 유효성 검사 (형식 검증 등)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Validation failed", errorMessages);
        }

        // 2. 엔티티 조회
        UserEntity? userToDelete = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        
        if (userToDelete == null)
        {
            throw new KeyNotFoundException($"User not found: {command.UserId}");
        }
        
        // 3. 데이터베이스 저장 (Soft Delete)
        // [중요] Repository의 DeleteAsync는 실제 삭제가 아니라 Soft Delete 플래그 처리를 수행해야 함
        await _userRepository.DeleteAsync(userToDelete, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("User soft-deleted successfully: {UserId}", userToDelete.Id);

        // 4. 이벤트 발행
        var now = _timeProvider.UtcNow;

        var userDeletedEvent = new UserAccountDeletedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = userToDelete.Id,
            OccurredOn = now,
            TriggeredBy = command.TriggeredBy, // Guid
            OrganizationId = command.OrganizationId, // Optional

            UserId = userToDelete.Id,
            Email = userToDelete.Email,
            DeletedByConnectedId = command.TriggeredBy,
            DeletedAt = now,
            IsSoftDelete = true,
            DataRetained = true,
            Reason = "Account deletion request"
        };

        await _mediator.Publish(userDeletedEvent, cancellationToken);
        
        return Unit.Value;
    }
}