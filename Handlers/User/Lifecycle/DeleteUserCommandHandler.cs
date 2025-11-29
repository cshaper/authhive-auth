using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Events.Lifecycle;
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

// [Fix CS0118] Entity 별칭
using UserEntity = AuthHive.Core.Entities.User.User;

// [Fix CS0436] Interface 충돌 방지를 위한 명시적 별칭 (Core의 인터페이스 강제 사용)
using ICoreUserValidator = AuthHive.Core.Interfaces.User.Validators.IUserValidator;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Handlers.User.Lifecycle
{
    /// <summary>
    /// [v17] "사용자 삭제" 유스케이스 핸들러 (SOP 1-Write-E)
    /// </summary>
    public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, Unit>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<DeleteUserCommandHandler> _logger;
        private readonly ICoreUserValidator _userValidator; // [Fix] 별칭 사용
        private readonly IDateTimeProvider _timeProvider;

        public DeleteUserCommandHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<DeleteUserCommandHandler> logger,
            ICoreUserValidator userValidator, // [Fix] 별칭 사용
            IDateTimeProvider timeProvider)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
            _timeProvider = timeProvider;
        }

        public async Task<Unit> Handle(DeleteUserCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling DeleteUserCommand for User {UserId}", command.UserId);

            // 1. 엔티티 조회
            // [Fix CS8600] Nullable(?) 타입으로 받아야 함
            UserEntity? userToDelete = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
            
            if (userToDelete == null)
            {
                throw new KeyNotFoundException($"User not found: {command.UserId}");
            }
            
            // 2. 유효성 검사
            var validationResult = await _userValidator.ValidateDeleteAsync(userToDelete, cancellationToken);
            if (!validationResult.IsValid)
            {
                // [Fix CS1061] Errors는 List<string>이므로 요소 자체가 메시지임 (.Message 속성 없음)
                var errorMessage = validationResult.Errors.First();
                throw new ValidationException(errorMessage);
            }
            
            // 3. 데이터베이스 저장 (Soft Delete)
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
                TriggeredBy = command.TriggeredBy,
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
}