// [AuthHive.Auth] DeleteUserCommandHandler.cs
// v17 CQRS "본보기": 'User' 엔티티를 삭제(Soft Delete)하는 'DeleteUserCommand'를 처리합니다.
// v17 철학에 따라 '쓰기' 핸들러는 데이터를 반환하지 않습니다 (IRequest<Unit>).

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Lifecycle; // UserAccountDeletedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "사용자 삭제" 유스케이스 핸들러 (SOP 1-Write-E)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, Unit>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<DeleteUserCommandHandler> _logger;
        private readonly IUserValidator _userValidator;

        public DeleteUserCommandHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<DeleteUserCommandHandler> logger,
            IUserValidator userValidator)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
        }

        public async Task<Unit> Handle(DeleteUserCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling DeleteUserCommand for User {UserId}", command.UserId);

            // 1. 엔티티 조회 (v16 UserService 로직)
            //    Validator와 Event 발행 모두에 User 엔티티가 필요함
            var userToDelete = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (userToDelete == null)
            {
                throw new KeyNotFoundException($"User not found: {command.UserId}");
            }
            
            // 2. 유효성 검사 (Validator로 책임 이관)
            //    v16 UserValidator.ValidateDeleteAsync(UserEntity entity) 로직 호출
            var validationResult = await _userValidator.ValidateDeleteAsync(userToDelete);
            if (!validationResult.IsValid)
            {
                // Validator가 반환한 첫 번째 오류를 예외로 변환
                var error = validationResult.Errors.First();
                throw new ValidationException(error.Message);
            }
            
            // [v17 수정] v16 UserService의 '조직 검사' 로직(IsUserInOrganizationAsync)은 v17 철학에 따라 제거

            // 3. 데이터베이스 저장 (Soft Delete)
            // (v16 UserService.DeleteAsync 로직 이관)
            await _userRepository.SoftDeleteAsync(userToDelete.Id, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("User soft-deleted successfully: {UserId}", userToDelete.Id);

            // 4. 이벤트 발행 (v17 본보기: 캐시/감사 로직 제외)
            var userDeletedEvent = new UserAccountDeletedEvent(
                userId: userToDelete.Id,
                email: userToDelete.Email,
                deletedByConnectedId: command.TriggeredBy, // 요청자
                organizationId: command.OrganizationId, // BaseCommand에서 상속 (삭제 컨텍스트)
                isSoftDelete: true, // SoftDeleteAsync를 호출했음
                dataRetained: true, // Soft Delete는 데이터 보존
                deletionReason: "Account deletion request", // (추후 Command에 추가 가능)
                correlationId: command.CorrelationId,
                source: "UserCommandHandler" // v17 표준
            );
            await _mediator.Publish(userDeletedEvent, cancellationToken);
            
            // 5. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }
    }
}