// [AuthHive.Auth] UpdateUserCommandHandler.cs
// v17 CQRS "본보기": 'User' 엔티티의 '일반 정보'를 수정하는 'UpdateUserCommand'를 처리합니다.
// [v17.2 수정] SRP 원칙에 따라 Status, 2FA 로직 제거

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Lifecycle; // UserUpdatedEvent
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
    /// [v17] "사용자 일반 정보 수정" 유스케이스 핸들러 (SOP 1-Write-C)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class UpdateUserCommandHandler : IRequestHandler<UpdateUserCommand, Unit>
    {
        private readonly IUserRepository _userRepository;
        // [v17 수정] 불필요한 UserProfileRepository 의존성 제거
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<UpdateUserCommandHandler> _logger;
        private readonly IUserValidator _userValidator;

        public UpdateUserCommandHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<UpdateUserCommandHandler> logger,
            IUserValidator userValidator)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
        }

        public async Task<Unit> Handle(UpdateUserCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling UpdateUserCommand for User {UserId}", command.UserId);

            // 1. 유효성 검사 (Validator로 책임 이관)
            // (v16 UserValidator.ValidateUpdateAsync 로직 이관 완료)
            var validationResult = await _userValidator.ValidateUpdateAsync(command);
            if (!validationResult.IsSuccess)
            {
                throw new ValidationException(validationResult.ErrorMessage ?? "User update validation failed.");
            }

            // 2. 엔티티 조회
            var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (user == null)
            {
                throw new KeyNotFoundException($"User not found: {command.UserId}");
            }

            // 3. 변경 사항 적용 (v16 UserService.UpdateAsync 로직 이관)
            var updatedFields = new List<string>();

            if (command.DisplayName != null && user.DisplayName != command.DisplayName)
            {
                user.DisplayName = command.DisplayName;
                updatedFields.Add(nameof(UserEntity.DisplayName));
            }

            if (command.Username != null && user.Username != command.Username)
            {
                user.Username = command.Username;
                updatedFields.Add(nameof(UserEntity.Username));
            }

            // [v17 수정] Status 변경 로직 "제거"
            /*
            if (command.Status.HasValue && user.Status != command.Status.Value)
            {
                user.Status = command.Status.Value;
                updatedFields.Add(nameof(UserEntity.Status));
            }
            */

            // [v17 수정] 2FA 변경 로직 "제거"
            /*
            if (command.IsTwoFactorEnabled.HasValue && user.IsTwoFactorEnabled != command.IsTwoFactorEnabled.Value)
            {
                user.IsTwoFactorEnabled = command.IsTwoFactorEnabled.Value;
                updatedFields.Add(nameof(UserEntity.IsTwoFactorEnabled));
            }
            */

            // 4. 데이터베이스 저장
            if (updatedFields.Any())
            {
                await _userRepository.UpdateAsync(user, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("User (General Info) updated successfully for {UserId}. Fields: {Fields}", user.Id, string.Join(", ", updatedFields));

                // 5. 이벤트 발행 (Notify) - 일반 업데이트 이벤트
                var userUpdatedEvent = new UserUpdatedEvent(
                    userId: user.Id,
                    updatedFields: updatedFields.ToArray(),
                    updatedByConnectedId: command.TriggeredBy ?? command.UserId, // 요청자 또는 본인
                    organizationId: command.OrganizationId, // BaseCommand에서 상속
                    correlationId: command.CorrelationId,
                    source: "UserCommandHandler" // v17 표준
                );
                await _mediator.Publish(userUpdatedEvent, cancellationToken);
            }
            else
            {
                _logger.LogInformation("No user (General Info) changes detected for {UserId}", command.UserId);
            }

            // 6. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }

        // [v17 수정] 불필요한 MapToDto 헬퍼 메서드 제거
    }
}