// [AuthHive.Auth] ChangeTwoFactorCommandHandler.cs
// v17 CQRS "본보기": 'User'의 2FA 설정을 변경하는 'ChangeTwoFactorCommand'를 처리합니다.
// (SOP 1-Write-Q, v16의 UpdateUserCommand에서 분리됨)

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Settings; // TwoFactorSettingChangedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Models.User.Events.Profile; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "2단계 인증 변경" 유스케이스 핸들러 (SOP 1-Write-Q)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class ChangeTwoFactorCommandHandler : IRequestHandler<ChangeTwoFactorCommand, Unit>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<ChangeTwoFactorCommandHandler> _logger;
        private readonly IUserValidator _userValidator;

        public ChangeTwoFactorCommandHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<ChangeTwoFactorCommandHandler> logger,
            IUserValidator userValidator)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
        }

        public async Task<Unit> Handle(ChangeTwoFactorCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling ChangeTwoFactorCommand for User {UserId}: Enabled={IsEnabled}, Type={Type}", 
                command.UserId, command.IsEnabled, command.TwoFactorType);

            // 1. 유효성 검사 (Validator로 책임 이관)
            var validationResult = await _userValidator.ValidateTwoFactorChangeAsync(command);
            if (!validationResult.IsSuccess)
            {
                throw new ValidationException(validationResult.ErrorMessage ?? "2FA setting validation failed.");
            }

            // 2. 엔티티 조회
            var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (user == null)
            {
                throw new KeyNotFoundException($"User not found: {command.UserId}");
            }

            // 3. 변경 사항 적용
            string currentType = user.TwoFactorMethod ?? "None";
            if (user.IsTwoFactorEnabled == command.IsEnabled && currentType == command.TwoFactorType)
            {
                _logger.LogInformation("2FA setting is already same for User {UserId}. Skipping.", command.UserId);
                return Unit.Value; // 멱등성(Idempotency)
            }

            // [v17 정합성] Command 데이터를 v16 엔티티 필드에 매핑
            user.IsTwoFactorEnabled = command.IsEnabled;
            user.TwoFactorMethod = command.IsEnabled ? command.TwoFactorType : null; // 비활성화 시 Type도 null로
            user.TwoFactorEnabledAt = command.IsEnabled ? DateTime.UtcNow : null; // v16 엔티티 필드

            // 4. 데이터베이스 저장 (Update)
            await _userRepository.UpdateAsync(user, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("2FA settings changed successfully for User {UserId}", command.UserId);

            // 5. 이벤트 발행 (Notify)
            var twoFactorChangedEvent = new TwoFactorSettingChangedEvent(
                userId: user.Id,
                enabled: user.IsTwoFactorEnabled,
                twoFactorType: command.TwoFactorType,
                changedByConnectedId: command.TriggeredBy, // 요청자
                organizationId: command.OrganizationId, // BaseCommand에서 상속 (작업 컨텍스트)
                backupCodes: null, // (별도 Command가 담당)
                correlationId: command.CorrelationId,
                ipAddress: command.IpAddress,
                source: "UserCommandHandler" // v17 표준
            );
            await _mediator.Publish(twoFactorChangedEvent, cancellationToken);
            
            // 6. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }
    }
}