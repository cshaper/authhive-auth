using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserRepository
using AuthHive.Core.Models.User.Commands.Security;
using AuthHive.Core.Models.User.Events.Settings; // TwoFactorSettingChangedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using AuthHive.Core.Exceptions;
using AuthHive.Core.Interfaces.Infra; 
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Models.User.Events.Profile;
using FluentValidation; // Event DTO 참조용 (필요 시)

namespace AuthHive.Auth.Handlers.User.Security;

/// <summary>
/// [v18] "2단계 인증 변경" 유스케이스 핸들러
/// </summary>
public class ChangeTwoFactorCommandHandler : IRequestHandler<ChangeTwoFactorCommand, Unit>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IMediator _mediator;
    private readonly ILogger<ChangeTwoFactorCommandHandler> _logger;
    private readonly IDateTimeProvider _timeProvider;
    private readonly IValidator<ChangeTwoFactorCommand> _validator;
    public ChangeTwoFactorCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IMediator mediator,
        ILogger<ChangeTwoFactorCommandHandler> logger,
        IDateTimeProvider timeProvider,
        IValidator<ChangeTwoFactorCommand> validator)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _mediator = mediator;
        _logger = logger;
        _timeProvider = timeProvider;
        _validator = validator;
    }

    public async Task<Unit> Handle(ChangeTwoFactorCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling ChangeTwoFactorCommand for User {UserId}: Enabled={IsEnabled}, Type={Type}", 
            command.UserId, command.IsEnabled, command.TwoFactorMethod);

        // 1. 유효성 검사 (FluentValidation 표준 메서드 사용)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            // [수정] ValidationFailure 객체 리스트를 string 컬렉션으로 변환 (CS1503 해결)
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            
            throw new DomainValidationException("Validation failed.", errorMessages);
        }

        // 2. 엔티티 조회
        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null)
        {
            throw new KeyNotFoundException($"User not found: {command.UserId}");
        }

        // 3. 변경 사항 적용 (DDD 메서드 호출)
        // [Fix CS0272] 직접 대입 코드 제거 및 SetTwoFactorStatus() 호출로 대체
        user.SetTwoFactorStatus(command.IsEnabled, command.TwoFactorMethod);

        // 4. 데이터베이스 저장 (Update)
        await _userRepository.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("2FA settings changed successfully for User {UserId}", command.UserId);

        // 5. 이벤트 발행 (Notify)
        var twoFactorChangedEvent = new TwoFactorSettingChangedEvent
        {
            // BaseEvent Props
            EventId = Guid.NewGuid(),
            AggregateId = user.Id,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = command.TriggeredBy, 
            OrganizationId = command.OrganizationId, 
            CorrelationId = command.CorrelationId?.ToString(), 

            // Event Props
            UserId = user.Id,
            IsEnabled = user.IsTwoFactorEnabled,
            Method = user.TwoFactorMethod!, // Fix: SetTwoFactorStatus가 값을 설정했으므로 사용 가능
            ChangedAt = _timeProvider.UtcNow
        };
        
        await _mediator.Publish(twoFactorChangedEvent, cancellationToken);
        
        return Unit.Value;
    }
}