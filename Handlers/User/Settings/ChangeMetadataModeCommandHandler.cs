using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.User.Validators;
using AuthHive.Core.Interfaces.Infra;

// [Models & Entities]
using AuthHive.Core.Models.User.Commands.Settings;
using AuthHive.Core.Models.User.Events.Settings;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Exceptions;
using static AuthHive.Core.Enums.Core.UserEnums; // UserMetadataMode 포함

namespace AuthHive.Auth.Handlers.User.Settings;

/// <summary>
/// [v18] "메타데이터 수집 모드 변경" 유스케이스 핸들러
/// </summary>
public class ChangeMetadataModeCommandHandler : IRequestHandler<ChangeMetadataModeCommand, Unit>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IUserValidator _validator;
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ILogger<ChangeMetadataModeCommandHandler> _logger;

    public ChangeMetadataModeCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IUserValidator validator,
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ILogger<ChangeMetadataModeCommandHandler> logger)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _mediator = mediator;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<Unit> Handle(ChangeMetadataModeCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling ChangeMetadataModeCommand for User {UserId}: NewMode={NewMode}",
            command.UserId, command.NewMode);

        // 1. 유효성 검사
        var validationResult = await _validator.ValidateChangeMetadataModeAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException(validationResult.Errors.First());
        }

        // 2. 엔티티 조회
        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null)
        {
            throw new KeyNotFoundException($"User not found: {command.UserId}");
        }

        // 3. 멱등성 및 상태 변경 (DDD - Entity Logic)
        var oldMode = user.MetadataMode; // [Fix CS1061] 이제 User 엔티티에 MetadataMode가 있습니다.

        if (oldMode == command.NewMode)
        {
            _logger.LogInformation("Metadata mode is already {NewMode}. Skipping.", command.NewMode);
            return Unit.Value;
        }

        user.SetMetadataMode(command.NewMode); // [Fix] DDD 메서드 호출

        // 4. 데이터베이스 저장
        await _userRepository.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. 이벤트 발행 (Notify)
        var modeChangedEvent = new MetadataModeChangedEvent
        {
            AggregateId = user.Id,
            OccurredOn = _timeProvider.UtcNow,

            // [Fix CS1061] Command에서 Audit 필드 매핑
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,

            UserId = user.Id,
            OldMode = oldMode,
            NewMode = user.MetadataMode,
            ChangedAt = _timeProvider.UtcNow,
            ChangedByConnectedId = command.TriggeredBy // [Fix CS9035]
        };


        await _mediator.Publish(modeChangedEvent, cancellationToken);

        _logger.LogInformation("Metadata mode changed successfully for User {UserId}: {OldMode} -> {NewMode}",
            command.UserId, oldMode, user.MetadataMode);

        return Unit.Value;
    }
}