using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.User.Repositories.Profile; 
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.User.Commands.Settings;
using AuthHive.Core.Models.User.Events.Settings;
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Exceptions;
using System.Collections.Generic; // KeyNotFoundException용
using UserProfileEntity = AuthHive.Core.Entities.User.UserProfile;
using FluentValidation; // UserProfile Entity

namespace AuthHive.Auth.Handlers.User.Settings;

/// <summary>
/// [v18] "타임존 변경" 유스케이스 핸들러
/// </summary>
public class ChangeTimeZoneCommandHandler : IRequestHandler<ChangeTimeZoneCommand, Unit>
{
    private readonly IUserProfileRepository _profileRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ILogger<ChangeTimeZoneCommandHandler> _logger;
    private readonly IValidator<ChangeTimeZoneCommand> _validator;

    public ChangeTimeZoneCommandHandler(
        IUserProfileRepository profileRepository,
        IUnitOfWork unitOfWork,
        IValidator<ChangeTimeZoneCommand> validator,
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ILogger<ChangeTimeZoneCommandHandler> logger)
    {
        _profileRepository = profileRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _mediator = mediator;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<Unit> Handle(ChangeTimeZoneCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling ChangeTimeZoneCommand for User {UserId}: NewTimeZone={NewTimeZone}", 
            command.UserId, command.NewTimeZone);

        // 1. 유효성 검사 (FluentValidation 표준 메서드 사용)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);

        if (!validationResult.IsValid)
        {
            // [수정] ValidationFailure 객체 리스트를 string 컬렉션으로 변환 (CS1503 해결)
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);

            throw new DomainValidationException("Validation failed.", errorMessages);
        }

        // 2. UserProfile 엔티티 조회
        // UserProfile은 UserId와 PK가 동일하므로 GetByIdAsync를 사용하거나 GetByUserIdAsync를 사용 (여기서는 GetByUserIdAsync가 명확)
        var profile = await _profileRepository.GetByUserIdAsync(command.UserId, cancellationToken);
        if (profile == null)
        {
            throw new KeyNotFoundException($"UserProfile not found for user: {command.UserId}");
        }

        var oldTimeZone = profile.TimeZone;
        
        if (oldTimeZone == command.NewTimeZone)
        {
            _logger.LogInformation("TimeZone is already {NewTimeZone}. Skipping.", command.NewTimeZone);
            return Unit.Value;
        }

        // 3. 변경 사항 적용 (DDD - Entity Logic)
        // [Fix CS1061] UpdateDetails 메서드 호출
        profile.UpdateDetails(
            bio: profile.Bio, // 기존 값 유지
            location: profile.Location,
            imageUrl: profile.ProfileImageUrl,
            language: profile.PreferredLanguage,
            timeZone: command.NewTimeZone, // 변경 값
            websiteUrl: profile.WebsiteUrl
        );

        // 4. 데이터베이스 저장
        await _profileRepository.UpdateAsync(profile, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. 이벤트 발행 (Notify)
        // [Fix CS1739] Object Initializer 사용
        var timeZoneChangedEvent = new TimeZoneChangedEvent
        {
            // BaseEvent Props
            EventId = Guid.NewGuid(),
            AggregateId = profile.UserId,
            OccurredOn = _timeProvider.UtcNow,
            // [Fix CS1061] Command에서 Audit 필드 매핑
            TriggeredBy = command.TriggeredBy, 
            OrganizationId = command.OrganizationId, 
            IpAddress = command.IpAddress, 

            // Event Props
            UserId = profile.UserId,
            OldTimeZone = oldTimeZone,
            NewTimeZone = profile.TimeZone, // 엔티티에 반영된 최신 값
            ChangedAt = _timeProvider.UtcNow
        };
        
        await _mediator.Publish(timeZoneChangedEvent, cancellationToken);
        
        _logger.LogInformation("TimeZone changed successfully for User {UserId}: {Old} -> {New}", 
            command.UserId, oldTimeZone, profile.TimeZone);
        
        return Unit.Value;
    }
}