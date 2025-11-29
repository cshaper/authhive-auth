using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

// [Interfaces]
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IValidator, IDateTimeProvider
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Events; // UserProfileUpdatedEvent

// [Exceptions]
using AuthHive.Core.Exceptions;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Handlers.User;

/// <summary>
/// [Identity Core] 사용자 프로필 수정 핸들러
/// </summary>
public class UpdateUserProfileCommandHandler : IRequestHandler<UpdateUserProfileCommand, UserProfileResponse>
{
    private readonly IUserProfileRepository _profileRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IValidator<UpdateUserProfileCommand> _validator;
    private readonly ICacheService _cacheService;
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ILogger<UpdateUserProfileCommandHandler> _logger;

    public UpdateUserProfileCommandHandler(
        IUserProfileRepository profileRepository,
        IUnitOfWork unitOfWork,
        IValidator<UpdateUserProfileCommand> validator,
        ICacheService cacheService,
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ILogger<UpdateUserProfileCommandHandler> logger)
    {
        _profileRepository = profileRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _cacheService = cacheService;
        _mediator = mediator;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<UserProfileResponse> Handle(UpdateUserProfileCommand command, CancellationToken cancellationToken)
    {
        // 1. [Validation] 유효성 검사 (Validator 위임)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException("Profile update failed.", validationResult.Errors);
        }

        // 2. [Load] 엔티티 조회 (없으면 예외)
        // UserProfile은 UserId와 1:1 관계이므로 UserId로 조회
        var profile = await _profileRepository.GetByUserIdAsync(command.UserId, cancellationToken);
        if (profile == null)
        {
            throw new DomainEntityNotFoundException("UserProfile", command.UserId);
        }

        // 3. [Domain Logic] 엔티티 수정 (DDD 메서드 호출)
        // Setter를 직접 쓰지 않고 의미 있는 메서드를 통해 변경
        profile.UpdateDetails(
            command.Bio, 
            command.Location, 
            command.ProfileImageUrl, 
            command.PreferredLanguage, 
            command.TimeZone,
            command.WebsiteUrl
        );

        // 4. [Persistence] 저장 및 커밋
        await _profileRepository.UpdateAsync(profile, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. [Event] 도메인 이벤트 발행 (Object Initializer 사용)
        var updatedEvent = new UserProfileUpdatedEvent
        {
            // BaseEvent 속성
            AggregateId = command.UserId,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = null, // 필요 시 PrincipalAccessor에서 주입

            // Event 속성
            UserId = command.UserId,
            UpdatedAt = profile.UpdatedAt ?? _timeProvider.UtcNow
        };

        await _mediator.Publish(updatedEvent, cancellationToken);

        // 6. [Cache] 캐시 무효화 (Cache Invalidation)
        // GetUserProfileQueryHandler가 사용하는 캐시 키를 정확히 제거
        string cacheKey = $"UserProfileResponse:{command.UserId}";
        await _cacheService.RemoveAsync(cacheKey, cancellationToken);

        _logger.LogInformation("UserProfile updated successfully. UserId: {UserId}", command.UserId);

        // 7. [Response] 응답 반환
        return new UserProfileResponse(
            profile.UserId,
            profile.Bio,
            profile.Location,
            profile.ProfileImageUrl,
            profile.PreferredLanguage,
            profile.TimeZone,
            profile.WebsiteUrl,
            0, // CompletionPercentage (계산 로직이 있다면 profile.CompletionPercentage)
            profile.UpdatedAt
        );
    }
}