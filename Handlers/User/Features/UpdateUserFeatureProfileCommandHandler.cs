using System;
using System.Linq; // [필수] Select 사용
using System.Threading;
using System.Threading.Tasks;

using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation; // [필수] 표준 Validator

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Features;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.User.Commands.Settings;
using AuthHive.Core.Models.User.Events.Features;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Exceptions;

namespace AuthHive.Auth.Handlers.User.Features;

/// <summary>
/// [Auth] 사용자 기능 프로필(설정/선호도) 수정 핸들러 (v18 Final)
/// <para>
/// 📌 역할: 사용자의 FeaturePreferences(JSON) 및 BetaFeatures(JSON)를 업데이트합니다.
/// 📌 특징: 프로필이 없으면 생성(Lazy Creation)하며, 변경 사항이 있을 때만 이벤트를 발행합니다.
/// </para>
/// </summary>
public class UpdateUserFeatureProfileCommandHandler : IRequestHandler<UpdateUserFeatureProfileCommand, Unit>
{
    private readonly IUserFeatureProfileRepository _profileRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDateTimeProvider _timeProvider;
    private readonly IMediator _mediator;
    private readonly ILogger<UpdateUserFeatureProfileCommandHandler> _logger;
    
    // [수정] 표준 FluentValidation 인터페이스 사용
    private readonly IValidator<UpdateUserFeatureProfileCommand> _validator;

    public UpdateUserFeatureProfileCommandHandler(
        IUserFeatureProfileRepository profileRepository,
        // [수정] 주입 타입 변경
        IValidator<UpdateUserFeatureProfileCommand> validator,
        IUnitOfWork unitOfWork,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<UpdateUserFeatureProfileCommandHandler> logger)
    {
        _profileRepository = profileRepository;
        _validator = validator;
        _unitOfWork = unitOfWork;
        _timeProvider = timeProvider;
        _mediator = mediator;
        _logger = logger;
    }

    public async Task<Unit> Handle(UpdateUserFeatureProfileCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Updating Feature Profile for User {UserId}", command.UserId);

        // 1. 유효성 검사 (표준화)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            // [수정] 에러 메시지 리스트 추출하여 예외 처리
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Feature profile update validation failed.", errorMessages);
        }

        // 2. 프로필 조회 (없으면 생성 - Lazy Creation)
        var profile = await _profileRepository.GetByUserIdAsync(command.UserId, cancellationToken);
        if (profile == null)
        {
            profile = new UserFeatureProfile
            {
                UserId = command.UserId,
                CreatedAt = _timeProvider.UtcNow,
                // [Entity Mapping] 기본값 설정
                FeaturePreferences = "{}",
                BetaFeatures = "{}",
                RecommendationData = "{}",
                ProfileCompleteness = 0
            };
            await _profileRepository.AddAsync(profile, cancellationToken);
        }

        // 3. 변경 사항 적용 (Partial Update)
        bool isChanged = false;

        // [Entity Mapping] FeaturePreferences
        if (command.NewPreferencesJson != null && command.NewPreferencesJson != profile.FeaturePreferences)
        {
            profile.FeaturePreferences = command.NewPreferencesJson;
            isChanged = true;
        }

        // [Entity Mapping] BetaFeatures
        if (command.NewBetaFeaturesJson != null && command.NewBetaFeaturesJson != profile.BetaFeatures)
        {
            profile.BetaFeatures = command.NewBetaFeaturesJson;
            isChanged = true;
        }

        // 활동 시간 갱신
        profile.LastActivityAt = _timeProvider.UtcNow;
        profile.UpdatedAt = _timeProvider.UtcNow;

        // 4. 저장 및 이벤트 발행
        if (isChanged)
        {
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            var changedEvent = new FeatureSettingsChangedEvent
            {
                EventId = Guid.NewGuid(),
                AggregateId = command.UserId,
                OccurredOn = _timeProvider.UtcNow,
                TriggeredBy = command.TriggeredBy,
                OrganizationId = command.OrganizationId,
                CorrelationId = Guid.NewGuid().ToString(),
                
                // Event Props
                UserId = command.UserId,
                NewPreferencesJson = command.NewPreferencesJson,
                NewBetaFeaturesJson = command.NewBetaFeaturesJson,
                UpdatedAt = _timeProvider.UtcNow
            };

            await _mediator.Publish(changedEvent, cancellationToken);
            _logger.LogInformation("Feature Profile updated for User {UserId}", command.UserId);
        }
        else
        {
            // 변경 사항이 없어도 신규 생성된 경우 저장을 위해 호출
            await _unitOfWork.SaveChangesAsync(cancellationToken);
        }

        return Unit.Value;
    }
}