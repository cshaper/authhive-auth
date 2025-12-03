using System;
using System.Linq; // [필수] Select 사용을 위해 추가
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation; // [필수] 표준 Validator 인터페이스

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories.Features;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.User.Commands.Features;
using AuthHive.Core.Models.User.Events.Features;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Exceptions;

namespace AuthHive.Auth.Handlers.User.Features;

/// <summary>
/// [Auth] 사용자 애드온 활성화 핸들러 (v18 Final - 1:1 JSON 방식)
/// </summary>
public class ActivateAddonCommandHandler : IRequestHandler<ActivateAddonCommand, Unit>
{
    private readonly IUserFeatureProfileRepository _featureRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDateTimeProvider _timeProvider;
    private readonly IMediator _mediator;
    private readonly ILogger<ActivateAddonCommandHandler> _logger;
    
    // [수정] 표준 FluentValidation 인터페이스 사용
    private readonly IValidator<ActivateAddonCommand> _validator;

    public ActivateAddonCommandHandler(
        IUserFeatureProfileRepository featureRepository,
        IUnitOfWork unitOfWork,
        // [수정] 주입 타입 변경
        IValidator<ActivateAddonCommand> validator,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<ActivateAddonCommandHandler> logger)
    {
        _featureRepository = featureRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _timeProvider = timeProvider;
        _mediator = mediator;
        _logger = logger;
    }

    public async Task<Unit> Handle(ActivateAddonCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Activating Addon {AddonKey} for User {UserId}", command.AddonKey, command.UserId);

        // 1. 유효성 검사 (표준화)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            // [수정] 에러 메시지 리스트 추출하여 예외 처리
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Addon activation validation failed.", errorMessages);
        }

        // 2. 프로필 조회 (없으면 생성 - Lazy Creation)
        var profile = await _featureRepository.GetByUserIdAsync(command.UserId, cancellationToken);
        if (profile == null)
        {
            profile = new UserFeatureProfile
            {
                UserId = command.UserId,
                CreatedAt = _timeProvider.UtcNow,
                FeaturePreferences = "{}",
                BetaFeatures = "{}"
            };
            await _featureRepository.AddAsync(profile, cancellationToken);
        }

        // 3. JSON 데이터 조작 (Addon 추가)
        var prefsNode = JsonNode.Parse(profile.FeaturePreferences ?? "{}") ?? new JsonObject();
        
        prefsNode[command.AddonKey] = new JsonObject
        {
            ["active"] = true,
            ["activatedAt"] = _timeProvider.UtcNow,
            ["reason"] = command.Reason
        };

        profile.FeaturePreferences = prefsNode.ToJsonString();
        profile.UpdatedAt = _timeProvider.UtcNow;
        profile.LastActivityAt = _timeProvider.UtcNow;

        // 4. 저장
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. 이벤트 발행
        var activatedEvent = new AddonActivatedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = command.UserId,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,
            CorrelationId = Guid.NewGuid().ToString(), // 필요 시 Context에서 가져오도록 고도화 가능

            UserId = command.UserId,
            ConnectedId = null,
            AddonKey = command.AddonKey,
            AddonName = command.AddonKey,
            ActivationReason = command.Reason,
            ActivatedByConnectedId = null,
            ActivatedAt = _timeProvider.UtcNow
        };

        await _mediator.Publish(activatedEvent, cancellationToken);

        return Unit.Value;
    }
}