using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MediatR;
using Microsoft.EntityFrameworkCore; // DbContext 사용을 위해 필요
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core & Infra]
using AuthHive.Infra.Persistence.Context; // [변경] AuthDbContext
using AuthHive.Core.Exceptions;

// [Models & Entities]
using AuthHive.Core.Entities.User; // UserFeatureProfile 엔티티 위치
using AuthHive.Core.Models.User.Commands.Features;
using AuthHive.Core.Models.User.Events.Features;

namespace AuthHive.Core.Handlers.User.Features; // Namespace 표준화

/// <summary>
/// [v18 Final] 사용자 애드온 활성화 핸들러 (DbContext 직접 사용)
/// </summary>
public class ActivateAddonCommandHandler : IRequestHandler<ActivateAddonCommand, Unit>
{
    private readonly AuthDbContext _context; // [변경] DbContext 직접 주입
    private readonly IPublisher _publisher; // [변경] IMediator -> IPublisher
    private readonly ILogger<ActivateAddonCommandHandler> _logger;
    private readonly IValidator<ActivateAddonCommand> _validator;

    public ActivateAddonCommandHandler(
        AuthDbContext context,
        IPublisher publisher,
        ILogger<ActivateAddonCommandHandler> logger,
        IValidator<ActivateAddonCommand> validator)
    {
        _context = context;
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<Unit> Handle(ActivateAddonCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Activating Addon {AddonKey} for User {UserId}", command.AddonKey, command.UserId);

        // 1. 유효성 검사 (표준화)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Addon activation validation failed.", errorMessages);
        }

        // 2. 프로필 조회 (DbContext 직접 사용)
        var profile = await _context.UserFeatureProfiles // DbSet 이름 확인 필요
            .FirstOrDefaultAsync(p => p.UserId == command.UserId, cancellationToken);
        
        var now = DateTime.UtcNow; // [변경] IDateTimeProvider 제거

        // 2.1. 없으면 생성 (Lazy Creation)
        bool isNewProfile = false;
        if (profile == null)
        {
            isNewProfile = true;
            profile = new UserFeatureProfile
            {
                UserId = command.UserId,
                CreatedAt = now,
                // 기본값 할당 (JSON 컬럼)
                FeaturePreferences = "{}", 
                BetaFeatures = "{}" 
            };
        }

        // 3. JSON 데이터 조작 (Addon 추가)
        var prefsNode = JsonNode.Parse(profile.FeaturePreferences ?? "{}") ?? new JsonObject();
        
        // Addon이 이미 활성화되어 있는지 확인 (멱등성)
        if (prefsNode[command.AddonKey]?["active"]?.GetValue<bool>() == true)
        {
             _logger.LogWarning("Addon {AddonKey} already active for User {UserId}. Skipping.", command.AddonKey, command.UserId);
             return Unit.Value;
        }

        // 데이터 업데이트
        prefsNode[command.AddonKey] = new JsonObject
        {
            ["active"] = true,
            ["activatedAt"] = now,
            ["reason"] = command.Reason
        };

        // 4. 엔티티 상태 갱신
        profile.FeaturePreferences = prefsNode.ToJsonString();
        profile.UpdatedAt = now;
        profile.LastActivityAt = now;

        // 5. 저장 (DbContext가 Add/Update를 모두 처리)
        if (isNewProfile)
        {
            _context.UserFeatureProfiles.Add(profile); // 새로운 프로필이면 Add
        }
        // SaveChangesAsync가 Change Tracking을 통해 상태가 변경된 기존 프로필을 업데이트
        await _context.SaveChangesAsync(cancellationToken); 

        // 6. 이벤트 발행
        var activatedEvent = new AddonActivatedEvent
        {
            // BaseEvent Props (필수 초기화)
            AggregateId = command.UserId,
            OccurredOn = now,

            // Context/Domain Props
            EventId = Guid.NewGuid(),
            UserId = command.UserId,
            AddonKey = command.AddonKey,
            ActivationReason = command.Reason,
            ActivatedAt = now,

            // [Audit Context] Command에서 받아온 값 그대로 사용
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,
            CorrelationId = Guid.NewGuid().ToString(),
            
            // TODO: AddonName은 다른 서비스(SystemProduct Master)에서 조회하여 채워야 할 수 있음
            AddonName = command.AddonKey, 
        };

        await _publisher.Publish(activatedEvent, cancellationToken); // [변경] IMediator -> IPublisher

        return Unit.Value;
    }
}