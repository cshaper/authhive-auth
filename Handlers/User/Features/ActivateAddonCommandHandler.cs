using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core Interfaces]
// ✅ Infra(DbContext) 제거 -> Repository Interface 추가
using AuthHive.Core.Interfaces.User.Repositories.Features; 
using AuthHive.Core.Exceptions;

// [Models & Entities]
using AuthHive.Core.Entities.User; 
using AuthHive.Core.Models.User.Commands.Features;
using AuthHive.Core.Models.User.Events.Features;

namespace AuthHive.Core.Handlers.User.Features; 

/// <summary>
/// [v18 Final] 사용자 애드온 활성화 핸들러 (Refactored)
/// </summary>
public class ActivateAddonCommandHandler : IRequestHandler<ActivateAddonCommand, Unit>
{
    // ❌ private readonly AuthDbContext _context; 
    private readonly IUserFeatureProfileRepository _repository; // ✅ Repository 사용
    private readonly IPublisher _publisher; 
    private readonly ILogger<ActivateAddonCommandHandler> _logger;
    private readonly IValidator<ActivateAddonCommand> _validator;

    public ActivateAddonCommandHandler(
        IUserFeatureProfileRepository repository, // ✅ 생성자 주입 변경
        IPublisher publisher,
        ILogger<ActivateAddonCommandHandler> logger,
        IValidator<ActivateAddonCommand> validator)
    {
        _repository = repository;
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<Unit> Handle(ActivateAddonCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Activating Addon {AddonKey} for User {UserId}", command.AddonKey, command.UserId);

        // 1. 유효성 검사
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Addon activation validation failed.", errorMessages);
        }

        // 2. 프로필 조회 (Repository 사용)
        // ✅ _context.UserFeatureProfiles.FirstOrDefaultAsync(...) 대체
        var profile = await _repository.GetByUserIdAsync(command.UserId, cancellationToken);
        
        var now = DateTime.UtcNow;

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
        // (Entity 내부 로직 혹은 여기서 처리 - 여기서는 핸들러에서 처리 유지)
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

        // 5. 저장 (Repository 분기 처리)
        // ✅ DbContext.Add/SaveChanges 대신 명시적 메서드 호출
        if (isNewProfile)
        {
            await _repository.AddAsync(profile, cancellationToken);
        }
        else
        {
            await _repository.UpdateAsync(profile, cancellationToken);
        }

        // 6. 이벤트 발행
        var activatedEvent = new AddonActivatedEvent
        {
            // BaseEvent Props 
            AggregateId = command.UserId,
            OccurredOn = now,

            // Context/Domain Props
            EventId = Guid.NewGuid(),
            UserId = command.UserId,
            AddonKey = command.AddonKey,
            ActivationReason = command.Reason,
            ActivatedAt = now,

            // [Audit Context]
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,
            CorrelationId = Guid.NewGuid().ToString(),
            
            AddonName = command.AddonKey, 
        };

        await _publisher.Publish(activatedEvent, cancellationToken); 

        return Unit.Value;
    }
}