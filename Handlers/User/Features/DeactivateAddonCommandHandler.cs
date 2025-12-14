// using System;
// using System.Linq; // [필수] Select 사용
// using System.Text.Json.Nodes;
// using System.Threading;
// using System.Threading.Tasks;

// using MediatR;
// using Microsoft.Extensions.Logging;
// using FluentValidation; // [필수] 표준 Validator

// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repositories.Features;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Models.User.Commands.Features;
// using AuthHive.Core.Models.User.Events.Features;
// using AuthHive.Core.Exceptions;

// namespace AuthHive.Auth.Handlers.User.Features;

// /// <summary>
// /// [Auth] 사용자 애드온 비활성화 핸들러 (v18 Final - 1:1 JSON 방식)
// /// </summary>
// public class DeactivateAddonCommandHandler : IRequestHandler<DeactivateAddonCommand, Unit>
// {
//     private readonly IUserFeatureProfileRepository _featureRepository;
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IDateTimeProvider _timeProvider;
//     private readonly IMediator _mediator;
//     private readonly ILogger<DeactivateAddonCommandHandler> _logger;
    
//     // [수정] 표준 FluentValidation 인터페이스 사용
//     private readonly IValidator<DeactivateAddonCommand> _validator;

//     public DeactivateAddonCommandHandler(
//         IUserFeatureProfileRepository featureRepository,
//         IUnitOfWork unitOfWork,
//         // [수정] 주입 타입 변경
//         IValidator<DeactivateAddonCommand> validator,
//         IDateTimeProvider timeProvider,
//         IMediator mediator,
//         ILogger<DeactivateAddonCommandHandler> logger)
//     {
//         _featureRepository = featureRepository;
//         _unitOfWork = unitOfWork;
//         _validator = validator;
//         _timeProvider = timeProvider;
//         _mediator = mediator;
//         _logger = logger;
//     }

//     public async Task<Unit> Handle(DeactivateAddonCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Deactivating Addon {AddonKey} for User {UserId}", command.AddonKey, command.UserId);

//         // 1. 유효성 검사 (표준화)
//         var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
//         if (!validationResult.IsValid)
//         {
//             // [수정] 에러 메시지 리스트 추출하여 예외 처리
//             var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
//             throw new DomainValidationException("Addon deactivation validation failed.", errorMessages);
//         }

//         // 2. 프로필 조회
//         var profile = await _featureRepository.GetByUserIdAsync(command.UserId, cancellationToken);
//         if (profile == null)
//         {
//             // Validator에서 걸러졌겠지만 안전장치
//             throw new KeyNotFoundException($"User profile not found for {command.UserId}");
//         }

//         // 3. JSON 데이터 조작 (Addon 제거)
//         if (command.Immediate)
//         {
//             var prefsNode = JsonNode.Parse(profile.FeaturePreferences ?? "{}");
//             if (prefsNode is JsonObject jsonObj && jsonObj.ContainsKey(command.AddonKey))
//             {
//                 jsonObj.Remove(command.AddonKey); // 키 삭제
//                 profile.FeaturePreferences = jsonObj.ToJsonString();
//             }
//         }
//         else
//         {
//             // 예약 종료 로직 (active: false 설정)
//             var prefsNode = JsonNode.Parse(profile.FeaturePreferences ?? "{}");
//             if (prefsNode != null && prefsNode[command.AddonKey] is JsonObject item)
//             {
//                 item["active"] = false;
//                 item["deactivatedAt"] = _timeProvider.UtcNow;
//                 item["reason"] = command.Reason;
//                 profile.FeaturePreferences = prefsNode.ToJsonString();
//             }
//         }

//         profile.UpdatedAt = _timeProvider.UtcNow;

//         // 4. 저장
//         await _unitOfWork.SaveChangesAsync(cancellationToken);

//         // 5. 이벤트 발행
//         var deactivatedEvent = new AddonDeactivatedEvent
//         {
//             EventId = Guid.NewGuid(),
//             AggregateId = command.UserId,
//             OccurredOn = _timeProvider.UtcNow,
//             TriggeredBy = command.TriggeredBy,
//             OrganizationId = command.OrganizationId,
//             CorrelationId = Guid.NewGuid().ToString(),

//             UserId = command.UserId,
//             ConnectedId = null,
//             AddonKey = command.AddonKey,
//             AddonName = command.AddonKey,
//             DeactivationReason = command.Reason,
//             DeactivatedByConnectedId = null,
//             DeactivatedAt = _timeProvider.UtcNow
//         };

//         await _mediator.Publish(deactivatedEvent, cancellationToken);

//         return Unit.Value;
//     }
// }