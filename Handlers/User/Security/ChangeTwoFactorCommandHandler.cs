// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; 
// using AuthHive.Core.Models.User.Commands.Security;
// using AuthHive.Core.Models.User.Events.Settings; 
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System.ComponentModel.DataAnnotations;
// using System;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using System.Collections.Generic;
// using AuthHive.Core.Exceptions;
// using AuthHive.Core.Interfaces.Infra; 
// using UserEntity = AuthHive.Core.Entities.User.User;
// using AuthHive.Core.Models.User.Events.Profile;
// using FluentValidation; 
// using IPublisher = MediatR.IPublisher; // ✅ IPublisher 사용 명확화

// namespace AuthHive.Auth.Handlers.User.Security;

// /// <summary>
// /// [v18] "2단계 인증 변경" 유스케이스 핸들러
// /// </summary>
// public class ChangeTwoFactorCommandHandler : IRequestHandler<ChangeTwoFactorCommand, Unit>
// {
//     private readonly IUserRepository _userRepository;
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IPublisher _publisher; // ✅ IMediator -> IPublisher 변경
//     private readonly ILogger<ChangeTwoFactorCommandHandler> _logger;
//     private readonly IDateTimeProvider _timeProvider;
//     private readonly IValidator<ChangeTwoFactorCommand> _validator;

//     public ChangeTwoFactorCommandHandler(
//         IUserRepository userRepository,
//         IUnitOfWork unitOfWork,
//         IPublisher publisher, // ✅ IMediator -> IPublisher 변경
//         ILogger<ChangeTwoFactorCommandHandler> logger,
//         IDateTimeProvider timeProvider,
//         IValidator<ChangeTwoFactorCommand> validator)
//     {
//         _userRepository = userRepository;
//         _unitOfWork = unitOfWork;
//         _publisher = publisher; // ✅ 필드 대입
//         _logger = logger;
//         _timeProvider = timeProvider;
//         _validator = validator;
//     }

//     public async Task<Unit> Handle(ChangeTwoFactorCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling ChangeTwoFactorCommand for User {UserId}: Enabled={IsEnabled}, Type={Type}", 
//             command.UserId, command.IsEnabled, command.TwoFactorMethod);

//         // 1. 유효성 검사
//         var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
//         if (!validationResult.IsValid)
//         {
//             var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
//             throw new DomainValidationException("Validation failed.", errorMessages);
//         }

//         // 2. 엔티티 조회
//         var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
//         if (user == null)
//         {
//             throw new KeyNotFoundException($"User not found: {command.UserId}");
//         }

//         // 3. 변경 사항 적용 (DDD 메서드 호출)
//         user.SetTwoFactorStatus(command.IsEnabled, command.TwoFactorMethod);

//         // 4. 데이터베이스 저장 (Update)
//         // UpdateAsync는 Change Tracking만 위임하고, SaveChangesAsync가 커밋을 담당합니다.
//         await _userRepository.UpdateAsync(user, cancellationToken);
//         await _unitOfWork.SaveChangesAsync(cancellationToken); // ✅ UoW를 통한 커밋

//         _logger.LogInformation("2FA settings changed successfully for User {UserId}", command.UserId);

//         // 5. 이벤트 발행 (Notify)
//         var twoFactorChangedEvent = new TwoFactorSettingChangedEvent
//         {
//             // BaseEvent Props
//             EventId = Guid.NewGuid(),
//             AggregateId = user.Id,
//             OccurredOn = _timeProvider.UtcNow,
//             TriggeredBy = command.TriggeredBy, 
//             OrganizationId = command.OrganizationId, 
//             CorrelationId = command.CorrelationId?.ToString(), 

//             // Event Props
//             UserId = user.Id,
//             IsEnabled = user.IsTwoFactorEnabled,
//             Method = user.TwoFactorMethod!, 
//             ChangedAt = _timeProvider.UtcNow
//         };
        
//         // ✅ _mediator.Publish(...) -> _publisher.Publish(...) 변경
//         await _publisher.Publish(twoFactorChangedEvent, cancellationToken);
        
//         return Unit.Value;
//     }
// }