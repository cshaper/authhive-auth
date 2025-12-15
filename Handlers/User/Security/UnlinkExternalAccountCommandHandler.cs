// using System;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using FluentValidation;

// // [Core Interfaces]
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserQueryRepository
// using AuthHive.Core.Interfaces.User.Repositories.Security;  // IUserSocialAccountCommandRepository
// using AuthHive.Core.Interfaces.Infra;

// // [Models & Entities]
// using AuthHive.Core.Models.User.Commands.Security;
// using AuthHive.Core.Models.User.Events.Integration;
// using AuthHive.Core.Enums.Auth;
// using AuthHive.Core.Exceptions;

// namespace AuthHive.Auth.Handlers.User.Security;

// /// <summary>
// /// [Auth] 외부 ID 계정 연결 해제 핸들러
// /// </summary>
// public class UnlinkExternalAccountCommandHandler : IRequestHandler<UnlinkExternalAccountCommand, Unit>
// {
//     // [변경] 조회 전용 리포지토리 (User 확인용)
//     private readonly IUserQueryRepository _userQueryRepository;
    
//     // [변경] 쓰기 전용 리포지토리 (Social Account 삭제용)
//     private readonly IUserSocialAccountCommandRepository _socialCommandRepository;
    
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IDateTimeProvider _timeProvider;
//     private readonly ILogger<UnlinkExternalAccountCommandHandler> _logger;
//     private readonly IValidator<UnlinkExternalAccountCommand> _validator;
    
//     // [추가] 이벤트 발행 전용
//     private readonly IPublisher _publisher;
    
//     // [추가] 요청자 식별
//     private readonly IPrincipalAccessor _principalAccessor;

//     public UnlinkExternalAccountCommandHandler(
//         IUserQueryRepository userQueryRepository,           // [변경]
//         IUserSocialAccountCommandRepository socialCommandRepository, // [변경]
//         IUnitOfWork unitOfWork,
//         IValidator<UnlinkExternalAccountCommand> validator,
//         IDateTimeProvider timeProvider,
//         IPublisher publisher,                               // [변경] IMediator -> IPublisher
//         ILogger<UnlinkExternalAccountCommandHandler> logger,
//         IPrincipalAccessor principalAccessor)               // [추가]
//     {
//         _userQueryRepository = userQueryRepository;
//         _socialCommandRepository = socialCommandRepository;
//         _unitOfWork = unitOfWork;
//         _validator = validator;
//         _timeProvider = timeProvider;
//         _publisher = publisher;
//         _logger = logger;
//         _principalAccessor = principalAccessor;
//     }

//     public async Task<Unit> Handle(UnlinkExternalAccountCommand command, CancellationToken cancellationToken)
//     {
//         // [Log] CommandId 사용 (IIdempotentCommand)
//         _logger.LogInformation("Handling UnlinkExternalAccount (Cmd: {CommandId}) for User {UserId} - Provider: {Type}",
//             command.CommandId, command.UserId, command.ExternalSystemType);

//         // 1. 유효성 검사
//         var validationResult = await _validator.ValidateAsync(command, cancellationToken);
//         if (!validationResult.IsValid)
//         {
//             var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
//             throw new DomainValidationException("Validation failed.", errorMessages);
//         }

//         // 2. 사용자 조회 (Query Repo 사용)
//         var user = await _userQueryRepository.GetByIdAsync(command.UserId, cancellationToken);
//         if (user == null)
//         {
//             throw new KeyNotFoundException($"Target User not found: {command.UserId}");
//         }

//         // 3. Provider Enum 변환
//         if (!Enum.TryParse<SocialProvider>(command.ExternalSystemType, ignoreCase: true, out var providerEnum))
//         {
//             throw new ArgumentException($"Invalid ExternalSystemType: {command.ExternalSystemType}");
//         }

//         // 4. 해제할 Social Account 조회 (Command Repo 사용 - 삭제할 대상을 가져옴)
//         // (Command Repo는 IRepository를 상속받으므로 조회 메서드도 사용 가능)
//         var socialAccountToDelete = await _socialCommandRepository.GetByProviderKeyAsync(
//             providerEnum,
//             command.ExternalUserId,
//             cancellationToken);

//         // [멱등성 처리] 이미 삭제되었거나 없으면 성공으로 간주
//         if (socialAccountToDelete == null)
//         {
//             _logger.LogWarning("Social account not found (or already unlinked). Skipping delete. User: {UserId}", command.UserId);
//             return Unit.Value;
//         }

//         // [보안 체크] (선택) 요청된 UserId와 소셜 계정의 소유자가 일치하는지 확인
//         if (socialAccountToDelete.UserId != command.UserId)
//         {
//              _logger.LogError("Security Alert: User {RequestUser} tried to unlink account belonging to {OwnerUser}", command.UserId, socialAccountToDelete.UserId);
//              throw new UnauthorizedAccessException("Social account does not belong to the specified user.");
//         }

//         // 5. 삭제 및 커밋 (Command Repo 사용)
//         await _socialCommandRepository.DeleteAsync(socialAccountToDelete, cancellationToken);
//         await _unitOfWork.SaveChangesAsync(cancellationToken);

//         // 6. 이벤트 발행 (IPublisher & Audit Info)
//         var unlinkedEvent = new ExternalSystemUnlinkedEvent
//         {
//             EventId = Guid.NewGuid(),
//             AggregateId = command.UserId,
//             OccurredAt = _timeProvider.UtcNow,

//             // Audit Context (PrincipalAccessor 활용)
//             TriggeredBy = _principalAccessor.UserId ?? command.UserId,
//             OrganizationId = _principalAccessor.OrganizationId,
//             CorrelationId = command.CommandId.ToString(), // CommandId 연결

//             // Event Props
//             UserId = command.UserId,
//             ExternalSystemType = command.ExternalSystemType,
//             ExternalUserId = command.ExternalUserId,
//             Reason = "User requested unlink", 
//             UnlinkedAt = _timeProvider.UtcNow
//         };

//         await _publisher.Publish(unlinkedEvent, cancellationToken);

//         _logger.LogInformation("External account {Provider} unlinked successfully. User: {UserId}", providerEnum, command.UserId);

//         return Unit.Value;
//     }
// }