// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // ✅ IUserRepository
// using AuthHive.Core.Interfaces.User.Repositories.Profile;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Models.User.Commands.Settings;
// using AuthHive.Core.Models.User.Events.Settings;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using AuthHive.Core.Exceptions;
// using System.Collections.Generic;
// using FluentValidation;
// using IPublisher = MediatR.IPublisher;

// namespace AuthHive.Auth.Handlers.User.Settings;

// public class ChangeTimeZoneCommandHandler : IRequestHandler<ChangeTimeZoneCommand, Unit>
// {
//     private readonly IUserProfileRepository _profileRepository;
//     private readonly IUserRepository _userRepository; // ✅ User 엔티티 동기화를 위해 추가
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IPublisher _publisher;
//     private readonly IDateTimeProvider _timeProvider;
//     private readonly ILogger<ChangeTimeZoneCommandHandler> _logger;
//     private readonly IValidator<ChangeTimeZoneCommand> _validator;

//     public ChangeTimeZoneCommandHandler(
//         IUserProfileRepository profileRepository,
//         IUserRepository userRepository, // ✅ 주입
//         IUnitOfWork unitOfWork,
//         IValidator<ChangeTimeZoneCommand> validator,
//         IPublisher publisher,
//         IDateTimeProvider timeProvider,
//         ILogger<ChangeTimeZoneCommandHandler> logger)
//     {
//         _profileRepository = profileRepository;
//         _userRepository = userRepository; // ✅ 필드 대입
//         _unitOfWork = unitOfWork;
//         _validator = validator;
//         _publisher = publisher;
//         _timeProvider = timeProvider;
//         _logger = logger;
//     }

//     public async Task<Unit> Handle(ChangeTimeZoneCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling ChangeTimeZoneCommand for User {UserId}: NewTimeZone={NewTimeZone}",
//             command.UserId, command.NewTimeZone);

//         // 1. 유효성 검사
//         var validationResult = await _validator.ValidateAsync(command, cancellationToken);
//         if (!validationResult.IsValid)
//         {
//             var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
//             throw new DomainValidationException("Validation failed.", errorMessages);
//         }

//         // 2. UserProfile 엔티티 조회
//         var profile = await _profileRepository.GetByUserIdAsync(command.UserId, cancellationToken);
//         if (profile == null)
//         {
//             throw new DomainEntityNotFoundException("UserProfile", command.UserId);
//         }
//         // 2.5. User 엔티티 조회 (동기화 대상)
//         var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
//         if (user == null)
//         {
//             // 프로필만 있고 User가 없으면 데이터 정합성 오류이므로 예외 처리
//             throw new DomainEntityNotFoundException("User", command.UserId, "Primary User entity is missing.");
//         }


//         var oldTimeZone = profile.TimeZone;

//         if (oldTimeZone == command.NewTimeZone)
//         {
//             _logger.LogInformation("TimeZone is already {NewTimeZone}. Skipping.", command.NewTimeZone);
//             return Unit.Value;
//         }

//         // 3. 변경 사항 적용 (DDD - Entity Logic)
//         // [Fix CS1061 대비] UserProfile에 UpdateTimeZone 메서드 호출
//         profile.UpdateTimeZone(command.NewTimeZone);

//         // ✅ User 엔티티 동기화 로직 (User 애그리거트의 LastUpdatedAt 등을 갱신한다고 가정)
//         user.MarkAsUpdated(); // User 엔티티에 감사(Audit) 필드 갱신을 위한 도메인 메서드 호출

//         // 4. 데이터베이스 저장 (Multi-Aggregate Update)
//         // 두 Repository 모두 업데이트를 위임
//         await _profileRepository.UpdateAsync(profile, cancellationToken);
//         await _userRepository.UpdateAsync(user, cancellationToken); // ✅ User 엔티티 업데이트

//         // UoW를 통해 두 Repository의 변경사항을 하나의 트랜잭션으로 커밋
//         await _unitOfWork.SaveChangesAsync(cancellationToken);

//         // 5. 이벤트 발행 (Notify)
//         var timeZoneChangedEvent = new TimeZoneChangedEvent
//         {
//             // ... (이벤트 속성 매핑 로직) ...
//             AggregateId = profile.UserId,
//             OccurredOn = _timeProvider.UtcNow,
//             TriggeredBy = command.TriggeredBy,
//             OrganizationId = command.OrganizationId,
//             IpAddress = command.IpAddress,
//             UserId = profile.UserId,
//             OldTimeZone = oldTimeZone,
//             NewTimeZone = profile.TimeZone,
//             ChangedAt = _timeProvider.UtcNow
//         };

//         await _publisher.Publish(timeZoneChangedEvent, cancellationToken);

//         _logger.LogInformation("TimeZone changed successfully for User {UserId}: {Old} -> {New}",
//             command.UserId, oldTimeZone, profile.TimeZone);

//         return Unit.Value;
//     }
// }