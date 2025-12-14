// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR; // IPublisher

// // [Interfaces]
// using AuthHive.Core.Interfaces.Base; 
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
// using AuthHive.Core.Interfaces.Security;

// // [Models]
// using AuthHive.Core.Models.User.Commands.Lifecycle;
// using AuthHive.Core.Models.User.Responses;
// using AuthHive.Core.Models.User.Events.Lifecycle;

// // [Alias]
// using UserEntity = AuthHive.Core.Entities.User.User;
// using AuthHive.Core.Interfaces.Infra;

// namespace AuthHive.Auth.Handlers.User.Lifecycle;

// public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, UserResponse>
// {
//     // ★ [핵심 변경] 읽기/쓰기가 분리된 Command 전용 리포지토리 주입
//     private readonly IUserCommandRepository _userCommandRepository;
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IPasswordHashProvider _passwordHasher;
//     private readonly IPublisher _publisher; // Mediator 대신 Publisher 사용 (ISP 준수)
//     private readonly IDateTimeProvider _timeProvider;

//     public CreateUserCommandHandler(
//         IUserCommandRepository userCommandRepository, 
//         IUnitOfWork unitOfWork,
//         IPasswordHashProvider passwordHasher,
//         IPublisher publisher,
//         IDateTimeProvider timeProvider)
//     {
//         _userCommandRepository = userCommandRepository;
//         _unitOfWork = unitOfWork;
//         _passwordHasher = passwordHasher;
//         _publisher = publisher;
//         _timeProvider = timeProvider;
//     }

//     public async Task<UserResponse> Handle(CreateUserCommand command, CancellationToken cancellationToken)
//     {
//         // 1. Entity 생성 (Domain Logic)
//         var user = new UserEntity();
        
//         // 도메인 규칙 적용 (Setter 대신 도메인 메서드 사용 권장)
//         user.SetEmail(command.Email);
        
//         if (!string.IsNullOrWhiteSpace(command.Password))
//         {
//             string hash = await _passwordHasher.HashPasswordAsync(command.Password);
//             user.SetPasswordHash(hash);
//         }

//         if (!string.IsNullOrWhiteSpace(command.PhoneNumber))
//         {
//             user.SetPhoneNumber(command.PhoneNumber);
//         }

//         // 2. 저장 (Persistence)
//         // IUserCommandRepository는 IRepository<User>를 상속받으므로 AddAsync 사용 가능
//         await _userCommandRepository.AddAsync(user, cancellationToken);
        
//         // 트랜잭션 확정 (만약 Pipeline에 TransactionBehavior가 없다면 필수)
//         await _unitOfWork.SaveChangesAsync(cancellationToken);

//         // 3. 도메인 이벤트 발행 (Side Effects 분리)
//         // 이 이벤트가 나가면 -> EmailSenderHandler, UserCacheHandler 등이 반응함
//         var createdEvent = new UserAccountCreatedEvent
//         {
//             EventId = Guid.NewGuid(),
//             AggregateId = user.Id,
//             OccurredAt = _timeProvider.UtcNow,
//             TriggeredBy = user.Id, // 가입 주체
            
//             UserId = user.Id,
//             Email = user.Email,
//             RegistrationMethod = "Email",
//             EmailVerified = user.IsEmailVerified,
//             Username = user.Username,
//             PhoneNumber = user.PhoneNumber
//         };

//         await _publisher.Publish(createdEvent, cancellationToken);

//         // 4. 응답 반환 (Response)
//         // QueryRepository를 쓰지 않고, 방금 만든 Entity에서 값을 매핑해 리턴 (속도 최적화)
//         return new UserResponse
//         {
//             Id = user.Id,
//             Email = user.Email,
//             Username = user.Username,
//             IsEmailVerified = user.IsEmailVerified,
//             PhoneNumber = user.PhoneNumber,
//             IsTwoFactorEnabled = user.IsTwoFactorEnabled,
//             Status = user.Status,
//             CreatedAt = user.CreatedAt,
//             LastLoginAt = user.LastLoginAt
//         };
//     }
// }