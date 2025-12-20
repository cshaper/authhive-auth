using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;

// [Core Entities]
using AuthHive.Core.Entities.User;
using AuthHive.Business.Core.Entities.Wallets; // PointWallet Entity

// [Core Interfaces]
using AuthHive.Core.Interfaces.Base; // IUnitOfWork (AuthDB용)
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserCommandRepository
using AuthHive.Core.Interfaces.User.Services; // Interface 위치
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider

// [Core Models] (수정된 경로 및 이벤트 이름 확인)
using AuthHive.Core.Models.User.Events.Lifecycle; // UserAccountCreatedEvent

// [Infra - DB Context]
using AuthHive.Business.Core.Interfaces.Commerce.Wallets.Repository;
using AuthHive.Business.Infra.Persistence.Context; // IPointWalletCommandRepository

namespace AuthHive.Auth.Services;

public class UserRegistrationService : IUserRegistrationService
{
    private readonly IUserCommandRepository _userCommandRepo;
    private readonly IPointWalletCommandRepository _walletCommandRepo;
    
    // Auth DB용 트랜잭션 관리자
    private readonly IAuthUnitOfWork _unitOfWork; 
     
    private readonly IPublisher _publisher;
    private readonly IDateTimeProvider _timeProvider;

    public UserRegistrationService(
        IUserCommandRepository userCommandRepo,
        IPointWalletCommandRepository walletCommandRepo,
        IAuthUnitOfWork unitOfWork,
        IPublisher publisher,
        IDateTimeProvider timeProvider)
    {
        _userCommandRepo = userCommandRepo;
        _walletCommandRepo = walletCommandRepo;
        _unitOfWork = unitOfWork;
        _publisher = publisher;
        _timeProvider = timeProvider;
    }

    public async Task<User> RegisterUserAsync(
        User user, 
        Guid? organizationId, 
        string registrationMethod, 
        string correlationId, 
        CancellationToken ct = default)
    {
        // -------------------------------------------------------
        // 1. Auth DB 처리 (User 저장)
        // -------------------------------------------------------
        // 이미 핸들러에서 user.AddDomainEvent()를 호출했으므로, 
        // user 객체 안에는 이벤트가 담겨 있습니다.
        await _userCommandRepo.AddAsync(user, ct);
        
        // Auth DB 커밋 -> User 테이블에 INSERT 되고, 
        // 동시에 UnitOfWork가 user 내부의 도메인 이벤트를 감지하여 Channel로 발송합니다. 🚀
        await _unitOfWork.SaveChangesAsync(ct);


        // -------------------------------------------------------
        // 2. Business DB 처리 (지갑 자동 생성)
        // -------------------------------------------------------
        // 지갑 생성 (팩토리 메서드 활용)
        var wallet = PointWallet.CreateForUser(user.Id);
        
        await _walletCommandRepo.AddAsync(wallet, ct);


        // -------------------------------------------------------
        // 3. [보완] 명시적 이벤트 추가 발행 (옵션)
        // -------------------------------------------------------
        // 핸들러에서 이미 AddDomainEvent를 했다면 이 블록은 사실 중복일 수 있습니다.
        // 하지만 서비스 차원에서 확실하게 이벤트를 한 번 더 쏘고 싶다면 아래 코드를 유지하세요.
        // (보통은 핸들러에서 AddDomainEvent를 했다면 여기서는 생략합니다.)

        /* var createdEvent = new UserAccountCreatedEvent
        {
            // BaseEvent 필수 필드
            AggregateId = user.Id,
            OccurredAt = _timeProvider.UtcNow,
            TriggeredBy = user.Id,
            OrganizationId = organizationId,
            CorrelationId = correlationId,

            // Payload
            UserId = user.Id, // (BaseEvent엔 없지만, UserAccountCreatedEvent에 복구했다면 사용)
            Email = user.Email,
            
            // [Fix] Null Safety: Username이 없으면 이메일 앞부분 사용
            Username = user.Username ?? user.Email.Split('@')[0], 
            
            PhoneNumber = user.PhoneNumber,
            EmailVerified = user.IsEmailVerified,
            RegistrationMethod = registrationMethod,
            RequiresAdditionalSetup = true 
        };

        await _publisher.Publish(createdEvent, ct);
        */

        return user;
    }
}