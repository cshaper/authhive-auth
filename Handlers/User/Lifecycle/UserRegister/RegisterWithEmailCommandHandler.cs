using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Security;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.User.Services;
using AuthHive.Core.Exceptions;

// [Core Models]
using AuthHive.Core.Models.User.Commands.Registration;
using AuthHive.Core.Models.User.Responses;

// [Core Entities]
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Models.User.Events.Lifecycle;

namespace AuthHive.Auth.Handlers.User.Registration;

public class RegisterWithEmailCommandHandler : IRequestHandler<RegisterWithEmailCommand, UserResponse>
{
    private readonly IUserQueryRepository _queryRepo;
    private readonly IPasswordHashProvider _passwordHasher;
    private readonly IUserRegistrationService _registrationService;

    public RegisterWithEmailCommandHandler(
        IUserQueryRepository queryRepo,
        IPasswordHashProvider passwordHasher,
        IUserRegistrationService registrationService)
    {
        _queryRepo = queryRepo;
        _passwordHasher = passwordHasher;
        _registrationService = registrationService;
    }

    public async Task<UserResponse> Handle(RegisterWithEmailCommand request, CancellationToken cancellationToken)
    {
        // 1. 중복 검사
        if (await _queryRepo.ExistsByEmailAsync(request.Email, cancellationToken))
        {
            throw new DomainValidationException("Email already exists.", new[] { $"The email '{request.Email}' is already registered." });
        }

        // 2. 비밀번호 해싱
        string passwordHash = await _passwordHasher.HashPasswordAsync(request.Password);

        // 3. 엔티티 생성
        var user = new UserEntity();
        user.SetEmail(request.Email);
        user.SetPasswordHash(passwordHash);

        string autoUsername = request.Email.Split('@')[0];
        user.SetUsername(autoUsername);
        if (!string.IsNullOrWhiteSpace(request.DisplayName))
        {
            user.SetName(request.DisplayName, null);
        }
        else
        {
            user.SetUsername(request.Email.Split('@')[0]);
        }

        if (!string.IsNullOrWhiteSpace(request.PhoneNumber))
        {
            user.SetPhoneNumber(request.PhoneNumber);
        }

        // =================================================================
        // ✅ [v18 핵심] 도메인 이벤트 장전 (Trigger)
        // 이 코드가 있어야 UnitOfWork가 저장할 때 이벤트를 감지하고 발송합니다.
        // =================================================================
        user.AddDomainEvent(new UserAccountCreatedEvent
        {
            // BaseEvent 필드
            AggregateId = user.Id,
            OrganizationId = request.OrganizationId,
            CorrelationId = request.CorrelationId?.ToString(),

            // Event 필드
            Email = user.Email,
            Username = user.Username ?? "Unknown",
            RegistrationMethod = "Email",
            PhoneNumber = request.PhoneNumber,

            // 상태 플래그 설정
            EmailVerified = false, // 이메일 가입은 기본적으로 false
            RequiresAdditionalSetup = true // 닉네임 등을 더 받아야 한다면 true
        });

        // 4. 도메인 서비스 호출
        // (주의: UserRegistrationService 내부에서 _unitOfWork.SaveChanges()를 호출해야 이벤트가 날아갑니다!)
        var registeredUser = await _registrationService.RegisterUserAsync(
            user,                            // User Entity (이벤트가 담긴 상태로 넘어감)
            request.OrganizationId,          // Org ID
            "Email",                         // Registration Method
            (request.CorrelationId ?? Guid.NewGuid()).ToString(),
            cancellationToken                // CancellationToken
        );

        // 5. 응답 반환
        return new UserResponse
        {
            Id = registeredUser.Id,
            Email = registeredUser.Email,
            Username = registeredUser.Username,
            PhoneNumber = registeredUser.PhoneNumber,
            IsEmailVerified = registeredUser.IsEmailVerified,
            IsTwoFactorEnabled = registeredUser.IsTwoFactorEnabled,
            Status = registeredUser.Status,
            CreatedAt = registeredUser.CreatedAt,
            LastLoginAt = registeredUser.LastLoginAt,
            Message = "Registration successful. Please check your inbox and verify your email to activate your account."
        };
    }
}