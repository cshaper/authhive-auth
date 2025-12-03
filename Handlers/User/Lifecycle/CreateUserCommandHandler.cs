using System;
using System.Linq; // [필수] .Select() 사용을 위해 추가
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Interfaces]
using AuthHive.Core.Interfaces.Base; 
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserRepository 위치 수정
using AuthHive.Core.Interfaces.Security;
using AuthHive.Core.Interfaces.Infra; // ICacheService가 여기 있는지 확인 필요

// [Models]
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Events.Lifecycle;

// [Exceptions]
using AuthHive.Core.Exceptions;

// [Alias]
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Handlers.User.Lifecycle; // 네임스페이스 위치 수정 (User -> User.Lifecycle)

public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, UserResponse>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHashProvider _passwordHasher;
    private readonly IValidator<CreateUserCommand> _validator;
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ICacheService _cacheService;
    private readonly ILogger<CreateUserCommandHandler> _logger;

    public CreateUserCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IPasswordHashProvider passwordHasher,
        IValidator<CreateUserCommand> validator,
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ICacheService cacheService,
        ILogger<CreateUserCommandHandler> logger)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _passwordHasher = passwordHasher;
        _validator = validator;
        _mediator = mediator;
        _timeProvider = timeProvider;
        _cacheService = cacheService;
        _logger = logger;
    }

    public async Task<UserResponse> Handle(CreateUserCommand command, CancellationToken cancellationToken)
    {
        // 1. 유효성 검사 (FluentValidation)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            // [Fix CS1503] ValidationFailure 객체를 string 메시지로 변환
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            
            throw new DomainValidationException("Validation failed", errorMessages);
        }

        // 2. Entity 생성 & 데이터 설정 (DDD)
        var user = new UserEntity();
        user.SetEmail(command.Email);
        
        if (!string.IsNullOrWhiteSpace(command.Password))
        {
            string hash = await _passwordHasher.HashPasswordAsync(command.Password);
            user.SetPasswordHash(hash);
        }

        if (!string.IsNullOrWhiteSpace(command.PhoneNumber))
        {
            user.SetPhoneNumber(command.PhoneNumber);
        }

        // 3. 저장
        await _userRepository.AddAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 4. 이벤트 발행
        var createdEvent = new UserAccountCreatedEvent
        {
            EventId = Guid.NewGuid(), // 필수값
            AggregateId = user.Id,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = Guid.Empty, // 회원가입은 주체가 없거나 본인
            OrganizationId = null, // Global User 생성 시점엔 Org 없음

            UserId = user.Id,
            Email = user.Email,
            RegistrationMethod = "Email",
            EmailVerified = user.IsEmailVerified,
            RequiresAdditionalSetup = false,
            Username = user.Username,
            PhoneNumber = user.PhoneNumber
        };

        await _mediator.Publish(createdEvent, cancellationToken);

        _logger.LogInformation("User created successfully. ID: {UserId}", user.Id);

        // 5. 응답 생성
        var response = new UserResponse
        {
            Id = user.Id,
            Email = user.Email,
            Username = user.Username,
            IsEmailVerified = user.IsEmailVerified,
            PhoneNumber = user.PhoneNumber,
            IsTwoFactorEnabled = user.IsTwoFactorEnabled,
            Status = user.Status,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt
        };

        // 6. 캐시 프리워밍
        string cacheKey = $"UserResponse:{user.Id}";
        
        // [체크] ICacheService 인터페이스 정의 파일에서 ': IService' 상속을 제거했는지 확인하세요.
        // 만약 IService 에러가 계속 나면, AuthHive.Core/Interfaces/Infra/ICacheService.cs 파일을 열어 수정해야 합니다.
        await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(15), cancellationToken);

        return response;
    }
}