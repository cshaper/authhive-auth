using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

// [Interfaces]
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IDateTimeProvider, IValidator
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Interfaces.Security; // IPasswordHashProvider
using AuthHive.Core.Interfaces.Infra.Cache; // [New] 캐시 서비스

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Events.Lifecycle;

// [Exceptions]
using AuthHive.Core.Exceptions;

// [Alias]
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.User.Commands.Lifecycle;

namespace AuthHive.Auth.Handlers.User;

public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, UserResponse>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHashProvider _passwordHasher;
    private readonly IValidator<CreateUserCommand> _validator;
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ICacheService _cacheService; // [New]
    private readonly ILogger<CreateUserCommandHandler> _logger;

    public CreateUserCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IPasswordHashProvider passwordHasher,
        IValidator<CreateUserCommand> validator,
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ICacheService cacheService, // 주입
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
        // 1. 유효성 검사
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException("Validation failed", validationResult.Errors);
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

        // 4. 이벤트 발행 (BaseEvent)
        var createdEvent = new UserAccountCreatedEvent
        {
            AggregateId = user.Id,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = null,
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

        // 6. [New] 캐시 프리워밍 (Cache Pre-warming)
        // 가입 직후 로그인이나 조회가 발생할 확률이 높으므로 미리 캐싱해둠.
        string cacheKey = $"UserResponse:{user.Id}";
        await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(15), cancellationToken);

        return response;
    }
}