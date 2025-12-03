using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

// [Core & Infra]
using AuthHive.Core.Interfaces.Base; // IValidator
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Infra.Persistence.Context; // [중요] AuthDbContext

// [Models]
using AuthHive.Core.Models.User.Commands.Profile; // UpdateUserCommand (namespace 확인 필요)
using AuthHive.Core.Models.User.Responses; // UserResponse
using AuthHive.Core.Models.User.Events.Lifecycle; // UserUpdatedEvent

// [Exceptions]
using AuthHive.Core.Exceptions;
using FluentValidation;

namespace AuthHive.Core.Handlers.User.Lifecycle;

public class UpdateUserCommandHandler : IRequestHandler<UpdateUserCommand, UserResponse>
{
    private readonly AuthDbContext _context; // [변경] Repository -> DbContext
    private readonly IValidator<UpdateUserCommand> _validator;
    private readonly ICacheService _cacheService;
    private readonly IPublisher _publisher; // [추가] 이벤트 발행용
    private readonly ILogger<UpdateUserCommandHandler> _logger;

    public UpdateUserCommandHandler(
        AuthDbContext context,
        IValidator<UpdateUserCommand> validator,
        ICacheService cacheService,
        IPublisher publisher,
        ILogger<UpdateUserCommandHandler> logger)
    {
        _context = context;
        _validator = validator;
        _cacheService = cacheService;
        _publisher = publisher;
        _logger = logger;
    }

    public async Task<UserResponse> Handle(UpdateUserCommand command, CancellationToken cancellationToken)
    {
        // 1. 유효성 검사 (FluentValidation)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);

        if (!validationResult.IsValid)
        {
            // [Fix CS1503] ValidationFailure 객체에서 ErrorMessage(string)만 추출하여 전달
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);

            throw new DomainValidationException("User update failed.", errorMessages);
        }
        // 2. 조회 (DbContext 직접 사용)
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == command.UserId, cancellationToken);

        if (user == null)
        {
            throw new DomainEntityNotFoundException("User", command.UserId);
        }

        // 3. 수정 (DDD 도메인 메서드 호출)
        // User Entity에 UpdateProfile 메서드가 구현되어 있어야 합니다.
        user.UpdateProfile(command.Username, command.PhoneNumber);

        // 4. 저장
        await _context.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("User updated. ID: {UserId}", user.Id);

        // 5. 캐시 무효화
        string cacheKey = $"UserResponse:{user.Id}";
        await _cacheService.RemoveAsync(cacheKey, cancellationToken);

        // 6. 이벤트 발행 (선택 사항이지만 권장됨)
        // 다른 서비스(알림, 로그 등)가 이 변경사항을 알 수 있게 합니다.
        await _publisher.Publish(new UserUpdatedEvent
        {
            // [BaseEvent 필수 속성]
            AggregateId = user.Id,
            OccurredOn = DateTime.UtcNow,

            UserId = user.Id,
            NewUsername = user.Username,
            NewPhoneNumber = user.PhoneNumber,
            UpdatedAt = DateTime.UtcNow // Entity의 UpdatedAt 사용 가능
        }, cancellationToken);

        // 7. 응답 반환
        return new UserResponse
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
    }
}