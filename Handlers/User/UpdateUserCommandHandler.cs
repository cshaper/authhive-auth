using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

// [Interfaces]
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IValidator
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Infra.Cache; // [New] 캐시 서비스

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Events.Lifecycle; // UserUpdatedEvent 필요 시 사용

// [Exceptions]
using AuthHive.Core.Exceptions;

namespace AuthHive.Auth.Handlers.User;

public class UpdateUserCommandHandler : IRequestHandler<UpdateUserCommand, UserResponse>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IValidator<UpdateUserCommand> _validator; // [New]
    private readonly ICacheService _cacheService; // [New]
    private readonly IMediator _mediator;
    private readonly ILogger<UpdateUserCommandHandler> _logger;

    public UpdateUserCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IValidator<UpdateUserCommand> validator,
        ICacheService cacheService,
        IMediator mediator,
        ILogger<UpdateUserCommandHandler> logger)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _cacheService = cacheService;
        _mediator = mediator;
        _logger = logger;
    }

    public async Task<UserResponse> Handle(UpdateUserCommand command, CancellationToken cancellationToken)
    {
        // 1. 유효성 검사
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException("User update failed.", validationResult.Errors);
        }

        // 2. 조회
        var user = await _userRepository.GetByIdAsync(command.UserId, cancellationToken);
        if (user == null)
        {
            throw new DomainEntityNotFoundException("User", command.UserId);
        }

        // 3. 수정 (DDD 메서드 호출)
        // User.cs에 UpdateProfile 메서드가 있다고 가정 (앞서 추가함)
        user.UpdateProfile(command.Username, command.PhoneNumber);

        // 4. 저장
        await _userRepository.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. 캐시 무효화 (Cache Invalidation)
        string cacheKey = $"UserResponse:{user.Id}";
        await _cacheService.RemoveAsync(cacheKey, cancellationToken);
        // 검색 캐시도 무효화하는 것이 안전함 (패턴 삭제 권장)
        // await _cacheService.RemoveByPatternAsync("SearchUsers:*", cancellationToken);

        // 6. 이벤트 발행 (선택 사항 - 변경 알림 등)
        // await _mediator.Publish(new UserUpdatedEvent { ... });

        _logger.LogInformation("User updated. ID: {UserId}", user.Id);

        return new UserResponse(
            user.Id, user.Email, user.Username, user.IsEmailVerified,
            user.PhoneNumber, user.IsTwoFactorEnabled, user.Status,
            user.CreatedAt, user.LastLoginAt
        );
    }
}