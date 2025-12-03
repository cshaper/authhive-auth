using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;

// [Core Interfaces]
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IDateTimeProvider
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // IUserRepository
using AuthHive.Core.Interfaces.Security; // ITokenService
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider

// [Models & Entities]
using AuthHive.Core.Models.User.Commands.Security; // RequestPasswordResetCommand
using AuthHive.Core.Models.User.Events.Security; // PasswordResetRequestedEvent (가정)
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Exceptions;
using FluentValidation;
using AuthHive.Core.Interfaces.Auth.Provider;

namespace AuthHive.Auth.Handlers.User.Security;

/// <summary>
/// [Auth] 비밀번호 재설정 요청 핸들러 (Forgot Password Flow Start)
/// </summary>
public class RequestPasswordResetCommandHandler : IRequestHandler<RequestPasswordResetCommand, Unit>
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ITokenProvider _tokenProvider; // 토큰 생성 전문가
    private readonly IDateTimeProvider _timeProvider;
    private readonly IMediator _mediator;
    private readonly ILogger<RequestPasswordResetCommandHandler> _logger;
    private readonly IValidator<RequestPasswordResetCommand> _validator;

    public RequestPasswordResetCommandHandler(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IValidator<RequestPasswordResetCommand> validator,
        ITokenProvider tokenProvider,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<RequestPasswordResetCommandHandler> logger)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _tokenProvider = tokenProvider;
        _timeProvider = timeProvider;
        _mediator = mediator;
        _logger = logger;
    }

    public async Task<Unit> Handle(RequestPasswordResetCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling RequestPasswordResetCommand for {Email}", command.Email);

      // 1. 유효성 검사 (FluentValidation 표준 메서드 사용)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            // [수정] ValidationFailure 객체 리스트를 string 컬렉션으로 변환 (CS1503 해결)
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            
            throw new DomainValidationException("Activity log validation failed.", errorMessages);
        }

        // 2. 사용자 조회 (정규화된 이메일 사용)
        var user = await _userRepository.GetByEmailAsync(command.Email, cancellationToken);
        
        if (user == null)
        {
            // [보안 원칙] 이메일이 존재하지 않더라도 외부에 정보를 노출하지 않고
            // 마치 성공한 것처럼 처리하여 악의적인 사용자에게 DB 정보를 노출하지 않습니다 (Security by Obscurity).
            _logger.LogWarning("Password reset requested for non-existent email: {Email}", command.Email);
            return Unit.Value; 
        }

        // 3. 토큰 생성 및 저장 (Token Service를 통해 DB/Cache에 토큰 저장)
        // [Fix] GenerateRefreshTokenAsync가 'Secure Random String'을 반환하므로 재사용합니다.
        var resetToken = await _tokenProvider.GenerateRefreshTokenAsync(cancellationToken);
        
        // 4. 이벤트 발행 (메일 발송 및 감사 로그)
        // (PasswordResetRequestedEvent DTO는 별도로 정의되어야 함)
        var requestedEvent = new PasswordResetRequestedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = user.Id,
            OccurredOn = _timeProvider.UtcNow,
            // Audit Context
            TriggeredBy = user.Id, // 사용자가 본인 계정으로 요청했다고 가정
            OrganizationId = null, // 전역 활동

            UserId = user.Id,
            Email = user.Email,
            ResetToken = resetToken,
            RequestedAt = _timeProvider.UtcNow,
            IpAddress = command.IpAddress
        };

        await _mediator.Publish(requestedEvent, cancellationToken);

        _logger.LogInformation("Password reset successfully requested for User {UserId}", user.Id);

        return Unit.Value;
    }
}