using System;
using System.Linq; // [필수] .Select() 사용을 위해 추가
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;

using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation; // [필수] IValidator<T> 사용을 위해 추가

// [Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Exceptions;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.User.Repositories.Activity;

// [Models]
using AuthHive.Core.Models.User.Commands.Activity;
using AuthHive.Core.Models.User.Events.Activity;

// [Entities]
using AuthHive.Core.Entities.User;

namespace AuthHive.Auth.Handlers.User.Activity;

/// <summary>
/// [Identity Core] 사용자 활동 로그 생성 핸들러
/// </summary>
public class CreateUserActivityLogCommandHandler : IRequestHandler<CreateUserActivityLogCommand, Guid>
{
    private readonly IUserActivityLogRepository _logRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDateTimeProvider _timeProvider;
    private readonly IMediator _mediator;
    private readonly ILogger<CreateUserActivityLogCommandHandler> _logger;
    
    // [수정] 표준 FluentValidation 인터페이스 사용
    private readonly IValidator<CreateUserActivityLogCommand> _validator;

    public CreateUserActivityLogCommandHandler(
        IUserActivityLogRepository logRepository,
        IUnitOfWork unitOfWork,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<CreateUserActivityLogCommandHandler> logger,
        IValidator<CreateUserActivityLogCommand> validator) // [수정] 주입 타입 변경
    {
        _logRepository = logRepository;
        _unitOfWork = unitOfWork;
        _timeProvider = timeProvider;
        _mediator = mediator;
        _logger = logger;
        _validator = validator;
    }

    public async Task<Guid> Handle(CreateUserActivityLogCommand command, CancellationToken cancellationToken)
    {
        // 1. 유효성 검사 (FluentValidation 표준 메서드 사용)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            // [수정] ValidationFailure 객체 리스트를 string 컬렉션으로 변환 (CS1503 해결)
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            
            throw new DomainValidationException("Activity log validation failed.", errorMessages);
        }
        
        var now = _timeProvider.UtcNow;

        // 2. [Entity] 로그 엔티티 생성 (DB 저장용)
        var log = new UserActivityLog
        {
            // 주체 정보
            UserId = command.UserId,
            ConnectedId = command.ConnectedId,
            OrganizationId = command.OrganizationId,
            ApplicationId = command.ApplicationId,

            // 활동 내용 (Mapping)
            ActivityType = command.ActivityType,
            Description = command.Summary, 
            ResourceType = command.TargetResourceType,
            // Guid? -> String 변환
            ResourceId = command.TargetResourceId?.ToString(), 

            // 환경 정보
            IpAddress = command.IpAddress,
            UserAgent = command.UserAgent,
            Location = command.Location,

            // 결과 (Mapping)
            IsSuccessful = command.IsSuccess, 
            ErrorMessage = command.FailureReason, 
            
            // Metadata (Dictionary -> JSON String)
            Metadata = command.Metadata != null 
                ? JsonSerializer.Serialize(command.Metadata) 
                : null
        };

        // 3. [Persistence] 저장
        await _logRepository.AddAsync(log, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 4. [Event] 이벤트 발행 (외부 시스템 전파용)
        var loggedEvent = new UserActivityLoggedEvent
        {
            // BaseEvent Props
            EventId = Guid.NewGuid(),
            AggregateId = log.UserId ?? log.ConnectedId ?? Guid.Empty, 
            OccurredOn = log.CreatedAt == default ? now : log.CreatedAt,
            TriggeredBy = log.ConnectedId ?? log.UserId ?? Guid.Empty,
            OrganizationId = log.OrganizationId,

            // Domain Props
            LogId = log.Id,
            UserId = log.UserId ?? Guid.Empty,
            ActivityType = log.ActivityType,
            IsSuccess = log.IsSuccessful,
            
            ConnectedId = log.ConnectedId,
            ApplicationId = log.ApplicationId,

            Summary = log.Description,
            FailureReason = log.ErrorMessage,

            TargetResourceId = command.TargetResourceId,
            TargetResourceType = command.TargetResourceType,

            IpAddress = log.IpAddress,
            UserAgent = log.UserAgent,
            Location = log.Location,

            Metadata = command.Metadata
        };

        await _mediator.Publish(loggedEvent, cancellationToken);

        _logger.LogDebug("Activity logged: {ActivityType} by {UserId}", log.ActivityType, log.UserId);

        // 5. [Response] Log ID 반환
        return log.Id;
    }
}