using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Text.Json;

// [Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Interfaces.User.Validators;
using AuthHive.Core.Exceptions;

// [Models]
using AuthHive.Core.Models.User.Commands.Activity;
using AuthHive.Core.Models.User.Events.Activity; // Event 위치 수정

// [Entities]
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Infra;

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
    private readonly IUserActivityLogValidator _validator;

    public CreateUserActivityLogCommandHandler(
        IUserActivityLogRepository logRepository,
        IUnitOfWork unitOfWork,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<CreateUserActivityLogCommandHandler> logger,
        IUserActivityLogValidator validator)
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
        // 1. 유효성 검사
        var validationResult = await _validator.ValidateCreateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException("Activity log validation failed.", validationResult.Errors);
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
            Description = command.Summary, // Entity: Description <-> Command: Summary
            ResourceType = command.TargetResourceType,
            // Guid? -> String 변환
            ResourceId = command.TargetResourceId?.ToString(), 

            // 환경 정보
            IpAddress = command.IpAddress,
            UserAgent = command.UserAgent,
            Location = command.Location,

            // 결과 (Mapping)
            IsSuccessful = command.IsSuccess, // Entity: IsSuccessful <-> Command: IsSuccess
            ErrorMessage = command.FailureReason, // Entity: ErrorMessage <-> Command: FailureReason
            
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
            // [Fix] AggregateId (Guid) 처리
            AggregateId = log.UserId ?? log.ConnectedId ?? Guid.Empty, 
            OccurredOn = log.CreatedAt == default ? now : log.CreatedAt,
            // [Fix] TriggeredBy (Guid) 처리: Nullable일 경우 Empty 할당
            TriggeredBy = log.ConnectedId ?? log.UserId ?? Guid.Empty,
            OrganizationId = log.OrganizationId,

            // Domain Props (Event Definition과 일치시킴)
            LogId = log.Id,
            UserId = log.UserId ?? Guid.Empty, // [Fix] Guid? -> Guid
            ActivityType = log.ActivityType,
            IsSuccess = log.IsSuccessful, 
            
            ConnectedId = log.ConnectedId,
            ApplicationId = log.ApplicationId,

            Summary = log.Description,
            FailureReason = log.ErrorMessage,

            // Entity는 String으로 저장했으나, Event는 Guid/Type 원본을 원하므로 Command 값을 사용
            TargetResourceId = command.TargetResourceId,
            TargetResourceType = command.TargetResourceType,

            IpAddress = log.IpAddress,
            UserAgent = log.UserAgent,
            Location = log.Location,

            // Entity는 JSON String이나, Event는 Dictionary를 원하므로 Command 값을 사용
            Metadata = command.Metadata
        };

        await _mediator.Publish(loggedEvent, cancellationToken);

        _logger.LogDebug("Activity logged: {ActivityType} by {UserId}", log.ActivityType, log.UserId);

        // 5. [Response] Log ID 반환
        return log.Id;
    }
}