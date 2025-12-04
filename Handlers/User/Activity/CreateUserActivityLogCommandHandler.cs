using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core & Infra]
using AuthHive.Infra.Persistence.Context; // [변경] AuthDbContext 직접 사용
using AuthHive.Core.Exceptions;

// [Models]
using AuthHive.Core.Models.User.Commands.Activity;
using AuthHive.Core.Models.User.Events.Activity;

// [Entities]
using AuthHive.Core.Entities.User;

namespace AuthHive.Auth.Handlers.User.Activity;

/// <summary>
/// [Identity Core] 사용자 활동 로그 생성 핸들러 (Refactored v18)
/// </summary>
public class CreateUserActivityLogCommandHandler : IRequestHandler<CreateUserActivityLogCommand, Guid>
{
    private readonly AuthDbContext _context; // [변경] Repository -> DbContext
    private readonly IValidator<CreateUserActivityLogCommand> _validator;
    private readonly IPublisher _publisher; // [변경] IMediator -> IPublisher
    private readonly ILogger<CreateUserActivityLogCommandHandler> _logger;

    public CreateUserActivityLogCommandHandler(
        AuthDbContext context,
        IValidator<CreateUserActivityLogCommand> validator,
        IPublisher publisher,
        ILogger<CreateUserActivityLogCommandHandler> logger)
    {
        _context = context;
        _validator = validator;
        _publisher = publisher;
        _logger = logger;
    }

    public async Task<Guid> Handle(CreateUserActivityLogCommand command, CancellationToken cancellationToken)
    {
        // 1. 유효성 검사
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Activity log validation failed.", errorMessages);
        }
        
        var now = DateTime.UtcNow; // [간소화] Provider 제거

        // 2. [Entity] 로그 엔티티 생성
        var log = new UserActivityLog
        {
            // 주체 정보
            UserId = command.UserId,
            ConnectedId = command.ConnectedId,
            OrganizationId = command.OrganizationId,
            ApplicationId = command.ApplicationId,

            // 활동 내용
            ActivityType = command.ActivityType,
            Description = command.Summary, 
            ResourceType = command.TargetResourceType,
            ResourceId = command.TargetResourceId?.ToString(), 

            // 환경 정보
            IpAddress = command.IpAddress,
            UserAgent = command.UserAgent,
            Location = command.Location,

            // 결과
            IsSuccessful = command.IsSuccess, 
            ErrorMessage = command.FailureReason, 
            
            // Metadata (JSON 변환)
            Metadata = command.Metadata != null 
                ? JsonSerializer.Serialize(command.Metadata) 
                : null,
                
            // Audit
            CreatedAt = now
        };

        // 3. [Persistence] 저장 (DbContext 직접 사용)
        _context.UserActivityLogs.Add(log);
        await _context.SaveChangesAsync(cancellationToken);

        // 4. [Event] 이벤트 발행
        var loggedEvent = new UserActivityLoggedEvent
        {
            // BaseEvent Props (필수 초기화)
            AggregateId = log.UserId ?? log.ConnectedId ?? Guid.Empty, 
            OccurredOn = now,
            
            // Context Props
            EventId = Guid.NewGuid(),
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

        await _publisher.Publish(loggedEvent, cancellationToken);

        _logger.LogDebug("Activity logged: {ActivityType} by {UserId}", log.ActivityType, log.UserId);

        // 5. Log ID 반환
        return log.Id;
    }
}