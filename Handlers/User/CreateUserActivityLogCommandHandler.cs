using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

// [Interfaces]
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IDateTimeProvider
using AuthHive.Core.Interfaces.User.Repository; // IUserActivityLogRepository

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Events; // UserActivityLoggedEvent

// [Entities]
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Exceptions; // UserActivityLog

namespace AuthHive.Auth.Handlers.User;

/// <summary>
/// [Identity Core] 사용자 활동 로그 생성 핸들러
/// 시스템 내 주요 활동을 불변 로그로 기록하고 이벤트를 발행합니다.
/// </summary>
public class CreateUserActivityLogCommandHandler : IRequestHandler<CreateUserActivityLogCommand, UserActivityLogResponse>
{
    private readonly IUserActivityLogRepository _logRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDateTimeProvider _timeProvider;
    private readonly IMediator _mediator;
    private readonly ILogger<CreateUserActivityLogCommandHandler> _logger;
    private readonly IUserActivityLogValidator _validator; // [New]

    public CreateUserActivityLogCommandHandler(
        IUserActivityLogRepository logRepository,
        IUnitOfWork unitOfWork,
        IDateTimeProvider timeProvider,
        IMediator mediator,
        ILogger<CreateUserActivityLogCommandHandler> logger,
        IUserActivityLogValidator validator) // [New] 주입)
    {
        _logRepository = logRepository;
        _unitOfWork = unitOfWork;
        _timeProvider = timeProvider;
        _mediator = mediator;
        _logger = logger;
        _validator = validator;
    }

    public async Task<UserActivityLogResponse> Handle(CreateUserActivityLogCommand command, CancellationToken cancellationToken)
    {
        // 1. [New] 유효성 검사 추가
        var validationResult = await _validator.ValidateCreateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            // 로깅 실패는 비즈니스를 멈추지 않아야 할 수도 있지만,
            // 개발 단계에서는 데이터 정합성을 위해 예외를 던지는 것이 좋습니다.
            throw new DomainValidationException("Activity log validation failed.", validationResult.Errors);
        }
        
        var now = _timeProvider.UtcNow;

        // 1. [Entity] 로그 엔티티 생성 (Immutable init)
        var log = new UserActivityLog
        {
            // 주체 정보
            UserId = command.UserId,
            ConnectedId = command.ConnectedId,
            OrganizationId = command.OrganizationId,
            ApplicationId = null, // 필요 시 Command에 추가하여 매핑

            // 활동 내용
            ActivityType = command.ActivityType,
            Description = command.Description,
            ResourceType = command.ResourceType,
            ResourceId = command.ResourceId,

            // 환경 정보
            IpAddress = command.IpAddress,
            UserAgent = command.UserAgent,
            // Location = ..., // GeoIP 서비스 연동이 필요하다면 여기서 주입받아 처리 가능

            // 결과
            IsSuccessful = command.IsSuccessful,
            ErrorMessage = command.ErrorMessage,
            Metadata = command.MetadataJson,
            
            // BaseEntity 속성은 EF Core가 처리하지만, 명시적 설정도 가능
            // CreatedAt = now 
        };

        // 2. [Persistence] 저장
        await _logRepository.AddAsync(log, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 3. [Event] 이벤트 발행 (비동기 후속 처리용 - BigQuery 적재, 알림 등)
        var loggedEvent = new UserActivityLoggedEvent
        {
            // BaseEvent Props
            EventId = Guid.NewGuid(),
            AggregateId = log.UserId ?? log.ConnectedId ?? Guid.Empty, // 주체가 없으면 Empty
            OccurredOn = log.CreatedAt == default ? now : log.CreatedAt,
            TriggeredBy = log.ConnectedId ?? log.UserId,
            OrganizationId = log.OrganizationId,

            // Domain Props
            LogId = log.Id,
            UserId = log.UserId,
            ConnectedId = log.ConnectedId,
            ActivityType = log.ActivityType,
            Description = log.Description,
            IsSuccessful = log.IsSuccessful,
            IpAddress = log.IpAddress,
            UserAgent = log.UserAgent
        };

        await _mediator.Publish(loggedEvent, cancellationToken);

        _logger.LogDebug("Activity logged: {ActivityType} by {UserId}", log.ActivityType, log.UserId);

        // 4. [Response] 응답 반환
        return new UserActivityLogResponse(
            Id: log.Id,
            UserId: log.UserId,
            ConnectedId: log.ConnectedId,
            ActivityType: log.ActivityType,
            Description: log.Description,
            IpAddress: log.IpAddress,
            Location: log.Location,
            IsSuccessful: log.IsSuccessful,
            Timestamp: log.CreatedAt == default ? now : log.CreatedAt
        );
    }
}