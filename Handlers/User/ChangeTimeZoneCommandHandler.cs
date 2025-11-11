// [AuthHive.Auth] ChangeTimeZoneCommandHandler.cs
// v17 CQRS "본보기": 'UserProfile'의 타임존을 변경하는 'ChangeTimeZoneCommand'를 처리합니다.
// v16 UserProfileService.ChangeTimeZoneAsync 로직을 이관합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Settings; // TimeZoneChangedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "타임존 변경" 유스케이스 핸들러 (SOP 1-Write-M)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// "이 사용자에게는 시간을 표시할 때 이 
    /// Timezone(예: 'Asia/Seoul')을 기준으로 변환해서 보여줘라"라고 정의하는 **사용자의 '개인 설정'**입니다.
    /// </summary>
    public class ChangeTimeZoneCommandHandler : IRequestHandler<ChangeTimeZoneCommand, Unit>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<ChangeTimeZoneCommandHandler> _logger;

        public ChangeTimeZoneCommandHandler(
            IUserProfileRepository profileRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<ChangeTimeZoneCommandHandler> logger)
        {
            _profileRepository = profileRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
        }

        public async Task<Unit> Handle(ChangeTimeZoneCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling ChangeTimeZoneCommand for User {UserId} to {NewTimeZone}", command.UserId, command.NewTimeZone);

            // 1. 엔티티 조회 (v16 로직 이관)
            var profile = await _profileRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (profile == null)
            {
                throw new KeyNotFoundException($"Profile not found for user: {command.UserId}");
            }
            
            // 2. 변경 사항 적용
            if (profile.TimeZone == command.NewTimeZone)
            {
                _logger.LogInformation("TimeZone is already {NewTimeZone} for User {UserId}. Skipping.", command.NewTimeZone, command.UserId);
                return Unit.Value; // 멱등성(Idempotency): 이미 적용된 상태
            }

            var oldTimeZone = profile.TimeZone;
            profile.TimeZone = command.NewTimeZone;
            
            // [v17 철학] 엔티티 도메인 메서드 호출 (v16 UpdateProfile 로직 참조)
            profile.UpdateProfile(); // LastProfileUpdateAt, CompletionPercentage 업데이트

            // 3. 데이터베이스 저장 (Update)
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("TimeZone changed for User {UserId} from {OldTimeZone} to {NewTimeZone}", 
                command.UserId, oldTimeZone, command.NewTimeZone);

            // 4. 이벤트 발행 (Notify)
            var timeZoneChangedEvent = new TimeZoneChangedEvent(
                userId: command.UserId,
                changedByConnectedId: command.TriggeredBy ?? command.UserId, // 요청자 또는 본인
                oldTimeZone: oldTimeZone,
                newTimeZone: command.NewTimeZone,
                organizationId: command.OrganizationId,
                correlationId: command.CorrelationId,
                ipAddress: command.IpAddress, // BaseCommand에서 상속
                source: "UserProfileHandler" // v17 표준
            );
            await _mediator.Publish(timeZoneChangedEvent, cancellationToken);
            
            // 5. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }
    }
}