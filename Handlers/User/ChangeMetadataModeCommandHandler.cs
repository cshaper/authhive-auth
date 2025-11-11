// [AuthHive.Auth] ChangeMetadataModeCommandHandler.cs
// v17 CQRS "본보기": 'UserProfile'의 메타데이터 모드를 변경하는 'ChangeMetadataModeCommand'를 처리합니다.
// v16 UserProfileService.ChangeMetadataModeAsync 로직을 이관합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Settings; // MetadataModeChangedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Core.UserEnums; // UserMetadataMode

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "메타데이터 모드 변경" 유스케이스 핸들러 (SOP 1-Write-L)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class ChangeMetadataModeCommandHandler : IRequestHandler<ChangeMetadataModeCommand, Unit>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<ChangeMetadataModeCommandHandler> _logger;
        // [v17 수정] v16의 Validator는 이 유스케이스에 대한 로직이 없었으므로 제외

        public ChangeMetadataModeCommandHandler(
            IUserProfileRepository profileRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<ChangeMetadataModeCommandHandler> logger)
        {
            _profileRepository = profileRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
        }

        public async Task<Unit> Handle(ChangeMetadataModeCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling ChangeMetadataModeCommand for User {UserId} to {NewMode}", command.UserId, command.NewMode);

            // 1. 엔티티 조회 (v16 로직 이관)
            var profile = await _profileRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (profile == null)
            {
                throw new KeyNotFoundException($"Profile not found for user: {command.UserId}");
            }
            
            // 2. 변경 사항 적용
            string newModeString = command.NewMode.ToString();
            if (profile.MetadataMode == newModeString)
            {
                _logger.LogInformation("MetadataMode is already {NewMode} for User {UserId}. Skipping.", command.NewMode, command.UserId);
                return Unit.Value; // 멱등성(Idempotency): 이미 적용된 상태
            }

            // [v17 정합성] 엔티티에 추가한 MetadataMode 필드 업데이트
            var oldModeString = profile.MetadataMode;
            profile.MetadataMode = newModeString;
            
            // TODO: v16 서비스의 CleanupMetadataAsync 로직 참조.
            // 모드가 'Minimal'로 변경될 경우, 'profile.ProfileMetadata'를 null로 비워야 함.
            if (command.NewMode == UserMetadataMode.Minimal)
            {
                profile.ProfileMetadata = null; // 개인정보 즉시 제거
            }
            
            // 3. 데이터베이스 저장 (Update)
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("MetadataMode changed for User {UserId} from {OldMode} to {NewMode}", 
                command.UserId, oldModeString, newModeString);

            // 4. 이벤트 발행 (Notify)
            var modeChangedEvent = new MetadataModeChangedEvent(
                userId: command.UserId,
                changedByConnectedId: command.TriggeredBy ?? command.UserId,
                oldMode: (UserMetadataMode)Enum.Parse(typeof(UserMetadataMode), oldModeString, true), // string -> Enum
                newMode: command.NewMode,
                organizationId: command.OrganizationId,
                correlationId: command.CorrelationId,
                ipAddress: command.IpAddress, // BaseCommand에서 상속
                source: "UserProfileHandler" // v17 표준
            );
            await _mediator.Publish(modeChangedEvent, cancellationToken);
            
            // 5. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }
    }
}