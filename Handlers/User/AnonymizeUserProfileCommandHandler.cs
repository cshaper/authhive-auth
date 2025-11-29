// [AuthHive.Auth] AnonymizeUserProfileCommandHandler.cs
// v17 CQRS "본보기": 'UserProfile'의 개인정보를 비식별화하는 'AnonymizeUserProfileCommand'를 처리합니다.
// v16 UserProfileService.DeleteAsync 로직을 이관하며, IRequest<Unit>을 반환합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Profile; // ProfileDataAnonymizedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Commands.Data;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "사용자 프로필 비식별화" 유스케이스 핸들러 (SOP 1-Write-F)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class AnonymizeUserProfileCommandHandler : IRequestHandler<AnonymizeUserProfileCommand, Unit>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<AnonymizeUserProfileCommandHandler> _logger;
        // [v17 수정] v16의 Validator는 이 유스케이스에 대한 로직이 없었으므로 주입 제외

        public AnonymizeUserProfileCommandHandler(
            IUserProfileRepository profileRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<AnonymizeUserProfileCommandHandler> logger)
        {
            _profileRepository = profileRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
        }

        public async Task<Unit> Handle(AnonymizeUserProfileCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling AnonymizeUserProfileCommand for User {UserId}", command.UserId);

            // 1. 엔티티 조회 (v16 UserProfileService.DeleteAsync 로직)
            var profile = await _profileRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (profile == null)
            {
                // 프로필이 없으면 이미 비식별화된 것과 같으므로, 성공으로 간주하고 조용히 종료
                _logger.LogWarning("Profile not found for anonymization (UserId: {UserId}). Skipping.", command.UserId);
                return Unit.Value;
            }
            
            // [v17 수정] v16 Validator는 별도 로직이 없었으므로 검증 단계 생략

            // 2. 엔티티 도메인 메서드 호출 (v16 AnonymizeProfileData 로직 이관)
            List<string> anonymizedFields = profile.Anonymize(); 
            // (이 메서드 내부에서 IsDeleted=true, DeletedAt=Now, CompletionPercentage=0이 설정됨)

            // 3. 데이터베이스 저장 (Update)
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Profile anonymized successfully for user {UserId}. Fields: {Fields}", profile.UserId, string.Join(", ", anonymizedFields));

            // 4. 이벤트 발행 (v17 본보기: 캐시/감사 로직 제외)
            var anonymizedEvent = new ProfileDataAnonymizedEvent(
                userId: profile.UserId,
                profileId: profile.Id,
                anonymizedByConnectedId: command.TriggeredBy, // 요청자
                organizationId: command.OrganizationId, // BaseCommand에서 상속 (작업 컨텍스트)
                anonymizedFields: anonymizedFields,
                anonymizationReason: command.AnonymizationReason,
                correlationId: command.CorrelationId,
                source: "UserProfileHandler" // v17 표준
            );
            await _mediator.Publish(anonymizedEvent, cancellationToken);
            
            // 5. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }
    }
}