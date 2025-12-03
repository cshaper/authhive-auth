using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Models.User.Events.Profile; // ProfileDataAnonymizedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Commands.Data;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.User.Repositories.Profile;

namespace AuthHive.Auth.Handlers.User.Data
{
    /// <summary>
    /// [v18] "사용자 프로필 비식별화" 유스케이스 핸들러
    /// </summary>
    public class AnonymizeUserProfileCommandHandler : IRequestHandler<AnonymizeUserProfileCommand, Unit>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly IDateTimeProvider _timeProvider;
        private readonly ILogger<AnonymizeUserProfileCommandHandler> _logger;

        public AnonymizeUserProfileCommandHandler(
            IUserProfileRepository profileRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            IDateTimeProvider timeProvider,
            ILogger<AnonymizeUserProfileCommandHandler> logger)
        {
            _profileRepository = profileRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _timeProvider = timeProvider;
            _logger = logger;
        }

        public async Task<Unit> Handle(AnonymizeUserProfileCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling AnonymizeUserProfileCommand for User {UserId}", command.UserId);

            // 1. 엔티티 조회
            var profile = await _profileRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (profile == null)
            {
                _logger.LogWarning("Profile not found for anonymization (UserId: {UserId}). Skipping.", command.UserId);
                return Unit.Value;
            }

            // 2. 엔티티 도메인 메서드 호출 (Anonymize)
            // 실제 엔티티 내부에서 Bio, Location, ImageUrl 등을 null로 만듭니다.
            profile.Anonymize(); 

            // [Fix] 실제 UserProfile 엔티티에 존재하는 필드들로 수정했습니다.
            // (FirstName, LastName 등은 UserProfile 엔티티에 없으므로 제거)
            var anonymizedFields = new List<string> 
            { 
                nameof(profile.Bio), 
                nameof(profile.Location), 
                nameof(profile.ProfileImageUrl),
                nameof(profile.WebsiteUrl),
                nameof(profile.ProfileMetadata)
            };

            // 3. 데이터베이스 저장 (Update)
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Profile anonymized successfully for user {UserId}.", profile.UserId);

            // 4. 이벤트 발행
            var now = _timeProvider.UtcNow;
            
            var anonymizedEvent = new ProfileDataAnonymizedEvent
            {
                // BaseEvent Props
                EventId = Guid.NewGuid(),
                AggregateId = profile.UserId,
                OccurredOn = now,
                TriggeredBy = Guid.Empty, 
                OrganizationId = null, 

                // Domain Props
                UserId = profile.UserId,
                ProfileId = profile.Id,
                AnonymizedByConnectedId = null,
                AnonymizedAt = now,
                AnonymizedFields = anonymizedFields.AsReadOnly(),
                AnonymizationReason = command.AnonymizationReason,
                IsSoftDeleted = true 
            };

            await _mediator.Publish(anonymizedEvent, cancellationToken);
            
            return Unit.Value;
        }
    }
}