// [AuthHive.Auth] UpdateUserProfileCommandHandler.cs
// v17 CQRS "본보기": 'UserProfile' 엔티티를 수정하는 'UpdateUserProfileCommand'를 처리합니다.
// v17 철학에 따라 '쓰기' 핸들러는 데이터를 반환하지 않습니다 (IRequest<Unit>).

using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Profile; // ProfileUpdatedEvent
using MediatR; // [v17 수정] Unit 사용
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "사용자 프로필 수정" 유스케이스 핸들러 (SOP 1-Write-B)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class UpdateUserProfileCommandHandler : IRequestHandler<UpdateUserProfileCommand, Unit> // [v17 수정]
    {
        private readonly IUserProfileRepository _profileRepository;
        // [v17 수정] 불필요한 IUserRepository 의존성 제거
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<UpdateUserProfileCommandHandler> _logger;
        private readonly IUserValidator _userValidator;

        public UpdateUserProfileCommandHandler(
            IUserProfileRepository profileRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<UpdateUserProfileCommandHandler> logger,
            IUserValidator userValidator)
        {
            _profileRepository = profileRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
        }

        public async Task<Unit> Handle(UpdateUserProfileCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling UpdateUserProfileCommand for User {UserId}", command.UserId);

            // 1. 유효성 검사 (Validator로 책임 이관)
            var validationResult = await _userValidator.ValidateProfileUpdateAsync(command);
            if (!validationResult.IsSuccess)
            {
                throw new ValidationException(validationResult.ErrorMessage ?? "Profile update validation failed.");
            }

            // 2. 엔티티 조회
            var profile = await _profileRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (profile == null)
            {
                throw new KeyNotFoundException($"Profile not found for user: {command.UserId}");
            }
            
            // 3. 변경 사항 적용 (v16 ApplyProfileChanges 로직 이관)
            var changes = new Dictionary<string, object>();
            var oldCompletionPercentage = profile.CompletionPercentage;
            bool hasChanges = ApplyProfileChanges(command, profile, changes);

            if (!hasChanges)
            {
                _logger.LogInformation("No profile changes detected for user {UserId}", command.UserId);
                return Unit.Value; // 변경 사항 없으므로 즉시 반환
            }

            // 4. 엔티티 도메인 메서드 호출 및 저장
            profile.UpdateProfile(); // LastProfileUpdateAt, CompletionPercentage 업데이트
            
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Profile updated successfully for user {UserId}", command.UserId);

            // 5. 이벤트 발행
            var profileUpdatedEvent = new ProfileUpdatedEvent(
                userId: profile.UserId,
                profileId: profile.Id, 
                updatedByConnectedId: command.TriggeredBy ?? command.UserId, // 요청자 또는 본인
                changes: changes,
                newCompletionPercentage: profile.CompletionPercentage,
                organizationId: command.OrganizationId,
                correlationId: command.CorrelationId,
                source: "UserProfileHandler"
            );
            // [v17 수정] OldCompletionPercentage는 v17 이벤트 DTO에 없으므로 제거
            await _mediator.Publish(profileUpdatedEvent, cancellationToken);
            
            // 6. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }

        /// <summary>
        /// v16 UserProfileService.ApplyProfileChanges 로직을 핸들러로 이관
        /// Command DTO의 값을 Entity에 적용하고 변경 내역(changes)을 기록합니다.
        /// </summary>
        private bool ApplyProfileChanges(UpdateUserProfileCommand command, UserProfile profile, Dictionary<string, object> changes)
        {
            bool hasChanges = false;
            
            Action<string, object?, object?> addChange = (key, oldVal, newVal) =>
            {
                if (newVal == null) return;
                if (oldVal == null || !oldVal.Equals(newVal))
                {
                    changes[key] = new { Old = oldVal, New = newVal };
                    hasChanges = true;
                }
            };
            
            addChange(nameof(profile.PhoneNumber), profile.PhoneNumber, command.PhoneNumber);
            if(changes.ContainsKey(nameof(profile.PhoneNumber)))
            {
                profile.PhoneNumber = command.PhoneNumber; 
                profile.PhoneVerified = false;
                profile.PhoneVerifiedAt = null;
            }

            addChange(nameof(profile.ProfileImageUrl), profile.ProfileImageUrl, command.ProfileImageUrl);
            if(changes.ContainsKey(nameof(profile.ProfileImageUrl))) profile.ProfileImageUrl = command.ProfileImageUrl;

            addChange(nameof(profile.TimeZone), profile.TimeZone, command.TimeZone);
            if(changes.ContainsKey(nameof(profile.TimeZone))) profile.TimeZone = command.TimeZone!;

            addChange(nameof(profile.PreferredLanguage), profile.PreferredLanguage, command.Language?.ToString());
            if(changes.ContainsKey(nameof(profile.PreferredLanguage))) profile.PreferredLanguage = command.Language!.Value.ToString();

            addChange(nameof(profile.PreferredCurrency), profile.PreferredCurrency, command.PreferredCurrency);
            if(changes.ContainsKey(nameof(profile.PreferredCurrency))) profile.PreferredCurrency = command.PreferredCurrency!;
            
            addChange(nameof(profile.Bio), profile.Bio, command.Bio);
            if(changes.ContainsKey(nameof(profile.Bio))) profile.Bio = command.Bio;

            addChange(nameof(profile.WebsiteUrl), profile.WebsiteUrl, command.WebsiteUrl);
            if(changes.ContainsKey(nameof(profile.WebsiteUrl))) profile.WebsiteUrl = command.WebsiteUrl;

            addChange(nameof(profile.Location), profile.Location, command.Location);
            if(changes.ContainsKey(nameof(profile.Location))) profile.Location = command.Location;

            addChange(nameof(profile.DateOfBirth), profile.DateOfBirth, command.DateOfBirth);
            if(changes.ContainsKey(nameof(profile.DateOfBirth))) profile.DateOfBirth = command.DateOfBirth;
            
            addChange(nameof(profile.Gender), profile.Gender, command.Gender);
            if(changes.ContainsKey(nameof(profile.Gender))) profile.Gender = command.Gender;

            addChange(nameof(profile.IsPublic), profile.IsPublic, command.IsPublic);
            if(changes.ContainsKey(nameof(profile.IsPublic))) profile.IsPublic = command.IsPublic!.Value;

            addChange(nameof(profile.EmailNotificationsEnabled), profile.EmailNotificationsEnabled, command.EmailNotificationsEnabled);
            if(changes.ContainsKey(nameof(profile.EmailNotificationsEnabled))) profile.EmailNotificationsEnabled = command.EmailNotificationsEnabled!.Value;

            addChange(nameof(profile.SmsNotificationsEnabled), profile.SmsNotificationsEnabled, command.SmsNotificationsEnabled);
            if(changes.ContainsKey(nameof(profile.SmsNotificationsEnabled))) profile.SmsNotificationsEnabled = command.SmsNotificationsEnabled!.Value;
            
            addChange(nameof(profile.ProfileMetadata), profile.ProfileMetadata, command.Metadata);
            if(changes.ContainsKey(nameof(profile.ProfileMetadata))) profile.ProfileMetadata = command.Metadata;

            return hasChanges;
        }
        
        // [v17 수정] 불필요한 MapToDto 헬퍼 메서드 제거
    }
}