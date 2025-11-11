// [AuthHive.Auth] UpdateOrganizationMemberProfileCommandHandler.cs
// v17 CQRS "본보기": 'OrganizationMemberProfile'을 수정하는 'Update...'Command를 처리합니다.
// v16 OrganizationMemberProfileService.UpsertProfileAsync의 '수정' 로직을 이관합니다.

using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Organization.Commands;
using AuthHive.Core.Models.Organization.Events; // MemberProfileUpdatedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; 
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OrganizationMemberProfileEntity = AuthHive.Core.Entities.Organization.OrganizationMemberProfile; // 별칭

namespace AuthHive.Auth.Handlers.Organization
{
    /// <summary>
    /// [v17] "조직 멤버 프로필 수정" 유스케이스 핸들러 (SOP 2-Write-C)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class UpdateOrganizationMemberProfileCommandHandler : IRequestHandler<UpdateOrganizationMemberProfileCommand, Unit>
    {
        private readonly IOrganizationMemberProfileRepository _profileRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<UpdateOrganizationMemberProfileCommandHandler> _logger;

        public UpdateOrganizationMemberProfileCommandHandler(
            IOrganizationMemberProfileRepository profileRepository,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<UpdateOrganizationMemberProfileCommandHandler> logger)
        {
            _profileRepository = profileRepository;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
        }

        public async Task<Unit> Handle(UpdateOrganizationMemberProfileCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation(
                "Handling UpdateOrganizationMemberProfileCommand for OrgId {OrganizationId}, ConnectedId {ConnectedId}",
                command.OrganizationId, command.ConnectedId);

            // 1. 엔티티 조회 (v16 UpsertProfileAsync 로직)
            // [v17 정합성] Command의 OrganizationId는 Guid? 이지만, 생성자에서 Guid를 받으므로 null이 아님
            var profile = await _profileRepository.GetByConnectedIdAsync(command.ConnectedId, command.OrganizationId!.Value, cancellationToken);
            if (profile == null)
            {
                // [v17 수정] ServiceResult.NotFound 대신 예외 사용
                throw new KeyNotFoundException($"Member profile not found for ConnectedId: {command.ConnectedId}");
            }

            // 2. 변경 사항 적용 (v16 UpdateProperty 헬퍼 로직 이관)
            var changes = new Dictionary<string, (object? Old, object? New)>();
            bool hasChanges = ApplyProfileChanges(command, profile, changes);

            if (!hasChanges)
            {
                _logger.LogInformation("No member profile changes detected for ConnectedId {ConnectedId}", command.ConnectedId);
                return Unit.Value; // 변경 사항 없으므로 즉시 반환
            }

            // 3. 데이터베이스 저장 (Update)
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Organization Member Profile updated successfully for ConnectedId {ConnectedId}", command.ConnectedId);

            // 4. 이벤트 발행 (Notify)
            var profileUpdatedEvent = new MemberProfileUpdatedEvent(
                organizationId: profile.OrganizationId,
                targetConnectedId: profile.ConnectedId, // AggregateId
                updatedByConnectedId: command.TriggeredBy ?? command.ConnectedId // 요청자 또는 본인
            );
            // [v17 수정] v16 이벤트는 '변경 내역'을 포함하지 않았음. (필요시 이벤트 DTO 수정)
            
            await _mediator.Publish(profileUpdatedEvent, cancellationToken);
            
            // 5. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }

        /// <summary>
        /// v16 OrganizationMemberProfileService.UpdateProperty 로직을 핸들러로 이관
        /// Command DTO의 값을 Entity에 적용하고 변경 내역(changes)을 기록합니다.
        /// </summary>
        private bool ApplyProfileChanges(UpdateOrganizationMemberProfileCommand command, OrganizationMemberProfileEntity profile, Dictionary<string, (object? Old, object? New)> changes)
        {
            bool hasChanges = false;
            
            Action<string, object?, object?, Action<object?>> addChange = (key, oldVal, newVal, setter) =>
            {
                // Command의 속성이 null이면 (업데이트 의도가 없으면) 무시
                if (newVal == null) return;
                
                // 기존 값과 다를 경우에만 변경
                if (oldVal == null || !oldVal.Equals(newVal))
                {
                    changes[key] = (oldVal, newVal);
                    setter(newVal); // 엔티티 속성 실제 변경
                    hasChanges = true;
                }
            };

            addChange(nameof(profile.JobTitle), profile.JobTitle, command.JobTitle, (val) => profile.JobTitle = (string?)val);
            addChange(nameof(profile.Department), profile.Department, command.Department, (val) => profile.Department = (string?)val);
            addChange(nameof(profile.EmployeeId), profile.EmployeeId, command.EmployeeId, (val) => profile.EmployeeId = (string?)val);
            addChange(nameof(profile.OfficeLocation), profile.OfficeLocation, command.OfficeLocation, (val) => profile.OfficeLocation = (string?)val);
            addChange(nameof(profile.ManagerConnectedId), profile.ManagerConnectedId, command.ManagerConnectedId, (val) => profile.ManagerConnectedId = (Guid?)val);
            addChange(nameof(profile.ContactInfo), profile.ContactInfo, command.ContactInfo, (val) => profile.ContactInfo = (string?)val);
            addChange(nameof(profile.StartDate), profile.StartDate, command.StartDate, (val) => profile.StartDate = (DateTime?)val);
            addChange(nameof(profile.IsTemporary), profile.IsTemporary, command.IsTemporary, (val) => profile.IsTemporary = (bool)val!);
            addChange(nameof(profile.Visibility), profile.Visibility, command.Visibility, (val) => profile.Visibility = (string)val!);

            return hasChanges;
        }
    }
}