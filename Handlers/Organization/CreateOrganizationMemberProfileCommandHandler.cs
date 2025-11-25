// // [AuthHive.Auth] CreateOrganizationMemberProfileCommandHandler.cs
// // v17 CQRS "본보기": 'OrganizationMemberProfile'을 생성하는 'Create...'Command를 처리합니다.
// // [v17 수정] CS0118 (네임스페이스 충돌), CS8629 (Nullable 경고) 오류를 해결합니다.

// using AuthHive.Core.Entities.Organization;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Organization.Repository;
// using AuthHive.Core.Interfaces.User.Repository; // UserId 확인용
// using AuthHive.Core.Models.Organization.Commands;
// using AuthHive.Core.Models.Organization.Events; // MemberProfileCreatedEvent
// using AuthHive.Core.Models.Organization.Responses;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System.ComponentModel.DataAnnotations; // ValidationException
// using System;
// using System.Collections.Generic;
// using System.Threading;
// using System.Threading.Tasks;
// // [CS0118 해결] 네임스페이스 충돌을 피하기 위해 엔티티 별칭(Alias) 사용
// using OrganizationMemberProfileEntity = AuthHive.Core.Entities.Organization.OrganizationMemberProfile;
// using UserEntity = AuthHive.Core.Entities.User.User;
// using AuthHive.Core.Models.Organization.Common;

// namespace AuthHive.Auth.Handlers.Organization
// {
//     /// <summary>
//     /// [v17] "조직 멤버 프로필 생성" 유스케이스 핸들러 (SOP 2-Write-B)
//     /// </summary>
//     public class CreateOrganizationMemberProfileCommandHandler : IRequestHandler<CreateOrganizationMemberProfileCommand, OrganizationMemberProfileResponse>
//     {
//         private readonly IOrganizationMemberProfileRepository _profileRepository;
//         private readonly IUserRepository _userRepository;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IMediator _mediator;
//         private readonly ILogger<CreateOrganizationMemberProfileCommandHandler> _logger;

//         public CreateOrganizationMemberProfileCommandHandler(
//             IOrganizationMemberProfileRepository profileRepository,
//             IUserRepository userRepository,
//             IUnitOfWork unitOfWork,
//             IMediator mediator,
//             ILogger<CreateOrganizationMemberProfileCommandHandler> logger)
//         {
//             _profileRepository = profileRepository;
//             _userRepository = userRepository;
//             _unitOfWork = unitOfWork;
//             _mediator = mediator;
//             _logger = logger;
//         }

//         public async Task<OrganizationMemberProfileResponse> Handle(CreateOrganizationMemberProfileCommand command, CancellationToken cancellationToken)
//         {
//             _logger.LogInformation(
//                 "Handling CreateOrganizationMemberProfileCommand for OrgId {OrganizationId}, ConnectedId {ConnectedId}",
//                 command.OrganizationId, command.ConnectedId);

//             // 1. 유효성 검사 (v16 UpsertProfileAsync 로직 이관)
            
//             // 1a. 프로필 중복 생성 검사
//             // [CS8629 해결] command.OrganizationId! (null 아님을 보장)
//             var existingProfile = await _profileRepository.GetByConnectedIdAsync(command.ConnectedId, command.OrganizationId!.Value, cancellationToken);
//             if (existingProfile != null)
//             {
//                 throw new ValidationException($"Profile already exists for ConnectedId: {command.ConnectedId}");
//             }

//             // 1b. [v17 정합성] UserId가 유효한지 확인 (엔티티 FK 제약조건)
//             var user = await _userRepository.GetByConnectedIdAsync(command.ConnectedId, cancellationToken);
//             if (user == null)
//             {
//                 throw new KeyNotFoundException($"User not found for ConnectedId: {command.ConnectedId}. Cannot create profile.");
//             }

//             // 2. 엔티티 매핑 (v16 UpsertProfileAsync 로직 이관)
//             // [CS0118 해결] new OrganizationMemberProfile -> new OrganizationMemberProfileEntity
//             var newProfile = new OrganizationMemberProfileEntity
//             {
//                 ConnectedId = command.ConnectedId,
//                 OrganizationId = command.OrganizationId.Value, // [CS8629 해결]
//                 UserId = user.Id, 

//                 JobTitle = command.JobTitle,
//                 Department = command.Department,
//                 EmployeeId = command.EmployeeId,
//                 OfficeLocation = command.OfficeLocation,
//                 ManagerConnectedId = command.ManagerConnectedId,
//                 ContactInfo = command.ContactInfo,
//                 StartDate = command.StartDate,
//                 IsTemporary = command.IsTemporary,
//                 Visibility = command.Visibility
//             };

//             // 3. 데이터베이스 저장
//             await _profileRepository.AddAsync(newProfile, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             _logger.LogInformation("Organization Member Profile created successfully for ConnectedId {ConnectedId} (ProfileId: {ProfileId})",
//                 newProfile.ConnectedId, newProfile.Id);

//             // 4. 이벤트 발행 (v17 본보기: 캐시/감사 로직 제외)
//             var profileCreatedEvent = new MemberProfileCreatedEvent(
//                 profileId: newProfile.Id,
//                 connectedId: newProfile.ConnectedId,
//                 userId: newProfile.UserId,
//                 organizationId: newProfile.OrganizationId,
//                 createdByConnectedId: command.TriggeredBy ?? command.ConnectedId, // 요청자 또는 본인
//                 jobTitle: newProfile.JobTitle,
//                 department: newProfile.Department,
//                 correlationId: command.CorrelationId,
//                 source: "OrgMemberProfileHandler" // v17 표준
//             );
//             await _mediator.Publish(profileCreatedEvent, cancellationToken);

//             // 5. 응답 DTO 반환 (v17 "Create" 본보기)
//             return MapToDto(newProfile, user);
//         }

//         /// <summary>
//         /// 엔티티를 v17 응답 DTO (OrganizationMemberProfileResponse)로 매핑
//         /// </summary>
//         // [CS0118 해결] OrganizationMemberProfile -> OrganizationMemberProfileEntity
//         private OrganizationMemberProfileResponse MapToDto(OrganizationMemberProfileEntity profile, UserEntity user)
//         {
//             return new OrganizationMemberProfileResponse(
//                 id: profile.Id,
//                 organizationId: profile.OrganizationId,
//                 connectedId: profile.ConnectedId,
//                 createdAt: profile.CreatedAt,
//                 status: "Active",
//                 isManager: false,
//                 directReportsCount: 0,
//                 roleCount: 0,
//                 accessibleApplicationsCount: 0,
//                 isTemporary: profile.IsTemporary,
//                 visibility: profile.Visibility,
//                 jobTitle: profile.JobTitle,
//                 department: profile.Department,
//                 employeeId: profile.EmployeeId,
//                 officeLocation: profile.OfficeLocation,
//                 managerConnectedId: profile.ManagerConnectedId,
//                 lastActivityAt: null,
//                 startDate: profile.StartDate,
//                 memberName: user.EffectiveDisplayName,
//                 memberEmail: user.Email,
//                 profileImageUrl: user.UserProfile?.ProfileImageUrl,
//                 managerName: null, 
//                 managerEmail: null,
//                 organizationName: null, 
//                 directReports: new List<DirectReportSummaryInfo>(),
//                 primaryRoles: new List<string>(),
//                 contactInfo: null, 
//                 customFields: null,
//                 createdByConnectedId: profile.CreatedByConnectedId,
//                 updatedAt: profile.UpdatedAt,
//                 updatedByConnectedId: profile.UpdatedByConnectedId,
//                 createdByName: null,
//                 updatedByName: null,
//                 rowVersion: null
//             );
//         }
//     }
// }