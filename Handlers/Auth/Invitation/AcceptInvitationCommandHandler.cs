// // 📍 위치: AuthHive.Auth/Handlers/Auth/Invitation/AcceptInvitationCommandHandler.cs
// // (CS0234, CS1061 오류 수정)

// using MediatR;
// using Microsoft.Extensions.Logging;
// using AuthHive.Core.Entities.Auth.ConnectedId;
// using AuthHive.Core.Entities.User; // [근거] User.cs 엔티티
// using AuthHive.Core.Enums.Auth;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Auth.Validator;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Interfaces.User.Repositories;
// using AuthHive.Core.Models.Auth.Invitation.Commands;
// using AuthHive.Core.Models.Auth.Invitation.Events;
// using AuthHive.Core.Models.Auth.Invitation.Responses;
// using AuthHive.Core.Models.Common;
//  
// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using ConnectedIdEntity = AuthHive.Core.Entities.Auth.ConnectedId.ConnectedId;
// using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
// using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;

// namespace AuthHive.Auth.Handlers.Auth.Invitation
// {
//     public class AcceptInvitationCommandHandler : IRequestHandler<AcceptInvitationCommand, ServiceResult<AcceptInvitationResponse>>
//     {
//         private readonly IMediator _mediator;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IInvitationRepository _invitationRepository;
//         private readonly IUserRepository _userRepository;
//         private readonly IConnectedIdRepository _connectedIdRepository;
//         private readonly IInvitationValidator _invitationValidator;
//         private readonly IDateTimeProvider _dateTimeProvider;
//         private readonly ILogger<AcceptInvitationCommandHandler> _logger;

//         public AcceptInvitationCommandHandler(
//             IMediator mediator,
//             IUnitOfWork unitOfWork,
//             IInvitationRepository invitationRepository,
//             IUserRepository userRepository,
//             IConnectedIdRepository connectedIdRepository,
//             IInvitationValidator invitationValidator,
//             IDateTimeProvider dateTimeProvider,
//             ILogger<AcceptInvitationCommandHandler> logger)
//         {
//             _mediator = mediator;
//             _unitOfWork = unitOfWork;
//             _invitationRepository = invitationRepository;
//             _userRepository = userRepository;
//             _connectedIdRepository = connectedIdRepository;
//             _invitationValidator = invitationValidator;
//             _dateTimeProvider = dateTimeProvider;
//             _logger = logger;
//         }

//         public async Task<ServiceResult<AcceptInvitationResponse>> Handle(AcceptInvitationCommand command, CancellationToken cancellationToken)
//         {
//             // 1. 검증 (SOP 2-1)
//             var validationResult = await _invitationValidator.ValidateAcceptAsync(command, cancellationToken);
//             if (!validationResult.IsValid)
//             {
//                 _logger.LogWarning("Invitation acceptance validation failed for code {Code}: {Error}", 
//                     command.InvitationCode, validationResult.GetFirstErrorMessage());
//                 return ServiceResult<AcceptInvitationResponse>.ValidationFailure(validationResult.GetFieldErrors());
//             }

//             // 2. 핵심 엔티티 조회 (SOP 2-2)
//             var invitation = await _invitationRepository.GetByCodeAsync(command.InvitationCode, cancellationToken);
//             var user = await _userRepository.GetByIdWithProfileAsync(command.UserId, cancellationToken); // [근거] UserProfile도 함께 조회

//             if (invitation == null)
//                 return ServiceResult<AcceptInvitationResponse>.NotFound("Invitation not found.");
//             if (user == null)
//                 return ServiceResult<AcceptInvitationResponse>.NotFound("User not found.");

//             // 3. 비즈니스 로직 (엔티티 생성 및 매핑) (SOP 2-3)
            
//             // [근거] Invitation.cs 엔티티
//             if (!invitation.CanBeAccepted(_dateTimeProvider.UtcNow))
//             {
//                 return ServiceResult<AcceptInvitationResponse>.Failure("Invitation cannot be accepted. It might be expired or already used.", "INVALID_STATE");
//             }
            
//             // [근거] User.cs 엔티티
//             if (!string.Equals(invitation.InviteeEmail, user.Email, StringComparison.OrdinalIgnoreCase))
//             {
//                 return ServiceResult<AcceptInvitationResponse>.Forbidden("This invitation is not intended for your email address.");
//             }

//             // [CS1061 오류 수정] command에 Provider가 없으므로, 수락한 ConnectedId에서 Provider 정보를 가져와야 함
//             var acceptingConnectedId = await _connectedIdRepository.GetByIdAsync(command.AcceptingConnectedId, cancellationToken);
//             var provider = acceptingConnectedId?.Provider ?? "Internal"; // [근거] ConnectedId.cs에 Provider 속성 있음


//             // [근거] ConnectedId.cs 엔티티
//             var newConnectedId = new ConnectedIdEntity
//             {
//                 UserId = user.Id,
//                 OrganizationId = invitation.OrganizationId,
//                 Status = ConnectedIdStatus.Active,
//                 MembershipType = invitation.ProposedMembershipType ?? MembershipType.Member, 
//                 InvitedByConnectedId = invitation.InvitedByConnectedId,
//                 InvitedAt = invitation.CreatedAt,
//                 JoinedAt = _dateTimeProvider.UtcNow,
//                 LastActiveAt = _dateTimeProvider.UtcNow,
//                 Provider = provider, // [CS1061 수정] 조회한 Provider 사용
                
//                 // --- [CS1061 오류 수정] User/UserProfile의 실제 속성으로 매핑 ---
//                 // [근거] User.cs의 DisplayName
//                 ProfileDisplayName = user.DisplayName, 
//                 // [근거] User.cs에는 FirstName/LastName이 없고 UserProfile.cs에 있음
//                 // FirstName = user.UserProfile?.FirstName, // UserProfile.cs에 FirstName 없음
//                 // LastName = user.UserProfile?.LastName, // UserProfile.cs에 LastName 없음
//                 // [근거] UserProfile.cs의 ProfileImageUrl
//                 ProfilePictureUrl = user.UserProfile?.ProfileImageUrl 
//             };

//             if (invitation.ProposedRoleId.HasValue)
//             {
//                 var newRoleAssignment = new ConnectedIdRole
//                 {
//                     RoleId = invitation.ProposedRoleId.Value,
//                     ApplicationId = invitation.ApplicationId, 
//                     AssignedByConnectedId = invitation.InvitedByConnectedId,
//                     AssignedAt = _dateTimeProvider.UtcNow,
//                     IsActive = true,
//                     AssignmentType = RoleAssignmentType.Direct, 
//                     Reason = "Assigned via invitation acceptance."
//                 };
//                 newConnectedId.RoleAssignments.Add(newRoleAssignment);
//             }

//             // 4. 저장 (SOP 2-4)
//             await _connectedIdRepository.AddAsync(newConnectedId, cancellationToken);

//             invitation.Status = InvitationStatus.Accepted;
//             invitation.AcceptedAt = _dateTimeProvider.UtcNow;
//             invitation.ResultingConnectedId = newConnectedId.Id; 
//             invitation.AcceptedFromIp = command.IpAddress;
            
//             await _invitationRepository.UpdateAsync(invitation, cancellationToken);

//             // 5. 커밋 (SOP 2-5)
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             // 6. 이벤트 발행 (SOP 2-6)
//             await _mediator.Publish(new InvitationAcceptedEvent(
//                 invitation.Id,
//                 newConnectedId.Id,
//                 invitation.OrganizationId
//             ), cancellationToken);

//             _logger.LogInformation("Invitation {InvitationId} accepted by User {UserId}. New ConnectedId {ConnectedId} created.",
//                 invitation.Id, user.Id, newConnectedId.Id);

//             // 7. 반환 (SOP 2-7)
//             var response = new AcceptInvitationResponse(
//                 success: true,
//                 resultingId: newConnectedId.Id,
//                 redirectUrl: $"/organization/{invitation.OrganizationId}/dashboard", 
//                 welcomeMessage: $"Welcome to the organization!" 
//             );
            
//             return ServiceResult<AcceptInvitationResponse>.Success(response);
//         }
//     }
// }