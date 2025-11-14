// 📍 위치: authhive.auth/Handlers/Organization/InviteOrganizationMemberCommandHandler.cs
// (OrganizationId에 대한 CS0266 오류 수정)

using MediatR;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Commands;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Auth.Repository; 
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Entities.Auth.Invitation; 
using AuthHive.Core.Enums.Auth; 
using AuthHive.Core.Models.Organization.Events;
using Microsoft.Extensions.Logging; 
using AuthHive.Core.Interfaces.Infra;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Handlers.Organization
{
    public class InviteOrganizationMemberCommandHandler : IRequestHandler<InviteOrganizationMemberCommand, ServiceResult<Guid>>
    {
        private readonly IMediator _mediator;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IInvitationRepository _invitationRepository;
        private readonly IOrganizationValidator _organizationValidator; 
        private readonly ILogger<InviteOrganizationMemberCommandHandler> _logger;
        private readonly IDateTimeProvider _dateTimeProvider; 

        public InviteOrganizationMemberCommandHandler(
            IMediator mediator,
            IUnitOfWork unitOfWork,
            IInvitationRepository invitationRepository,
            IOrganizationValidator organizationValidator,
            IDateTimeProvider dateTimeProvider,
            ILogger<InviteOrganizationMemberCommandHandler> logger)
        {
            _mediator = mediator;
            _unitOfWork = unitOfWork;
            _invitationRepository = invitationRepository;
            _organizationValidator = organizationValidator;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task<ServiceResult<Guid>> Handle(InviteOrganizationMemberCommand command, CancellationToken cancellationToken)
        {
            // 1. 검증 (SOP 2-1)
            // TODO: Validator에 ValidateInviteMemberAsync(command) 구현 필요

            // --- [CS0266 / CS8629 오류 수정 1: InvitedByConnectedId] ---
            // if (command.InvitedByConnectedId == null)
            // {
            //     _logger.LogWarning("InviteOrganizationMemberCommand received with null InvitedByConnectedId.");
            //     return ServiceResult<Guid>.Failure("Inviter ConnectedId is missing.", "BAD_REQUEST");
            // }
            var inviterId = command.InvitedByConnectedId; // .Value 사용
            // --- [수정 완료 1] ---

            if (command.OrganizationId == null)
            {
                _logger.LogWarning("InviteOrganizationMemberCommand received with null OrganizationId.");
                return ServiceResult<Guid>.Failure("OrganizationId is missing.", "BAD_REQUEST");
            }
            var organizationId = command.OrganizationId.Value; // .Value 사용
            // --- [수정 완료 2] ---


            // 2. 엔티티 생성 및 매핑 (SOP 2-2, 2-3)
            var invitation = new Invitation
            {
                // [오류 수정] non-nullable 변수 할당
                OrganizationId = organizationId, 
                Type = InvitationType.Organization, 
                
                InviteeEmail = command.InviteeEmail,
                
                // [오류 수정] non-nullable 변수 할당
                InvitedByConnectedId = inviterId, 
                
                ProposedMembershipType = command.ProposedMembershipType,
                ProposedRoleId = command.ProposedRoleId,
                CustomMessage = command.CustomMessage,
                CreatedFromIp = command.CreatedFromIp,
                
                Status = InvitationStatus.Sent,
                ExpiresAt = _dateTimeProvider.UtcNow.AddDays(7), 
            };

            // 3. 저장 (SOP 2-4)
            await _invitationRepository.AddAsync(invitation);

            // 4. 커밋 (SOP 2-5)
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 5. 이벤트 발행 (SOP 2-6)
            await _mediator.Publish(new OrganizationMemberInvitedEvent(
                invitation.Id,
                organizationId, // [오류 수정] non-nullable 변수 전달
                invitation.InviteeEmail,
                inviterId        // [오류 수정] non-nullable 변수 전달
            ), cancellationToken);

            _logger.LogInformation("Organization member invitation created: {InvitationId} for {Email}", invitation.Id, command.InviteeEmail);

            // 6. 반환 (SOP 2-7)
            return ServiceResult<Guid>.Success(invitation.Id, "Invitation sent successfully.");
        }
    }
}