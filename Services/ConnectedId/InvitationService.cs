using System;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.User.Repository;

// using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Services
{
    public class InvitationService : IInvitationService
    {
        private readonly IConnectedIdRepository _connectedIdRepo;
        private readonly IUserRepository _userRepo;
        // private readonly IEmailService _emailService;
        private readonly ILogger<InvitationService> _logger;

        public InvitationService(
            IConnectedIdRepository connectedIdRepository,
            IUserRepository userRepository,
            ILogger<InvitationService> logger)
        {
            _connectedIdRepo = connectedIdRepository;
            _userRepo = userRepository;
            _logger = logger;
        }

        #region IService Implementation

        public Task<bool> IsHealthyAsync()
        {
            return Task.FromResult(_connectedIdRepo != null && _userRepo != null);
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("InvitationService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region Invitation Management

        public async Task<ServiceResult<InvitationResponse>> InviteToOrganizationAsync(InviteToOrganizationRequest request)
        {
            try
            {
                // ... 권한 확인 로직 ...

                var userToInvite = await _userRepo.GetByEmailAsync(request.Email);
                if (userToInvite == null)
                {
                    return ServiceResult<InvitationResponse>.Failure($"User with email {request.Email} not found.");
                }

                if (await _connectedIdRepo.IsMemberOfOrganizationAsync(userToInvite.Id, request.OrganizationId))
                {
                    return ServiceResult<InvitationResponse>.Failure("User is already a member of this organization.");
                }

                var pendingConnectedId = new ConnectedId
                {
                    UserId = userToInvite.Id,
                    OrganizationId = request.OrganizationId,
                    Status = ConnectedIdStatus.Pending,
                    InvitedByConnectedId = request.InvitedByConnectedId, 
                    InvitedAt = DateTime.UtcNow,
                    MembershipType = request.InviteMembershipType, 
                    Provider = "invitation",
                    ProviderUserId = request.Email
                };

                await _connectedIdRepo.AddAsync(pendingConnectedId);

                // TODO: 이메일 발송 로직
                _logger.LogInformation("Invitation sent to {Email} for organization {OrganizationId}", request.Email, request.OrganizationId);

                var response = new InvitationResponse
                {
                    InvitationId = pendingConnectedId.Id,
                    OrganizationId = request.OrganizationId,
                    Email = request.Email,
                    UserId = userToInvite.Id,
                    Status = InvitationStatus.Sent,
                    // ✨ [수정] DTO의 정확한 속성 이름 사용
                    MembershipType = request.InviteMembershipType,
                    // ✨ [수정] DTO의 정확한 속성 이름 사용
                    InvitedByConnectedId = request.InvitedByConnectedId,
                    InvitedAt = pendingConnectedId.InvitedAt.Value,
                    ExpiresAt = request.ExpiresAt,
                    PersonalMessage = request.PersonalMessage,
                    // ✨ [수정] DTO의 정확한 속성 이름 사용
                    AssignedRoleIds = request.InitialRoleIds
                };
                
                return ServiceResult<InvitationResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send invitation to {Email}", request.Email);
                return ServiceResult<InvitationResponse>.Failure("An error occurred while sending the invitation.");
            }
        }

        // ... Accept, Decline, Cancel 메서드 ...
        public async Task<ServiceResult<ConnectedIdResponse>> AcceptInvitationAsync(Guid invitationId)
        {
            return await Task.FromResult(ServiceResult<ConnectedIdResponse>.Failure("Not implemented."));
        }

        public async Task<ServiceResult> DeclineInvitationAsync(Guid invitationId)
        {
            return await Task.FromResult(ServiceResult.Failure("Not implemented."));
        }

        public async Task<ServiceResult> CancelInvitationAsync(Guid invitationId)
        {
            return await Task.FromResult(ServiceResult.Failure("Not implemented."));
        }

        #endregion
    }
}