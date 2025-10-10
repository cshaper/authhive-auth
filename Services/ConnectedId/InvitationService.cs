using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Invitation.Responses;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Models.Auth.Invitation.Requests;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.User.Repository;
using System.Text.Json; // IEmailService

// 필요한 네임스페이스들을 추가합니다.
// ...

namespace AuthHive.Auth.Services.ConnectedId
{
    /// <summary>
    /// 초대 관련 비즈니스 로직을 총괄하는 서비스 구현체입니다.
    /// 이 클래스는 AuthHive 서비스 아키텍처의 표준을 제시합니다.
    /// </summary>
    public class InvitationService : IInvitationService
    {
        // 1. 의존성: 필요한 모든 서비스를 private readonly 필드로 선언
        private readonly IInvitationRepository _invitationRepository;
        private readonly IOrganizationRepository _organizationRepository; // 유효성 검증용
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPlanRestrictionService _planRestrictionService; // 요금제 정책 검증
        private readonly IEmailService _emailService; // 이메일 발송
        private readonly IDateTimeProvider _dateTimeProvider; // 시간 관리
        private readonly IAuthorizationService _authorizationService; // 권한 검증
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationMembershipRepository _membershipRepository;
        private readonly ILogger<InvitationService> _logger; // 로깅

        // 2. 생성자: 의존성 주입(DI) 컨테이너로부터 모든 의존성을 주입받음
        public InvitationService(
               IInvitationRepository invitationRepository,
               IOrganizationRepository organizationRepository,
               IUnitOfWork unitOfWork,
               IPlanRestrictionService planRestrictionService,
               IEmailService emailService,
               IDateTimeProvider dateTimeProvider,
               IAuthorizationService authorizationService,
               IUserRepository userRepository,
               IOrganizationMembershipRepository membershipRepository,
               ILogger<InvitationService> logger)
        {
            _invitationRepository = invitationRepository ?? throw new ArgumentNullException(nameof(invitationRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _planRestrictionService = planRestrictionService ?? throw new ArgumentNullException(nameof(planRestrictionService));
            _emailService = emailService ?? throw new ArgumentNullException(nameof(emailService));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _authorizationService = authorizationService ?? throw new ArgumentNullException(nameof(authorizationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _membershipRepository = membershipRepository ?? throw new ArgumentNullException(nameof(membershipRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region 초대 생성

        /// <summary>
        /// 조직에 새로운 멤버를 초대하고, 초대 이메일을 발송합니다.
        /// </summary>
        public async Task<ServiceResult<InvitationResponse>> InviteToOrganizationAsync(
            InviteToOrganizationRequest request,
            Guid invitedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // --- 1단계: 유효성 검증 (Guard Clauses) ---
                // 서비스의 가장 중요한 역할: 비즈니스 규칙에 맞는지 확인
                _logger.LogInformation("Attempting to invite {Email} to organization {OrgId}", request.InviteeEmail, request.OrganizationId);

                // 1-1. [구현 완료] 초대 권한 확인 (Authorization)
                var authzResult = await _authorizationService.HasPermissionAsync(
                          invitedByConnectedId,
                          ScopeStyleConstants.Invitations.Create,
                          cancellationToken);
                if (!authzResult.IsSuccess || !authzResult.Data)
                {
                    _logger.LogWarning(
                        "Authorization failed: ConnectedId {InviterId} lacks '{Permission}' permission for organization {OrgId}.",
                        invitedByConnectedId,
                        ScopeStyleConstants.Invitations.Create,
                        request.OrganizationId);

                    return ServiceResult<InvitationResponse>.Forbidden("You do not have permission to create invitations for this organization.");
                }
                _logger.LogInformation("Authorization successful for {InviterId}", invitedByConnectedId);

                // 1-2. 요금제 한도 확인 (Business Rule)
                var canInviteResult = await CanInviteAsync(request.OrganizationId, InvitationType.Organization, cancellationToken);
                if (!canInviteResult.IsSuccess)
                {
                    return ServiceResult<InvitationResponse>.Failure(canInviteResult.ErrorMessage, canInviteResult.ErrorCode);
                }

                // 1-3. 중복 초대 확인 (Anti-Spam)
                var recentDuplicates = await _invitationRepository.GetRecentDuplicatesAsync(
                    request.InviteeEmail, request.OrganizationId, TimeSpan.FromMinutes(10), cancellationToken);
                if (recentDuplicates.Any())
                {
                    _logger.LogWarning("Duplicate invitation attempt for {Email} in organization {OrgId}", request.InviteeEmail, request.OrganizationId);
                    return ServiceResult<InvitationResponse>.Failure("A similar invitation was sent recently. Please wait before trying again.", "DUPLICATE_INVITATION");
                }

                // 1-3. [구현 완료] 이미 멤버인지 확인
                // 새로 추가한 IsMemberByEmailAsync 메서드를 사용하여 이메일로 직접 멤버십 여부를 확인합니다.
                // 이 방식은 User와 ConnectedId의 복잡한 관계를 Repository 내부에 캡슐화하여 서비스 로직을 단순하게 유지합니다.
                var isMember = await _membershipRepository.IsMemberByEmailAsync(
                    request.OrganizationId,
                    request.InviteeEmail,
                    cancellationToken);

                if (isMember)
                {
                    _logger.LogWarning("Invitation failed: User with email {Email} is already a member of organization {OrgId}", request.InviteeEmail, request.OrganizationId);
                    return ServiceResult<InvitationResponse>.Failure("This user is already a member of the organization.", "ALREADY_MEMBER");
                }
                // --- 2단계: 엔티티 생성 ---
                var invitation = new Invitation
                {
                    OrganizationId = request.OrganizationId,
                    InviteeEmail = request.InviteeEmail.ToLowerInvariant(),

                    // [수정] 표시 이름을 InviteeName에 저장합니다.
                    InviteeName = request.InviteeDisplayName,

                    InvitedByConnectedId = invitedByConnectedId,
                    Type = InvitationType.Organization,
                    Status = InvitationStatus.Sent,
                    InviteCode = Guid.NewGuid().ToString("N").Substring(0, 16).ToUpper(),
                    ExpiresAt = _dateTimeProvider.UtcNow.AddHours(request.ExpirationInHours),
                    ProposedRoleId = request.RoleIds.FirstOrDefault(),
                    CustomMessage = request.CustomMessage,

                    // [추가] Username은 나중에 사용할 수 있도록 Metadata에 저장합니다.
                    Metadata = !string.IsNullOrEmpty(request.InviteeUsername)
                                   ? JsonSerializer.Serialize(new { InviteeUsername = request.InviteeUsername })
                                   : null,

                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = invitedByConnectedId
                };

                // --- 3단계: 데이터베이스 컨텍스트에 추가 ---
                await _invitationRepository.BulkCreateAsync(new List<Invitation> { invitation }, cancellationToken);

                // --- 4단계: 최종 저장 (Unit of Work) ---
                // 관련된 모든 DB 변경사항을 하나의 트랜잭션으로 묶어 저장합니다.
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                _logger.LogInformation("Successfully created Invitation {InvitationId} for {Email}", invitation.Id, invitation.InviteeEmail);

                // --- 5단계: 후속 작업 (이메일 발송) ---
                if (request.SendInvitationEmail)
                {
                    // TODO: 실제 이메일 발송 로직 구현
                    // await _emailService.SendInvitationEmailAsync(invitation, request.RedirectUrl);
                    _logger.LogInformation("Invitation email dispatch requested for {Email}", invitation.InviteeEmail);
                }

                // --- 6단계: 응답 DTO 변환 및 반환 ---
                var response = MapToInvitationResponse(invitation);
                return ServiceResult<InvitationResponse>.Success(response, "Invitation sent successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred while creating an organization invitation. Request: {@Request}", request);
                return ServiceResult<InvitationResponse>.Failure("An unexpected error occurred. Please try again later.", "SYSTEM_ERROR");
            }
        }
        public Task<ServiceResult<InvitationResponse>> InviteToApplicationAsync(InviteToApplicationRequest request, Guid invitedByConnectedId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult<InvitationResponse>> InviteToProjectAsync(InviteToProjectRequest request, Guid invitedByConnectedId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult<BulkInvitationResponse>> BulkInviteAsync(BulkInvitationRequest request, Guid invitedByConnectedId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }
        #endregion
        #region 초대 응답

        public Task<ServiceResult<AcceptInvitationResponse>> AcceptInvitationAsync(string inviteCode, Guid? userId = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult> DeclineInvitationAsync(string inviteCode, string? reason = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult> CancelInvitationAsync(Guid invitationId, Guid cancelledByConnectedId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region 초대 관리

        public Task<ServiceResult> ResendInvitationAsync(Guid invitationId, Guid resentByConnectedId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult<int>> SendPendingRemindersAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult> ExtendInvitationAsync(Guid invitationId, int additionalHours, Guid extendedByConnectedId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region 조회

        public Task<ServiceResult<InvitationDetailResponse>> GetInvitationByCodeAsync(string inviteCode, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult<PagedResult<InvitationSummaryResponse>>> GetOrganizationInvitationsAsync(Guid organizationId, InvitationFilterRequest? filter = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult<PagedResult<InvitationSummaryResponse>>> GetMySentInvitationsAsync(Guid connectedId, InvitationFilterRequest? filter = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult<InvitationStatistics>> GetStatisticsAsync(Guid organizationId, DateTime? startDate = null, DateTime? endDate = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        #endregion
        #region 검증

        public Task<ServiceResult<InvitationValidationResponse>> ValidateInvitationAsync(string inviteCode, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<ServiceResult> CanInviteAsync(Guid organizationId, InvitationType type, CancellationToken cancellationToken = default)
        {
            // 이 메서드는 IPlanRestrictionService를 호출하는 로직을 포함하게 될 것입니다.
            throw new NotImplementedException();
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// Invitation 엔티티를 InvitationResponse DTO로 변환합니다.
        /// </summary>
        private InvitationResponse MapToInvitationResponse(Invitation invitation)
        {
            return new InvitationResponse
            {
                InvitationId = invitation.Id,
                OrganizationId = invitation.OrganizationId,
                InviteeEmail = invitation.InviteeEmail,
                Status = invitation.Status,
                ExpiresAt = invitation.ExpiresAt,
                InviteCode = invitation.InviteCode
            };
        }

        #endregion
    }
}