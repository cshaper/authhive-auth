// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserInvitedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserInvitedToOrganizationEvent의 두 번째 핸들러입니다.
// 목적: 조직 초대에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Organization.Repository; // For IOrganizationRepository
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using AuthHive.Core.Entities.Organization; // (Organization 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserInvitedToOrganizationEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserInvitedAuditHandler
        : IDomainEventHandler<UserInvitedToOrganizationEvent>
    {
        // 알림(100) 이후 실행
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<LogUserInvitedAuditHandler> _logger;

        public LogUserInvitedAuditHandler(
            IAuditLogService auditLogService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<LogUserInvitedAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 초대 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserInvitedToOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("LogUserInvitedAuditHandler received. OrganizationId is null. (InvitationId: {InvitationId})", @event.InvitationId);
                return;
            }

            try
            {
                // 1. 로그에 필요한 추가 정보 조회
                var inviterUser = await _userRepository.GetByConnectedIdAsync(@event.InvitedByUserConnectedId, cancellationToken);
                var organization = await _organizationRepository.GetByIdAsync(@event.OrganizationId.Value, cancellationToken);

                string inviterName = inviterUser?.Username ?? @event.InvitedByUserConnectedId.ToString();
                string orgName = organization?.Name ?? @event.OrganizationId.Value.ToString();

                _logger.LogInformation(
                    "Recording audit log for invitation to {InviteeEmail} for Org {OrgName} sent by {InviterName}.",
                    @event.InvitedUserEmail, orgName, inviterName);

                // 2. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "InvitedUserEmail", @event.InvitedUserEmail },
                    { "InvitedUserId", @event.InvitedUserId?.ToString() },
                    { "ExpiresAt", $"{@event.ExpiresAt:o}" },// ISO 8601 format
                    { "InitialRole", @event.InitialRole },
                    // { "InvitationToken", "[MASKED]" } // 토큰은 민감 정보일 수 있으므로 마스킹 또는 제외
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId.Value,
                    ActionType = AuditActionType.Create, // 초대 '생성'
                    Action = "user.organization.invited",
                    ResourceType = "Invitation", // 대상 리소스는 '초대' 자체
                    ResourceId = @event.InvitationId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(),
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 3. 감사 로그 서비스의 CreateAsync 메서드 호출
                // 행위자: InvitedByUserConnectedId (초대를 보낸 사람)
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.InvitedByUserConnectedId
                );

                // 4. v16 ServiceResult DTO로 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for invitation. (InvitationId: {InvitationId})",
                        @event.InvitationId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for invitation. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for invitation was cancelled. (InvitationId: {InvitationId})", @event.InvitationId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserInvitedAuditHandler. (InvitationId: {InvitationId})",
                    @event.InvitationId);
                // 감사 로그 실패가 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
