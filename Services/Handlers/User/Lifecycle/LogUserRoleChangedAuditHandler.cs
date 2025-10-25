// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserRoleChangedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserRoleChangedEvent의 두 번째 핸들러입니다.
// 목적: 사용자의 역할 변경에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events; // *** 올바른 이벤트 ***
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
    /// <see cref="UserRoleChangedEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserRoleChangedAuditHandler 
        : IDomainEventHandler<UserRoleChangedEvent>
    {
        // 읽기 모델(100)과 알림(200) 사이에 실행
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<LogUserRoleChangedAuditHandler> _logger;

        public LogUserRoleChangedAuditHandler(
            IAuditLogService auditLogService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<LogUserRoleChangedAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 역할 변경 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserRoleChangedEvent @event, CancellationToken cancellationToken = default)
        {
            // 이 핸들러는 '조직' 역할 변경에만 관심이 있습니다.
            if (@event.OrganizationId == null)
            {
                _logger.LogInformation("LogUserRoleChangedAuditHandler received non-organizational role change. Skipping. (UserId: {UserId})", @event.UserId);
                return;
            }

            try
            {
                // 1. 로그에 필요한 추가 정보 조회
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                var organization = await _organizationRepository.GetByIdAsync(@event.OrganizationId.Value, cancellationToken);

                string userName = user?.Username ?? @event.UserId.ToString();
                string orgName = organization?.Name ?? @event.OrganizationId.Value.ToString();
                
                _logger.LogInformation(
                    "Recording audit log for User {UserName} role change in Org {OrgName}.",
                    userName, orgName);

                // 2. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "Reason", @event.ChangeReason },
                    { "OldRole", @event.OldRole },
                    { "NewRole", @event.NewRole },
                    { "TargetUserId", @event.UserId.ToString() }, 
                    { "TargetConnectedId", @event.ConnectedId.ToString() }
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId.Value,
                    ActionType = AuditActionType.Update, // 역할 '업데이트'
                    Action = "user.role.changed",
                    ResourceType = "Membership", // 대상 리소스는 '멤버십'
                    ResourceId = @event.ConnectedId.ToString(), 
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(), 
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 4. 감사 로그 서비스의 CreateAsync 메서드 호출
                // 행위자: ChangedByConnectedId (역할을 변경한 관리자)
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest, 
                    @event.ChangedByConnectedId
                );

                // 5. v16 ServiceResult DTO로 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for role change. (ConnectedId: {ConnectedId})",
                        @event.ConnectedId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for role change. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording was cancelled. (ConnectedId: {ConnectedId})", @event.ConnectedId);
                throw; 
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserRoleChangedAuditHandler. (ConnectedId: {ConnectedId})",
                    @event.ConnectedId);
                // 감사 로그 실패가 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}
