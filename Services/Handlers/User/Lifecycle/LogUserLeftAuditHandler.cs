// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserLeftAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserLeftOrganizationEvent의 세 번째 핸들러입니다.
// 목적: 조직 탈퇴/제외에 대한 감사 로그를 기록합니다.
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
    /// <see cref="UserLeftOrganizationEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogUserLeftAuditHandler 
        : IDomainEventHandler<UserLeftOrganizationEvent>
    {
        // 읽기 모델(100)과 알림(200) 사이에 실행
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<LogUserLeftAuditHandler> _logger;

        public LogUserLeftAuditHandler(
            IAuditLogService auditLogService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<LogUserLeftAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 탈퇴 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserLeftOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("LogUserLeftAuditHandler received. OrganizationId is null. (UserId: {UserId})", @event.UserId);
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
                    "Recording audit log for User {UserName} leaving Org {OrgName}.",
                    userName, orgName);

                // 2. 감사 로그 요청 DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "LeaveReason", @event.LeaveReason },
                    { "RemovedByConnectedId", @event.RemovedByConnectedId?.ToString() },
                    { "TargetUserId", @event.UserId.ToString() }, 
                    { "TargetConnectedId", @event.ConnectedId.ToString() }
                };

                // 3. 행위자와 액션 유형 결정
                // 관리자가 제거했는지(RemovedByConnectedId) 자발적으로 나갔는지(null) 확인
                bool wasRemovedByAdmin = @event.RemovedByConnectedId.HasValue;
                
                string actionName = wasRemovedByAdmin 
                    ? "user.organization.removed" // 관리자에 의한 제거
                    : "user.organization.left";   // 자발적 탈퇴

                // 행위자: 관리자(RemovedByConnectedId) 또는 사용자 본인(ConnectedId)
                Guid? performerConnectedId = @event.RemovedByConnectedId ?? @event.ConnectedId;

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId.Value,
                    ActionType = AuditActionType.Delete, // 멤버십 '삭제' 또는 '비활성화'에 해당
                    Action = actionName,
                    ResourceType = "Membership",
                    ResourceId = @event.ConnectedId.ToString(), // 대상 리소스는 '멤버십'
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    RequestId = @event.CorrelationId.ToString(), 
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 4. 감사 로그 서비스의 CreateAsync 메서드 호출
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest, 
                    performerConnectedId 
                );

                // 5. v16 ServiceResult DTO로 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for user leaving. (ConnectedId: {ConnectedId}, Org: {OrgId})",
                        @event.ConnectedId,
                        @event.OrganizationId.Value);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for user leaving. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                // 리포지토리 조회 중 취소
                _logger.LogWarning("Audit log recording was cancelled. (ConnectedId: {ConnectedId})", @event.ConnectedId);
                throw; 
            }
            catch (Exception ex)
            {
                // 감사 로그 실패는 중요하지만, 이미 성공한 읽기 모델 삭제(Prio 100)를 롤백시키면 안 됨.
                // 로그만 남기고 throw하지 않습니다.
                _logger.LogError(ex,
                    "Error in LogUserLeftAuditHandler. (ConnectedId: {ConnectedId}, Org: {OrgId})",
                    @event.ConnectedId,
                    @event.OrganizationId);
            }
        }
    }
}
