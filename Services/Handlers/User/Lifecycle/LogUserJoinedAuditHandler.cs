// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogUserJoinedAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// (수정) IAuditLogService의 실제 CreateAsync 메서드 시그니처를 사용
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using System.Linq; // For FirstOrDefault()
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository
using AuthHive.Core.Interfaces.Organization.Repository; // For IOrganizationRepository
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models; // For AuditLogResponse (참조용)
using AuthHive.Core.Models.Audit.Requests; // *** (추가) For CreateAuditLogRequest ***
using AuthHive.Core.Models.Audit.Responses; // *** (추가) For AuditLogResponse ***
using AuthHive.Core.Models.Common; // *** (추가) For ServiceResult ***
using AuthHive.Core.Enums.Core; 
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Organization;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserJoinedOrganizationEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// (수정) CreateAuditLogRequest를 사용하여 로그를 기록합니다.
    /// </summary>
    public class LogUserJoinedAuditHandler 
        : IDomainEventHandler<UserJoinedOrganizationEvent>
    {
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly IUserRepository _userRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly ILogger<LogUserJoinedAuditHandler> _logger;

        public LogUserJoinedAuditHandler(
            IAuditLogService auditLogService,
            IUserRepository userRepository,
            IOrganizationRepository organizationRepository,
            ILogger<LogUserJoinedAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _organizationRepository = organizationRepository ?? throw new ArgumentNullException(nameof(organizationRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 조직 합류 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(UserJoinedOrganizationEvent @event, CancellationToken cancellationToken = default)
        {
            if (@event.OrganizationId == null)
            {
                _logger.LogWarning("LogUserJoinedAuditHandler received. OrganizationId is null. (UserId: {UserId})", @event.UserId);
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
                    "Recording audit log for User {UserName} joining Org {OrgName}.",
                    userName, orgName);

                // 2. (수정) CreateAuditLogRequest DTO 생성
                var details = new Dictionary<string, string?>
                {
                    { "JoinMethod", @event.JoinMethod },
                    { "InitialRole", @event.InitialRole },
                    { "InvitedByUserId", @event.InvitedByUserId?.ToString() },
                    { "TargetUserId", @event.UserId.ToString() }, 
                    { "TargetConnectedId", @event.ConnectedId.ToString() }
                };

                // (가정) CreateAuditLogRequest의 속성이 AuditLogResponse의 속성과 유사하다고 가정
                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId.Value,
                    
                    ActionType = AuditActionType.Create,
                    Action = "user.organization.joined",
                    
                    ResourceType = "Membership",
                    ResourceId = @event.ConnectedId.ToString(),
                    
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    
                    // 이벤트의 CorrelationId를 RequestId로 사용
                    RequestId = @event.CorrelationId.ToString(), 
                    
                    Metadata = JsonSerializer.Serialize(details)
                    
                    // PerformedByConnectedId는 별도 파라미터로 전달됨
                };

                // 3. (수정) 감사 로그 서비스의 CreateAsync 메서드 호출
                //    (참고) CreateAsync 시그니처에는 CancellationToken이 없습니다.
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest, 
                    @event.AddedByConnectedId // <-- performedByConnectedId 파라미터
                );

                // 4. (추가) 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully. (User: {UserId}, Org: {OrgId})",
                        @event.UserId,
                        @event.OrganizationId.Value);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log. Reason: {Error}",
                       result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                // CancellationToken은 HandleAsync에 여전히 유효함 (예: DB 조회 중 취소)
                _logger.LogWarning("Audit log recording was cancelled. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId);
                throw; 
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogUserJoinedAuditHandler. (User: {UserId}, Org: {OrgId})",
                    @event.UserId,
                    @event.OrganizationId);
            }
        }
    }
}

