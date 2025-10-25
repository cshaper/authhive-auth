// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/LogFirstLoginAuditHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// (수정) 올바른 FirstLoginEvent 모델을 처리하는 핸들러입니다.
// 목적: 사용자의 첫 로그인에 대한 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
using AuthHive.Core.Models.User.Events.Lifecycle; // (수정) 올바른 이벤트 모델 사용
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository;    // For IUserRepository (Optional, for username)
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Common; // For ServiceResult<T>
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity
using AuthHive.Core.Entities.User; // (User 엔티티 가정을 위해 추가)
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="FirstLoginEvent"/>를 처리하는 감사 로그 핸들러입니다.
    /// </summary>
    public class LogFirstLoginAuditHandler
        : IDomainEventHandler<FirstLoginEvent>
    {
        // 감사 로그는 중요하므로 비교적 높은 우선순위
        public int Priority => 150;
        public bool IsEnabled => true;

        private readonly IAuditLogService _auditLogService;
        private readonly IUserRepository _userRepository; // 사용자 이름 로깅 위해 추가 (선택적)
        private readonly ILogger<LogFirstLoginAuditHandler> _logger;

        public LogFirstLoginAuditHandler(
            IAuditLogService auditLogService,
            IUserRepository userRepository,
            ILogger<LogFirstLoginAuditHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository)); // userRepository 주입은 선택사항
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 첫 로그인 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(FirstLoginEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // (선택적) 사용자 이름 로깅. Username은 이벤트 자체에도 있음.
                // var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);
                // string userName = user?.Username ?? @event.Username ?? @event.UserId.ToString();
                string userName = @event.Username ?? @event.UserId.ToString(); // 이벤트의 Username 사용

                _logger.LogInformation(
                    "Recording audit log for first login of User {UserName} ({UserId}). Source: {Source}",
                    userName, @event.UserId, @event.RegistrationSource);

                // 2. 감사 로그 요청 DTO 생성 (수정된 이벤트 모델 반영)
                var details = new Dictionary<string, string?>
                {
                    { "RegistrationSource", @event.RegistrationSource },
                    { "IpAddress", @event.ClientIpAddress }, // BaseEvent에서 가져옴
                    { "UserAgent", @event.UserAgent }       // BaseEvent에서 가져옴
                    // { "LoginTime", @event.CreatedAt.ToString("o") } // LoginTime 대신 CreatedAt 사용 가능
                };

                var auditRequest = new CreateAuditLogRequest
                {
                    OrganizationId = @event.OrganizationId, // 로그인 컨텍스트의 OrgId (있을 경우)
                    ActionType = AuditActionType.Authentication, // 인증 액션
                    Action = "user.login.first", // 상세 액션: 첫 로그인
                    ResourceType = "User", // (수정) 리소스는 '사용자'
                    ResourceId = @event.UserId.ToString(), // (수정) 리소스 ID는 사용자 ID
                    IpAddress = @event.ClientIpAddress, // BaseEvent에서 가져옴
                    UserAgent = @event.UserAgent,       // BaseEvent에서 가져옴
                    Success = true,
                    Severity = AuditEventSeverity.Info, // 첫 로그인은 정보성 이벤트
                    RequestId = @event.CorrelationId.ToString(),
                    Metadata = JsonSerializer.Serialize(details)
                };

                // 3. 감사 로그 서비스의 CreateAsync 메서드 호출
                // (수정) 행위자: @event.UserId (첫 로그인은 사용자 본인이 수행)
                ServiceResult<AuditLogResponse> result = await _auditLogService.CreateAsync(
                    auditRequest,
                    @event.UserId // UserId를 performedByConnectedId 대신 사용 (ConnectedId 없음)
                                  // 서비스 구현 시 UserId를 ConnectedId로 변환하거나 null 처리 필요할 수 있음
                );

                // 4. 결과 확인
                if (result.IsSuccess)
                {
                    _logger.LogInformation(
                        "Audit log recorded successfully for first login. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    _logger.LogError(
                        "Failed to record audit log for first login. Reason: {Error}",
                        result.ErrorMessage ?? "Unknown error");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Audit log recording for first login was cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error in LogFirstLoginAuditHandler. (UserId: {UserId})",
                    @event.UserId);
                // 감사 로그 실패가 다른 핸들러에 영향을 주지 않도록 throw하지 않습니다.
            }
        }
    }
}

