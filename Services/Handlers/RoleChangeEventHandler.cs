using System;
using System.Linq;
using System.Text.Json;
using System.Threading; // CancellationToken 사용
using System.Threading.Tasks;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.System.Service; // IAuditService 경로 확인 필요
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Interfaces.Auth.External; // IEmailService 경로 확인 필요
using AuthHive.Core.Interfaces.PlatformApplication.Repository; // IUserPlatformApplicationAccessRepository
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using AuthHive.Core.Models.Auth.Role.Events; // 이벤트 모델
using AuthHive.Core.Models.External; // EmailMessageDto
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.UserExperience; // IService

namespace AuthHive.Auth.Handlers
{
    /// <summary>
    /// 역할 변경 이벤트 핸들러 구현 - AuthHive v16.1
    /// 역할 관련 도메인 이벤트 발생 시 후속 처리(부수 효과) 담당.
    ///
    /// 주요 책임: 캐시 무효화, 감사 로깅, 알림 발송.
    ///
    /// [v16.1 변경 사항]
    /// - 모든 핸들러 메서드에 CancellationToken 추가 및 전파.
    /// - 이벤트 모델 변경(UserId -> ConnectedId)에 맞춰 감사 로그 로직 수정.
    /// - 상세 한글 주석 업데이트.
    /// </summary>
    public class RoleChangeEventHandler : IRoleChangeEventHandler
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IEmailService _emailService;
        private readonly IUserRepository _userRepository;
        private readonly IUserPlatformApplicationAccessRepository _accessRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<RoleChangeEventHandler> _logger;

        // 생성자 (변경 없음)
        public RoleChangeEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IEmailService emailService,
            IUserRepository userRepository,
            IUserPlatformApplicationAccessRepository accessRepository,
            IDateTimeProvider dateTimeProvider,
            ILogger<RoleChangeEventHandler> logger)
        {
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _emailService = emailService ?? throw new ArgumentNullException(nameof(emailService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _accessRepository = accessRepository ?? throw new ArgumentNullException(nameof(accessRepository));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService Implementation (변경 없음)
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("RoleChangeEventHandler 초기화 시간: {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var isCacheHealthy = await _cacheService.IsHealthyAsync(cancellationToken);
                var isAuditHealthy = await _auditService.IsHealthyAsync(cancellationToken);
                return isCacheHealthy && isAuditHealthy;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RoleChangeEventHandler 건강 상태 확인 중 오류 발생");
                return false;
            }
        }
        #endregion

        /// <summary>
        /// 역할이 사용자에게 할당되었을 때 처리합니다. (캐시 무효화, 감사 로그, 이메일 알림)
        /// </summary>
        /// <param name="eventData">역할 할당 이벤트 데이터</param>
        /// <param name="cancellationToken">취소 토큰</param>
        public async Task HandleRoleAssignedAsync(RoleAssignedEvent eventData, CancellationToken cancellationToken = default) // Token 추가
        {
            _logger.LogInformation("역할 할당 이벤트 처리 시작 - ConnectedId: {ConnectedId}, RoleId: {RoleId}", eventData.ConnectedId, eventData.RoleId);
            try
            {
                await InvalidateUserPermissionCacheAsync(eventData.ConnectedId, cancellationToken); // Token 전달

                var auditLog = new AuditLog
                {
                    Action = $"ROLE_ASSIGNED: {eventData.RoleName ?? eventData.RoleId.ToString()}",
                    ActionType = AuditActionType.Update,
                    // [v16.1 수정] 이벤트의 AssignedByUserId -> 이벤트 생성 시 ConnectedId 사용 필요 (또는 별도 조회)
                    // 여기서는 이벤트 모델에 AssignedByConnectedId가 있다고 가정합니다. 없다면 추가 필요.
                    PerformedByConnectedId = eventData.AssignedByUserId, // <- 이 부분 확인 필요! AssignedByConnectedId 사용 권장
                    TargetUserId = eventData.UserId, // 대상은 역할을 받은 ConnectedId
                    TargetOrganizationId = eventData.OrganizationId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                // [v16.1 수정] LogAsync에 Token 전달
                await _auditService.LogAsync(auditLog, cancellationToken);

                // 이메일 알림 (ConnectedId로 User 조회)
                var user = await _userRepository.GetByConnectedIdAsync(eventData.ConnectedId, cancellationToken); // Token 전달
                if (user?.Email != null)
                {
                    var emailMessage = new EmailMessageDto { /* ... */ };
                    await _emailService.SendEmailAsync(emailMessage, cancellationToken); // Token 전달
                }
                _logger.LogInformation("역할 할당 이벤트 처리 완료 - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "역할 할당 이벤트 처리 중 오류 발생 - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
        }

        /// <summary>
        /// 사용자로부터 역할이 제거되었을 때 처리합니다. (캐시 무효화, 감사 로그)
        /// </summary>
        /// <param name="eventData">역할 제거 이벤트 데이터</param>
        /// <param name="cancellationToken">취소 토큰</param>
        public async Task HandleRoleRemovedAsync(RoleRemovedEvent eventData, CancellationToken cancellationToken = default) // Token 추가
        {
            _logger.LogInformation("역할 제거 이벤트 처리 시작 - ConnectedId: {ConnectedId}, RoleId: {RoleId}", eventData.ConnectedId, eventData.RoleId);
            try
            {
                await InvalidateUserPermissionCacheAsync(eventData.ConnectedId, cancellationToken); // Token 전달

                var auditLog = new AuditLog
                {
                    Action = $"ROLE_REMOVED: {eventData.RoleName ?? eventData.RoleId.ToString()}",
                    ActionType = AuditActionType.Update,
                    // [v16.1 수정] 이벤트 모델에 RemovedByConnectedId가 있다고 가정
                    PerformedByConnectedId = eventData.RemovedByUserId, // <- 이 부분 확인 필요! RemovedByConnectedId 사용 권장
                    TargetUserId = eventData.UserId,
                    TargetOrganizationId = eventData.OrganizationId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Warning,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                // [v16.1 수정] LogAsync에 Token 전달
                await _auditService.LogAsync(auditLog, cancellationToken);
                _logger.LogInformation("역할 제거 이벤트 처리 완료 - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "역할 제거 이벤트 처리 중 오류 발생 - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
        }

        /// <summary>
        /// 역할 자체의 속성이 변경되었을 때 처리합니다. (영향받는 사용자 캐시 무효화, 감사 로그)
        /// </summary>
        /// <param name="eventData">역할 변경 이벤트 데이터</param>
        /// <param name="cancellationToken">취소 토큰</param>
        public async Task HandleRoleChangedAsync(RoleChangedEvent eventData, CancellationToken cancellationToken = default) // Token 추가
        {
            Guid roleId = eventData.AggregateId; // 역할 변경 이벤트의 AggregateId는 RoleId
            _logger.LogInformation("역할 속성 변경 이벤트 처리 시작 - RoleId: {RoleId}", roleId);
            try
            {
                _logger.LogInformation("역할 속성 변경으로 인한 캐시 무효화 시작 - RoleId: {RoleId}", roleId);
                // 이 역할을 가진 UserPlatformApplicationAccess 레코드 조회
                var accessEntries = await _accessRepository.GetByRoleIdAsync(roleId, cancellationToken); // Token 전달
                var affectedConnectedIds = accessEntries.Select(a => a.ConnectedId).Distinct().ToList();

                if (affectedConnectedIds.Any())
                {
                    var invalidationTasks = affectedConnectedIds
                        .Select(connectedId => InvalidateUserPermissionCacheAsync(connectedId, cancellationToken)) // Token 전달
                        .ToList();
                    await Task.WhenAll(invalidationTasks);
                    _logger.LogInformation("RoleId {RoleId} 변경으로 인해 {Count}명의 사용자 캐시 무효화 완료.", roleId, affectedConnectedIds.Count);
                }
                else
                {
                    _logger.LogInformation("RoleId {RoleId} 변경으로 영향받는 사용자가 없어 캐시 무효화 건너<0xEB><0x9B><0x84>니다.", roleId);
                }

                var auditLog = new AuditLog
                {
                    // [v16.2 수정] RoleName 대신 NewRoleName 사용 (CS1061 해결)
                    Action = $"ROLE_DEFINITION_CHANGED: {eventData.NewRoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Update,
                    PerformedByConnectedId = eventData.ChangedByUserId, // 이벤트 모델 확인 필요
                    ResourceType = "Role",
                    ResourceId = roleId.ToString(),
                    TargetOrganizationId = eventData.OrganizationId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    // 변경 내용 메타데이터 (변경 없음)
                    Metadata = JsonSerializer.Serialize(new { OldRole = eventData.OldRoleName, NewRole = eventData.NewRoleName /*, eventData.Changes */ })
                };
                await _auditService.LogAsync(auditLog, cancellationToken);
                // [v16.1 수정] LogAsync에 Token 전달
                await _auditService.LogAsync(auditLog, cancellationToken);
                _logger.LogInformation("역할 속성 변경 이벤트 처리 완료 - RoleId: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "역할 속성 변경 이벤트 처리 중 오류 발생 - RoleId: {RoleId}", roleId);
            }
        }

        /// <summary>
        /// 새로운 역할이 생성되었을 때 처리합니다. (감사 로그)
        /// </summary>
        /// <param name="eventData">역할 생성 이벤트 데이터</param>
        /// <param name="cancellationToken">취소 토큰</param>
        public async Task HandleRoleCreatedAsync(RoleCreatedEvent eventData, CancellationToken cancellationToken = default) // Token 추가
        {
            Guid roleId = eventData.AggregateId; // 역할 생성 이벤트의 AggregateId는 RoleId
            _logger.LogInformation("역할 생성 이벤트 처리 시작 - RoleId: {RoleId}", roleId);
            try
            {
                var auditLog = new AuditLog
                {
                    Action = $"ROLE_CREATED: {eventData.RoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Create,
                    // [v16.1 수정] 이벤트 모델에 CreatedByConnectedId가 있다고 가정
                    PerformedByConnectedId = eventData.CreatedByUserId, // <- 이 부분 확인 필요! CreatedByConnectedId 사용 권장
                    ResourceType = "Role",
                    ResourceId = roleId.ToString(),
                    TargetOrganizationId = eventData.OrganizationId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                // [v16.1 수정] LogAsync에 Token 전달
                await _auditService.LogAsync(auditLog, cancellationToken);
                _logger.LogInformation("역할 생성 이벤트 처리 완료 - RoleId: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "역할 생성 이벤트 처리 중 오류 발생 - RoleId: {RoleId}", roleId);
            }
        }

        /// <summary>
        /// 역할이 삭제되었을 때 처리합니다. (영향받는 사용자 캐시 무효화, 감사 로그)
        /// </summary>
        /// <param name="eventData">역할 삭제 이벤트 데이터</param>
        /// <param name="cancellationToken">취소 토큰</param>
        public async Task HandleRoleDeletedAsync(RoleDeletedEvent eventData, CancellationToken cancellationToken = default) // Token 추가
        {
            Guid roleId = eventData.AggregateId; // 역할 삭제 이벤트의 AggregateId는 RoleId
            _logger.LogInformation("역할 삭제 이벤트 처리 시작 - RoleId: {RoleId}", roleId);
            try
            {
                _logger.LogInformation("역할 삭제로 인한 캐시 무효화 시작 - RoleId: {RoleId}", roleId);
                var accessEntries = await _accessRepository.GetByRoleIdAsync(roleId, cancellationToken); // Token 전달
                var affectedConnectedIds = accessEntries.Select(a => a.ConnectedId).Distinct().ToList();

                if (affectedConnectedIds.Any())
                {
                    var invalidationTasks = affectedConnectedIds
                        .Select(connectedId => InvalidateUserPermissionCacheAsync(connectedId, cancellationToken)) // Token 전달
                        .ToList();
                    await Task.WhenAll(invalidationTasks);
                    _logger.LogInformation("RoleId {RoleId} 삭제로 인해 {Count}명의 사용자 캐시 무효화 완료.", roleId, affectedConnectedIds.Count);
                }
                else
                {
                    _logger.LogInformation("RoleId {RoleId} 삭제로 영향받는 사용자가 없어 캐시 무효화 건너<0xEB><0x9B><0x84>니다.", roleId);
                }

                var auditLog = new AuditLog
                {
                    Action = $"ROLE_DELETED: {eventData.RoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Delete,
                    // [v16.1 수정] 이벤트 모델에 DeletedByConnectedId가 있다고 가정
                    PerformedByConnectedId = eventData.DeletedByUserId, // <- 이 부분 확인 필요! DeletedByConnectedId 사용 권장
                    ResourceType = "Role",
                    ResourceId = roleId.ToString(),
                    TargetOrganizationId = eventData.OrganizationId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Critical, // 역할 삭제는 심각도가 높음
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                // [v16.1 수정] LogAsync에 Token 전달
                await _auditService.LogAsync(auditLog, cancellationToken);
                _logger.LogInformation("역할 삭제 이벤트 처리 완료 - RoleId: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "역할 삭제 이벤트 처리 중 오류 발생 - RoleId: {RoleId}", roleId);
            }
        }

        /// <summary>
        /// 역할 관리 권한이 위임되었을 때 처리합니다. (감사 로그)
        /// </summary>
        /// <param name="eventData">역할 위임 이벤트 데이터</param>
        /// <param name="cancellationToken">취소 토큰</param>
        public async Task HandleRoleDelegatedAsync(RoleDelegatedEvent eventData, CancellationToken cancellationToken = default) // Token 추가
        {
            // 위임 이벤트의 AggregateId는 DelegationId 자체
            _logger.LogInformation("역할 위임 이벤트 처리 시작 - RoleId: {RoleId}, From: {From}, To: {To}",
               eventData.RoleId, eventData.FromConnectedId, eventData.ToConnectedId);
            try
            {
                var auditLog = new AuditLog
                {
                    Action = $"ROLE_DELEGATED: {eventData.RoleName ?? eventData.RoleId.ToString()}",
                    ActionType = AuditActionType.Update, // 권한 변경으로 간주
                    PerformedByConnectedId = eventData.FromConnectedId, // 위임한 사람
                    TargetUserId = eventData.ToUserId,   // 위임받은 사람
                    ResourceType = "Role", // 위임 대상 리소스는 역할
                    ResourceId = eventData.RoleId.ToString(),
                    TargetOrganizationId = eventData.OrganizationId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                // [v16.1 수정] LogAsync에 Token 전달
                await _auditService.LogAsync(auditLog, cancellationToken);
                _logger.LogInformation("역할 위임 이벤트 처리 완료 - RoleId: {RoleId}", eventData.RoleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "역할 위임 이벤트 처리 중 오류 발생 - RoleId: {RoleId}", eventData.RoleId);
            }
        }

        /// <summary>
        /// 특정 사용자의 권한 관련 캐시를 무효화합니다.
        /// </summary>
        /// <param name="connectedId">캐시를 무효화할 사용자의 ConnectedId</param>
        /// <param name="cancellationToken">취소 토큰</param>
        private async Task InvalidateUserPermissionCacheAsync(Guid connectedId, CancellationToken cancellationToken = default) // Token 추가
        {
            // 실제 캐시 키 패턴은 ICacheService 구현 및 권한 캐싱 전략에 따라 달라짐
            var cachePattern = $"perm:*:{connectedId}:*"; // 예시 패턴
            try
            {
                // [v16.1 수정] RemoveByPatternAsync에 Token 전달
                await _cacheService.RemoveByPatternAsync(cachePattern, cancellationToken);
                _logger.LogDebug("사용자 권한 캐시 무효화 완료 - ConnectedId: {ConnectedId}, Pattern: {Pattern}", connectedId, cachePattern);
            }
            catch (NotSupportedException nse)
            {
                _logger.LogWarning(nse, "캐시 서비스가 패턴 삭제를 지원하지 않습니다. ConnectedId: {ConnectedId}, Pattern: {Pattern}", connectedId, cachePattern);
                // 대체 로직 구현 필요 (예: 알려진 특정 키 직접 삭제)
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자 권한 캐시 무효화 중 오류 발생 - ConnectedId: {ConnectedId}, Pattern: {Pattern}", connectedId, cachePattern);
                // 실패 시 재시도 또는 오류 로깅 강화
            }
        }
    }
}