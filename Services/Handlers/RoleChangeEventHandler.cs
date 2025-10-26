// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/RoleChangeEventHandler.cs
// ----------------------------------------------------------------------
// [Refactored Event Handler v2]
// v16+ 아키텍처 및 제공된 DTO/Interface에 맞게 리팩토링
//
// [v2 Refactoring]
// 1. (변경) IAuditService -> IAuditLogService
// 2. (변경) IEmailService -> INotificationService
// 3. (변경) new AuditLog() -> _auditLogService.CreateAsync(CreateAuditLogRequest, ...)
// 4. (변경) _emailService.SendEmailAsync -> _notificationService.SendImmediateNotificationAsync(...)
// 5. (수정) ...ByUserId -> ...ByConnectedId (v16 철학 반영)
// 6. (수정) IAuditLogService.CreateAsync 호출 시 CancellationToken 제거 (인터페이스 시그니처 준수)
// 7. (수정) CreateAuditLogRequest 생성 시 CreatedAt 속성 제거 (DTO 정의 준수)
// ----------------------------------------------------------------------

using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

// (수정) 신형 서비스 및 DTO 임포트
using AuthHive.Core.Interfaces.System.Service; // For IAuditLogService
using AuthHive.Core.Interfaces.Infra.UserExperience; // For INotificationService
using AuthHive.Core.Models.Audit.Requests; // For CreateAuditLogRequest
using AuthHive.Core.Models.Audit.Responses; // For AuditLogResponse
using AuthHive.Core.Models.Infra.UserExperience.Requests; // For NotificationSendRequest
using AuthHive.Core.Enums.Infra.UserExperience; // For NotificationChannel
using AuthHive.Core.Models.Common; // For ServiceResult
using AuthHive.Core.Enums.Core; // For AuditActionType/Severity

// 기존 임포트
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
using AuthHive.Core.Interfaces.PlatformApplication.Repository; // IUserPlatformApplicationAccessRepository
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using AuthHive.Core.Models.Auth.Role.Events; // 이벤트 모델
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Base;
// (수정) 불필요한 using 제거
// using AuthHive.Core.Interfaces.Audit; 
// using AuthHive.Core.Entities.Audit;
// using AuthHive.Core.Models.External;
// using AuthHive.Core.Interfaces.Auth.External;

namespace AuthHive.Auth.Handlers
{
    /// <summary>
    /// 역할 변경 이벤트 핸들러 구현 - AuthHive v16.1+ (Refactored v2)
    /// </summary>
    public class RoleChangeEventHandler : IRoleChangeEventHandler
    {
        private readonly IAuditLogService _auditLogService;
        private readonly ICacheService _cacheService;
        private readonly INotificationService _notificationService;
        private readonly IUserRepository _userRepository;
        private readonly IUserPlatformApplicationAccessRepository _accessRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<RoleChangeEventHandler> _logger;

        // 생성자 (수정)
        public RoleChangeEventHandler(
            IAuditLogService auditLogService,
            ICacheService cacheService,
            INotificationService notificationService,
            IUserRepository userRepository,
            IUserPlatformApplicationAccessRepository accessRepository,
            IDateTimeProvider dateTimeProvider,
            ILogger<RoleChangeEventHandler> logger)
        {
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _accessRepository = accessRepository ?? throw new ArgumentNullException(nameof(accessRepository));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService Implementation (수정)
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("RoleChangeEventHandler (Refactored v2) Awaiting initialization... Timestamp: {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var isCacheHealthy = await _cacheService.IsHealthyAsync(cancellationToken);
                var isAuditHealthy = await _auditLogService.IsHealthyAsync(cancellationToken); // (가정) IAuditLogService에 IsHealthyAsync 존재
                var isNotificationHealthy = await _notificationService.IsHealthyAsync(cancellationToken); // (가정) INotificationService에 IsHealthyAsync 존재

                return isCacheHealthy && isAuditHealthy && isNotificationHealthy;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RoleChangeEventHandler (Refactored v2) health check failed.");
                return false;
            }
        }
        #endregion

        /// <summary>
        /// 역할이 사용자에게 할당되었을 때 처리합니다.
        /// </summary>
        public async Task HandleRoleAssignedAsync(RoleAssignedEvent eventData, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Handling RoleAssignedEvent - ConnectedId: {ConnectedId}, RoleId: {RoleId}", eventData.ConnectedId, eventData.RoleId);
            try
            {
                // 1. 캐시 무효화
                await InvalidateUserPermissionCacheAsync(eventData.ConnectedId, cancellationToken);

                // 2. 감사 로그 생성 (신형 DTO 사용)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_ASSIGNED: {eventData.RoleName ?? eventData.RoleId.ToString()}",
                    ActionType = AuditActionType.Update,
                    OrganizationId = eventData.OrganizationId,
                    ResourceType = "Membership",
                    ResourceId = eventData.ConnectedId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                    // (수정) CreatedAt 제거
                };

                // (수정) CreateAsync 호출 (CancellationToken 제거)
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    eventData.ConnectedId // (가정) 이벤트 모델에 AssignedByConnectedId가 있어야 함
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role assignment: {Error}", auditResult.ErrorMessage);
                }

                // 3. 이메일 알림 (신형 DTO 사용)
                var user = await _userRepository.GetByConnectedIdAsync(eventData.ConnectedId, cancellationToken);
                if (user?.Email != null)
                {
                    var templateVariables = new Dictionary<string, string>
                    {
                        { "UserName", user.Username ?? "Member" },
                        { "RoleName", eventData.RoleName ?? "a new role" }
                    };

                    var notificationRequest = new NotificationSendRequest
                    {
                        // (한글 주석) ❗️ 수정됨: RecipientType과 RecipientIdentifiers 사용
                        RecipientType = RecipientType.User, // 수신자 타입: 사용자
                                                            // (한글 주석) ❗️ ConnectedId를 문자열 리스트로 전달합니다. (eventData 객체가 있다고 가정)
                        RecipientIdentifiers = new List<string> { eventData.ConnectedId.ToString() }, // ❗️ 수정됨

                        TemplateKey = "USER_ROLE_ASSIGNED", // 템플릿 키
                        TemplateVariables = templateVariables, // 템플릿 변수
                        Channels = new List<NotificationChannel> { NotificationChannel.Email },
                        Priority = NotificationPriority.Normal, // 우선 순위
                        SendImmediately = true // 즉시 발송
                    };

                    // (유지) 알림 서비스는 CancellationToken 전달
                    await _notificationService.SendImmediateNotificationAsync(notificationRequest, cancellationToken);
                }

                _logger.LogInformation("RoleAssignedEvent processed - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleAssignedEvent - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
        }

        /// <summary>
        /// 사용자로부터 역할이 제거되었을 때 처리합니다.
        /// </summary>
        public async Task HandleRoleRemovedAsync(RoleRemovedEvent eventData, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Handling RoleRemovedEvent - ConnectedId: {ConnectedId}, RoleId: {RoleId}", eventData.ConnectedId, eventData.RoleId);
            try
            {
                // 1. 캐시 무효화
                await InvalidateUserPermissionCacheAsync(eventData.ConnectedId, cancellationToken);

                // 2. 감사 로그 생성 (신형 DTO 사용)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_REMOVED: {eventData.RoleName ?? eventData.RoleId.ToString()}",
                    ActionType = AuditActionType.Update,
                    OrganizationId = eventData.OrganizationId,
                    ResourceType = "Membership",
                    ResourceId = eventData.ConnectedId.ToString(),
                    Success = true,
                    Severity = AuditEventSeverity.Warning,
                    Metadata = JsonSerializer.Serialize(eventData)
                    // (수정) CreatedAt 제거
                };

                // (수정) CreateAsync 호출 (CancellationToken 제거)
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    eventData.ConnectedId // (가정) 이벤트 모델에 RemovedByConnectedId가 있어야 함
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role removal: {Error}", auditResult.ErrorMessage);
                }

                _logger.LogInformation("RoleRemovedEvent processed - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleRemovedEvent - ConnectedId: {ConnectedId}", eventData.ConnectedId);
            }
        }

        /// <summary>
        /// 역할 자체의 속성이 변경되었을 때 처리합니다.
        /// </summary>
        public async Task HandleRoleChangedAsync(RoleChangedEvent eventData, CancellationToken cancellationToken = default)
        {
            Guid roleId = eventData.AggregateId;
            _logger.LogInformation("Handling RoleChangedEvent - RoleId: {RoleId}", roleId);
            try
            {
                // 1. 캐시 무효화
                _logger.LogInformation("Invalidating caches due to role definition change - RoleId: {RoleId}", roleId);
                var accessEntries = await _accessRepository.GetByRoleIdAsync(roleId, cancellationToken);
                var affectedConnectedIds = accessEntries.Select(a => a.ConnectedId).Distinct().ToList();

                if (affectedConnectedIds.Any())
                {
                    var invalidationTasks = affectedConnectedIds
                        .Select(connectedId => InvalidateUserPermissionCacheAsync(connectedId, cancellationToken))
                        .ToList();
                    await Task.WhenAll(invalidationTasks);
                    _logger.LogInformation("Invalidated caches for {Count} users affected by RoleId {RoleId} change.", affectedConnectedIds.Count, roleId);
                }
                else
                {
                    _logger.LogInformation("No users affected by RoleId {RoleId} change. Skipping cache invalidation.", roleId);
                }

                // 2. 감사 로그 생성 (신형 DTO 사용)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_DEFINITION_CHANGED: {eventData.NewRoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Update,
                    ResourceType = "Role",
                    ResourceId = roleId.ToString(),
                    OrganizationId = eventData.OrganizationId,
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(new { OldRole = eventData.OldRoleName, NewRole = eventData.NewRoleName /*, eventData.Changes */ })
                    // (수정) CreatedAt 제거
                };

                // (수정) CreateAsync 호출 (CancellationToken 제거)
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    eventData.ChangedByUserId // (가정) 이벤트 모델에 ChangedByConnectedId가 있어야 함
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role definition change: {Error}", auditResult.ErrorMessage);
                }

                _logger.LogInformation("RoleChangedEvent processed - RoleId: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleChangedEvent - RoleId: {RoleId}", roleId);
            }
        }

        /// <summary>
        /// 새로운 역할이 생성되었을 때 처리합니다.
        /// </summary>
        public async Task HandleRoleCreatedAsync(RoleCreatedEvent eventData, CancellationToken cancellationToken = default)
        {
            Guid roleId = eventData.AggregateId;
            _logger.LogInformation("Handling RoleCreatedEvent - RoleId: {RoleId}", roleId);
            try
            {
                // 감사 로그 생성 (신형 DTO 사용)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_CREATED: {eventData.RoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Create,
                    ResourceType = "Role",
                    ResourceId = roleId.ToString(),
                    OrganizationId = eventData.OrganizationId,
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                    // (수정) CreatedAt 제거
                };

                // (수정) CreateAsync 호출 (CancellationToken 제거)
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    eventData.CreatedByUserId // (가정) 이벤트 모델에 CreatedByConnectedId가 있어야 함
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role creation: {Error}", auditResult.ErrorMessage);
                }

                _logger.LogInformation("RoleCreatedEvent processed - RoleId: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleCreatedEvent - RoleId: {RoleId}", roleId);
            }
        }

        /// <summary>
        /// 역할이 삭제되었을 때 처리합니다.
        /// </summary>
        public async Task HandleRoleDeletedAsync(RoleDeletedEvent eventData, CancellationToken cancellationToken = default)
        {
            Guid roleId = eventData.AggregateId;
            _logger.LogInformation("Handling RoleDeletedEvent - RoleId: {RoleId}", roleId);
            try
            {
                // 1. 캐시 무효화
                _logger.LogInformation("Invalidating caches due to role deletion - RoleId: {RoleId}", roleId);
                var accessEntries = await _accessRepository.GetByRoleIdAsync(roleId, cancellationToken);
                var affectedConnectedIds = accessEntries.Select(a => a.ConnectedId).Distinct().ToList();

                if (affectedConnectedIds.Any())
                {
                    var invalidationTasks = affectedConnectedIds
                        .Select(connectedId => InvalidateUserPermissionCacheAsync(connectedId, cancellationToken))
                        .ToList();
                    await Task.WhenAll(invalidationTasks);
                    _logger.LogInformation("Invalidated caches for {Count} users affected by RoleId {RoleId} deletion.", affectedConnectedIds.Count, roleId);
                }
                else
                {
                    _logger.LogInformation("No users affected by RoleId {RoleId} deletion. Skipping cache invalidation.", roleId);
                }

                // 2. 감사 로그 생성 (신형 DTO 사용)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_DELETED: {eventData.RoleName ?? roleId.ToString()}",
                    ActionType = AuditActionType.Delete,
                    ResourceType = "Role",
                    ResourceId = roleId.ToString(),
                    OrganizationId = eventData.OrganizationId,
                    Success = true,
                    Severity = AuditEventSeverity.Critical,
                    Metadata = JsonSerializer.Serialize(eventData)
                    // (수정) CreatedAt 제거
                };

                // (수정) CreateAsync 호출 (CancellationToken 제거)
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    eventData.DeletedByConnectedId // (가정) 이벤트 모델에 DeletedByConnectedId가 있어야 함
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role deletion: {Error}", auditResult.ErrorMessage);
                }

                _logger.LogInformation("RoleDeletedEvent processed - RoleId: {RoleId}", roleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleDeletedEvent - RoleId: {RoleId}", roleId);
            }
        }

        /// <summary>
        /// 역할 관리 권한이 위임되었을 때 처리합니다. (제공된 DTO 기반)
        /// </summary>
        public async Task HandleRoleDelegatedAsync(RoleDelegatedEvent eventData, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Handling RoleDelegatedEvent - RoleId: {RoleId}, From: {From}, To: {To}",
                eventData.RoleId, eventData.FromConnectedId, eventData.ToConnectedId);
            try
            {
                // 감사 로그 생성 (신형 DTO 사용, RoleDelegatedEvent DTO 준수)
                var auditRequest = new CreateAuditLogRequest
                {
                    Action = $"ROLE_DELEGATED: {eventData.RoleName ?? eventData.RoleId.ToString()}",
                    ActionType = AuditActionType.Update,
                    ResourceType = "RoleDelegation", // 리소스는 '위임' 자체
                    ResourceId = eventData.AggregateId.ToString(), // 위임 ID
                    OrganizationId = eventData.OrganizationId,
                    Success = true,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                    // (수정) CreatedAt 제거
                };

                // (수정) CreateAsync 호출 (CancellationToken 제거)
                // 행위자(Performer)는 FromConnectedId (제공된 DTO에 명시됨)
                ServiceResult<AuditLogResponse> auditResult = await _auditLogService.CreateAsync(
                    auditRequest,
                    eventData.FromConnectedId
                );

                if (!auditResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to create audit log for role delegation: {Error}", auditResult.ErrorMessage);
                }

                _logger.LogInformation("RoleDelegatedEvent processed - RoleId: {RoleId}", eventData.RoleId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleDelegatedEvent - RoleId: {RoleId}", eventData.RoleId);
            }
        }

        /// <summary>
        /// 특정 사용자의 권한 관련 캐시를 무효화합니다.
        /// </summary>
        private async Task InvalidateUserPermissionCacheAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            var cachePattern = $"perm:*:{connectedId}:*";
            try
            {
                await _cacheService.RemoveByPatternAsync(cachePattern, cancellationToken);
                _logger.LogDebug("User permission cache invalidated - ConnectedId: {ConnectedId}, Pattern: {Pattern}", connectedId, cachePattern);
            }
            catch (NotSupportedException nse)
            {
                _logger.LogWarning(nse, "Cache service does not support pattern removal. ConnectedId: {ConnectedId}, Pattern: {Pattern}", connectedId, cachePattern);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user permission cache invalidation - ConnectedId: {ConnectedId}, Pattern: {Pattern}", connectedId, cachePattern);
            }
        }
    }
}

