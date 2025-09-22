using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Infra.Monitoring;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Infra.Monitoring;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Infra.Monitoring;
using AuthHive.Core.Constants.Auth;
using Newtonsoft.Json;
using static AuthHive.Core.Enums.Auth.PermissionEnums;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Infra.Security;

namespace AuthHive.Auth.Services.Handlers
{
    /// <summary>
    /// 권한 변경 이벤트 핸들러 구현체 - AuthHive v15 최종본
    /// 권한 관련 모든 변경사항을 처리하고 감사 로그를 생성하며 관련자에게 알림을 발송
    /// </summary>
    public class PermissionChangeEventHandler : IPermissionChangeEventHandler
    {
        #region Fields
        
        private readonly ILogger<PermissionChangeEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly INotificationService _notificationService;
        private readonly IPermissionValidationLogRepository _permissionValidationLogRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IUserRepository _userRepository;
        private readonly IDistributedCache _distributedCache;
        private readonly IMemoryCache _memoryCache;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ISecurityEventService _securityEventService;
        private readonly IPermissionService _permissionService;
        
        #endregion

        #region Constructor

        public PermissionChangeEventHandler(
            ILogger<PermissionChangeEventHandler> logger,
            IAuditService auditService,
            INotificationService notificationService,
            IPermissionValidationLogRepository permissionValidationLogRepository,
            IConnectedIdRepository connectedIdRepository,
            IUserRepository userRepository,
            IDistributedCache distributedCache,
            IMemoryCache memoryCache,
            IUnitOfWork unitOfWork,
            ISecurityEventService securityEventService,
            IPermissionService permissionService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _notificationService = notificationService ?? throw new ArgumentNullException(nameof(notificationService));
            _permissionValidationLogRepository = permissionValidationLogRepository ?? throw new ArgumentNullException(nameof(permissionValidationLogRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
            _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _securityEventService = securityEventService ?? throw new ArgumentNullException(nameof(securityEventService));
            _permissionService = permissionService ?? throw new ArgumentNullException(nameof(permissionService));
        }

        #endregion

        #region IPermissionChangeEventHandler Implementation

        /// <summary>
        /// 권한 부여 이벤트 처리
        /// </summary>
        public async Task HandlePermissionGrantedAsync(PermissionGrantedEvent eventData)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionGrantedEvent");
                return;
            }

            try
            {
                _logger.LogInformation(
                    "Processing permission granted event: User {UserId} granted permission {Scope} by {GrantedBy}",
                    eventData.UserId, eventData.PermissionScope, eventData.GrantedByUserId);

                // 1. 권한 정보 조회
                var permissionResult = await _permissionService.GetByScopeAsync(eventData.PermissionScope);
                if (!permissionResult.IsSuccess || permissionResult.Data == null)
                {
                    _logger.LogWarning("Permission {Scope} not found in system", eventData.PermissionScope);
                    return;
                }

                var permission = permissionResult.Data;

                // 2. 캐시 무효화
                await InvalidatePermissionCacheAsync(eventData.UserId, eventData.PermissionScope);

                // 3. 감사 로그 생성
                await _auditService.LogActionAsync(
                    eventData.GrantedByUserId,
                    $"Granted permission '{permission.Name}' to user",
                    AuditActionType.Create,
                    "Permission",
                    eventData.PermissionScope,
                    true,
                    JsonConvert.SerializeObject(new
                    {
                        TargetUserId = eventData.UserId,
                        ConnectedId = eventData.ConnectedId,
                        PermissionScope = eventData.PermissionScope,
                        PermissionName = permission.Name,
                        ExpiresAt = eventData.ExpiresAt,
                        Reason = eventData.Reason,
                        GrantedAt = eventData.GrantedAt
                    }));

                // 4. 권한 변경 로그
                await _auditService.LogPermissionChangeAsync(
                    "User",
                    eventData.UserId.ToString(),
                    eventData.PermissionScope,
                    "GRANT",
                    eventData.ConnectedId ?? eventData.UserId,
                    eventData.GrantedByUserId);

                // 5. 보안 이벤트 기록
                var securityEvent = new SecurityEvent
                {
                    EventType = SecurityEventType.PermissionGranted,
                    Severity = SecuritySeverityLevel.Info,
                    TriggeringConnectedId = eventData.ConnectedId,
                    TargetConnectedId = eventData.ConnectedId,
                    EventDescription = $"Permission {eventData.PermissionScope} granted to user {eventData.UserId}",
                    ResourceType = "Permission",
                    ResourceId = permission.Id,
                    AttemptedAction = "GRANT",
                    OccurredAt = DateTime.UtcNow,
                    AdditionalContext = JsonConvert.SerializeObject(new Dictionary<string, object>
                    {
                        ["permissionScope"] = eventData.PermissionScope,
                        ["grantedBy"] = eventData.GrantedByUserId,
                        ["expiresAt"] = eventData.ExpiresAt?.ToString() ?? "Never",
                        ["reason"] = eventData.Reason ?? "No reason provided"
                    })
                };

                await _securityEventService.RecordEventAsync(securityEvent);

                // 6. 권한 검증 로그 생성 (기존 PermissionValidationResult enum 사용)
                var validationLog = new PermissionValidationLog
                {
                    ConnectedId = eventData.ConnectedId ?? eventData.UserId,
                    RequestedScope = eventData.PermissionScope,
                    IsAllowed = true,
                    ValidationResult = PermissionValidationResult.Granted,
                    Timestamp = DateTime.UtcNow,
                    RequestContext = JsonConvert.SerializeObject(new { EventType = "PermissionGranted" })
                };

                await _permissionValidationLogRepository.AddAsync(validationLog);
                await _unitOfWork.SaveChangesAsync();

                // 7. 사용자 알림
                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "새로운 권한이 부여되었습니다",
                    GenerateGrantNotificationMessage(permission.Name, eventData.Reason, eventData.ExpiresAt));

                _logger.LogInformation(
                    "Successfully processed permission granted event for user {UserId}, permission {Scope}",
                    eventData.UserId, eventData.PermissionScope);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error processing permission granted event for user {UserId}, permission {Scope}",
                    eventData.UserId, eventData.PermissionScope);

                await LogFailureAsync(
                    "PERMISSION_GRANT_FAILED",
                    eventData.GrantedByUserId,
                    ex.Message,
                    eventData);

                throw;
            }
        }

        /// <summary>
        /// 권한 취소 이벤트 처리
        /// </summary>
        public async Task HandlePermissionRevokedAsync(PermissionRevokedEvent eventData)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionRevokedEvent");
                return;
            }

            try
            {
                _logger.LogInformation(
                    "Processing permission revoked event: User {UserId} permission {Scope} revoked by {RevokedBy}",
                    eventData.UserId, eventData.PermissionScope, eventData.RevokedByUserId);

                // 1. 권한 정보 조회
                var permissionResult = await _permissionService.GetByScopeAsync(eventData.PermissionScope);
                var permissionName = permissionResult.IsSuccess && permissionResult.Data != null
                    ? permissionResult.Data.Name
                    : eventData.PermissionScope;

                // 2. 캐시 무효화
                await InvalidatePermissionCacheAsync(eventData.UserId, eventData.PermissionScope);

                // 3. 감사 로그
                await _auditService.LogActionAsync(
                    eventData.RevokedByUserId,
                    $"Revoked permission '{permissionName}' from user",
                    AuditActionType.Delete,
                    "Permission",
                    eventData.PermissionScope,
                    true,
                    JsonConvert.SerializeObject(new
                    {
                        TargetUserId = eventData.UserId,
                        ConnectedId = eventData.ConnectedId,
                        PermissionScope = eventData.PermissionScope,
                        Reason = eventData.Reason,
                        RevokedAt = eventData.RevokedAt
                    }));

                // 4. 권한 변경 로그
                await _auditService.LogPermissionChangeAsync(
                    "User",
                    eventData.UserId.ToString(),
                    eventData.PermissionScope,
                    "REVOKE",
                    eventData.ConnectedId ?? eventData.UserId,
                    eventData.RevokedByUserId);

                // 5. 보안 이벤트 기록
                var securityEvent = new SecurityEvent
                {
                    EventType = SecurityEventType.PermissionRevoked,
                    Severity = SecuritySeverityLevel.Warning,
                    TriggeringConnectedId = eventData.ConnectedId,
                    TargetConnectedId = eventData.ConnectedId,
                    EventDescription = $"Permission {eventData.PermissionScope} revoked from user {eventData.UserId}",
                    ResourceType = "Permission",
                    AttemptedAction = "REVOKE",
                    OccurredAt = DateTime.UtcNow,
                    AdditionalContext = JsonConvert.SerializeObject(new Dictionary<string, object>
                    {
                        ["permissionScope"] = eventData.PermissionScope,
                        ["revokedBy"] = eventData.RevokedByUserId,
                        ["reason"] = eventData.Reason ?? "No reason provided"
                    })
                };

                await _securityEventService.RecordEventAsync(securityEvent);

                // 6. 사용자 알림
                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "권한이 취소되었습니다",
                    GenerateRevokeNotificationMessage(permissionName, eventData.Reason));

                _logger.LogInformation(
                    "Successfully processed permission revoked event for user {UserId}",
                    eventData.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error processing permission revoked event for user {UserId}, permission {Scope}",
                    eventData.UserId, eventData.PermissionScope);

                await LogFailureAsync(
                    "PERMISSION_REVOKE_FAILED",
                    eventData.RevokedByUserId,
                    ex.Message,
                    eventData);

                throw;
            }
        }

        /// <summary>
        /// 권한 변경 이벤트 처리
        /// </summary>
        public async Task HandlePermissionModifiedAsync(PermissionModifiedEvent eventData)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionModifiedEvent");
                return;
            }

            try
            {
                _logger.LogInformation(
                    "Processing permission modified event: Permission {PermissionId} modified by {ModifiedBy}",
                    eventData.PermissionId, eventData.ModifiedByUserId);

                // 1. 변경 내역 생성
                var changes = BuildChangeList(eventData.OldValues, eventData.NewValues);

                // 2. 감사 로그
                await _auditService.LogActionAsync(
                    eventData.ModifiedByUserId,
                    $"Modified permission '{eventData.PermissionScope}'",
                    AuditActionType.Update,
                    "Permission",
                    eventData.PermissionId.ToString(),
                    true,
                    JsonConvert.SerializeObject(new
                    {
                        PermissionScope = eventData.PermissionScope,
                        Changes = changes,
                        ModifiedAt = eventData.ModifiedAt,
                        AffectedUserCount = eventData.AffectedUserIds?.Count ?? 0
                    }));

                // 3. 영향받는 사용자들의 캐시 무효화 및 알림
                if (eventData.AffectedUserIds != null && eventData.AffectedUserIds.Any())
                {
                    var tasks = new List<Task>();

                    foreach (var userId in eventData.AffectedUserIds)
                    {
                        tasks.Add(InvalidatePermissionCacheAsync(userId, eventData.PermissionScope));
                        tasks.Add(_notificationService.SendSecurityAlertAsync(
                            userId,
                            "권한이 변경되었습니다",
                            $"'{eventData.PermissionScope}' 권한이 변경되었습니다.\n변경 사항: {string.Join(", ", changes)}"));
                    }

                    await Task.WhenAll(tasks);
                }

                // 4. 보안 이벤트 기록
                var securityEvent = new SecurityEvent
                {
                    EventType = SecurityEventType.PermissionModified,
                    Severity = SecuritySeverityLevel.Info,
                    TriggeringConnectedId = eventData.ModifiedByConnectedId,
                    EventDescription = $"Permission {eventData.PermissionScope} modified",
                    ResourceType = "Permission",
                    ResourceId = eventData.PermissionId,
                    AttemptedAction = "MODIFY",
                    OccurredAt = DateTime.UtcNow,
                    AdditionalContext = JsonConvert.SerializeObject(new Dictionary<string, object>
                    {
                        ["changes"] = changes,
                        ["affectedUserCount"] = eventData.AffectedUserIds?.Count ?? 0
                    })
                };

                await _securityEventService.RecordEventAsync(securityEvent);

                _logger.LogInformation(
                    "Successfully processed permission modified event for permission {PermissionId}",
                    eventData.PermissionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error processing permission modified event for permission {PermissionId}",
                    eventData.PermissionId);

                await LogFailureAsync(
                    "PERMISSION_MODIFY_FAILED",
                    eventData.ModifiedByUserId,
                    ex.Message,
                    eventData);

                throw;
            }
        }

        /// <summary>
        /// 권한 만료 이벤트 처리
        /// </summary>
        public async Task HandlePermissionExpiredAsync(PermissionExpiredEvent eventData)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionExpiredEvent");
                return;
            }

            try
            {
                // 단일 권한 만료 처리
                var permissionScope = !string.IsNullOrEmpty(eventData.PermissionScope) 
                    ? eventData.PermissionScope 
                    : eventData.ExpiredPermissions?.FirstOrDefault() ?? string.Empty;

                _logger.LogInformation(
                    "Processing permission expired event: User {UserId} permission {Scope} expired",
                    eventData.UserId, permissionScope);

                // 1. 캐시 무효화
                if (!string.IsNullOrEmpty(permissionScope))
                {
                    await InvalidatePermissionCacheAsync(eventData.UserId, permissionScope);
                }

                // 다중 권한 만료 처리
                if (eventData.ExpiredPermissions != null && eventData.ExpiredPermissions.Any())
                {
                    foreach (var expiredPermission in eventData.ExpiredPermissions)
                    {
                        await InvalidatePermissionCacheAsync(eventData.UserId, expiredPermission);
                    }
                }

                // 2. 감사 로그
                await _auditService.LogActionAsync(
                    eventData.UserId,
                    $"Permission(s) expired",
                    AuditActionType.Update,
                    "Permission",
                    permissionScope,
                    true,
                    JsonConvert.SerializeObject(new
                    {
                        UserId = eventData.UserId,
                        ConnectedId = eventData.ConnectedId,
                        ExpiredPermissions = eventData.ExpiredPermissions ?? new List<string> { permissionScope },
                        ExpiredAt = eventData.ExpiredAt,
                        OriginallyGrantedAt = eventData.OriginallyGrantedAt,
                        OriginallyGrantedBy = eventData.OriginallyGrantedBy,
                        IsAutoExpired = eventData.IsAutoExpired
                    }));

                // 3. 보안 이벤트
                var securityEvent = new SecurityEvent
                {
                    EventType = SecurityEventType.PermissionExpired,
                    Severity = SecuritySeverityLevel.Info,
                    TriggeringConnectedId = eventData.ConnectedId,
                    TargetConnectedId = eventData.ConnectedId,
                    EventDescription = $"Permission(s) expired for user {eventData.UserId}",
                    ResourceType = "Permission",
                    AttemptedAction = "EXPIRE",
                    OccurredAt = eventData.ExpiredAt,
                    AdditionalContext = JsonConvert.SerializeObject(new Dictionary<string, object>
                    {
                        ["expiredPermissions"] = eventData.ExpiredPermissions ?? new List<string> { permissionScope },
                        ["expiredAt"] = eventData.ExpiredAt,
                        ["isAutoExpired"] = eventData.IsAutoExpired
                    })
                };

                await _securityEventService.RecordEventAsync(securityEvent);

                // 4. 사용자 알림
                var permissionsList = eventData.ExpiredPermissions?.Any() == true
                    ? string.Join(", ", eventData.ExpiredPermissions)
                    : permissionScope;

                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "권한이 만료되었습니다",
                    $"'{permissionsList}' 권한이 {eventData.ExpiredAt:yyyy-MM-dd HH:mm}에 만료되었습니다.");

                _logger.LogInformation(
                    "Successfully processed permission expired event for user {UserId}",
                    eventData.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error processing permission expired event for user {UserId}",
                    eventData.UserId);

                await LogFailureAsync(
                    "PERMISSION_EXPIRY_FAILED",
                    eventData.UserId,
                    ex.Message,
                    eventData);

                throw;
            }
        }

        /// <summary>
        /// 권한 상속 이벤트 처리
        /// </summary>
        public async Task HandlePermissionInheritedAsync(PermissionInheritedEvent eventData)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionInheritedEvent");
                return;
            }

            try
            {
                _logger.LogInformation(
                    "Processing permission inherited event: User {UserId} inherited permission {Scope} from {Source}",
                    eventData.UserId, eventData.PermissionScope, eventData.InheritedFrom);

                // 1. 캐시 업데이트
                await InvalidatePermissionCacheAsync(eventData.UserId, eventData.PermissionScope);

                // 2. 감사 로그
                await _auditService.LogActionAsync(
                    eventData.UserId,
                    $"Inherited permission '{eventData.PermissionScope}' from {eventData.InheritedFrom}",
                    AuditActionType.Create,
                    "Permission",
                    eventData.PermissionScope,
                    true,
                    JsonConvert.SerializeObject(new
                    {
                        UserId = eventData.UserId,
                        ConnectedId = eventData.ConnectedId,
                        PermissionScope = eventData.PermissionScope,
                        InheritedFrom = eventData.InheritedFrom,
                        InheritedFromId = eventData.InheritedFromId,
                        InheritedFromName = eventData.InheritedFromName,
                        InheritedAt = eventData.InheritedAt,
                        InheritanceChain = eventData.InheritanceChain,
                        IsDirectInheritance = eventData.IsDirectInheritance
                    }));

                // 3. 보안 이벤트
                var securityEvent = new SecurityEvent
                {
                    EventType = SecurityEventType.PermissionInherited,
                    Severity = SecuritySeverityLevel.Info,
                    TriggeringConnectedId = eventData.ConnectedId,
                    TargetConnectedId = eventData.ConnectedId,
                    EventDescription = $"Permission {eventData.PermissionScope} inherited from {eventData.InheritedFrom}",
                    ResourceType = "Permission",
                    ResourceId = eventData.InheritedFromId,
                    AttemptedAction = "INHERIT",
                    OccurredAt = eventData.InheritedAt,
                    AdditionalContext = JsonConvert.SerializeObject(new Dictionary<string, object>
                    {
                        ["permissionScope"] = eventData.PermissionScope,
                        ["inheritedFrom"] = eventData.InheritedFrom,
                        ["inheritedFromName"] = eventData.InheritedFromName,
                        ["isDirectInheritance"] = eventData.IsDirectInheritance
                    })
                };

                await _securityEventService.RecordEventAsync(securityEvent);

                // 4. 사용자 알림
                await _notificationService.SendSecurityAlertAsync(
                    eventData.UserId,
                    "새로운 권한이 상속되었습니다",
                    $"'{eventData.PermissionScope}' 권한이 {eventData.InheritedFromName}({eventData.InheritedFrom})로부터 상속되었습니다.");

                _logger.LogInformation(
                    "Successfully processed permission inherited event for user {UserId}",
                    eventData.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error processing permission inherited event for user {UserId}, permission {Scope}",
                    eventData.UserId, eventData.PermissionScope);

                await LogFailureAsync(
                    "PERMISSION_INHERIT_FAILED",
                    eventData.UserId,
                    ex.Message,
                    eventData);

                throw;
            }
        }

        /// <summary>
        /// 권한 위임 이벤트 처리
        /// </summary>
        public async Task HandlePermissionDelegatedAsync(PermissionDelegatedEvent eventData)
        {
            if (eventData == null)
            {
                _logger.LogWarning("Received null PermissionDelegatedEvent");
                return;
            }

            try
            {
                _logger.LogInformation(
                    "Processing permission delegated event: User {DelegatorId} delegated permission {Scope} to {DelegateId}",
                    eventData.DelegatorUserId, eventData.PermissionScope, eventData.DelegateUserId);

                // 1. 양쪽 사용자의 캐시 업데이트
                await InvalidatePermissionCacheAsync(eventData.DelegatorUserId, eventData.PermissionScope);
                await InvalidatePermissionCacheAsync(eventData.DelegateUserId, eventData.PermissionScope);

                // 2. 감사 로그
                await _auditService.LogActionAsync(
                    eventData.DelegatorUserId,
                    $"Delegated permission '{eventData.PermissionScope}' to another user",
                    AuditActionType.Update,
                    "Permission",
                    eventData.PermissionScope,
                    true,
                    JsonConvert.SerializeObject(new
                    {
                        DelegatorUserId = eventData.DelegatorUserId,
                        DelegateUserId = eventData.DelegateUserId,
                        PermissionScope = eventData.PermissionScope,
                        DelegatedAt = eventData.DelegatedAt,
                        ExpiresAt = eventData.ExpiresAt,
                        CanSubDelegate = eventData.CanSubDelegate,
                        DelegationLevel = eventData.DelegationLevel
                    }));

                // 3. 권한 변경 로그
                await _auditService.LogPermissionChangeAsync(
                    "User",
                    eventData.DelegateUserId.ToString(),
                    eventData.PermissionScope,
                    "DELEGATE",
                    eventData.DelegateConnectedId ?? eventData.DelegateUserId,
                    eventData.DelegatorUserId);

                // 4. 보안 이벤트
                var securityEvent = new SecurityEvent
                {
                    EventType = SecurityEventType.PermissionDelegated,
                    Severity = SecuritySeverityLevel.Warning,
                    TriggeringConnectedId = eventData.DelegatorConnectedId,
                    TargetConnectedId = eventData.DelegateConnectedId,
                    EventDescription = $"Permission {eventData.PermissionScope} delegated from user {eventData.DelegatorUserId} to {eventData.DelegateUserId}",
                    ResourceType = "Permission",
                    AttemptedAction = "DELEGATE",
                    OccurredAt = eventData.DelegatedAt,
                    AdditionalContext = JsonConvert.SerializeObject(new Dictionary<string, object>
                    {
                        ["delegatorUserId"] = eventData.DelegatorUserId,
                        ["delegateUserId"] = eventData.DelegateUserId,
                        ["permissionScope"] = eventData.PermissionScope,
                        ["expiresAt"] = eventData.ExpiresAt?.ToString() ?? "Never",
                        ["canSubDelegate"] = eventData.CanSubDelegate
                    })
                };

                await _securityEventService.RecordEventAsync(securityEvent);

                // 5. 양쪽 사용자에게 알림
                await _notificationService.SendSecurityAlertAsync(
                    eventData.DelegateUserId,
                    "권한이 위임되었습니다",
                    GenerateDelegationNotificationForDelegate(
                        eventData.PermissionScope,
                        eventData.DelegatorUserId,
                        eventData.ExpiresAt,
                        eventData.CanSubDelegate));

                await _notificationService.SendSecurityAlertAsync(
                    eventData.DelegatorUserId,
                    "권한을 위임했습니다",
                    GenerateDelegationNotificationForDelegator(
                        eventData.PermissionScope,
                        eventData.DelegateUserId,
                        eventData.ExpiresAt));

                _logger.LogInformation(
                    "Successfully processed permission delegated event from user {DelegatorId} to {DelegateId}",
                    eventData.DelegatorUserId, eventData.DelegateUserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error processing permission delegated event from user {DelegatorId} to {DelegateId}",
                    eventData.DelegatorUserId, eventData.DelegateUserId);

                await LogFailureAsync(
                    "PERMISSION_DELEGATE_FAILED",
                    eventData.DelegatorUserId,
                    ex.Message,
                    eventData);

                throw;
            }
        }

        #endregion

        #region Helper Methods

        private async Task InvalidatePermissionCacheAsync(Guid userId, string permissionScope)
        {
            try
            {
                var cacheKeys = new[]
                {
                    $"{AuthConstants.CacheKeys.PermissionPrefix}{userId}",
                    $"{AuthConstants.CacheKeys.PermissionPrefix}{userId}:{permissionScope}",
                    $"{AuthConstants.CacheKeys.UserPrefix}permissions:{userId}"
                };

                foreach (var key in cacheKeys)
                {
                    await _distributedCache.RemoveAsync(key);
                }

                _memoryCache.Remove($"user_permissions:{userId}");
                _memoryCache.Remove($"permission:{permissionScope}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to invalidate permission cache for user {UserId}", userId);
            }
        }

        private async Task LogFailureAsync(string eventType, Guid userId, string errorMessage, object eventData)
        {
            try
            {
                await _auditService.LogSecurityEventAsync(
                    eventType,
                    AuditEventSeverity.Error,
                    errorMessage,
                    userId,
                    new Dictionary<string, object>
                    {
                        ["errorMessage"] = errorMessage,
                        ["eventData"] = JsonConvert.SerializeObject(eventData),
                        ["timestamp"] = DateTime.UtcNow
                    });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log failure audit for event type {EventType}", eventType);
            }
        }

        private string GenerateGrantNotificationMessage(string permissionName, string? reason, DateTime? expiresAt)
        {
            var message = $"'{permissionName}' 권한이 부여되었습니다.";

            if (!string.IsNullOrWhiteSpace(reason))
            {
                message += $"\n사유: {reason}";
            }

            if (expiresAt.HasValue)
            {
                message += $"\n만료일: {expiresAt.Value:yyyy-MM-dd HH:mm}";
            }
            else
            {
                message += "\n만료일: 무기한";
            }

            return message;
        }

        private string GenerateRevokeNotificationMessage(string permissionName, string? reason)
        {
            var message = $"'{permissionName}' 권한이 취소되었습니다.";

            if (!string.IsNullOrWhiteSpace(reason))
            {
                message += $"\n사유: {reason}";
            }

            return message;
        }

        private string GenerateDelegationNotificationForDelegate(
            string permissionScope,
            Guid delegatorUserId,
            DateTime? expiresAt,
            bool canSubDelegate)
        {
            var message = $"사용자 {delegatorUserId}로부터 '{permissionScope}' 권한을 위임받았습니다.";

            if (expiresAt.HasValue)
            {
                message += $"\n위임 만료일: {expiresAt.Value:yyyy-MM-dd HH:mm}";
            }

            if (canSubDelegate)
            {
                message += "\n이 권한을 다른 사용자에게 재위임할 수 있습니다.";
            }
            else
            {
                message += "\n이 권한은 재위임할 수 없습니다.";
            }

            return message;
        }

        private string GenerateDelegationNotificationForDelegator(
            string permissionScope,
            Guid delegateUserId,
            DateTime? expiresAt)
        {
            var message = $"'{permissionScope}' 권한을 사용자 {delegateUserId}에게 위임했습니다.";

            if (expiresAt.HasValue)
            {
                message += $"\n위임 만료일: {expiresAt.Value:yyyy-MM-dd HH:mm}";
                message += "\n만료 시점에 자동으로 위임이 해제됩니다.";
            }

            return message;
        }

        private List<string> BuildChangeList(Dictionary<string, object>? oldValues, Dictionary<string, object>? newValues)
        {
            var changes = new List<string>();

            if (oldValues == null || newValues == null)
            {
                return changes;
            }

            foreach (var key in newValues.Keys)
            {
                if (!oldValues.ContainsKey(key))
                {
                    changes.Add($"{key}: 추가됨 ('{newValues[key]}')");
                }
                else if (!Equals(oldValues[key], newValues[key]))
                {
                    changes.Add($"{key}: '{oldValues[key]}' → '{newValues[key]}'");
                }
            }

            foreach (var key in oldValues.Keys)
            {
                if (!newValues.ContainsKey(key))
                {
                    changes.Add($"{key}: 제거됨 (이전 값: '{oldValues[key]}')");
                }
            }

            return changes;
        }

        #endregion
    }
}