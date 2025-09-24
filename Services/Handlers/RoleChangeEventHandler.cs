using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Handler;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.External;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Handlers
{
    /// <summary>
    /// Handles role change events and propagates side effects to relevant systems.
    /// Key Responsibilities: Cache invalidation, audit logging, and user notifications.
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

        public RoleChangeEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IEmailService emailService,
            IUserRepository userRepository,
            IUserPlatformApplicationAccessRepository accessRepository,
            IDateTimeProvider dateTimeProvider,
            ILogger<RoleChangeEventHandler> logger)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _emailService = emailService;
            _userRepository = userRepository;
            _accessRepository = accessRepository;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        #region IService Implementation

        public Task InitializeAsync()
        {
            _logger.LogInformation("RoleChangeEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            var isCacheHealthy = await _cacheService.IsHealthyAsync();
            var isAuditHealthy = await _auditService.IsHealthyAsync();
            return isCacheHealthy && isAuditHealthy;
        }

        #endregion

        public async Task HandleRoleAssignedAsync(RoleAssignedEvent eventData)
        {
            _logger.LogInformation("Handling RoleAssignedEvent for UserId: {UserId}, RoleId: {RoleId}", eventData.UserId, eventData.RoleId);
            try
            {
                await InvalidateUserPermissionCacheAsync(eventData.ConnectedId);

                var auditLog = new AuditLog
                {
                    Action = "ROLE_ASSIGNED",
                    ActionType = AuditActionType.Update,
                    PerformedByConnectedId = eventData.AssignedByUserId,
                    TargetUserId = eventData.UserId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                await _auditService.LogAsync(auditLog);

                var user = await _userRepository.GetByIdAsync(eventData.UserId);
                if (user?.Email != null)
                {
                    // === 이메일 내용 영어로 수정된 부분 ===
                    var emailMessage = new EmailMessageDto
                    {
                        To = user.Email,
                        Subject = "Role Assignment Notification",
                        Body = $"Hello {user.Username}, you have been assigned the role: '{eventData.RoleName}'."
                    };
                    await _emailService.SendEmailAsync(emailMessage);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleAssignedEvent for UserId: {UserId}", eventData.UserId);
            }
        }

        public async Task HandleRoleRemovedAsync(RoleRemovedEvent eventData)
        {
            _logger.LogInformation("Handling RoleRemovedEvent for UserId: {UserId}, RoleId: {RoleId}", eventData.UserId, eventData.RoleId);
            try
            {
                await InvalidateUserPermissionCacheAsync(eventData.ConnectedId);

                var auditLog = new AuditLog
                {
                    Action = "ROLE_REMOVED",
                    ActionType = AuditActionType.Update,
                    PerformedByConnectedId = eventData.RemovedByUserId,
                    TargetUserId = eventData.UserId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Warning,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                await _auditService.LogAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleRemovedEvent for UserId: {UserId}", eventData.UserId);
            }
        }

        public async Task HandleRoleChangedAsync(RoleChangedEvent eventData)
        {
            _logger.LogInformation("Handling RoleChangedEvent for UserId: {UserId}", eventData.UserId);
            try
            {
                await InvalidateUserPermissionCacheAsync(eventData.ConnectedId);
                var auditLog = new AuditLog
                {
                    Action = "ROLE_CHANGED",
                    ActionType = AuditActionType.Update,
                    PerformedByConnectedId = eventData.ChangedByUserId,
                    TargetUserId = eventData.UserId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                await _auditService.LogAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleChangedEvent for UserId: {UserId}", eventData.UserId);
            }
        }

        public async Task HandleRoleCreatedAsync(RoleCreatedEvent eventData)
        {
            _logger.LogInformation("Handling RoleCreatedEvent for RoleId: {RoleId}", eventData.RoleId);
            try
            {
                var auditLog = new AuditLog
                {
                    Action = "ROLE_CREATED",
                    ActionType = AuditActionType.Create,
                    PerformedByConnectedId = eventData.CreatedByUserId,
                    TargetOrganizationId = eventData.OrganizationId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                await _auditService.LogAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleCreatedEvent for RoleId: {RoleId}", eventData.RoleId);
            }
        }

        public async Task HandleRoleDeletedAsync(RoleDeletedEvent eventData)
        {
            _logger.LogInformation("Handling RoleDeletedEvent for RoleId: {RoleId}", eventData.RoleId);
            try
            {
                if (eventData.AffectedUsers > 0)
                {
                    var affectedAccessEntries = await _accessRepository.GetByRoleIdAsync(eventData.RoleId);
                    var invalidationTasks = affectedAccessEntries
                        .Select(access => InvalidateUserPermissionCacheAsync(access.ConnectedId))
                        .ToList();
                    
                    await Task.WhenAll(invalidationTasks);
                    _logger.LogInformation("Invalidated caches for {Count} users affected by RoleId {RoleId} deletion.", invalidationTasks.Count, eventData.RoleId);
                }

                var auditLog = new AuditLog
                {
                    Action = "ROLE_DELETED",
                    ActionType = AuditActionType.Delete,
                    PerformedByConnectedId = eventData.DeletedByUserId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Critical,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                await _auditService.LogAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleDeletedEvent for RoleId: {RoleId}", eventData.RoleId);
            }
        }

        public async Task HandleRoleDelegatedAsync(RoleDelegatedEvent eventData)
        {
            _logger.LogInformation("Handling RoleDelegatedEvent for RoleId: {RoleId}", eventData.RoleId);
            try
            {
                var auditLog = new AuditLog
                {
                    Action = "ROLE_DELEGATED",
                    ActionType = AuditActionType.Update,
                    PerformedByConnectedId = eventData.FromUserId,
                    TargetUserId = eventData.ToUserId,
                    Success = true,
                    Timestamp = _dateTimeProvider.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(eventData)
                };
                await _auditService.LogAsync(auditLog);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling RoleDelegatedEvent for RoleId: {RoleId}", eventData.RoleId);
            }
        }

        private async Task InvalidateUserPermissionCacheAsync(Guid connectedId)
        {
            var cachePattern = $"perm:*:{connectedId}:*";
            await _cacheService.RemoveByPatternAsync(cachePattern);
            _logger.LogDebug("Invalidated permission cache for ConnectedId: {ConnectedId} with pattern: {Pattern}", connectedId, cachePattern);
        }
    }
}
