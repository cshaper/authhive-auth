using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Handler;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Organization.Events;
using Microsoft.Extensions.Logging;

namespace AuthHive.Organization.Handlers
{
    /// <summary>
    /// 조직 도메인 이벤트를 처리하고, 캐시 무효화 및 감사 로깅과 같은 후속 조치를 수행합니다.
    /// </summary>
    public class OrganizationEventHandler : IOrganizationEventHandler, IService
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IUserPlatformApplicationAccessRepository _accessRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<OrganizationEventHandler> _logger;

        public OrganizationEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IOrganizationRepository organizationRepository,
            IUserPlatformApplicationAccessRepository accessRepository,
            IDateTimeProvider dateTimeProvider,
            ILogger<OrganizationEventHandler> logger)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _organizationRepository = organizationRepository;
            _accessRepository = accessRepository;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        #region IService Implementation
        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            return await _cacheService.IsHealthyAsync() && await _auditService.IsHealthyAsync();
        }
        #endregion

        #region Creation, Update, Deletion Events

        public async Task HandleOrganizationCreatedAsync(OrganizationCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            // OrganizationCreatedEvent는 BaseEvent를 상속받아 AggregateId를 가짐
            var organizationId = @event.AggregateId;
            var createdBy = @event.TriggeredBy ?? Guid.Empty;
            
            await LogOrgEventAsync("ORGANIZATION_CREATED", AuditActionType.Create, createdBy, organizationId, @event);
            
            // 신규 조직 생성 시, 기본 설정을 캐시에 미리 넣어 'Cache Warming'을 할 수 있습니다.
            // 예: await _cacheService.SetAsync(GetOrgCacheKey(organizationId), newlyCreatedOrgDto);
        }

        public async Task HandleOrganizationUpdatedAsync(OrganizationUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var updatedBy = @event.TriggeredBy ?? Guid.Empty;
            
            // 1. 감사 로그 기록
            await LogOrgEventAsync("ORGANIZATION_UPDATED", AuditActionType.Update, updatedBy, organizationId, @event);
            
            // 2. (가장 중요) 해당 조직의 캐시를 무효화하여 다음 요청 시 새로운 정보를 가져오도록 합니다.
            await InvalidateOrganizationCacheAsync(organizationId);
        }

        public async Task HandleOrganizationDeletedAsync(OrganizationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var deletedBy = @event.TriggeredBy ?? Guid.Empty;
            
            await LogOrgEventAsync("ORGANIZATION_DELETED", AuditActionType.Delete, deletedBy, organizationId, @event, AuditEventSeverity.Critical);
            
            // 조직 삭제 시 관련 캐시(조직 정보, 사용자 권한 등)를 모두 정리합니다.
            await InvalidateOrganizationCacheAsync(organizationId);
            await InvalidateAllUserPermissionsInOrgAsync(organizationId);
        }

        #endregion

        #region Status Change Events (Replacing OrganizationStatusChangedEvent)

        public async Task HandleOrganizationActivatedAsync(OrganizationActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var activatedBy = @event.TriggeredBy ?? Guid.Empty;
            
            await LogOrgEventAsync("ORGANIZATION_ACTIVATED", AuditActionType.Update, activatedBy, organizationId, 
                new { @event.PreviousStatus, @event.Reason });
            
            await InvalidateOrganizationCacheAsync(organizationId);
            
            // 조직이 활성화되면 하위 조직들도 영향을 받을 수 있으므로 권한 재계산
            await InvalidateAllUserPermissionsInOrgAsync(organizationId, includeChildren: true);
            
            _logger.LogInformation(
                "Organization activated: {OrganizationId}, Previous: {PreviousStatus}, Reason: {Reason}", 
                organizationId, @event.PreviousStatus, @event.Reason);
        }

        public async Task HandleOrganizationSuspendedAsync(OrganizationSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var suspendedBy = @event.TriggeredBy ?? Guid.Empty;
            
            // Log the suspension with the reason from the event
            var auditLog = new AuditLog
            {
                Action = "ORGANIZATION_SUSPENDED",
                ActionType = AuditActionType.Update,
                PerformedByConnectedId = suspendedBy,
                TargetOrganizationId = organizationId,
                Success = true,
                Timestamp = _dateTimeProvider.UtcNow,
                Severity = AuditEventSeverity.Critical,
                Metadata = JsonSerializer.Serialize(new
                {
                    @event.PreviousStatus,
                    @event.Reason,
                    @event.Priority,
                    @event.Tags
                })
            };
            await _auditService.LogAsync(auditLog);
            
            await InvalidateOrganizationCacheAsync(organizationId);
            
            // When organization is suspended, invalidate all user permissions
            await InvalidateAllUserPermissionsInOrgAsync(organizationId, includeChildren: true);
            
            _logger.LogWarning(
                "Organization {OrganizationId} suspended. Previous status: {PreviousStatus}, Reason: {Reason}", 
                organizationId, 
                @event.PreviousStatus, 
                @event.Reason);
        }

        public async Task HandleOrganizationDeactivatedAsync(OrganizationDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var deactivatedBy = @event.TriggeredBy ?? Guid.Empty;
            
            await LogOrgEventAsync("ORGANIZATION_DEACTIVATED", AuditActionType.Update, deactivatedBy, organizationId,
                new { @event.PreviousStatus, @event.Reason },
                AuditEventSeverity.Warning);
            
            await InvalidateOrganizationCacheAsync(organizationId);
            
            // 비활성화된 조직의 모든 사용자 권한 무효화
            await InvalidateAllUserPermissionsInOrgAsync(organizationId, includeChildren: false);
            
            _logger.LogWarning(
                "Organization deactivated: {OrganizationId}, Previous: {PreviousStatus}, Reason: {Reason}", 
                organizationId, @event.PreviousStatus, @event.Reason);
        }

        #endregion

        #region Hierarchy Change Events

        public async Task HandleOrganizationParentChangedAsync(OrganizationParentChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var updatedBy = @event.TriggeredBy ?? Guid.Empty;
            
            await LogOrgEventAsync("ORGANIZATION_PARENT_CHANGED", AuditActionType.Update, updatedBy, organizationId, @event);

            // 조직의 계층 구조가 변경되면, 자신과 부모의 캐시를 모두 무효화합니다.
            await InvalidateOrganizationCacheAsync(organizationId);
            
            if (@event.OldParentId.HasValue) 
                await InvalidateOrganizationCacheAsync(@event.OldParentId.Value);
                
            if (@event.NewParentId.HasValue) 
                await InvalidateOrganizationCacheAsync(@event.NewParentId.Value);

            // 권한 상속 모델을 사용하는 경우, 조직 이동은 모든 하위 구성원의 권한에 영향을 줄 수 있습니다.
            await InvalidateAllUserPermissionsInOrgAsync(organizationId, includeChildren: true);
        }

        #endregion

        #region Domain Events

        public async Task HandleDomainVerifiedAsync(DomainVerifiedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var verifiedBy = @event.TriggeredBy ?? Guid.Empty;
            
            await LogOrgEventAsync("DOMAIN_VERIFIED", AuditActionType.Update, verifiedBy, organizationId,
                new { @event.DomainName, @event.VerificationMethod, @event.VerifiedAt });
            
            await InvalidateOrganizationCacheAsync(organizationId);
            
            _logger.LogInformation(
                "Domain verified for organization: {OrganizationId}, Domain: {DomainName}, Method: {Method}", 
                organizationId, @event.DomainName, @event.VerificationMethod);
        }

        public async Task HandlePrimaryDomainChangedAsync(PrimaryDomainChangedEvent @event, CancellationToken cancellationToken = default)
        {
            var organizationId = @event.AggregateId;
            var changedBy = @event.TriggeredBy ?? Guid.Empty;
            
            await LogOrgEventAsync("PRIMARY_DOMAIN_CHANGED", AuditActionType.Update, changedBy, organizationId,
                new { @event.OldDomain, @event.NewDomain, @event.Reason });
            
            await InvalidateOrganizationCacheAsync(organizationId);
            
            _logger.LogInformation(
                "Primary domain changed for organization: {OrganizationId}, Old: {OldDomain}, New: {NewDomain}", 
                organizationId, @event.OldDomain, @event.NewDomain);
        }

        #endregion

        #region Private Helper Methods

        private Task LogOrgEventAsync(string action, AuditActionType actionType, Guid performedBy, Guid orgId, object eventData, AuditEventSeverity severity = AuditEventSeverity.Info)
        {
            var auditLog = new AuditLog
            {
                Action = action,
                ActionType = actionType,
                PerformedByConnectedId = performedBy,
                TargetOrganizationId = orgId,
                Success = true,
                Timestamp = _dateTimeProvider.UtcNow,
                Severity = severity,
                Metadata = JsonSerializer.Serialize(eventData)
            };
            return _auditService.LogAsync(auditLog);
        }

        private async Task InvalidateOrganizationCacheAsync(Guid organizationId)
        {
            var cacheKey = $"org:id:{organizationId}"; // IOrganizationRepository의 캐시 키 규칙과 일치해야 함
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated organization cache for OrganizationId: {OrganizationId}", organizationId);
        }

        private async Task InvalidateAllUserPermissionsInOrgAsync(Guid organizationId, bool includeChildren = false)
        {
            var orgIdsToProcess = new List<Guid> { organizationId };

            if (includeChildren)
            {
                // 실제 프로덕션에서는 재귀적으로 모든 하위 조직을 찾는 효율적인 쿼리가 필요합니다.
                var children = await _organizationRepository.GetDescendantsAsync(organizationId);
                orgIdsToProcess.AddRange(children.Select(c => c.Id));
            }

            foreach (var orgId in orgIdsToProcess)
            {
                var accessEntries = await _accessRepository.GetByOrganizationIdAsync(orgId);
                var invalidationTasks = accessEntries
                    .Select(access => InvalidateUserPermissionCacheAsync(access.ConnectedId))
                    .ToList();

                await Task.WhenAll(invalidationTasks);
                _logger.LogInformation("Invalidated permission caches for {UserCount} users in OrganizationId: {OrganizationId}", invalidationTasks.Count, orgId);
            }
        }

        private Task InvalidateUserPermissionCacheAsync(Guid connectedId)
        {
            var cachePattern = $"perm:*:{connectedId}:*"; // PermissionValidationService의 캐시 키 패턴과 일치
            return _cacheService.RemoveByPatternAsync(cachePattern);
        }

        #endregion
    }
}