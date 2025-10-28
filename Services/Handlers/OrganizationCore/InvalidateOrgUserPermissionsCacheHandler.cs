// File: AuthHive.Auth/Services/Handlers/OrganizationCore/InvalidateOrgUserPermissionsCacheHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Organization.Events;
using AuthHive.Core.Entities.Organization; // ❗️ [FIX] 엔티티 using 추가
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.OrganizationCore
{
    /// <summary>
    /// [신규] 조직의 상태가 변경되어(정지, 삭제, 상위 변경) 조직 전체의 권한에 영향을 미칠 때,
    /// 해당 조직 및 모든 하위 조직 구성원들의 사용자 권한 캐시("perm:*:{connectedId}:*")를 무효화합니다.
    /// </summary>
    public class InvalidateOrgUserPermissionsCacheHandler :
        IDomainEventHandler<OrganizationSuspendedEvent>,
        IDomainEventHandler<OrganizationDeletedEvent>,
        IDomainEventHandler<OrganizationParentChangedEvent>,
        IService
    {
        private readonly ICacheService _cacheService;
        private readonly IOrganizationHierarchyRepository _hierarchyRepository;
        private readonly IOrganizationMembershipRepository _membershipRepository;
        private readonly ILogger<InvalidateOrgUserPermissionsCacheHandler> _logger;

        private const string PermissionCachePatternFormat = "perm:*:{0}:*";

        public int Priority => 60;
        public bool IsEnabled => true;

        public InvalidateOrgUserPermissionsCacheHandler(
            ICacheService cacheService,
            IOrganizationHierarchyRepository hierarchyRepository,
            IOrganizationMembershipRepository membershipRepository,
            ILogger<InvalidateOrgUserPermissionsCacheHandler> logger)
        {
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _hierarchyRepository = hierarchyRepository ?? throw new ArgumentNullException(nameof(hierarchyRepository));
            _membershipRepository = membershipRepository ?? throw new ArgumentNullException(nameof(membershipRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // --- 핸들러 구현 ---

        public Task HandleAsync(OrganizationSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidatePermissionsRecursiveAsync(@event.AggregateId, @event.EventType, includeChildren: true, cancellationToken);
        }

        public Task HandleAsync(OrganizationDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidatePermissionsRecursiveAsync(@event.AggregateId, @event.EventType, includeChildren: true, cancellationToken);
        }

        public Task HandleAsync(OrganizationParentChangedEvent @event, CancellationToken cancellationToken = default)
        {
            return InvalidatePermissionsRecursiveAsync(@event.AggregateId, @event.EventType, includeChildren: true, cancellationToken);
        }

        private async Task InvalidatePermissionsRecursiveAsync(Guid organizationId, string eventType, bool includeChildren, CancellationToken cancellationToken)
        {
            if (organizationId == Guid.Empty)
            {
                _logger.LogWarning("Invalid OrganizationId (Guid.Empty) received from {EventType}. Skipping permission cache invalidation.", eventType);
                return;
            }

            var orgIdsToProcess = new HashSet<Guid> { organizationId };

            if (includeChildren)
            {
                try
                {
                    // ❗️ [FIX 1] GetDescendantsAsync (존재하는 메서드) 호출
                    var descendantOrgs = await _hierarchyRepository.GetDescendantsAsync(organizationId, null, cancellationToken);
                    // ❗️ [FIX 1.1] 결과(Organization 엔티티)에서 ID 목록 추출
                    var descendants = descendantOrgs.Select(org => org.Id); 
                    
                    foreach (var id in descendants)
                    {
                        orgIdsToProcess.Add(id);
                    }
                    _logger.LogInformation("Found {DescendantCount} descendant orgs for OrgId {OrgId} (Total: {TotalCount})", descendants.Count(), organizationId, orgIdsToProcess.Count);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to retrieve descendants for OrgId {OrgId}. Proceeding with target org only.", organizationId);
                }
            }

            foreach (var orgId in orgIdsToProcess)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    // ❗️ [FIX 2] GetMembersAsync (존재하는 메서드) 호출 (비활성 멤버 포함)
                    var memberships = await _membershipRepository.GetMembersAsync(orgId, includeInactive: true, cancellationToken);
                    // ❗️ [FIX 2.1] 결과(OrganizationMembership 엔티티)에서 ConnectedId 목록 추출
                    var memberIds = memberships.Select(m => m.ConnectedId).Distinct();

                    if (!memberIds.Any())
                    {
                        _logger.LogDebug("No members found in OrgId {OrgId}. Skipping.", orgId);
                        continue;
                    }

                    var invalidationTasks = new List<Task>();
                    foreach (var connectedId in memberIds)
                    {
                        var cachePattern = string.Format(PermissionCachePatternFormat, connectedId);
                        invalidationTasks.Add(_cacheService.RemoveByPatternAsync(cachePattern, cancellationToken));
                    }

                    await Task.WhenAll(invalidationTasks);
                    _logger.LogInformation("Invalidated permission caches for {UserCount} users in OrgId: {OrgId} (Triggered by {EventType})", invalidationTasks.Count, orgId, eventType);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to invalidate permission caches for OrgId {OrgId}.", orgId);
                }
            }
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}