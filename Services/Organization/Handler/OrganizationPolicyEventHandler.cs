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
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Policy.Commands;
using AuthHive.Core.Models.Policy.Events;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Organization.Handlers
{
    /// <summary>
    /// 조직 정책 이벤트 핸들러 - 정책 관련 도메인 이벤트를 처리하고 후속 작업을 수행합니다.
    /// </summary>
    public class OrganizationPolicyEventHandler : IOrganizationPolicyEventHandler, IService
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationPolicyRepository _policyRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<OrganizationPolicyEventHandler> _logger;
        private readonly IEventBus _eventBus;

        // 캐시 키 접두사 상수
        private const string POLICY_CACHE_PREFIX = "org:policy";
        private const string POLICY_LIST_CACHE_PREFIX = "org:policies";
        private const string EFFECTIVE_POLICY_CACHE_PREFIX = "org:effective-policy";
        private const string POLICY_CONFLICT_CACHE_PREFIX = "org:policy-conflicts";
        
        // 감사 액션 상수
        private const string POLICY_CREATED = "ORGANIZATION_POLICY_CREATED";
        private const string POLICY_UPDATED = "ORGANIZATION_POLICY_UPDATED";
        private const string POLICY_DELETED = "ORGANIZATION_POLICY_DELETED";
        private const string POLICY_ENABLED = "ORGANIZATION_POLICY_ENABLED";
        private const string POLICY_DISABLED = "ORGANIZATION_POLICY_DISABLED";
        private const string POLICY_APPLIED = "ORGANIZATION_POLICY_APPLIED";
        private const string POLICY_INHERITANCE_SET = "ORGANIZATION_POLICY_INHERITANCE_SET";
        private const string POLICY_PROPAGATED = "ORGANIZATION_POLICY_PROPAGATED";
        private const string POLICY_CONFLICT_DETECTED = "ORGANIZATION_POLICY_CONFLICT_DETECTED";
        private const string AUDIT_POLICY_CHANGED = "ORGANIZATION_AUDIT_POLICY_CHANGED";

        public OrganizationPolicyEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IOrganizationRepository organizationRepository,
            IOrganizationPolicyRepository policyRepository,
            IDateTimeProvider dateTimeProvider,
            ILogger<OrganizationPolicyEventHandler> logger,
            IEventBus eventBus)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _organizationRepository = organizationRepository;
            _policyRepository = policyRepository;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
            _eventBus = eventBus;
        }

        #region IService Implementation
        
        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationPolicyEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            return await _cacheService.IsHealthyAsync() && await _auditService.IsHealthyAsync();
        }
        
        #endregion

        #region Policy CRUD Events

        public async Task HandlePolicyCreatedAsync(PolicyCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing policy created event: PolicyId={PolicyId}, Organization={OrganizationId}, Type={PolicyType}",
                    @event.PolicyId, @event.OrganizationId, @event.PolicyType);

                // 1. 감사 로그 기록
                await LogPolicyEventAsync(
                    POLICY_CREATED,
                    AuditActionType.Create,
                    @event.CreatedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        PolicyType = @event.PolicyType.ToString(),
                        PolicyName = @event.PolicyName,
                        Priority = @event.Priority,
                        IsEnabled = @event.IsEnabled,
                        IsInheritable = @event.IsInheritable,
                        EffectiveFrom = @event.EffectiveFrom,
                        EffectiveTo = @event.EffectiveTo
                    }
                );

                // 2. 정책 목록 캐시 무효화
                await InvalidatePolicyListCacheAsync(@event.OrganizationId);

                // 3. 상속 가능한 정책이면 하위 조직에 전파 준비
                if (@event.IsInheritable)
                {
                    await PrepareInheritancePropagationAsync(@event.OrganizationId, @event.PolicyId);
                }

                // 4. 정책 충돌 체크
                await CheckForPolicyConflictsAsync(@event.OrganizationId, @event.PolicyType);

                _logger.LogInformation("Successfully processed policy created event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy created event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        public async Task HandlePolicyUpdatedAsync(PolicyUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing policy updated event: PolicyId={PolicyId}, Organization={OrganizationId}",
                    @event.PolicyId, @event.OrganizationId);

                // 1. 감사 로그 기록
                await LogPolicyEventAsync(
                    POLICY_UPDATED,
                    AuditActionType.Update,
                    @event.UpdatedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        PolicyType = @event.PolicyType.ToString(),
                        ChangedProperties = @event.ChangedProperties,
                        Version = @event.Version
                    },
                    GetSeverityForPolicyUpdate(@event.ChangedProperties)
                );

                // 2. 정책 캐시 무효화
                await InvalidatePolicyCacheAsync(@event.OrganizationId, @event.PolicyId);
                await InvalidateEffectivePolicyCacheAsync(@event.OrganizationId, @event.PolicyType);

                // 3. 중요한 속성이 변경되었는지 확인
                if (HasCriticalChanges(@event.ChangedProperties))
                {
                    await NotifyCriticalPolicyChangeAsync(@event.OrganizationId, @event.PolicyId, @event.ChangedProperties);
                }

                // 4. 버전 관리를 위한 백업
                await BackupPolicyVersionAsync(@event.OrganizationId, @event.PolicyId, @event.Version);

                _logger.LogInformation("Successfully processed policy updated event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy updated event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        public async Task HandlePolicyDeletedAsync(PolicyDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing policy deleted event: PolicyId={PolicyId}, Organization={OrganizationId}, Name={PolicyName}",
                    @event.PolicyId, @event.OrganizationId, @event.PolicyName);

                // 1. 삭제 전 백업 생성
                await CreatePolicyDeletionBackupAsync(@event.OrganizationId, @event.PolicyId, @event.PolicyName);

                // 2. 감사 로그 기록 (Critical)
                await LogPolicyEventAsync(
                    POLICY_DELETED,
                    AuditActionType.Delete,
                    @event.DeletedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        PolicyName = @event.PolicyName,
                        PolicyType = @event.PolicyType.ToString()
                    },
                    AuditEventSeverity.Critical
                );

                // 3. 모든 관련 캐시 무효화
                await InvalidatePolicyCacheAsync(@event.OrganizationId, @event.PolicyId);
                await InvalidatePolicyListCacheAsync(@event.OrganizationId);
                await InvalidateEffectivePolicyCacheAsync(@event.OrganizationId, @event.PolicyType);

                // 4. 하위 조직에서 상속된 정책 제거
                await RemoveInheritedPoliciesAsync(@event.OrganizationId, @event.PolicyId);

                _logger.LogWarning("Successfully processed policy deleted event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy deleted event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        #endregion

        #region Policy State Change Events

        public async Task HandlePolicyEnabledAsync(PolicyEnabledEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing policy enabled event: PolicyId={PolicyId}, Organization={OrganizationId}",
                    @event.PolicyId, @event.OrganizationId);

                // 1. 감사 로그 기록
                await LogPolicyEventAsync(
                    POLICY_ENABLED,
                    AuditActionType.Update,
                    @event.EnabledByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        PolicyName = @event.PolicyName,
                        PolicyType = @event.PolicyType.ToString()
                    }
                );

                // 2. 캐시 무효화
                await InvalidateEffectivePolicyCacheAsync(@event.OrganizationId, @event.PolicyType);

                // 3. 정책 활성화 알림
                await NotifyPolicyStateChangeAsync(@event.OrganizationId, @event.PolicyId, true);

                // 4. 즉시 적용이 필요한 정책인지 확인
                if (RequiresImmediateApplication(@event.PolicyType))
                {
                    await ApplyPolicyImmediatelyAsync(@event.OrganizationId, @event.PolicyId);
                }

                _logger.LogInformation("Successfully processed policy enabled event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy enabled event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        public async Task HandlePolicyDisabledAsync(PolicyDisabledEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing policy disabled event: PolicyId={PolicyId}, Organization={OrganizationId}",
                    @event.PolicyId, @event.OrganizationId);

                // 1. 감사 로그 기록
                await LogPolicyEventAsync(
                    POLICY_DISABLED,
                    AuditActionType.Update,
                    @event.DisabledByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        PolicyName = @event.PolicyName,
                        PolicyType = @event.PolicyType.ToString()
                    },
                    AuditEventSeverity.Warning
                );

                // 2. 캐시 무효화
                await InvalidateEffectivePolicyCacheAsync(@event.OrganizationId, @event.PolicyType);

                // 3. 정책 비활성화 알림
                await NotifyPolicyStateChangeAsync(@event.OrganizationId, @event.PolicyId, false);

                // 4. 보안 정책이면 경고
                if (IsSecurityPolicy(@event.PolicyType))
                {
                    await WarnSecurityPolicyDisabledAsync(@event.OrganizationId, @event.PolicyId, @event.PolicyType);
                }

                _logger.LogWarning("Successfully processed policy disabled event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy disabled event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        public async Task HandlePolicyAppliedAsync(PolicyAppliedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing policy applied event: PolicyId={PolicyId}, AffectedEntities={Count}",
                    @event.PolicyId, @event.AffectedEntitiesCount);

                // 1. 감사 로그 기록
                await LogPolicyEventAsync(
                    POLICY_APPLIED,
                    AuditActionType.Execute,
                    @event.AppliedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        PolicyName = @event.PolicyName,
                        PolicyType = @event.PolicyType.ToString(),
                        PolicyRules = @event.PolicyRules,
                        AffectedEntitiesCount = @event.AffectedEntitiesCount
                    }
                );

                // 2. 적용 통계 업데이트
                await UpdatePolicyApplicationStatsAsync(@event.OrganizationId, @event.PolicyId, @event.AffectedEntitiesCount);

                // 3. 영향받은 엔티티들의 캐시 무효화
                if (@event.AffectedEntitiesCount > 0)
                {
                    await InvalidateAffectedEntitiesCacheAsync(@event.OrganizationId, @event.PolicyType);
                }

                _logger.LogInformation("Successfully processed policy applied event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy applied event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        #endregion

        #region Policy Inheritance Events

        public async Task HandlePolicyInheritanceSetAsync(PolicyInheritanceSetEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing policy inheritance set event: PolicyId={PolicyId}, IsInheritable={IsInheritable}",
                    @event.PolicyId, @event.IsInheritable);

                // 1. 감사 로그 기록
                await LogPolicyEventAsync(
                    POLICY_INHERITANCE_SET,
                    AuditActionType.Update,
                    @event.SetByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        IsInheritable = @event.IsInheritable
                    }
                );

                // 2. 상속 설정에 따른 처리
                if (@event.IsInheritable)
                {
                    // 하위 조직에 정책 전파 준비
                    await PrepareInheritancePropagationAsync(@event.OrganizationId, @event.PolicyId);
                }
                else
                {
                    // 기존 상속된 정책 제거
                    await RemoveInheritedPoliciesAsync(@event.OrganizationId, @event.PolicyId);
                }

                // 3. 캐시 무효화
                await InvalidatePolicyCacheAsync(@event.OrganizationId, @event.PolicyId);

                _logger.LogInformation("Successfully processed policy inheritance set event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy inheritance set event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        public async Task HandlePolicyPropagatedAsync(PolicyPropagatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Processing policy propagated event: PolicyId={PolicyId}, Success={Success}, Failed={Failed}",
                    @event.PolicyId, @event.SuccessCount, @event.FailureCount);

                // 1. 감사 로그 기록
                await LogPolicyEventAsync(
                    POLICY_PROPAGATED,
                    AuditActionType.Update,
                    @event.PropagatedByConnectedId,
                    @event.SourceOrganizationId,
                    new
                    {
                        PolicyId = @event.PolicyId,
                        TargetOrganizations = @event.TargetOrganizationIds,
                        SuccessCount = @event.SuccessCount,
                        FailureCount = @event.FailureCount,
                        IncludedAllDescendants = @event.IncludedAllDescendants
                    },
                    @event.FailureCount > 0 ? AuditEventSeverity.Warning : AuditEventSeverity.Info
                );

                // 2. 대상 조직들의 캐시 무효화
                foreach (var targetOrgId in @event.TargetOrganizationIds)
                {
                    await InvalidatePolicyListCacheAsync(targetOrgId);
                }

                // 3. 전파 실패 처리
                if (@event.FailureCount > 0)
                {
                    await HandlePropagationFailuresAsync(@event.PolicyId, @event.TargetOrganizationIds, @event.SuccessCount, @event.FailureCount);
                }

                // 4. 전파 통계 업데이트
                await UpdatePropagationStatisticsAsync(@event.PolicyId, @event.SuccessCount, @event.FailureCount);

                _logger.LogInformation("Successfully processed policy propagated event for PolicyId={PolicyId}", @event.PolicyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy propagated event for PolicyId={PolicyId}", @event.PolicyId);
                throw;
            }
        }

        #endregion

        #region Policy Conflict Events

        public async Task HandlePolicyConflictDetectedAsync(PolicyConflictDetectedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing policy conflict detected: Organization={OrganizationId}, Type={PolicyType}, ConflictingPolicies={Count}",
                    @event.OrganizationId, @event.PolicyType, @event.ConflictingPolicyIds.Count);

                // 1. 감사 로그 기록 (경고 레벨)
                await LogPolicyEventAsync(
                    POLICY_CONFLICT_DETECTED,
                    AuditActionType.System,
                    Guid.Empty, // System generated event
                    @event.OrganizationId,
                    new
                    {
                        PolicyType = @event.PolicyType.ToString(),
                        ConflictingPolicyIds = @event.ConflictingPolicyIds,
                        ConflictDescription = @event.ConflictDescription,
                        ResolutionStrategy = @event.ResolutionStrategy
                    },
                    AuditEventSeverity.Warning
                );

                // 2. 충돌 정보 캐시에 저장
                await CachePolicyConflictAsync(@event.OrganizationId, @event.PolicyType, @event.ConflictingPolicyIds, @event.ConflictDescription);

                // 3. 충돌 해결 시도
                if (!string.IsNullOrEmpty(@event.ResolutionStrategy))
                {
                    await AttemptConflictResolutionAsync(@event.OrganizationId, @event.PolicyType, @event.ConflictingPolicyIds, @event.ResolutionStrategy);
                }

                // 4. 관리자에게 충돌 알림
                await NotifyPolicyConflictAsync(@event.OrganizationId, @event.PolicyType, @event.ConflictDescription);

                _logger.LogWarning("Successfully processed policy conflict for Organization={OrganizationId}", @event.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing policy conflict event for Organization={OrganizationId}", @event.OrganizationId);
                throw;
            }
        }

        #endregion

        #region Audit Policy Events

        public async Task HandleAuditPolicyChangedAsync(AuditPolicyChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Processing audit policy change: Organization={OrganizationId}, DetailedAudit={Detailed}, RealTime={RealTime}",
                    @event.OrganizationId, @event.IsDetailedAuditEnabled, @event.IsRealTimeMonitoringEnabled);

                // 1. 감사 로그 기록 (Critical - 감사 정책은 중요)
                await LogPolicyEventAsync(
                    AUDIT_POLICY_CHANGED,
                    AuditActionType.Update,
                    @event.ChangedByConnectedId,
                    @event.OrganizationId,
                    new
                    {
                        IsDetailedAuditEnabled = @event.IsDetailedAuditEnabled,
                        IsActivityTrackingEnabled = @event.IsActivityTrackingEnabled,
                        IsRealTimeMonitoringEnabled = @event.IsRealTimeMonitoringEnabled,
                        ComplianceStandards = @event.ComplianceStandards,
                        ViolationAction = @event.ViolationAction
                    },
                    AuditEventSeverity.Critical
                );

                // 2. 감사 설정 캐시 무효화
                await InvalidateAuditPolicyCacheAsync(@event.OrganizationId);

                // 3. 실시간 모니터링 설정 변경 처리
                if (@event.IsRealTimeMonitoringEnabled)
                {
                    await EnableRealTimeMonitoringAsync(@event.OrganizationId);
                }
                else
                {
                    await DisableRealTimeMonitoringAsync(@event.OrganizationId);
                }

                // 4. 컴플라이언스 표준 확인
                if (!string.IsNullOrEmpty(@event.ComplianceStandards))
                {
                    await ValidateComplianceStandardsAsync(@event.OrganizationId, @event.ComplianceStandards);
                }

                // 5. Violation Action 설정
                await ConfigureViolationActionAsync(@event.OrganizationId, @event.ViolationAction);

                _logger.LogWarning("Successfully processed audit policy change for Organization={OrganizationId}", @event.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing audit policy change for Organization={OrganizationId}", @event.OrganizationId);
                throw;
            }
        }

        #endregion

        #region Private Helper Methods

        private Task LogPolicyEventAsync(
            string action,
            AuditActionType actionType,
            Guid performedBy,
            Guid orgId,
            object eventData,
            AuditEventSeverity severity = AuditEventSeverity.Info)
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

        private async Task InvalidatePolicyCacheAsync(Guid organizationId, Guid policyId)
        {
            var cacheKey = $"{POLICY_CACHE_PREFIX}:{organizationId}:{policyId}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated policy cache for Organization={OrganizationId}, PolicyId={PolicyId}",
                organizationId, policyId);
        }

        private async Task InvalidatePolicyListCacheAsync(Guid organizationId)
        {
            var cacheKey = $"{POLICY_LIST_CACHE_PREFIX}:{organizationId}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated policy list cache for Organization={OrganizationId}", organizationId);
        }

        private async Task InvalidateEffectivePolicyCacheAsync(Guid organizationId, OrganizationPolicyType policyType)
        {
            var cacheKey = $"{EFFECTIVE_POLICY_CACHE_PREFIX}:{organizationId}:{policyType}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated effective policy cache for Organization={OrganizationId}, Type={PolicyType}",
                organizationId, policyType);
        }

        private async Task InvalidateAuditPolicyCacheAsync(Guid organizationId)
        {
            var cachePattern = $"org:audit-policy:{organizationId}:*";
            await _cacheService.RemoveByPatternAsync(cachePattern);
            _logger.LogDebug("Invalidated audit policy cache for Organization={OrganizationId}", organizationId);
        }

        private async Task InvalidateAffectedEntitiesCacheAsync(Guid organizationId, OrganizationPolicyType policyType)
        {
            // 정책 타입에 따라 영향받는 엔티티들의 캐시를 무효화
            var cachePatterns = GetCachePatternsForPolicyType(policyType);
            foreach (var pattern in cachePatterns)
            {
                await _cacheService.RemoveByPatternAsync($"{pattern}:{organizationId}:*");
            }
        }

        private List<string> GetCachePatternsForPolicyType(OrganizationPolicyType policyType)
        {
            return policyType switch
            {
                OrganizationPolicyType.Security => new List<string> { "user:permissions", "user:session", "org:security" },
                OrganizationPolicyType.Authentication => new List<string> { "user:auth", "user:mfa", "user:login" },
                OrganizationPolicyType.AccessControl => new List<string> { "user:access", "user:roles", "user:permissions" },
                OrganizationPolicyType.SessionManagement => new List<string> { "user:session", "session:active" },
                OrganizationPolicyType.ApiUsage => new List<string> { "api:rate-limit", "api:quota" },
                _ => new List<string> { "org:policy" }
            };
        }

        private AuditEventSeverity GetSeverityForPolicyUpdate(Dictionary<string, object?> changes)
        {
            // 중요한 속성 변경 확인
            var criticalProperties = new[] { "PolicyRules", "Priority", "IsEnabled", "EffectiveFrom", "EffectiveTo" };
            if (changes.Keys.Any(k => criticalProperties.Contains(k)))
            {
                return AuditEventSeverity.Warning;
            }
            return AuditEventSeverity.Info;
        }

        private bool HasCriticalChanges(Dictionary<string, object?> changes)
        {
            var criticalProperties = new[] { "PolicyRules", "Priority", "IsEnabled" };
            return changes.Keys.Any(k => criticalProperties.Contains(k));
        }

        private bool RequiresImmediateApplication(OrganizationPolicyType policyType)
        {
            // 즉시 적용이 필요한 정책 타입들
            return policyType is OrganizationPolicyType.Security or 
                   OrganizationPolicyType.Authentication or 
                   OrganizationPolicyType.AccessControl;
        }

        private bool IsSecurityPolicy(OrganizationPolicyType policyType)
        {
            return policyType is OrganizationPolicyType.Security or 
                   OrganizationPolicyType.Authentication or 
                   OrganizationPolicyType.Compliance;
        }

        private async Task PrepareInheritancePropagationAsync(Guid organizationId, Guid policyId)
        {
            // 하위 조직 찾기
            var descendants = await _organizationRepository.GetDescendantsAsync(organizationId);
            if (descendants.Any())
            {
                // 전파 이벤트 발행
                await _eventBus.PublishAsync(new PropagatePolicyCommand(organizationId)
                {
                    PolicyId = policyId,
                    SourceOrganizationId = organizationId,
                    TargetOrganizationIds = descendants.Select(d => d.Id).ToList()
                });
            }
        }

        private async Task RemoveInheritedPoliciesAsync(Guid organizationId, Guid policyId)
        {
            var descendants = await _organizationRepository.GetDescendantsAsync(organizationId);
            foreach (var descendant in descendants)
            {
                await InvalidatePolicyListCacheAsync(descendant.Id);
            }
        }

        private async Task NotifyCriticalPolicyChangeAsync(Guid organizationId, Guid policyId, Dictionary<string, object?> changes)
        {
            await _eventBus.PublishAsync(new CriticalPolicyChangeNotification(organizationId)
            {
                OrganizationId = organizationId,
                PolicyId = policyId,
                Changes = changes
            });
        }

        private async Task NotifyPolicyStateChangeAsync(Guid organizationId, Guid policyId, bool isEnabled)
        {
            await _eventBus.PublishAsync(new PolicyStateChangeNotification(organizationId)
            {
                OrganizationId = organizationId,
                PolicyId = policyId,
                IsEnabled = isEnabled
            });
        }

        private async Task NotifyPolicyConflictAsync(Guid organizationId, OrganizationPolicyType policyType, string description)
        {
            await _eventBus.PublishAsync(new PolicyConflictNotification(organizationId)
            {
                OrganizationId = organizationId,
                PolicyType = policyType,
                Description = description
            });
        }

        private async Task WarnSecurityPolicyDisabledAsync(Guid organizationId, Guid policyId, OrganizationPolicyType policyType)
        {
            _logger.LogWarning("SECURITY ALERT: Security policy disabled - Organization={OrganizationId}, PolicyId={PolicyId}, Type={PolicyType}",
                organizationId, policyId, policyType);
            
            await _eventBus.PublishAsync(new SecurityPolicyDisabledWarning(organizationId)
            {
                OrganizationId = organizationId,
                PolicyId = policyId,
                PolicyType = policyType
            });
        }

        private async Task ApplyPolicyImmediatelyAsync(Guid organizationId, Guid policyId)
        {
            _logger.LogInformation("Applying policy immediately: Organization={OrganizationId}, PolicyId={PolicyId}",
                organizationId, policyId);
            // 즉시 적용 로직
            await Task.CompletedTask;
        }

        private async Task BackupPolicyVersionAsync(Guid organizationId, Guid policyId, int version)
        {
            var backupKey = $"backup:policy:{organizationId}:{policyId}:v{version}";
            var policy = await _policyRepository.GetByIdAsync(policyId);
            if (policy != null)
            {
                await _cacheService.SetAsync(backupKey, JsonSerializer.Serialize(policy), TimeSpan.FromDays(90));
            }
        }

        private async Task CreatePolicyDeletionBackupAsync(Guid organizationId, Guid policyId, string policyName)
        {
            var backupKey = $"backup:deleted-policy:{organizationId}:{policyId}";
            var backupData = new { PolicyId = policyId, PolicyName = policyName, DeletedAt = _dateTimeProvider.UtcNow };
            await _cacheService.SetAsync(backupKey, JsonSerializer.Serialize(backupData), TimeSpan.FromDays(30));
        }

        private async Task UpdatePolicyApplicationStatsAsync(Guid organizationId, Guid policyId, int affectedCount)
        {
            var statsKey = $"stats:policy-application:{organizationId}:{policyId}";
            await _cacheService.IncrementAsync(statsKey, affectedCount);
        }

        private async Task UpdatePropagationStatisticsAsync(Guid policyId, int successCount, int failureCount)
        {
            var statsKey = $"stats:policy-propagation:{policyId}";
            var stats = new { Success = successCount, Failed = failureCount, Timestamp = _dateTimeProvider.UtcNow };
            await _cacheService.SetAsync(statsKey, JsonSerializer.Serialize(stats), TimeSpan.FromDays(7));
        }

        private async Task HandlePropagationFailuresAsync(Guid policyId, List<Guid> targetOrgs, int successCount, int failureCount)
        {
            _logger.LogError("Policy propagation partially failed: PolicyId={PolicyId}, Success={Success}, Failed={Failed}",
                policyId, successCount, failureCount);
            // 실패 처리 로직
            await Task.CompletedTask;
        }

        private async Task CachePolicyConflictAsync(Guid organizationId, OrganizationPolicyType policyType, List<Guid> conflictingIds, string description)
        {
            var cacheKey = $"{POLICY_CONFLICT_CACHE_PREFIX}:{organizationId}:{policyType}";
            var conflictData = new
            {
                PolicyType = policyType,
                ConflictingPolicies = conflictingIds,
                Description = description,
                DetectedAt = _dateTimeProvider.UtcNow
            };
            await _cacheService.SetAsync(cacheKey, JsonSerializer.Serialize(conflictData), TimeSpan.FromHours(24));
        }

        private async Task AttemptConflictResolutionAsync(Guid organizationId, OrganizationPolicyType policyType, List<Guid> conflictingIds, string strategy)
        {
            _logger.LogInformation("Attempting conflict resolution: Organization={OrganizationId}, Strategy={Strategy}",
                organizationId, strategy);
            // TODO: 충돌 해결 로직 구현
            await Task.CompletedTask;
        }

        private async Task CheckForPolicyConflictsAsync(Guid organizationId, OrganizationPolicyType policyType)
        {
            // 동일 타입의 다른 정책들과 충돌 확인
            var existingPolicies = await _policyRepository.GetByTypeAsync(organizationId, policyType);
            if (existingPolicies.Count() > 1)
            {
                _logger.LogWarning("Multiple policies of same type detected: Organization={OrganizationId}, Type={PolicyType}, Count={Count}",
                    organizationId, policyType, existingPolicies.Count());
            }
        }

        private async Task EnableRealTimeMonitoringAsync(Guid organizationId)
        {
            _logger.LogInformation("Enabling real-time monitoring for Organization={OrganizationId}", organizationId);
            // TODO: 실시간 모니터링 활성화 로직
            await Task.CompletedTask;
        }

        private async Task DisableRealTimeMonitoringAsync(Guid organizationId)
        {
            _logger.LogInformation("Disabling real-time monitoring for Organization={OrganizationId}", organizationId);
            // TODO: 실시간 모니터링 비활성화 로직
            await Task.CompletedTask;
        }

        private async Task ValidateComplianceStandardsAsync(Guid organizationId, string standards)
        {
            _logger.LogInformation("Validating compliance standards: Organization={OrganizationId}, Standards={Standards}",
                organizationId, standards);
            // TODO: 컴플라이언스 표준 검증 로직
            await Task.CompletedTask;
        }

        private async Task ConfigureViolationActionAsync(Guid organizationId, string violationAction)
        {
            _logger.LogInformation("Configuring violation action: Organization={OrganizationId}, Action={Action}",
                organizationId, violationAction);
            //TODO: Violation action 설정 로직
            await Task.CompletedTask;
        }

        #endregion
    }
}