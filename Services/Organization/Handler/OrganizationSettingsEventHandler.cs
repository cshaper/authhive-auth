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
using Microsoft.Extensions.Logging;

namespace AuthHive.Organization.Handlers
{
    /// <summary>
    /// 조직 설정 이벤트를 처리하고, 캐시 무효화 및 감사 로깅과 같은 후속 조치를 수행합니다.
    /// </summary>
    public class OrganizationSettingsEventHandler : IOrganizationSettingsEventHandler, IService
    {
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationSettingsRepository _settingsRepository;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<OrganizationSettingsEventHandler> _logger;
        private readonly IEventBus _eventBus;

        // 캐시 키 접두사 상수
        private const string SETTINGS_CACHE_PREFIX = "org:settings";
        private const string BRANDING_CACHE_PREFIX = "org:branding";
        private const string SECURITY_CACHE_PREFIX = "org:security";
        
        // 감사 액션 상수
        private const string SETTINGS_CHANGED = "ORGANIZATION_SETTINGS_CHANGED";
        private const string BRANDING_UPDATED = "ORGANIZATION_BRANDING_UPDATED";
        private const string SECURITY_POLICY_CHANGED = "ORGANIZATION_SECURITY_POLICY_CHANGED";
        private const string SETTINGS_EXPORTED = "ORGANIZATION_SETTINGS_EXPORTED";
        private const string SETTINGS_IMPORTED = "ORGANIZATION_SETTINGS_IMPORTED";
        private const string SETTINGS_RESET = "ORGANIZATION_SETTINGS_RESET";

        public OrganizationSettingsEventHandler(
            IAuditService auditService,
            ICacheService cacheService,
            IOrganizationRepository organizationRepository,
            IOrganizationSettingsRepository settingsRepository,
            IDateTimeProvider dateTimeProvider,
            ILogger<OrganizationSettingsEventHandler> logger,
            IEventBus eventBus)
        {
            _auditService = auditService;
            _cacheService = cacheService;
            _organizationRepository = organizationRepository;
            _settingsRepository = settingsRepository;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
            _eventBus = eventBus;
        }

        #region IService Implementation
        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationSettingsEventHandler initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync()
        {
            return await _cacheService.IsHealthyAsync() && await _auditService.IsHealthyAsync();
        }
        #endregion

        #region IOrganizationSettingsEventHandler Implementation

        /// <summary>
        /// 설정 변경 이벤트 처리
        /// </summary>
        public async Task OnSettingsChangedAsync(SettingsChangedEventArgs args)
        {
            try
            {
                _logger.LogInformation("Processing settings changed event for Organization {OrganizationId} with {ChangeCount} changes",
                    args.OrganizationId, args.Changes.Count);

                // 1. 감사 로그 기록
                var changeDetails = args.Changes.Select(c => new
                {
                    c.Value.Key,
                    c.Value.OldValue,
                    c.Value.NewValue,
                    c.Value.Category
                }).ToList();

                await LogSettingsEventAsync(
                    SETTINGS_CHANGED,
                    AuditActionType.Update,
                    args.ModifiedByConnectedId,
                    args.OrganizationId,
                    new { Changes = changeDetails, Timestamp = args.OccurredAt }
                );

                // 2. 캐시 무효화 - 변경된 카테고리별로 처리
                var affectedCategories = args.Changes.Values
                    .Select(c => c.Category)
                    .Distinct()
                    .ToList();

                foreach (var category in affectedCategories)
                {
                    await InvalidateSettingsCacheAsync(args.OrganizationId, category);
                }

                // 3. 중요한 설정 변경 시 알림 전송
                var criticalChanges = args.Changes.Values
                    .Where(c => IsCriticalSetting(c.Key))
                    .ToList();

                if (criticalChanges.Any())
                {
                    await NotifyCriticalSettingsChangeAsync(args.OrganizationId, criticalChanges);
                }

                _logger.LogInformation("Successfully processed settings changed event for Organization {OrganizationId}",
                    args.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing settings changed event for Organization {OrganizationId}",
                    args.OrganizationId);
                throw;
            }
        }

        /// <summary>
        /// 브랜딩 업데이트 이벤트 처리
        /// </summary>
        public async Task OnBrandingUpdatedAsync(BrandingUpdatedEventArgs args)
        {
            try
            {
                _logger.LogInformation("Processing branding update for Organization {OrganizationId}", args.OrganizationId);

                // 1. 감사 로그 기록
                await LogSettingsEventAsync(
                    BRANDING_UPDATED,
                    AuditActionType.Update,
                    args.UpdatedByConnectedId,
                    args.OrganizationId,
                    new
                    {
                        OldLogo = args.OldLogoUrl,
                        NewLogo = args.NewLogoUrl,
                        OldColor = args.OldBrandColor,
                        NewColor = args.NewBrandColor,
                        CustomBranding = args.CustomBranding,
                        Timestamp = args.OccurredAt
                    }
                );

                // 2. 브랜딩 캐시 무효화
                await InvalidateBrandingCacheAsync(args.OrganizationId);

                // 3. CDN 캐시 무효화 (로고 URL이 변경된 경우)
                if (args.OldLogoUrl != args.NewLogoUrl && !string.IsNullOrEmpty(args.NewLogoUrl))
                {
                    await InvalidateCdnCacheAsync(args.NewLogoUrl);
                }

                // 4. 하위 조직에도 브랜딩 변경 전파 (필요한 경우)
                if (await ShouldPropagateBrandingAsync(args.OrganizationId))
                {
                    await PropagateBrandingToChildOrganizationsAsync(args.OrganizationId);
                }

                _logger.LogInformation("Successfully processed branding update for Organization {OrganizationId}",
                    args.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing branding update for Organization {OrganizationId}",
                    args.OrganizationId);
                throw;
            }
        }

        /// <summary>
        /// 보안 정책 변경 이벤트 처리
        /// </summary>
        public async Task OnSecurityPolicyChangedAsync(SecurityPolicyChangedEventArgs args)
        {
            try
            {
                _logger.LogWarning("Processing security policy change for Organization {OrganizationId}, Type: {PolicyType}",
                    args.OrganizationId, args.PolicyType);

                // 1. 감사 로그 기록 (중요도: Critical)
                await LogSettingsEventAsync(
                    SECURITY_POLICY_CHANGED,
                    AuditActionType.Update,
                    args.ChangedByConnectedId,
                    args.OrganizationId,
                    new
                    {
                        PolicyType = args.PolicyType,
                        OldPolicy = args.OldPolicy,
                        NewPolicy = args.NewPolicy,
                        RequiresUserAction = args.RequiresUserAction,
                        Timestamp = args.OccurredAt
                    },
                    AuditEventSeverity.Critical
                );

                // 2. 보안 관련 캐시 무효화
                await InvalidateSecurityCacheAsync(args.OrganizationId);
                
                // 3. 모든 사용자 세션 무효화 (필요한 경우)
                if (RequiresSessionInvalidation(args.PolicyType, args.NewPolicy))
                {
                    await InvalidateAllUserSessionsAsync(args.OrganizationId);
                }

                // 4. 사용자 액션이 필요한 경우 알림
                if (args.RequiresUserAction)
                {
                    await NotifyUsersAboutSecurityPolicyChangeAsync(
                        args.OrganizationId,
                        args.PolicyType,
                        args.NewPolicy
                    );
                }

                // 5. 컴플라이언스 검증
                await ValidateComplianceAsync(args.OrganizationId, args.PolicyType, args.NewPolicy);

                _logger.LogWarning("Successfully processed security policy change for Organization {OrganizationId}",
                    args.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing security policy change for Organization {OrganizationId}",
                    args.OrganizationId);
                throw;
            }
        }

        /// <summary>
        /// 설정 내보내기 이벤트 처리
        /// </summary>
        public async Task OnSettingsExportedAsync(SettingsExportedEventArgs args)
        {
            try
            {
                _logger.LogInformation("Processing settings export for Organization {OrganizationId}, Format: {Format}, Size: {Size}",
                    args.OrganizationId, args.DataFormat, args.ExportedDataSize);

                // 1. 감사 로그 기록
                await LogSettingsEventAsync(
                    SETTINGS_EXPORTED,
                    AuditActionType.Read,
                    args.ExportedByConnectedId,
                    args.OrganizationId,
                    new
                    {
                        Format = args.DataFormat,
                        DataSize = args.ExportedDataSize,
                        Categories = args.ExportedCategories,
                        Timestamp = args.OccurredAt
                    },
                    AuditEventSeverity.Info
                );

                // 2. 내보내기 통계 업데이트
                await UpdateExportStatisticsAsync(args.OrganizationId, args.ExportedDataSize);

                _logger.LogInformation("Successfully processed settings export for Organization {OrganizationId}",
                    args.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing settings export for Organization {OrganizationId}",
                    args.OrganizationId);
                throw;
            }
        }

        /// <summary>
        /// 설정 가져오기 이벤트 처리
        /// </summary>
        public async Task OnSettingsImportedAsync(SettingsImportedEventArgs args)
        {
            try
            {
                _logger.LogInformation("Processing settings import for Organization {OrganizationId}, Imported: {Imported}, Skipped: {Skipped}",
                    args.OrganizationId, args.SettingsImported, args.SettingsSkipped);

                // 1. 감사 로그 기록
                await LogSettingsEventAsync(
                    SETTINGS_IMPORTED,
                    AuditActionType.Create,
                    args.ImportedByConnectedId,
                    args.OrganizationId,
                    new
                    {
                        Format = args.ImportFormat,
                        DataSize = args.ImportedDataSize,
                        ImportedCount = args.SettingsImported,
                        SkippedCount = args.SettingsSkipped,
                        Mode = args.ImportMode,
                        Timestamp = args.OccurredAt
                    },
                    AuditEventSeverity.Warning
                );

                // 2. 전체 설정 캐시 무효화
                await InvalidateAllSettingsCacheAsync(args.OrganizationId);

                // 3. 설정 유효성 재검증
                await ValidateImportedSettingsAsync(args.OrganizationId);

                // 4. 관련 서비스에 설정 변경 알림
                await NotifyServicesAboutSettingsImportAsync(args.OrganizationId);

                _logger.LogInformation("Successfully processed settings import for Organization {OrganizationId}",
                    args.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing settings import for Organization {OrganizationId}",
                    args.OrganizationId);
                throw;
            }
        }

        /// <summary>
        /// 설정 초기화 이벤트 처리
        /// </summary>
        public async Task OnSettingsResetAsync(SettingsResetEventArgs args)
        {
            try
            {
                _logger.LogWarning("Processing settings reset for Organization {OrganizationId}, Category: {Category}, Count: {Count}",
                    args.OrganizationId, args.ResetCategory ?? "ALL", args.SettingsResetCount);

                // 1. 백업 생성 (이미 백업 데이터가 제공됨)
                if (args.BackupData.Any())
                {
                    await StoreBackupDataAsync(args.OrganizationId, args.BackupData, args.OccurredAt);
                }

                // 2. 감사 로그 기록 (중요도: Critical)
                await LogSettingsEventAsync(
                    SETTINGS_RESET,
                    AuditActionType.Delete,
                    args.ResetByConnectedId,
                    args.OrganizationId,
                    new
                    {
                        Category = args.ResetCategory,
                        ResetCount = args.SettingsResetCount,
                        BackupCreated = args.BackupData.Any(),
                        Timestamp = args.OccurredAt
                    },
                    AuditEventSeverity.Critical
                );

                // 3. 캐시 무효화
                if (string.IsNullOrEmpty(args.ResetCategory))
                {
                    await InvalidateAllSettingsCacheAsync(args.OrganizationId);
                }
                else
                {
                    await InvalidateSettingsCacheAsync(args.OrganizationId, args.ResetCategory);
                }

                // 4. 기본 설정 적용 확인
                await EnsureDefaultSettingsAsync(args.OrganizationId, args.ResetCategory);

                // 5. 사용자에게 초기화 알림
                await NotifyUsersAboutSettingsResetAsync(args.OrganizationId, args.ResetCategory);

                _logger.LogWarning("Successfully processed settings reset for Organization {OrganizationId}",
                    args.OrganizationId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing settings reset for Organization {OrganizationId}",
                    args.OrganizationId);
                throw;
            }
        }

        #endregion

        #region Private Helper Methods

        private Task LogSettingsEventAsync(
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

        private async Task InvalidateSettingsCacheAsync(Guid organizationId, string category)
        {
            var cacheKey = $"{SETTINGS_CACHE_PREFIX}:{organizationId}:{category}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated settings cache for Organization {OrganizationId}, Category: {Category}",
                organizationId, category);
        }

        private async Task InvalidateBrandingCacheAsync(Guid organizationId)
        {
            var cacheKey = $"{BRANDING_CACHE_PREFIX}:{organizationId}";
            await _cacheService.RemoveAsync(cacheKey);
            _logger.LogDebug("Invalidated branding cache for Organization {OrganizationId}", organizationId);
        }

        private async Task InvalidateSecurityCacheAsync(Guid organizationId)
        {
            var cachePattern = $"{SECURITY_CACHE_PREFIX}:{organizationId}:*";
            await _cacheService.RemoveByPatternAsync(cachePattern);
            _logger.LogDebug("Invalidated security cache for Organization {OrganizationId}", organizationId);
        }

        private async Task InvalidateAllSettingsCacheAsync(Guid organizationId)
        {
            var cachePattern = $"{SETTINGS_CACHE_PREFIX}:{organizationId}:*";
            await _cacheService.RemoveByPatternAsync(cachePattern);
            _logger.LogDebug("Invalidated all settings cache for Organization {OrganizationId}", organizationId);
        }

        private bool IsCriticalSetting(string settingKey)
        {
            // 중요한 설정 키 목록
            var criticalKeys = new[]
            {
                "security.mfa.enabled",
                "security.password.policy",
                "security.session.timeout",
                "compliance.gdpr.enabled",
                "compliance.audit.level",
                "billing.plan",
                "billing.limit"
            };

            return criticalKeys.Any(k => settingKey.StartsWith(k, StringComparison.OrdinalIgnoreCase));
        }

        private async Task NotifyCriticalSettingsChangeAsync(Guid organizationId, List<SettingChange> criticalChanges)
        {
            // 중요 설정 변경 알림 발송
            await _eventBus.PublishAsync(new CriticalSettingsChangedNotification
            {
                OrganizationId = organizationId,
                Changes = criticalChanges
            });

            _logger.LogWarning("Critical settings changed for Organization {OrganizationId}: {Settings}",
                organizationId, string.Join(", ", criticalChanges.Select(c => c.Key)));
        }

        private async Task InvalidateCdnCacheAsync(string logoUrl)
        {
            // CDN 캐시 무효화 로직
            _logger.LogDebug("Invalidating CDN cache for URL: {Url}", logoUrl);
            // CDN API 호출 등의 구현
            await Task.CompletedTask;
        }

        private async Task<bool> ShouldPropagateBrandingAsync(Guid organizationId)
        {
            // 브랜딩 전파 여부 결정 로직
            // 계층 구조에서 하위 조직이 있는지 확인
            var org = await _organizationRepository.GetByIdAsync(organizationId);
            if (org == null) return false;
            
            // 하위 조직이 있는지 확인 (ParentOrganizationId로 판단)
            var hasChildren = await _organizationRepository.HasChildrenAsync(organizationId);
            
            // 정책 상속 모드를 확인하여 브랜딩 전파 여부 결정
            return hasChildren && org.PolicyInheritanceMode == PolicyInheritanceMode.Cascade;
        }

        private async Task PropagateBrandingToChildOrganizationsAsync(Guid parentOrgId)
        {
            var children = await _organizationRepository.GetDescendantsAsync(parentOrgId);
            foreach (var child in children)
            {
                await InvalidateBrandingCacheAsync(child.Id);
            }
            _logger.LogInformation("Propagated branding changes to {Count} child organizations", children.Count());
        }

        private bool RequiresSessionInvalidation(string policyType, Dictionary<string, object> newPolicy)
        {
            // 세션 무효화가 필요한 정책 타입
            var sessionInvalidatingPolicies = new[]
            {
                "MFA_ENFORCEMENT",
                "PASSWORD_POLICY",
                "IP_RESTRICTION",
                "DEVICE_TRUST"
            };

            return sessionInvalidatingPolicies.Contains(policyType, StringComparer.OrdinalIgnoreCase);
        }

        private async Task InvalidateAllUserSessionsAsync(Guid organizationId)
        {
            _logger.LogWarning("Invalidating all user sessions for Organization {OrganizationId}", organizationId);
            // 세션 무효화 로직 구현
            await _eventBus.PublishAsync(new InvalidateOrganizationSessionsCommand
            {
                OrganizationId = organizationId,
                Reason = "Security policy change"
            });
        }

        private async Task NotifyUsersAboutSecurityPolicyChangeAsync(
            Guid organizationId,
            string policyType,
            Dictionary<string, object> newPolicy)
        {
            // 사용자 알림 발송
            await _eventBus.PublishAsync(new SecurityPolicyChangeNotification
            {
                OrganizationId = organizationId,
                PolicyType = policyType,
                NewPolicy = newPolicy,
                RequiresUserAction = true
            });
        }

        private async Task ValidateComplianceAsync(
            Guid organizationId,
            string policyType,
            Dictionary<string, object> newPolicy)
        {
            // 컴플라이언스 검증 로직
            _logger.LogInformation("Validating compliance for Organization {OrganizationId}, Policy: {PolicyType}",
                organizationId, policyType);
            // 실제 컴플라이언스 검증 구현
            await Task.CompletedTask;
        }

        private async Task UpdateExportStatisticsAsync(Guid organizationId, long exportedDataSize)
        {
            // 내보내기 통계 업데이트
            var statsCacheKey = $"stats:export:{organizationId}";
            await _cacheService.IncrementAsync(statsCacheKey, 1);
            await _cacheService.IncrementAsync($"{statsCacheKey}:size", exportedDataSize);
        }

        private async Task ValidateImportedSettingsAsync(Guid organizationId)
        {
            // 가져온 설정 유효성 검증
            _logger.LogInformation("Validating imported settings for Organization {OrganizationId}", organizationId);
            // 설정 유효성 검증 로직
            await Task.CompletedTask;
        }

        private async Task NotifyServicesAboutSettingsImportAsync(Guid organizationId)
        {
            // 관련 서비스에 설정 가져오기 알림
            await _eventBus.PublishAsync(new SettingsImportedNotification
            {
                OrganizationId = organizationId
            });
        }

        private async Task StoreBackupDataAsync(
            Guid organizationId,
            Dictionary<string, string> backupData,
            DateTime timestamp)
        {
            // 백업 데이터 저장
            var backupKey = $"backup:settings:{organizationId}:{timestamp:yyyyMMddHHmmss}";
            await _cacheService.SetAsync(backupKey, JsonSerializer.Serialize(backupData), TimeSpan.FromDays(30));
            _logger.LogInformation("Stored backup data for Organization {OrganizationId} at {Timestamp}",
                organizationId, timestamp);
        }

        private async Task EnsureDefaultSettingsAsync(Guid organizationId, string? category)
        {
            // 기본 설정 적용 확인
            _logger.LogInformation("Ensuring default settings for Organization {OrganizationId}, Category: {Category}",
                organizationId, category ?? "ALL");
            // 기본 설정 적용 로직
            await Task.CompletedTask;
        }

        private async Task NotifyUsersAboutSettingsResetAsync(Guid organizationId, string? category)
        {
            // 설정 초기화 사용자 알림
            await _eventBus.PublishAsync(new SettingsResetNotification
            {
                OrganizationId = organizationId,
                Category = category
            });
        }

        #endregion
    }

    #region Domain Event Classes

    /// <summary>
    /// 중요 설정 변경 알림 이벤트
    /// </summary>
    internal class CriticalSettingsChangedNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public List<SettingChange> Changes { get; set; } = new();
    }

    /// <summary>
    /// 조직 세션 무효화 명령 이벤트
    /// </summary>
    internal class InvalidateOrganizationSessionsCommand : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    /// <summary>
    /// 보안 정책 변경 알림 이벤트
    /// </summary>
    internal class SecurityPolicyChangeNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string PolicyType { get; set; } = string.Empty;
        public Dictionary<string, object> NewPolicy { get; set; } = new();
        public bool RequiresUserAction { get; set; }
    }

    /// <summary>
    /// 설정 가져오기 완료 알림 이벤트
    /// </summary>
    internal class SettingsImportedNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
    }

    /// <summary>
    /// 설정 초기화 알림 이벤트
    /// </summary>
    internal class SettingsResetNotification : IDomainEvent
    {
        public Guid EventId { get; set; } = Guid.NewGuid();
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public Guid OrganizationId { get; set; }
        public string? Category { get; set; }
    }

    #endregion

    #region Extension Methods

    /// <summary>
    /// IOrganizationRepository 확장 메서드
    /// </summary>
    internal static class OrganizationRepositoryExtensions
    {
        /// <summary>
        /// 조직에 하위 조직이 있는지 확인합니다.
        /// </summary>
        public static async Task<bool> HasChildrenAsync(this IOrganizationRepository repository, Guid organizationId)
        {
            var children = await repository.GetDescendantsAsync(organizationId);
            return children.Any();
        }
    }

    #endregion
}