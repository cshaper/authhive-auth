using Microsoft.EntityFrameworkCore;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Models.Organization.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Constants.Auth;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationPolicy Repository 구현체 - AuthHive v16
    /// 조직의 운영 및 보안 정책(접근제어, 비밀번호 규칙 등)에 대한 데이터베이스 작업을 처리합니다.
    /// </summary>
    public class OrganizationPolicyRepository : BaseRepository<OrganizationPolicy>, IOrganizationPolicyRepository
    {
        private readonly ILogger<OrganizationPolicyRepository> _logger;

        /// <summary>
        /// 생성자: 필요한 서비스(DbContext, CacheService, Logger)를 주입받습니다.
        /// </summary>
        public OrganizationPolicyRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<OrganizationPolicyRepository> logger)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티가 조직 범위에 속하는지 여부를 결정합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;

        #region 정책 타입별 조회

        /// <summary>
        /// 특정 조직의 정책을 타입별로 조회합니다. (비활성화된 정책 포함 여부 선택 가능)
        /// 사용: 관리 페이지에서 '보안 정책', '접근 제어 정책' 등 타입별로 정책 목록을 필터링하여 보여줄 때 호출됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByTypeAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            bool includeDisabled = false,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType);

            if (!includeDisabled)
            {
                query = query.Where(p => p.IsEnabled);
            }

            return await query
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.PolicyName)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직 내에서 정책 이름으로 정책을 조회합니다. (캐시 활용)
        /// 사용: 새 정책 생성 시 이름 중복을 확인하거나, 이름 기반으로 특정 정책의 상세 정보를 가져올 때 사용됩니다.
        /// </summary>
        public async Task<OrganizationPolicy?> GetByNameAsync(
            Guid organizationId,
            string policyName,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"OrgPolicy:Name:{organizationId}:{policyName.ToLowerInvariant()}";
            if (_cacheService != null)
            {
                var cachedPolicy = await _cacheService.GetAsync<OrganizationPolicy>(cacheKey, cancellationToken);
                if (cachedPolicy != null) return cachedPolicy;
            }

            var policy = await QueryForOrganization(organizationId)
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.PolicyName == policyName, cancellationToken);

            if (policy != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, policy, TimeSpan.FromMinutes(15), cancellationToken);
            }
            return policy;
        }

        #endregion

        #region 정책 상태 관리

        /// <summary>
        /// 특정 조직의 활성화된(IsEnabled = true) 모든 정책을 조회합니다.
        /// 사용: 실제 정책 적용 엔진이 현재 조직에 적용해야 할 모든 유효한 정책 목록을 가져올 때 호출됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetEnabledPoliciesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.IsEnabled)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 시점(asOfDate) 기준으로 유효한(활성화 상태이며 기간 내에 있는) 정책들을 조회합니다.
        /// 사용: "어제 날짜 기준으로 어떤 정책이 적용되었는가?" 와 같이 과거 시점의 정책 적용 상태를 확인하는 감사(Audit) 기능에 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetEffectivePoliciesAsync(
            Guid organizationId,
            DateTime asOfDate,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.IsEnabled &&
                            p.EffectiveFrom <= asOfDate &&
                            (p.EffectiveUntil == null || p.EffectiveUntil >= asOfDate))
                .OrderBy(p => p.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 전체 조직을 대상으로 만료가 임박한(기본 30일 이내) 정책들을 조회합니다.
        /// 사용: 주기적인 배치 작업에서 실행되어, 정책 만료 전에 관리자에게 갱신 알림을 보내는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetExpiringPoliciesAsync(int daysBeforeExpiry = 30, CancellationToken cancellationToken = default)
        {
            var targetDate = DateTime.UtcNow.AddDays(daysBeforeExpiry);
            return await _dbSet
                .Where(p => p.EffectiveUntil.HasValue &&
                            p.EffectiveUntil.Value <= targetDate &&
                            p.EffectiveUntil.Value > DateTime.UtcNow &&
                            p.IsEnabled && !p.IsDeleted)
                .OrderBy(p => p.EffectiveUntil)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 정책 우선순위

        /// <summary>
        /// 특정 조직의 정책들을 우선순위 순으로 정렬하여 조회합니다. (선택적으로 정책 타입 필터링 가능)
        /// 사용: 정책 관리 UI에서 우선순위 목록을 표시하거나, 정책 적용 엔진이 순서대로 정책을 평가할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByPriorityAsync(
            Guid organizationId,
            OrganizationPolicyType? policyType = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId).Where(p => p.IsEnabled);

            if (policyType.HasValue)
            {
                query = query.Where(p => p.PolicyType == policyType.Value);
            }

            return await query
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.PolicyName)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직 및 정책 타입 내에서 가장 높은 우선순위(가장 작은 숫자)를 가진 정책을 조회합니다.
        /// 사용: "MFA 정책 중 가장 먼저 적용될 정책은 무엇인가?" 와 같이 여러 정책이 충돌할 때 최종적으로 적용될 하나의 정책을 결정하는 데 사용됩니다.
        /// </summary>
        public async Task<OrganizationPolicy?> GetHighestPriorityAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"HighestPolicy:{organizationId}:{policyType}";
            if (_cacheService != null)
            {
                var cachedPolicy = await _cacheService.GetAsync<OrganizationPolicy>(cacheKey, cancellationToken);
                if (cachedPolicy != null) return cachedPolicy;
            }

            var policy = await QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType && p.IsEnabled)
                .OrderBy(p => p.Priority)
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken);

            if (policy != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, policy, TimeSpan.FromMinutes(15), cancellationToken);
            }
            return policy;
        }

        #endregion

        #region 정책 상속

        /// <summary>
        /// 특정 조직의 정책 중 하위 조직으로 상속 가능한(IsInheritable = true) 정책들을 조회합니다.
        /// 사용: 새로운 하위 조직이 생성될 때, 부모 조직의 어떤 정책들을 자동으로 물려받을지를 결정하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetInheritablePoliciesAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.IsInheritable && p.IsEnabled)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 시스템 전체에 적용되는 전역 정책(IsSystemPolicy = true) 목록을 조회합니다.
        /// 사용: 조직별 설정과 관계없이 모든 조직에 강제적으로 적용해야 하는 최소 보안 요구사항 등을 설정할 때 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetSystemPoliciesAsync(CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(p => p.IsSystemPolicy && p.IsEnabled && !p.IsDeleted)
                .OrderBy(p => p.PolicyType)
                .ThenBy(p => p.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 정책 검증

        /// <summary>
        /// 마지막 검증일로부터 일정 기간(기본 90일)이 경과하여 재검증이 필요한 정책 목록을 조회합니다.
        /// 사용: 정기적인 컴플라이언스 감사나 정책 유효성 검토 프로세스에서 검토 대상을 식별하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetRequiringValidationAsync(
            int daysSinceLastValidation = 90, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-daysSinceLastValidation);
            return await _dbSet
                .Where(p => (p.LastValidatedAt == null || p.LastValidatedAt < cutoffDate) &&
                            p.IsEnabled && !p.IsDeleted)
                .OrderBy(p => p.LastValidatedAt ?? DateTime.MinValue)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 새로 추가하려는 정책과 동일한 우선순위를 가져 충돌이 발생할 수 있는 기존 정책을 조회합니다.
        /// 사용: 관리자가 새 정책을 저장하기 전에, 동일한 우선순위의 정책이 이미 존재하는지 확인하여 사용자에게 경고하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetConflictingPoliciesAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            int priority,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType &&
                            p.Priority == priority &&
                            p.IsEnabled)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 모니터링 정책

        /// <summary>
        /// '감사(Audit)' 기능이 활성화된 모니터링 정책을 가진 조직들의 ID 목록을 조회합니다.
        /// 사용: 감사 로그 수집 시스템이 어떤 조직들의 활동을 로깅해야 하는지 대상을 결정할 때 호출됩니다.
        /// </summary>
        public async Task<IEnumerable<Guid>> GetAuditEnabledOrganizationsAsync(CancellationToken cancellationToken = default)
        {
            // PolicyRules는 JSON 문자열이므로 Contains로 검색. EF.Functions.JsonContains가 더 효율적일 수 있음.
            return await _dbSet
                .Where(p => p.PolicyType == OrganizationPolicyType.Monitoring &&
                            p.IsEnabled && !p.IsDeleted &&
                            p.PolicyRules.Contains("\"auditEnabled\":true"))
                .Select(p => p.OrganizationId)
                .Distinct()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// '활동 추적' 기능이 활성화된 모니터링 정책을 가진 조직들의 ID 목록을 조회합니다.
        /// 사용: 사용자 활동 대시보드나 분석 시스템이 어떤 조직의 데이터를 수집할지 결정하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<Guid>> GetActivityTrackingEnabledOrganizationsAsync(CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(p => p.PolicyType == OrganizationPolicyType.Monitoring &&
                            p.IsEnabled && !p.IsDeleted &&
                            p.PolicyRules.Contains("\"activityTrackingEnabled\":true"))
                .Select(p => p.OrganizationId)
                .Distinct()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// '실시간 모니터링' 기능이 활성화된 보안 정책을 가진 조직들의 ID 목록을 조회합니다.
        /// 사용: 비정상 행위 탐지(Anomaly Detection)나 실시간 보안 알림 시스템이 모니터링할 대상을 결정하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<Guid>> GetRealTimeMonitoringEnabledOrganizationsAsync(CancellationToken cancellationToken = default)
        {
            return await _dbSet
                .Where(p => p.PolicyType == OrganizationPolicyType.Security &&
                            p.IsEnabled && !p.IsDeleted &&
                            p.PolicyRules.Contains("\"realTimeMonitoring\":true"))
                .Select(p => p.OrganizationId)
                .Distinct()
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 컴플라이언스

        /// <summary>
        /// 특정 컴플라이언스 표준(예: "GDPR")과 관련된 정책들을 조회합니다.
        /// 사용: 특정 규제(예: GDPR) 준수 현황 보고서를 생성할 때, 해당 규제와 관련된 모든 정책들을 필터링하는 데 사용됩니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByComplianceStandardAsync(
            string complianceStandard, CancellationToken cancellationToken = default)
        {
            // PolicyRules JSON 문자열에 complianceStandard가 포함되어 있는지 확인
            return await _dbSet
                .Where(p => p.PolicyRules.Contains(complianceStandard) &&
                            p.IsEnabled && !p.IsDeleted)
                .OrderBy(p => p.OrganizationId)
                .ThenBy(p => p.Priority)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직이 선언한 컴플라이언스 표준들을 실제로 준수하고 있는지 검증합니다.
        /// 사용: 조직의 컴플라이언스 인증 상태를 갱신하거나, 내부/외부 감사에 대응할 때 자동화된 검증을 수행하기 위해 호출됩니다.
        /// </summary>
        public async Task<ComplianceVerificationResult> VerifyComplianceAsync(
            Guid organizationId,
            IEnumerable<ComplianceReportType> declaredCompliances,
            CancellationToken cancellationToken = default)
        {
            var result = new ComplianceVerificationResult { OrganizationId = organizationId, DeclaredCompliances = declaredCompliances.ToList() };
            var activePolicies = await GetEnabledPoliciesAsync(organizationId, cancellationToken);

            foreach (var compliance in declaredCompliances)
            {
                var verification = VerifySingleCompliance(activePolicies, compliance);
                result.ComplianceResults[compliance] = verification;
                if (!verification.IsCompliant)
                {
                    result.OverallCompliant = false;
                }
            }
            return result;
        }
        
        /// <summary>
        /// 단일 컴플라이언스 표준에 대한 준수 여부를 검증하는 내부 헬퍼 메서드.
        /// </summary>
        private SingleComplianceResult VerifySingleCompliance(IEnumerable<OrganizationPolicy> activePolicies, ComplianceReportType complianceType)
        {
            var requiredPolicies = GetRequiredPoliciesForCompliance(complianceType);
            var result = new SingleComplianceResult { ComplianceType = complianceType, RequiredPolicyCount = requiredPolicies.Count };

            foreach (var req in requiredPolicies)
            {
                bool hasPolicy = activePolicies.Any(p => p.PolicyType == req.PolicyType && p.PolicyRules.Contains(req.RequiredRule));
                if (hasPolicy) result.SatisfiedPolicies.Add(req.PolicyName);
                else result.MissingPolicies.Add(req.PolicyName);
            }

            result.IsCompliant = result.MissingPolicies.Count == 0;
            result.ComplianceRate = result.RequiredPolicyCount > 0 ? (double)result.SatisfiedPolicies.Count / result.RequiredPolicyCount : 1.0;
            return result;
        }

        /// <summary>
        /// 각 컴플라이언스 타입별로 필요한 정책 요구사항 목록을 반환하는 헬퍼 메서드.
        /// </summary>
        private List<CompliancePolicyRequirement> GetRequiredPoliciesForCompliance(ComplianceReportType complianceType)
        {
            // 이 부분은 설정 파일이나 별도의 서비스에서 관리하는 것이 더 유연할 수 있습니다.
            return complianceType switch
            {
                ComplianceReportType.GDPR => new List<CompliancePolicyRequirement>
                {
                    new(CompliancePolicyName.DataEncryption, OrganizationPolicyType.Security, PolicyRuleKeys.DataEncryption, true),
                    new(CompliancePolicyName.AccessLogging, OrganizationPolicyType.Monitoring, PolicyRuleKeys.AuditEnabled, true),
                },
                ComplianceReportType.HIPAA => new List<CompliancePolicyRequirement>
                {
                    new(CompliancePolicyName.PHIEncryption, OrganizationPolicyType.Security, PolicyRuleKeys.PHIEncryption, true),
                    new(CompliancePolicyName.AccessControls, OrganizationPolicyType.AccessControl, PolicyRuleKeys.MFARequired, true),
                },
                // ... 다른 컴플라이언스 타입에 대한 정의 ...
                _ => new List<CompliancePolicyRequirement>()
            };
        }


        #endregion

        #region 유틸리티

        /// <summary>
        /// 특정 조직 및 정책 타입 내의 여러 정책들의 우선순위를 한 번에 재정렬합니다.
        /// 사용: 관리 페이지에서 사용자가 드래그 앤 드롭으로 정책 순서를 변경한 후, 변경된 순서를 DB에 일괄 저장할 때 호출됩니다.
        /// </summary>
        public async Task<bool> ReorderPrioritiesAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            Dictionary<Guid, int> newPriorities,
            CancellationToken cancellationToken = default)
        {
            var policiesToUpdate = await QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType && newPriorities.Keys.Contains(p.Id))
                .ToListAsync(cancellationToken);

            if (!policiesToUpdate.Any()) return false;

            foreach (var policy in policiesToUpdate)
            {
                if (newPriorities.TryGetValue(policy.Id, out var newPriority))
                {
                    policy.Priority = newPriority;
                    // UpdatedAt 등은 Interceptor가 처리
                }
            }
            // 실제 저장은 UnitOfWork에서 처리 (SaveChangesAsync 호출 없음)
            // 캐시 무효화는 서비스 레이어에서 처리하거나 여기서 각 policy에 대해 수행
            var invalidationTasks = policiesToUpdate.Select(p => InvalidatePolicyCacheAsync(p, cancellationToken));
            await Task.WhenAll(invalidationTasks);

            return true;
        }

        /// <summary>
        /// 여러 정책 ID를 받아 해당 정책들의 활성화/비활성화 상태를 일괄적으로 변경합니다.
        /// 사용: 관리자가 여러 정책을 선택하여 한 번에 '사용 안 함'으로 변경하거나, 시스템 장애 시 특정 유형의 정책들을 긴급히 비활성화할 때 사용됩니다.
        /// </summary>
        public async Task<int> BulkToggleStatusAsync(
            IEnumerable<Guid> policyIds,
            bool isEnabled,
            Guid updatedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            // ExecuteUpdateAsync를 사용하여 효율적으로 일괄 업데이트
            var affectedRows = await _dbSet
                .Where(p => policyIds.Contains(p.Id) && !p.IsDeleted)
                .ExecuteUpdateAsync(updates => updates
                    .SetProperty(p => p.IsEnabled, isEnabled)
                    .SetProperty(p => p.UpdatedAt, DateTime.UtcNow)
                    .SetProperty(p => p.UpdatedByConnectedId, updatedByConnectedId),
                    cancellationToken);

            // 일괄 업데이트 후 관련 캐시 무효화
            // 주의: 어떤 정책이 변경되었는지 정확히 알 수 없으므로, 관련된 캐시를 더 광범위하게 무효화해야 할 수 있음.
            // 여기서는 간단히 ID 기반으로만 처리 (개선 필요)
            if (affectedRows > 0 && _cacheService != null)
            {
                // This is inefficient. A better approach would be to fetch the policies first
                // to invalidate specific caches, or use a more advanced cache tagging system.
                _logger.LogWarning("BulkToggleStatusAsync executed. Consider a more granular cache invalidation strategy.");
            }

            return affectedRows;
        }

        /// <summary>
        /// 특정 조직 및 정책 타입 내에서 주어진 우선순위가 이미 사용 중인지 확인합니다. (수정 시 자신은 제외)
        /// 사용: 새 정책을 생성하거나 기존 정책의 우선순위를 변경할 때, 해당 우선순위가 다른 정책과 중복되는지 검사하는 데 사용됩니다.
        /// </summary>
        public async Task<bool> IsPriorityTakenAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            int priority,
            Guid? excludePolicyId = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType && p.Priority == priority);

            if (excludePolicyId.HasValue)
            {
                // 수정 중인 자기 자신은 중복 검사에서 제외
                query = query.Where(p => p.Id != excludePolicyId.Value);
            }
            
            return await query.AnyAsync(cancellationToken);
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 특정 정책과 관련된 캐시 항목들을 무효화합니다.
        /// </summary>
        private async Task InvalidatePolicyCacheAsync(OrganizationPolicy policy, CancellationToken cancellationToken)
        {
            if (_cacheService == null || policy == null) return;

            var tasks = new List<Task>
            {
                // 이름 기반 캐시
                _cacheService.RemoveAsync($"OrgPolicy:Name:{policy.OrganizationId}:{policy.PolicyName.ToLowerInvariant()}", cancellationToken),
                // 최고 우선순위 캐시
                _cacheService.RemoveAsync($"HighestPolicy:{policy.OrganizationId}:{policy.PolicyType}", cancellationToken)
            };
            
            try
            {
                await Task.WhenAll(tasks);
            }
            catch(Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache for policy {PolicyId}", policy.Id);
            }
        }

        #endregion
    }
}
