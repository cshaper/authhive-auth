using Microsoft.EntityFrameworkCore;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Audit;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Models.Organization.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Constants.Auth;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationPolicy Repository 구현체 - AuthHive v15
    /// 조직 정책의 CRUD, 상속, 우선순위, 컴플라이언스 등 정책 관리를 담당합니다.
    /// </summary>
    public class OrganizationPolicyRepository : BaseRepository<OrganizationPolicy>, IOrganizationPolicyRepository
    {
        public OrganizationPolicyRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache) { }

        #region 정책 타입별 조회

        /// <summary>
        /// 정책 타입별 조회
        /// 사용 시점: 보안 정책 목록, 접근 제어 정책 설정 페이지
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByTypeAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            bool includeDisabled = false)
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
                .ToListAsync();
        }

        /// <summary>
        /// 정책명으로 조회
        /// 사용 시점: 정책 중복 체크, 특정 정책 상세 조회
        /// </summary>
        public async Task<OrganizationPolicy?> GetByNameAsync(Guid organizationId, string policyName)
        {
            return await FirstOrDefaultAsync(p =>
                p.OrganizationId == organizationId &&
                p.PolicyName == policyName);
        }

        #endregion

        #region 정책 상태 관리

        /// <summary>
        /// 활성 정책 조회
        /// 사용 시점: 현재 적용 중인 정책 확인, 정책 적용 엔진
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetEnabledPoliciesAsync(Guid organizationId)
        {
            return await FindByOrganizationAsync(
                organizationId,
                p => p.IsEnabled
            );
        }

        /// <summary>
        /// 유효 기간 내 정책 조회
        /// 사용 시점: 특정 시점의 정책 적용 확인, 감사 로그
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetEffectivePoliciesAsync(
            Guid organizationId,
            DateTime asOfDate)
        {
            return await QueryForOrganization(organizationId)
                .Where(p =>
                    p.IsEnabled &&
                    p.EffectiveFrom <= asOfDate &&
                    (p.EffectiveUntil == null || p.EffectiveUntil >= asOfDate))
                .OrderBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 만료 예정 정책 조회
        /// 사용 시점: 정책 갱신 알림, 만료 대시보드
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetExpiringPoliciesAsync(int daysBeforeExpiry = 30)
        {
            var targetDate = DateTime.UtcNow.AddDays(daysBeforeExpiry);

            return await _dbSet
                .Include(p => p.Organization)
                .Where(p =>
                    p.EffectiveUntil.HasValue &&
                    p.EffectiveUntil.Value <= targetDate &&
                    p.EffectiveUntil.Value > DateTime.UtcNow &&
                    p.IsEnabled &&
                    !p.IsDeleted)
                .OrderBy(p => p.EffectiveUntil)
                .ToListAsync();
        }

        #endregion

        #region 정책 우선순위

        /// <summary>
        /// 우선순위 순으로 정렬된 정책 조회
        /// 사용 시점: 정책 충돌 해결, 우선순위 관리 UI
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByPriorityAsync(
            Guid organizationId,
            OrganizationPolicyType? policyType = null)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.IsEnabled);

            if (policyType.HasValue)
            {
                query = query.Where(p => p.PolicyType == policyType.Value);
            }

            return await query
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.PolicyName)
                .ToListAsync();
        }

        /// <summary>
        /// 최고 우선순위 정책 조회
        /// 사용 시점: 정책 적용 시 최우선 규칙 결정
        /// </summary>
        public async Task<OrganizationPolicy?> GetHighestPriorityAsync(
            Guid organizationId,
            OrganizationPolicyType policyType)
        {
            return await QueryForOrganization(organizationId)
                .Where(p =>
                    p.PolicyType == policyType &&
                    p.IsEnabled)
                .OrderBy(p => p.Priority)
                .FirstOrDefaultAsync();
        }

        #endregion

        #region 정책 상속

        /// <summary>
        /// 상속 가능한 정책 조회
        /// 사용 시점: 하위 조직 생성 시 정책 상속
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetInheritablePoliciesAsync(Guid organizationId)
        {
            return await FindByOrganizationAsync(
                organizationId,
                p => p.IsInheritable && p.IsEnabled
            );
        }

        /// <summary>
        /// 시스템 정책 조회
        /// 사용 시점: 전역 정책 적용, 기본 정책 설정
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetSystemPoliciesAsync()
        {
            return await _dbSet
                .Where(p =>
                    p.IsSystemPolicy &&
                    p.IsEnabled &&
                    !p.IsDeleted)
                .OrderBy(p => p.PolicyType)
                .ThenBy(p => p.Priority)
                .ToListAsync();
        }

        #endregion

        #region 정책 검증

        /// <summary>
        /// 검증이 필요한 정책 조회
        /// 사용 시점: 정기 정책 검토, 컴플라이언스 감사
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetRequiringValidationAsync(
            int daysSinceLastValidation = 90)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-daysSinceLastValidation);

            return await _dbSet
                .Include(p => p.Organization)
                .Where(p =>
                    (p.LastValidatedAt == null || p.LastValidatedAt < cutoffDate) &&
                    p.IsEnabled &&
                    !p.IsDeleted)
                .OrderBy(p => p.LastValidatedAt ?? DateTime.MinValue)
                .ToListAsync();
        }

        /// <summary>
        /// 정책 충돌 확인
        /// 사용 시점: 새 정책 추가 시 충돌 검사
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetConflictingPoliciesAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            int priority)
        {
            return await FindByOrganizationAsync(
                organizationId,
                p => p.PolicyType == policyType &&
                     p.Priority == priority &&
                     p.IsEnabled
            );
        }

        #endregion

        #region 모니터링 정책

        /// <summary>
        /// 감사 활성화된 조직 조회
        /// 사용 시점: 감사 로그 수집 대상 결정
        /// </summary>
        public async Task<IEnumerable<Guid>> GetAuditEnabledOrganizationsAsync()
        {
            return await _dbSet
                .Where(p =>
                    p.PolicyType == OrganizationPolicyType.Monitoring &&
                    p.IsEnabled &&
                    !p.IsDeleted &&
                    p.PolicyRules.Contains("\"auditEnabled\":true"))
                .Select(p => p.OrganizationId)
                .Distinct()
                .ToListAsync();
        }

        /// <summary>
        /// 활동 추적 활성화된 조직 조회
        /// 사용 시점: 사용자 활동 모니터링 대상 결정
        /// </summary>
        public async Task<IEnumerable<Guid>> GetActivityTrackingEnabledOrganizationsAsync()
        {
            return await _dbSet
                .Where(p =>
                    p.PolicyType == OrganizationPolicyType.Monitoring &&
                    p.IsEnabled &&
                    !p.IsDeleted &&
                    p.PolicyRules.Contains("\"activityTrackingEnabled\":true"))
                .Select(p => p.OrganizationId)
                .Distinct()
                .ToListAsync();
        }

        /// <summary>
        /// 실시간 모니터링 활성화된 조직 조회
        /// 사용 시점: 실시간 알림 시스템 대상 결정
        /// </summary>
        public async Task<IEnumerable<Guid>> GetRealTimeMonitoringEnabledOrganizationsAsync()
        {
            return await _dbSet
                .Where(p =>
                    p.PolicyType == OrganizationPolicyType.Security &&
                    p.IsEnabled &&
                    !p.IsDeleted &&
                    p.PolicyRules.Contains("\"realTimeMonitoring\":true"))
                .Select(p => p.OrganizationId)
                .Distinct()
                .ToListAsync();
        }

        #endregion

        #region 컴플라이언스

        /// <summary>
        /// 컴플라이언스 표준별 정책 조회
        /// 사용 시점: 규제 준수 보고서 생성
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByComplianceStandardAsync(
            string complianceStandard)
        {
            return await _dbSet
                .Include(p => p.Organization)
                .Where(p =>
                    p.PolicyRules.Contains(complianceStandard) &&
                    p.IsEnabled &&
                    !p.IsDeleted)
                .OrderBy(p => p.OrganizationId)
                .ThenBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 조직의 컴플라이언스 검증
        /// 사용 시점: 인증 갱신, 감사 대응
        /// </summary>
        public async Task<ComplianceVerificationResult> VerifyComplianceAsync(
            Guid organizationId,
            IEnumerable<ComplianceReportType> declaredCompliances)
        {
            var result = new ComplianceVerificationResult
            {
                OrganizationId = organizationId,
                DeclaredCompliances = declaredCompliances.ToList()
            };

            foreach (var compliance in declaredCompliances)
            {
                var verification = await VerifySingleComplianceAsync(organizationId, compliance);
                result.ComplianceResults[compliance] = verification;

                if (!verification.IsCompliant)
                {
                    result.OverallCompliant = false;
                }
            }

            return result;
        }

        /// <summary>
        /// 단일 컴플라이언스 표준 검증 (내부 헬퍼)
        /// </summary>
        private async Task<SingleComplianceResult> VerifySingleComplianceAsync(
            Guid organizationId,
            ComplianceReportType complianceType)
        {
            var requiredPolicies = GetRequiredPoliciesForCompliance(complianceType);
            var orgPolicies = await FindByOrganizationAsync(
                organizationId,
                p => p.IsEnabled
            );

            var result = new SingleComplianceResult
            {
                ComplianceType = complianceType,
                RequiredPolicyCount = requiredPolicies.Count
            };

            foreach (var requiredPolicy in requiredPolicies)
            {
                var hasPolicy = orgPolicies.Any(p =>
                    p.PolicyType == requiredPolicy.PolicyType &&
                    p.PolicyRules.Contains(requiredPolicy.RequiredRule));

                if (hasPolicy)
                {
                    result.SatisfiedPolicies.Add(requiredPolicy.PolicyName);
                }
                else
                {
                    result.MissingPolicies.Add(requiredPolicy.PolicyName);
                }
            }

            result.IsCompliant = result.MissingPolicies.Count == 0;
            result.ComplianceRate = result.RequiredPolicyCount > 0 ?
                (double)result.SatisfiedPolicies.Count / result.RequiredPolicyCount : 0;

            return result;
        }

        #endregion

private List<CompliancePolicyRequirement> GetRequiredPoliciesForCompliance(ComplianceReportType complianceType)
{
    return complianceType switch
    {
        ComplianceReportType.GDPR => new List<CompliancePolicyRequirement>
        {
            new(CompliancePolicyName.DataEncryption, OrganizationPolicyType.Security, PolicyRuleKeys.DataEncryption, true),
            new(CompliancePolicyName.AccessLogging, OrganizationPolicyType.Monitoring, PolicyRuleKeys.AuditEnabled, true),
            new(CompliancePolicyName.DataRetention, OrganizationPolicyType.Compliance, PolicyRuleKeys.DataRetentionDays, true),
            new(CompliancePolicyName.ConsentManagement, OrganizationPolicyType.Compliance, PolicyRuleKeys.ConsentRequired, true)
        },
        
        ComplianceReportType.HIPAA => new List<CompliancePolicyRequirement>
        {
            new(CompliancePolicyName.PHIEncryption, OrganizationPolicyType.Security, PolicyRuleKeys.PHIEncryption, true),
            new(CompliancePolicyName.AccessControls, OrganizationPolicyType.AccessControl, PolicyRuleKeys.MFARequired, true),
            new(CompliancePolicyName.AuditTrails, OrganizationPolicyType.Monitoring, PolicyRuleKeys.DetailedAudit, true),
            new(CompliancePolicyName.BreachDetection, OrganizationPolicyType.Security, PolicyRuleKeys.BreachDetection, true)
        },
        
        ComplianceReportType.SOC2 => new List<CompliancePolicyRequirement>
        {
            new(CompliancePolicyName.SystemMonitoring, OrganizationPolicyType.Monitoring, PolicyRuleKeys.RealTimeMonitoring, true),
            new(CompliancePolicyName.ChangeManagement, OrganizationPolicyType.Security, PolicyRuleKeys.ChangeApproval, true),
            new(CompliancePolicyName.IncidentResponse, OrganizationPolicyType.Security, PolicyRuleKeys.IncidentResponse, true)
        },
        
        ComplianceReportType.ISO27001 => new List<CompliancePolicyRequirement>
        {
            new(CompliancePolicyName.RiskAssessment, OrganizationPolicyType.Security, PolicyRuleKeys.RiskAssessment, true),
            new(CompliancePolicyName.SecurityTraining, OrganizationPolicyType.Security, PolicyRuleKeys.SecurityTraining, true),
            new(CompliancePolicyName.ContinuousMonitoring, OrganizationPolicyType.Monitoring, PolicyRuleKeys.ContinuousMonitoring, true)
        },
        
        ComplianceReportType.PCI_DSS => new List<CompliancePolicyRequirement>
        {
            new(CompliancePolicyName.CardDataEncryption, OrganizationPolicyType.Security, PolicyRuleKeys.CardDataEncryption, true),
            new(CompliancePolicyName.NetworkSegmentation, OrganizationPolicyType.Security, PolicyRuleKeys.NetworkSegmentation, true),
            new(CompliancePolicyName.VulnerabilityScanning, OrganizationPolicyType.Security, PolicyRuleKeys.VulnerabilityScanning, true)
        },
        
        _ => new List<CompliancePolicyRequirement>()
    };
}
        #region 추가 유틸리티 메서드

        /// <summary>
        /// 정책 우선순위 재정렬
        /// 사용 시점: 정책 우선순위 드래그앤드롭 관리
        /// </summary>
        public async Task<bool> ReorderPrioritiesAsync(
            Guid organizationId,
            OrganizationPolicyType policyType,
            Dictionary<Guid, int> newPriorities)
        {
            var policies = await QueryForOrganization(organizationId)
                .Where(p =>
                    p.PolicyType == policyType &&
                    newPriorities.Keys.Contains(p.Id))
                .ToListAsync();

            foreach (var policy in policies)
            {
                if (newPriorities.TryGetValue(policy.Id, out var newPriority))
                {
                    policy.Priority = newPriority;
                    policy.UpdatedAt = DateTime.UtcNow;
                    InvalidateCache(policy.Id);
                }
            }

            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 정책 일괄 활성화/비활성화
        /// 사용 시점: 대량 정책 관리, 긴급 정책 비활성화
        /// </summary>
        public async Task<int> BulkToggleStatusAsync(
            IEnumerable<Guid> policyIds,
            bool isEnabled,
            Guid updatedByConnectedId)
        {
            var policies = await _dbSet
                .Where(p => policyIds.Contains(p.Id) && !p.IsDeleted)
                .ToListAsync();

            var timestamp = DateTime.UtcNow;
            foreach (var policy in policies)
            {
                policy.IsEnabled = isEnabled;
                policy.UpdatedAt = timestamp;
                policy.UpdatedByConnectedId = updatedByConnectedId;
                InvalidateCache(policy.Id);
            }

            await _context.SaveChangesAsync();
            return policies.Count;
        }

        #endregion
    }
}