using Microsoft.EntityFrameworkCore;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Audit;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OrganizationPolicy Repository 구현체 - AuthHive v15
    /// 조직 정책의 CRUD, 상속, 우선순위, 컴플라이언스 등 정책 관리를 담당합니다.
    /// </summary>
    public class OrganizationPolicyRepository : OrganizationScopedRepository<OrganizationPolicy>, IOrganizationPolicyRepository
    {
        public OrganizationPolicyRepository(AuthDbContext context) : base(context)
        {
        }

        #region 정책 타입별 조회

        /// <summary>
        /// 정책 타입별 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByTypeAsync(Guid organizationId, OrganizationPolicyType policyType, bool includeDisabled = false)
        {
            var query = _dbSet.Where(p => 
                p.OrganizationId == organizationId && 
                p.PolicyType == policyType && 
                !p.IsDeleted);

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
        /// </summary>
        public async Task<OrganizationPolicy?> GetByNameAsync(Guid organizationId, string policyName)
        {
            return await _dbSet
                .FirstOrDefaultAsync(p => 
                    p.OrganizationId == organizationId && 
                    p.PolicyName == policyName && 
                    !p.IsDeleted);
        }

        /// <summary>
        /// 조직의 컴플라이언스 실제 준수 여부 검증
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="declaredCompliances">조직이 선언한 준수 표준들</param>
        /// <returns>실제 준수 여부와 누락된 요구사항</returns>
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
        /// 단일 컴플라이언스 표준 검증
        /// </summary>
        private async Task<SingleComplianceResult> VerifySingleComplianceAsync(
            Guid organizationId, 
            ComplianceReportType complianceType)
        {
            var requiredPolicies = GetRequiredPoliciesForCompliance(complianceType);
            var orgPolicies = await _dbSet
                .Where(p => p.OrganizationId == organizationId && p.IsEnabled && !p.IsDeleted)
                .ToListAsync();

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
            result.ComplianceRate = (double)result.SatisfiedPolicies.Count / result.RequiredPolicyCount;

            return result;
        }

        /// <summary>
        /// 컴플라이언스별 필수 정책 요구사항 정의
        /// </summary>
        private List<CompliancePolicyRequirement> GetRequiredPoliciesForCompliance(ComplianceReportType complianceType)
        {
            return complianceType switch
            {
                ComplianceReportType.GDPR => new List<CompliancePolicyRequirement>
                {
                    new("Data Encryption", OrganizationPolicyType.Security, "\"dataEncryption\":true"),
                    new("Access Logging", OrganizationPolicyType.Monitoring, "\"auditEnabled\":true"),
                    new("Data Retention", OrganizationPolicyType.Compliance, "\"dataRetentionDays\""),
                    new("Consent Management", OrganizationPolicyType.Compliance, "\"consentRequired\":true")
                },
                
                ComplianceReportType.HIPAA => new List<CompliancePolicyRequirement>
                {
                    new("PHI Encryption", OrganizationPolicyType.Security, "\"phiEncryption\":true"),
                    new("Access Controls", OrganizationPolicyType.AccessControl, "\"mfaRequired\":true"),
                    new("Audit Trails", OrganizationPolicyType.Monitoring, "\"detailedAudit\":true"),
                    new("Breach Detection", OrganizationPolicyType.Security, "\"breachDetection\":true")
                },
                
                ComplianceReportType.SOC2 => new List<CompliancePolicyRequirement>
                {
                    new("System Monitoring", OrganizationPolicyType.Monitoring, "\"realTimeMonitoring\":true"),
                    new("Change Management", OrganizationPolicyType.Security, "\"changeApproval\":true"),
                    new("Incident Response", OrganizationPolicyType.Security, "\"incidentResponse\":true")
                },
                
                ComplianceReportType.ISO27001 => new List<CompliancePolicyRequirement>
                {
                    new("Risk Assessment", OrganizationPolicyType.Security, "\"riskAssessment\":true"),
                    new("Security Training", OrganizationPolicyType.Security, "\"securityTraining\":true"),
                    new("Continuous Monitoring", OrganizationPolicyType.Monitoring, "\"continuousMonitoring\":true")
                },
                
                ComplianceReportType.PCI_DSS => new List<CompliancePolicyRequirement>
                {
                    new("Card Data Encryption", OrganizationPolicyType.Security, "\"cardDataEncryption\":true"),
                    new("Network Segmentation", OrganizationPolicyType.Security, "\"networkSegmentation\":true"),
                    new("Vulnerability Scanning", OrganizationPolicyType.Security, "\"vulnerabilityScanning\":true")
                },
                
                _ => new List<CompliancePolicyRequirement>()
            };
        }

        #endregion

        #region 정책 상태 관리

        /// <summary>
        /// 활성 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetEnabledPoliciesAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(p => 
                    p.OrganizationId == organizationId && 
                    p.IsEnabled && 
                    !p.IsDeleted)
                .OrderBy(p => p.PolicyType)
                .ThenBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 유효 기간 내 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetEffectivePoliciesAsync(Guid organizationId, DateTime asOfDate)
        {
            return await _dbSet
                .Where(p => 
                    p.OrganizationId == organizationId && 
                    p.IsEnabled &&
                    p.EffectiveFrom <= asOfDate &&  // EffectiveFrom은 non-nullable DateTime
                    (p.EffectiveUntil == null || p.EffectiveUntil >= asOfDate) &&  // EffectiveUntil은 nullable DateTime?
                    !p.IsDeleted)
                .OrderBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 만료 예정 정책 조회 - 수정된 부분
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetExpiringPoliciesAsync(int daysBeforeExpiry = 30)
        {
            var targetDate = DateTime.UtcNow.AddDays(daysBeforeExpiry);

            return await _dbSet
                .Include(p => p.Organization)
                .Where(p => 
                    p.EffectiveUntil.HasValue &&
                    p.EffectiveUntil.Value <= targetDate &&
                    p.EffectiveUntil.Value > DateTime.UtcNow &&  // 수정: null과 비교하는 대신 DateTime.UtcNow와 비교
                    p.IsEnabled &&
                    !p.IsDeleted)
                .OrderBy(p => p.EffectiveUntil)
                .ToListAsync();
        }

        #endregion

        #region 정책 우선순위

        /// <summary>
        /// 우선순위 순으로 정렬된 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByPriorityAsync(Guid organizationId, OrganizationPolicyType? policyType = null)
        {
            var query = _dbSet.Where(p => 
                p.OrganizationId == organizationId && 
                p.IsEnabled && 
                !p.IsDeleted);

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
        /// </summary>
        public async Task<OrganizationPolicy?> GetHighestPriorityAsync(Guid organizationId, OrganizationPolicyType policyType)
        {
            return await _dbSet
                .Where(p => 
                    p.OrganizationId == organizationId && 
                    p.PolicyType == policyType && 
                    p.IsEnabled && 
                    !p.IsDeleted)
                .OrderBy(p => p.Priority)
                .FirstOrDefaultAsync();
        }

        #endregion

        #region 정책 상속

        /// <summary>
        /// 상속 가능한 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetInheritablePoliciesAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(p => 
                    p.OrganizationId == organizationId && 
                    p.IsInheritable && 
                    p.IsEnabled && 
                    !p.IsDeleted)
                .OrderBy(p => p.PolicyType)
                .ThenBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 시스템 정책 조회
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
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetRequiringValidationAsync(int daysSinceLastValidation = 90)
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-daysSinceLastValidation);

            return await _dbSet
                .Include(p => p.Organization)
                .Where(p => 
                    (p.LastValidatedAt == null || p.LastValidatedAt < cutoffDate) &&
                    p.IsEnabled && 
                    !p.IsDeleted)
                .OrderBy(p => p.LastValidatedAt ?? DateTime.MinValue)  // 수정: null 대신 DateTime.MinValue 사용
                .ToListAsync();
        }

        /// <summary>
        /// 정책 충돌 확인
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetConflictingPoliciesAsync(Guid organizationId, OrganizationPolicyType policyType, int priority)
        {
            return await _dbSet
                .Where(p => 
                    p.OrganizationId == organizationId && 
                    p.PolicyType == policyType && 
                    p.Priority == priority && 
                    p.IsEnabled && 
                    !p.IsDeleted)
                .ToListAsync();
        }

        #endregion

        #region 모니터링 정책

        /// <summary>
        /// 감사 활성화된 조직 조회
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
        /// 컴플라이언스 표준별 정책 조회 (문자열)
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByComplianceStandardAsync(string complianceStandard)
        {
            return await _dbSet
                .Include(p => p.Organization)
                .Where(p => 
                    p.PolicyRules.Contains(complianceStandard) && // 임시: PolicyRules에서 검색
                    p.IsEnabled && 
                    !p.IsDeleted)
                .OrderBy(p => p.OrganizationId)
                .ThenBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 컴플라이언스 표준별 정책 조회 (Enum)
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByComplianceTypeAsync(ComplianceReportType complianceType)
        {
            return await GetByComplianceStandardAsync(complianceType.ToString());
        }

        /// <summary>
        /// 다중 컴플라이언스 표준 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByComplianceTypesAsync(IEnumerable<ComplianceReportType> complianceTypes)
        {
            var complianceStrings = complianceTypes.Select(c => c.ToString()).ToList();
            
            return await _dbSet
                .Include(p => p.Organization)
                .Where(p => 
                    complianceStrings.Any(cs => p.PolicyRules.Contains(cs)) &&
                    p.IsEnabled && 
                    !p.IsDeleted)
                .OrderBy(p => p.OrganizationId)
                .ThenBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 모든 컴플라이언스 표준을 만족하는 정책 조회 (AND 조건)
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> GetByAllComplianceTypesAsync(IEnumerable<ComplianceReportType> complianceTypes)
        {
            var complianceStrings = complianceTypes.Select(c => c.ToString()).ToList();
            
            var query = _dbSet.Include(p => p.Organization)
                .Where(p => p.IsEnabled && !p.IsDeleted);

            // 모든 컴플라이언스 표준을 포함하는 정책만 필터링
            foreach (var compliance in complianceStrings)
            {
                query = query.Where(p => p.PolicyRules.Contains(compliance));
            }

            return await query
                .OrderBy(p => p.OrganizationId)
                .ThenBy(p => p.Priority)
                .ToListAsync();
        }

        /// <summary>
        /// 조직별 컴플라이언스 커버리지 조회
        /// </summary>
        public async Task<Dictionary<Guid, List<ComplianceReportType>>> GetComplianceCoverageAsync()
        {
            var policies = await _dbSet
                .Where(p => p.IsEnabled && !p.IsDeleted)
                .Select(p => new { p.OrganizationId, p.PolicyRules })
                .ToListAsync();

            var coverage = new Dictionary<Guid, List<ComplianceReportType>>();
            var allComplianceTypes = Enum.GetValues<ComplianceReportType>();

            foreach (var policy in policies)
            {
                if (!coverage.ContainsKey(policy.OrganizationId))
                {
                    coverage[policy.OrganizationId] = new List<ComplianceReportType>();
                }

                foreach (var complianceType in allComplianceTypes)
                {
                    if (policy.PolicyRules.Contains(complianceType.ToString()) && 
                        !coverage[policy.OrganizationId].Contains(complianceType))
                    {
                        coverage[policy.OrganizationId].Add(complianceType);
                    }
                }
            }

            return coverage;
        }

        /// <summary>
        /// 특정 조직의 컴플라이언스 갭 분석
        /// </summary>
        public async Task<List<ComplianceReportType>> GetComplianceGapsAsync(Guid organizationId, IEnumerable<ComplianceReportType> requiredCompliances)
        {
            var orgPolicies = await _dbSet
                .Where(p => p.OrganizationId == organizationId && p.IsEnabled && !p.IsDeleted)
                .Select(p => p.PolicyRules)
                .ToListAsync();

            var coveredCompliances = new HashSet<ComplianceReportType>();

            foreach (var policyRules in orgPolicies)
            {
                foreach (var compliance in requiredCompliances)
                {
                    if (policyRules.Contains(compliance.ToString()))
                    {
                        coveredCompliances.Add(compliance);
                    }
                }
            }

            return requiredCompliances.Except(coveredCompliances).ToList();
        }

        #endregion

        #region 추가 유틸리티 메서드

        /// <summary>
        /// 조직의 모든 정책 통계 조회
        /// </summary>
        public async Task<Dictionary<OrganizationPolicyType, int>> GetPolicyCountByTypeAsync(Guid organizationId)
        {
            return await _dbSet
                .Where(p => p.OrganizationId == organizationId && !p.IsDeleted)
                .GroupBy(p => p.PolicyType)
                .ToDictionaryAsync(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// 정책 우선순위 재정렬
        /// </summary>
        public async Task<bool> ReorderPrioritiesAsync(Guid organizationId, OrganizationPolicyType policyType, Dictionary<Guid, int> newPriorities)
        {
            var policies = await _dbSet
                .Where(p => 
                    p.OrganizationId == organizationId && 
                    p.PolicyType == policyType && 
                    newPriorities.Keys.Contains(p.Id) &&
                    !p.IsDeleted)
                .ToListAsync();

            foreach (var policy in policies)
            {
                if (newPriorities.TryGetValue(policy.Id, out var newPriority))
                {
                    policy.Priority = newPriority;
                    policy.UpdatedAt = DateTime.UtcNow;
                }
            }

            _dbSet.UpdateRange(policies);
            await _context.SaveChangesAsync();

            return true;
        }

        /// <summary>
        /// 정책 복제 (다른 조직으로)
        /// </summary>
        public async Task<OrganizationPolicy> ClonePolicyAsync(Guid sourcePolicyId, Guid targetOrganizationId, Guid clonedByConnectedId)
        {
            var sourcePolicy = await GetByIdAsync(sourcePolicyId);
            if (sourcePolicy == null) 
                throw new InvalidOperationException("Source policy not found");

            var clonedPolicy = new OrganizationPolicy
            {
                Id = Guid.NewGuid(),
                OrganizationId = targetOrganizationId,
                PolicyType = sourcePolicy.PolicyType,
                PolicyName = $"{sourcePolicy.PolicyName} (Copy)",
                Description = sourcePolicy.Description,
                PolicyRules = sourcePolicy.PolicyRules,
                Priority = sourcePolicy.Priority,
                IsEnabled = false, // 복제된 정책은 기본적으로 비활성
                IsInheritable = sourcePolicy.IsInheritable,
                RequiresApproval = sourcePolicy.RequiresApproval,
                
                EffectiveFrom = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow,
                CreatedByConnectedId = clonedByConnectedId
            };

            return await AddAsync(clonedPolicy);
        }

        /// <summary>
        /// 정책 일괄 활성화/비활성화
        /// </summary>
        public async Task<int> BulkToggleStatusAsync(IEnumerable<Guid> policyIds, bool isEnabled, Guid updatedByConnectedId)
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
            }

            _dbSet.UpdateRange(policies);
            await _context.SaveChangesAsync();

            return policies.Count;
        }

        /// <summary>
        /// 특정 조직의 정책 템플릿 적용
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> ApplyPolicyTemplateAsync(Guid organizationId, string templateName, Guid appliedByConnectedId)
        {
            // 실제로는 별도 템플릿 저장소에서 정책 템플릿을 가져와야 함
            var templatePolicies = await GetPolicyTemplateAsync(templateName);
            var appliedPolicies = new List<OrganizationPolicy>();

            foreach (var template in templatePolicies)
            {
                var policy = new OrganizationPolicy
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId,
                    PolicyType = template.PolicyType,
                    PolicyName = template.PolicyName,
                    Description = template.Description,
                    PolicyRules = template.PolicyRules,
                    Priority = template.Priority,
                    IsEnabled = template.IsEnabled,
                    IsInheritable = template.IsInheritable,
                    // RequiresApproval = template.RequiresApproval, // 제거
                    ComplianceStandards = template.ComplianceStandards,
                    EffectiveFrom = DateTime.UtcNow,
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = appliedByConnectedId
                };

                appliedPolicies.Add(await AddAsync(policy));
            }

            return appliedPolicies;
        }

        /// <summary>
        /// 정책 백업 데이터 생성
        /// </summary>
        public async Task<string> BackupPoliciesAsync(Guid organizationId)
        {
            var policies = await GetByOrganizationIdAsync(organizationId);

            var backup = new
            {
                OrganizationId = organizationId,
                BackupDate = DateTime.UtcNow,
                Version = "15.0",
                Policies = policies.Select(p => new
                {
                    p.PolicyType,
                    p.PolicyName,
                    p.Description,
                    p.PolicyRules,
                    p.Priority,
                    p.IsEnabled,
                    p.IsInheritable,
                    p.RequiresApproval,
                    // ComplianceFramework = p.ComplianceFramework, // 제거 
                    p.EffectiveFrom,
                    p.EffectiveUntil
                })
            };

            return System.Text.Json.JsonSerializer.Serialize(backup, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        }

        /// <summary>
        /// 조직 정책 상속 처리
        /// </summary>
        public async Task<IEnumerable<OrganizationPolicy>> InheritPoliciesFromParentAsync(Guid organizationId, Guid parentOrganizationId, bool overrideExisting = false)
        {
            var parentPolicies = await GetInheritablePoliciesAsync(parentOrganizationId);
            var inheritedPolicies = new List<OrganizationPolicy>();

            foreach (var parentPolicy in parentPolicies)
            {
                var existingPolicy = await GetByNameAsync(organizationId, parentPolicy.PolicyName);
                
                if (existingPolicy == null || overrideExisting)
                {
                    var inheritedPolicy = new OrganizationPolicy
                    {
                        Id = Guid.NewGuid(),
                        OrganizationId = organizationId,
                        PolicyType = parentPolicy.PolicyType,
                        PolicyName = parentPolicy.PolicyName,
                        Description = $"[Inherited] {parentPolicy.Description}",
                        PolicyRules = parentPolicy.PolicyRules,
                        Priority = parentPolicy.Priority,
                        IsEnabled = parentPolicy.IsEnabled,
                        IsInheritable = true,
                        // RequiresApproval = parentPolicy.RequiresApproval, // 제거
                        ComplianceStandards = parentPolicy.ComplianceStandards,
                        EffectiveFrom = DateTime.UtcNow,
                        // IsInherited = true, // 엔티티에 없음
                        // InheritedFromOrganizationId = parentOrganizationId, // 엔티티에 없음
                        CreatedAt = DateTime.UtcNow
                    };

                    if (existingPolicy == null)
                    {
                        inheritedPolicies.Add(await AddAsync(inheritedPolicy));
                    }
                    else
                    {
                        // 기존 정책 업데이트
                        existingPolicy.PolicyRules = inheritedPolicy.PolicyRules;
                        existingPolicy.Priority = inheritedPolicy.Priority;
                        existingPolicy.IsEnabled = inheritedPolicy.IsEnabled;
                        existingPolicy.UpdatedAt = DateTime.UtcNow;
                        
                        await UpdateAsync(existingPolicy);
                        inheritedPolicies.Add(existingPolicy);
                    }
                }
            }

            return inheritedPolicies;
        }

        #endregion

        #region 헬퍼 메서드

        /// <summary>
        /// 정책 템플릿 조회 (실제로는 별도 구현 필요)
        /// </summary>
        private async Task<IEnumerable<OrganizationPolicy>> GetPolicyTemplateAsync(string templateName)
        {
            // 실제로는 별도 템플릿 저장소에서 조회
            // 현재는 빈 목록 반환
            await Task.CompletedTask;
            return Enumerable.Empty<OrganizationPolicy>();
        }

        #endregion
    }

    #region Helper Classes for Compliance Verification

    /// <summary>
    /// 컴플라이언스 검증 결과
    /// </summary>
    public class ComplianceVerificationResult
    {
        public Guid OrganizationId { get; set; }
        public List<ComplianceReportType> DeclaredCompliances { get; set; } = new();
        public Dictionary<ComplianceReportType, SingleComplianceResult> ComplianceResults { get; set; } = new();
        public bool OverallCompliant { get; set; } = true;
        public DateTime VerifiedAt { get; set; } = DateTime.UtcNow;
        
        /// <summary>
        /// 전체 컴플라이언스 준수율
        /// </summary>
        public double OverallComplianceRate => 
            ComplianceResults.Values.Any() ? 
            ComplianceResults.Values.Average(r => r.ComplianceRate) : 0.0;
    }

    /// <summary>
    /// 단일 컴플라이언스 검증 결과  
    /// </summary>
    public class SingleComplianceResult
    {
        public ComplianceReportType ComplianceType { get; set; }
        public bool IsCompliant { get; set; }
        public int RequiredPolicyCount { get; set; }
        public List<string> SatisfiedPolicies { get; set; } = new();
        public List<string> MissingPolicies { get; set; } = new();
        public double ComplianceRate { get; set; }
        
        /// <summary>
        /// 위험 수준 (High: <50%, Medium: 50-80%, Low: >80%)
        /// </summary>
        public string RiskLevel => ComplianceRate switch
        {
            < 0.5 => "High",
            < 0.8 => "Medium", 
            _ => "Low"
        };
    }

    /// <summary>
    /// 컴플라이언스별 필수 정책 요구사항
    /// </summary>
    public record CompliancePolicyRequirement(
        string PolicyName,
        OrganizationPolicyType PolicyType, 
        string RequiredRule
    );

    #endregion
}