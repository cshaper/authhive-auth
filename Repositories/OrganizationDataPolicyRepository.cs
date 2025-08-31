using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Common;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using System.Text.Json;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Enums.Audit;


namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 데이터 정책 Repository 구현체 - AuthHive v15
    /// 조직의 데이터 관리 정책(보존, 암호화, 개인정보 처리 등)을 관리합니다.
    /// </summary>
    public class OrganizationDataPolicyRepository : OrganizationScopedRepository<OrganizationDataPolicy>, IOrganizationDataPolicyRepository
    {
        public OrganizationDataPolicyRepository(AuthDbContext context) : base(context)
        {
        }

        #region 기본 조회

        /// <summary>
        /// 조직의 데이터 정책 조회
        /// </summary>
        public async Task<OrganizationDataPolicy?> GetByOrganizationAsync(Guid organizationId)
        {
            return await _dbSet
                .FirstOrDefaultAsync(p => p.OrganizationId == organizationId && !p.IsDeleted);
        }

        /// <summary>
        /// 여러 조직의 데이터 정책 일괄 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByOrganizationsAsync(
            IEnumerable<Guid> organizationIds)
        {
            var orgIds = organizationIds.ToList();
            return await _dbSet
                .Where(p => orgIds.Contains(p.OrganizationId) && !p.IsDeleted)
                .ToListAsync();
        }

        /// <summary>
        /// 조직의 정책 존재 여부 확인
        /// </summary>
        public async Task<bool> PolicyExistsForOrganizationAsync(Guid organizationId)
        {
            return await _dbSet
                .AnyAsync(p => p.OrganizationId == organizationId && !p.IsDeleted);
        }

        /// <summary>
        /// 정책 버전으로 조회
        /// </summary>
        public async Task<OrganizationDataPolicy?> GetByVersionAsync(
            Guid organizationId,
            int version)
        {
            return await _dbSet
                .FirstOrDefaultAsync(p => p.OrganizationId == organizationId && 
                                         p.PolicyVersion == version && 
                                         !p.IsDeleted);
        }

        #endregion

        #region 컴플라이언스 검증 - 표준화된 버전

        /// <summary>
        /// 컴플라이언스 표준별 정책 준수 확인 (임시 enum 정의 사용)
        /// </summary>
        public async Task<(bool IsCompliant, List<string> Violations)> CheckComplianceAsync(
            Guid organizationId,
            ComplianceReportType complianceType)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return (false, new List<string> { "조직 데이터 정책이 없습니다" });

            var violations = new List<string>();

            switch (complianceType)
            {
                case ComplianceReportType.GDPR:
                    ValidateGDPRCompliance(policy, violations);
                    break;
                    
                case ComplianceReportType.HIPAA:
                    ValidateHIPAACompliance(policy, violations);
                    break;
                    
                case ComplianceReportType.SOC2:
                    ValidateSOC2Compliance(policy, violations);
                    break;
                    
                case ComplianceReportType.ISO27001:
                    ValidateISO27001Compliance(policy, violations);
                    break;
                    
                case ComplianceReportType.PCI_DSS:
                    ValidatePCIDSSCompliance(policy, violations);
                    break;
            }

            return (violations.Count == 0, violations);
        }

        /// <summary>
        /// 여러 컴플라이언스 표준 동시 검증
        /// </summary>
        public async Task<Dictionary<ComplianceReportType, (bool IsCompliant, List<string> Violations)>> CheckMultipleComplianceAsync(
            Guid organizationId,
            IEnumerable<ComplianceReportType> complianceTypes)
        {
            var results = new Dictionary<ComplianceReportType, (bool, List<string>)>();
            
            foreach (var type in complianceTypes)
            {
                results[type] = await CheckComplianceAsync(organizationId, type);
            }
            
            return results;
        }

        #region 개별 컴플라이언스 검증 로직

        private void ValidateGDPRCompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (!policy.EnableAutoAnonymization)
                violations.Add("GDPR requires data anonymization capability (Article 17)");
                
            if (policy.DataRetentionDays > 1095) // 3년
                violations.Add("GDPR recommends data retention period under 3 years (Article 5)");
                
            if (policy.EncryptionLevel == DataEncryptionLevel.None)
                violations.Add("GDPR requires appropriate security measures including encryption (Article 32)");
                
            if (!policy.AllowDataExport)
                violations.Add("GDPR requires data portability capability (Article 20)");
        }

        private void ValidateHIPAACompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (policy.EncryptionLevel < DataEncryptionLevel.Enhanced)
                violations.Add("HIPAA requires enhanced encryption for PHI (§ 164.312(a)(2)(iv))");
                
            if (policy.AuditLogRetentionDays < 2190) // 6년
                violations.Add("HIPAA requires audit log retention for at least 6 years (§ 164.316(b)(2))");
                
            if (policy.AllowDataExport && !IsHealthcareSystemOnly(policy))
                violations.Add("HIPAA restricts PHI export to authorized healthcare systems only");
        }

        private void ValidateSOC2Compliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (policy.AuditLogRetentionDays < 365)
                violations.Add("SOC2 requires audit log retention for at least 1 year");
                
            if (policy.LastReviewedAt == null || policy.LastReviewedAt < DateTime.UtcNow.AddMonths(-6))
                violations.Add("SOC2 requires policy review at least every 6 months");
                
            if (policy.EncryptionLevel == DataEncryptionLevel.None)
                violations.Add("SOC2 requires data encryption at rest and in transit");
        }

        private void ValidateISO27001Compliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (policy.EncryptionLevel < DataEncryptionLevel.Standard)
                violations.Add("ISO27001 requires appropriate cryptographic controls (A.10.1)");
                
            if (!policy.EnableAutoAnonymization)
                violations.Add("ISO27001 requires data minimization practices (A.18.1.4)");
                
            if (policy.LastReviewedAt == null || policy.LastReviewedAt < DateTime.UtcNow.AddYears(-1))
                violations.Add("ISO27001 requires annual policy review (A.5.1.1)");
        }

        private void ValidatePCIDSSCompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (policy.EncryptionLevel < DataEncryptionLevel.Enhanced)
                violations.Add("PCI DSS requires strong encryption for cardholder data (Requirement 3.4)");
                
            if (policy.DataRetentionDays > 365)
                violations.Add("PCI DSS requires minimal data retention for cardholder data (Requirement 3.1)");
                
            if (policy.AllowSqlDumpExport)
                violations.Add("PCI DSS prohibits unencrypted database exports (Requirement 3.4)");
        }

        private bool IsHealthcareSystemOnly(OrganizationDataPolicy policy)
        {
            if (string.IsNullOrEmpty(policy.AllowedExternalSystems))
                return false;
                
            try
            {
                var systems = JsonSerializer.Deserialize<List<string>>(policy.AllowedExternalSystems);
                return systems?.All(s => s.Contains("Healthcare") || s.Contains("Medical")) ?? false;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #endregion

        #region 정책 생성 및 업데이트 - 표준화된 버전

        /// <summary>
        /// 데이터 정책 생성 또는 업데이트 (표준화된 검증 포함)
        /// </summary>
        public async Task<OrganizationDataPolicy> UpsertAsync(OrganizationDataPolicy policy)
        {
            // 정책 유효성 검증
            var (isValid, errors) = await ValidatePolicyAsync(policy);
            if (!isValid)
            {
                throw new ArgumentException($"Policy validation failed: {string.Join(", ", errors)}");
            }

            var existing = await GetByOrganizationAsync(policy.OrganizationId);
            
            if (existing == null)
            {
                policy.PolicyVersion = 1;
                return await AddAsync(policy);
            }
            else
            {
                // 기존 정책을 업데이트하고 버전 증가
                UpdatePolicyFields(existing, policy);
                existing.PolicyVersion++;
                existing.UpdatedAt = DateTime.UtcNow;
                existing.UpdatedByConnectedId = policy.UpdatedByConnectedId;

                await UpdateAsync(existing);
                return existing;
            }
        }

        /// <summary>
        /// 정책 필드 업데이트 (표준화된 방식)
        /// </summary>
        private void UpdatePolicyFields(OrganizationDataPolicy existing, OrganizationDataPolicy newPolicy)
        {
            existing.UserMetadataMode = newPolicy.UserMetadataMode;
            existing.CollectMemberProfile = newPolicy.CollectMemberProfile;
            existing.CollectUserProfile = newPolicy.CollectUserProfile;
            existing.ApiKeyManagement = newPolicy.ApiKeyManagement;
            existing.DataRetentionDays = newPolicy.DataRetentionDays;
            existing.AuditLogRetentionDays = newPolicy.AuditLogRetentionDays;
            existing.PointTransactionRetentionDays = newPolicy.PointTransactionRetentionDays;
            existing.AllowDataExport = newPolicy.AllowDataExport;
            existing.AllowSqlDumpExport = newPolicy.AllowSqlDumpExport;
            existing.AllowBulkApiAccess = newPolicy.AllowBulkApiAccess;
            existing.EnableAutoAnonymization = newPolicy.EnableAutoAnonymization;
            existing.AnonymizationAfterDays = newPolicy.AnonymizationAfterDays;
            existing.AllowExternalSync = newPolicy.AllowExternalSync;
            existing.AllowedExternalSystems = newPolicy.AllowedExternalSystems;
            existing.EncryptionLevel = newPolicy.EncryptionLevel;
        }

        /// <summary>
        /// 정책 유효성 검증 (표준화된 버전)
        /// </summary>
        public Task<(bool IsValid, List<string> Errors)> ValidatePolicyAsync(
            OrganizationDataPolicy policy)
        {
            var errors = new List<string>();

            // 기본 검증
            if (policy.DataRetentionDays <= 0)
                errors.Add("데이터 보존 기간은 0보다 커야 합니다");

            if (policy.AuditLogRetentionDays <= 0)
                errors.Add("감사 로그 보존 기간은 0보다 커야 합니다");

            if (policy.EnableAutoAnonymization && policy.AnonymizationAfterDays <= 0)
                errors.Add("자동 익명화가 활성화된 경우 익명화 기간을 설정해야 합니다");

            // 비즈니스 로직 검증
            if (policy.EnableAutoAnonymization && policy.AnonymizationAfterDays < 30)
                errors.Add("익명화 기간은 최소 30일 이상이어야 합니다");

            if (policy.AllowDataExport && policy.EncryptionLevel == DataEncryptionLevel.None)
                errors.Add("데이터 내보내기를 허용하려면 암호화를 활성화해야 합니다");

            if (policy.AllowSqlDumpExport && policy.EncryptionLevel < DataEncryptionLevel.Enhanced)
                errors.Add("SQL 덤프 내보내기를 허용하려면 향상된 암호화 이상이 필요합니다");

            return Task.FromResult((errors.Count == 0, errors));
        }

        #endregion

        #region 통계 및 분석 - 표준화된 버전

        /// <summary>
        /// 정책 사용 통계 (표준화된 구조)
        /// </summary>
        public async Task<DataPolicyStatistics> GetDataPolicyStatisticsAsync()
        {
            var policies = await _dbSet.Where(p => !p.IsDeleted).ToListAsync();

            return new DataPolicyStatistics
            {
                TotalOrganizations = policies.Count, // TotalPolicies 대신 사용
                OrganizationsWithPolicy = policies.Count, // 정책이 있는 조직 수
                EncryptionLevelDist = policies.GroupBy(p => p.EncryptionLevel).ToDictionary(g => g.Key.ToString(), g => g.Count()),
                MetadataModeDist = policies.GroupBy(p => p.UserMetadataMode).ToDictionary(g => g.Key.ToString(), g => g.Count()),
                AllowDataExportCount = policies.Count(p => p.AllowDataExport),
                AutoAnonymizationEnabledCount = policies.Count(p => p.EnableAutoAnonymization),
                RegulationComplianceDist = GetComplianceBreakdown(policies)
            };
        }

        /// <summary>
        /// 컴플라이언스별 분석
        /// </summary>
        private Dictionary<string, int> GetComplianceBreakdown(List<OrganizationDataPolicy> policies)
        {
            var breakdown = new Dictionary<string, int>();
            
            foreach (ComplianceReportType complianceType in Enum.GetValues<ComplianceReportType>())
            {
                int compliantCount = 0;
                foreach (var policy in policies)
                {
                    var (isCompliant, _) = CheckComplianceAsync(policy.OrganizationId, complianceType).Result;
                    if (isCompliant) compliantCount++;
                }
                breakdown[complianceType.ToString()] = compliantCount;
            }
            
            return breakdown;
        }

        /// <summary>
        /// 조직별 정책 준수율 계산 (표준화된 버전)
        /// </summary>
        public async Task<double> GetComplianceScoreAsync(Guid organizationId)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return 0.0;

            var score = 0.0;
            var maxScore = 10.0;

            // 암호화 수준 (2점)
            if (policy.EncryptionLevel != DataEncryptionLevel.None) 
                score += 2.0;

            // 데이터 보존 정책 (2점)
            if (policy.DataRetentionDays <= 1095) // 3년 이하
                score += 2.0;

            // 감사 로그 보존 (2점)
            if (policy.AuditLogRetentionDays >= 365) // 1년 이상
                score += 2.0;

            // 자동 익명화 (2점)
            if (policy.EnableAutoAnonymization) 
                score += 2.0;

            // 외부 시스템 제한 (1점)
            if (!string.IsNullOrEmpty(policy.AllowedExternalSystems)) 
                score += 1.0;

            // 정기 검토 (1점)
            if (policy.LastReviewedAt != null && policy.LastReviewedAt > DateTime.UtcNow.AddMonths(-6)) 
                score += 1.0;

            return Math.Round((score / maxScore) * 100, 2);
        }

        #endregion

        #region 정책 업데이트 메서드들

        /// <summary>
        /// 정책 업데이트 (버전 자동 증가)
        /// </summary>
        public async Task<OrganizationDataPolicy?> UpdatePolicyAsync(
            Guid organizationId,
            Action<OrganizationDataPolicy> updates)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return null;

            updates(policy);
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            return policy;
        }

        /// <summary>
        /// 정책 버전 증가
        /// </summary>
        public async Task<int> IncrementVersionAsync(Guid organizationId)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return -1;

            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            
            await UpdateAsync(policy);
            return policy.PolicyVersion;
        }

        #endregion

        #region 데이터 보존 정책

        /// <summary>
        /// 데이터 보존 기간 업데이트
        /// </summary>
        public async Task<bool> UpdateRetentionPolicyAsync(
            Guid organizationId,
            int? dataRetentionDays = null,
            int? auditLogRetentionDays = null,
            int? pointTransactionRetentionDays = null)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            bool updated = false;
            
            if (dataRetentionDays.HasValue)
            {
                policy.DataRetentionDays = dataRetentionDays.Value;
                updated = true;
            }
            
            if (auditLogRetentionDays.HasValue)
            {
                policy.AuditLogRetentionDays = auditLogRetentionDays.Value;
                updated = true;
            }
            
            if (pointTransactionRetentionDays.HasValue)
            {
                policy.PointTransactionRetentionDays = pointTransactionRetentionDays.Value;
                updated = true;
            }

            if (updated)
            {
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy);
            }

            return updated;
        }

        /// <summary>
        /// 보존 기간이 만료된 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetExpiredRetentionPoliciesAsync(
            string dataType)
        {
            var cutoffDate = DateTime.UtcNow;
            
            return dataType.ToLower() switch
            {
                "audit" => await _dbSet
                    .Where(p => p.AuditLogRetentionDays > 0 && 
                               p.CreatedAt.AddDays(p.AuditLogRetentionDays) < cutoffDate && 
                               !p.IsDeleted)
                    .ToListAsync(),
                
                "point" => await _dbSet
                    .Where(p => p.PointTransactionRetentionDays > 0 && 
                               p.CreatedAt.AddDays(p.PointTransactionRetentionDays) < cutoffDate && 
                               !p.IsDeleted)
                    .ToListAsync(),
                
                _ => await _dbSet
                    .Where(p => p.DataRetentionDays > 0 && 
                               p.CreatedAt.AddDays(p.DataRetentionDays) < cutoffDate && 
                               !p.IsDeleted)
                    .ToListAsync()
            };
        }

        /// <summary>
        /// 보존 정책별 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByRetentionRangeAsync(
            int minRetentionDays,
            int maxRetentionDays)
        {
            return await _dbSet
                .Where(p => p.DataRetentionDays >= minRetentionDays && 
                           p.DataRetentionDays <= maxRetentionDays && 
                           !p.IsDeleted)
                .OrderBy(p => p.DataRetentionDays)
                .ToListAsync();
        }

        #endregion

        #region 사용자 데이터 정책

        /// <summary>
        /// 사용자 메타데이터 모드 업데이트
        /// </summary>
        public async Task<bool> UpdateUserMetadataModeAsync(
            Guid organizationId,
            UserMetadataMode mode)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            policy.UserMetadataMode = mode;
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 프로필 수집 설정 업데이트
        /// </summary>
        public async Task<bool> UpdateProfileCollectionAsync(
            Guid organizationId,
            bool? collectMemberProfile = null,
            bool? collectUserProfile = null)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            bool updated = false;
            
            if (collectMemberProfile.HasValue)
            {
                policy.CollectMemberProfile = collectMemberProfile.Value;
                updated = true;
            }
            
            if (collectUserProfile.HasValue)
            {
                policy.CollectUserProfile = collectUserProfile.Value;
                updated = true;
            }

            if (updated)
            {
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy);
            }

            return updated;
        }

        /// <summary>
        /// 특정 메타데이터 모드를 사용하는 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByMetadataModeAsync(
            UserMetadataMode mode)
        {
            return await _dbSet
                .Where(p => p.UserMetadataMode == mode && !p.IsDeleted)
                .ToListAsync();
        }

        #endregion

        #region API 키 관리

        /// <summary>
        /// API 키 관리 정책 업데이트
        /// </summary>
        public async Task<bool> UpdateApiKeyManagementAsync(
            Guid organizationId,
            ApiKeyManagementPolicy policy)
        {
            var dataPolicy = await GetByOrganizationAsync(organizationId);
            if (dataPolicy == null)
                return false;

            dataPolicy.ApiKeyManagement = policy;
            dataPolicy.PolicyVersion++;
            dataPolicy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(dataPolicy);
            return true;
        }

        /// <summary>
        /// API 키 관리 정책별 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByApiKeyPolicyAsync(
            ApiKeyManagementPolicy policy)
        {
            return await _dbSet
                .Where(p => p.ApiKeyManagement == policy && !p.IsDeleted)
                .ToListAsync();
        }

        #endregion

        #region 데이터 내보내기

        /// <summary>
        /// 데이터 내보내기 권한 설정
        /// </summary>
        public async Task<bool> UpdateExportPermissionsAsync(
            Guid organizationId,
            bool? allowDataExport = null,
            bool? allowSqlDumpExport = null,
            bool? allowBulkApiAccess = null)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            bool updated = false;
            
            if (allowDataExport.HasValue)
            {
                policy.AllowDataExport = allowDataExport.Value;
                updated = true;
            }
            
            if (allowSqlDumpExport.HasValue)
            {
                policy.AllowSqlDumpExport = allowSqlDumpExport.Value;
                updated = true;
            }
            
            if (allowBulkApiAccess.HasValue)
            {
                policy.AllowBulkApiAccess = allowBulkApiAccess.Value;
                updated = true;
            }

            if (updated)
            {
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy);
            }

            return updated;
        }

        /// <summary>
        /// 데이터 내보내기가 허용된 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetOrganizationsWithExportAsync(
            string exportType)
        {
            return exportType.ToLower() switch
            {
                "data" => await _dbSet
                    .Where(p => p.AllowDataExport && !p.IsDeleted)
                    .ToListAsync(),
                
                "sql" => await _dbSet
                    .Where(p => p.AllowSqlDumpExport && !p.IsDeleted)
                    .ToListAsync(),
                
                "bulk" => await _dbSet
                    .Where(p => p.AllowBulkApiAccess && !p.IsDeleted)
                    .ToListAsync(),
                
                _ => await _dbSet
                    .Where(p => (p.AllowDataExport || p.AllowSqlDumpExport || p.AllowBulkApiAccess) && 
                               !p.IsDeleted)
                    .ToListAsync()
            };
        }

        #endregion

        #region 개인정보 보호

        /// <summary>
        /// 익명화 설정 업데이트
        /// </summary>
        public async Task<bool> UpdateAnonymizationSettingsAsync(
            Guid organizationId,
            bool? enableAutoAnonymization = null,
            int? anonymizationAfterDays = null)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            bool updated = false;
            
            if (enableAutoAnonymization.HasValue)
            {
                policy.EnableAutoAnonymization = enableAutoAnonymization.Value;
                updated = true;
            }
            
            if (anonymizationAfterDays.HasValue)
            {
                policy.AnonymizationAfterDays = anonymizationAfterDays.Value;
                updated = true;
            }

            if (updated)
            {
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy);
            }

            return updated;
        }

        /// <summary>
        /// 익명화가 필요한 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetOrganizationsNeedingAnonymizationAsync(
            DateTime asOfDate)
        {
            return await _dbSet
                .Where(p => p.EnableAutoAnonymization && 
                           p.CreatedAt.AddDays(p.AnonymizationAfterDays) <= asOfDate && 
                           !p.IsDeleted)
                .ToListAsync();
        }

        /// <summary>
        /// 암호화 수준 업데이트
        /// </summary>
        public async Task<bool> UpdateEncryptionLevelAsync(
            Guid organizationId,
            DataEncryptionLevel level)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            policy.EncryptionLevel = level;
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 암호화 수준별 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByEncryptionLevelAsync(
            DataEncryptionLevel level)
        {
            return await _dbSet
                .Where(p => p.EncryptionLevel == level && !p.IsDeleted)
                .ToListAsync();
        }

        #endregion

        #region 외부 시스템 동기화

        /// <summary>
        /// 외부 동기화 설정 업데이트
        /// </summary>
        public async Task<bool> UpdateExternalSyncSettingsAsync(
            Guid organizationId,
            bool? allowExternalSync = null,
            IEnumerable<string>? allowedSystems = null)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            bool updated = false;
            
            if (allowExternalSync.HasValue)
            {
                policy.AllowExternalSync = allowExternalSync.Value;
                updated = true;
            }
            
            if (allowedSystems != null)
            {
                policy.AllowedExternalSystems = JsonSerializer.Serialize(allowedSystems.ToList());
                updated = true;
            }

            if (updated)
            {
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy);
            }

            return updated;
        }

        /// <summary>
        /// 특정 외부 시스템과 동기화 가능한 조직 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetOrganizationsAllowingSystemAsync(
            string systemName)
        {
            return await _dbSet
                .Where(p => p.AllowExternalSync && 
                           p.AllowedExternalSystems != null &&
                           p.AllowedExternalSystems.Contains(systemName) && 
                           !p.IsDeleted)
                .ToListAsync();
        }

        /// <summary>
        /// 허용된 외부 시스템 추가
        /// </summary>
        public async Task<bool> AddAllowedExternalSystemAsync(
            Guid organizationId,
            string systemName)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            var allowedSystems = new List<string>();
            
            if (!string.IsNullOrEmpty(policy.AllowedExternalSystems))
            {
                allowedSystems = JsonSerializer.Deserialize<List<string>>(policy.AllowedExternalSystems) ?? new List<string>();
            }

            if (!allowedSystems.Contains(systemName))
            {
                allowedSystems.Add(systemName);
                policy.AllowedExternalSystems = JsonSerializer.Serialize(allowedSystems);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                
                await UpdateAsync(policy);
                return true;
            }

            return false;
        }

        /// <summary>
        /// 허용된 외부 시스템 제거
        /// </summary>
        public async Task<bool> RemoveAllowedExternalSystemAsync(
            Guid organizationId,
            string systemName)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null || string.IsNullOrEmpty(policy.AllowedExternalSystems))
                return false;

            var allowedSystems = JsonSerializer.Deserialize<List<string>>(policy.AllowedExternalSystems) ?? new List<string>();
            
            if (allowedSystems.Remove(systemName))
            {
                policy.AllowedExternalSystems = JsonSerializer.Serialize(allowedSystems);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                
                await UpdateAsync(policy);
                return true;
            }

            return false;
        }

        #endregion

        #region 정책 검토

        /// <summary>
        /// 정책 검토 날짜 업데이트
        /// </summary>
        public async Task<bool> UpdateReviewDatesAsync(
            Guid organizationId,
            DateTime reviewedAt,
            DateTime? nextReviewDate = null)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            policy.LastReviewedAt = reviewedAt;
            policy.NextReviewDate = nextReviewDate ?? reviewedAt.AddDays(365); // 기본 1년 후
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 검토가 필요한 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetPoliciesNeedingReviewAsync(
            DateTime asOfDate)
        {
            return await _dbSet
                .Where(p => (p.NextReviewDate == null || p.NextReviewDate <= asOfDate) && 
                           !p.IsDeleted)
                .OrderBy(p => p.NextReviewDate ?? DateTime.MinValue)
                .ToListAsync();
        }

        /// <summary>
        /// 검토 이력 조회 (간단 구현 - 실제로는 별도 테이블 필요)
        /// </summary>
        public async Task<IEnumerable<DataPolicyReviewHistory>> GetReviewHistoryAsync(
            Guid organizationId,
            int limit = 10)
        {
            // 실제 구현에서는 별도의 ReviewHistory 테이블이 필요
            // 여기서는 간단한 구현으로 정책의 LastReviewedAt 정보만 반환
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy?.LastReviewedAt == null)
                return new List<DataPolicyReviewHistory>();

            return new List<DataPolicyReviewHistory>
            {
                new DataPolicyReviewHistory
                {
                    OrganizationId = organizationId,
                    ReviewDate = policy.LastReviewedAt.Value,
                    PolicyVersion = policy.PolicyVersion,
                    ReviewedByConnectedId = policy.UpdatedByConnectedId ?? Guid.Empty
                }
            };
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 여러 조직에 기본 정책 적용
        /// </summary>
        public async Task<int> ApplyDefaultPolicyAsync(
            IEnumerable<Guid> organizationIds,
            OrganizationDataPolicy templatePolicy)
        {
            var orgIds = organizationIds.ToList();
            var existingPolicies = await GetByOrganizationsAsync(orgIds);
            var existingOrgIds = existingPolicies.Select(p => p.OrganizationId).ToHashSet();
            
            var newPolicies = new List<OrganizationDataPolicy>();
            
            foreach (var orgId in orgIds.Where(id => !existingOrgIds.Contains(id)))
            {
                var newPolicy = new OrganizationDataPolicy
                {
                    OrganizationId = orgId,
                    UserMetadataMode = templatePolicy.UserMetadataMode,
                    CollectMemberProfile = templatePolicy.CollectMemberProfile,
                    CollectUserProfile = templatePolicy.CollectUserProfile,
                    ApiKeyManagement = templatePolicy.ApiKeyManagement,
                    DataRetentionDays = templatePolicy.DataRetentionDays,
                    AuditLogRetentionDays = templatePolicy.AuditLogRetentionDays,
                    PointTransactionRetentionDays = templatePolicy.PointTransactionRetentionDays,
                    AllowDataExport = templatePolicy.AllowDataExport,
                    AllowSqlDumpExport = templatePolicy.AllowSqlDumpExport,
                    AllowBulkApiAccess = templatePolicy.AllowBulkApiAccess,
                    EnableAutoAnonymization = templatePolicy.EnableAutoAnonymization,
                    AnonymizationAfterDays = templatePolicy.AnonymizationAfterDays,
                    AllowExternalSync = templatePolicy.AllowExternalSync,
                    AllowedExternalSystems = templatePolicy.AllowedExternalSystems,
                    EncryptionLevel = templatePolicy.EncryptionLevel,
                    PolicyVersion = 1,
                    CreatedByConnectedId = templatePolicy.CreatedByConnectedId
                };
                newPolicies.Add(newPolicy);
            }

            if (newPolicies.Any())
            {
                await AddRangeAsync(newPolicies);
            }

            return newPolicies.Count;
        }

        /// <summary>
        /// 정책 일괄 업데이트
        /// </summary>
        public async Task<int> BulkUpdateAsync(
            IEnumerable<Guid> organizationIds,
            Action<OrganizationDataPolicy> updates)
        {
            var policies = await GetByOrganizationsAsync(organizationIds);
            var updateCount = 0;

            foreach (var policy in policies)
            {
                updates(policy);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                updateCount++;
            }

            if (updateCount > 0)
            {
                await UpdateRangeAsync(policies);
            }

            return updateCount;
        }

        /// <summary>
        /// 플랜별 정책 자동 조정 (간단 구현)
        /// </summary>
        public async Task<bool> AdjustPolicyForPlanAsync(
            Guid organizationId,
            string planType)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            // 플랜별 기본 설정 적용
            switch (planType.ToLower())
            {
                case "basic":
                    policy.AllowDataExport = false;
                    policy.AllowSqlDumpExport = false;
                    policy.AllowBulkApiAccess = false;
                    policy.EncryptionLevel = DataEncryptionLevel.Standard;
                    break;
                    
                case "business":
                    policy.AllowDataExport = true;
                    policy.AllowSqlDumpExport = true;
                    policy.AllowBulkApiAccess = true;
                    policy.EncryptionLevel = DataEncryptionLevel.Enhanced;
                    break;
                    
                case "enterprise":
                    policy.AllowDataExport = true;
                    policy.AllowSqlDumpExport = true;
                    policy.AllowBulkApiAccess = true;
                    policy.EncryptionLevel = DataEncryptionLevel.Maximum;
                    break;
            }

            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        #endregion

        #region 통계 및 분석 - 기존 메서드명 수정

        /// <summary>
        /// 정책 사용 통계 (인터페이스와 일치)
        /// </summary>
        public async Task<DataPolicyStatistics> GetDataolicyStatisticsAsync()
        {
            return await GetDataPolicyStatisticsAsync();
        }

        /// <summary>
        /// 정책 트렌드 분석 (간단 구현)
        /// </summary>
        public async Task<IEnumerable<DataPolicyTrend>> GetDataPolicyTrendsAsync(int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            var policies = await _dbSet
                .Where(p => p.UpdatedAt >= startDate && !p.IsDeleted)
                .OrderBy(p => p.UpdatedAt)
                .ToListAsync();

            // 간단한 트렌드 분석
            return policies
                .GroupBy(p => p.UpdatedAt?.Date ?? p.CreatedAt.Date)
                .Select(g => new DataPolicyTrend
                {
                    Period = g.Key,
                    PolicyUpdates = g.Count(),
                    EncryptionUpgrades = g.Count(p => p.EncryptionLevel > DataEncryptionLevel.Standard)
                })
                .ToList();
        }

        #endregion

        #region 검증 및 규정 준수 - 기존 string 버전

        /// <summary>
        /// 규정 준수 확인 (기존 string 파라미터 버전)
        /// </summary>
        public async Task<(bool IsCompliant, List<string> Violations)> CheckComplianceAsync(
            Guid organizationId,
            IEnumerable<string> regulations)
        {
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return (false, new List<string> { "No data policy found" });

            var violations = new List<string>();

            foreach (var regulation in regulations)
            {
                switch (regulation.ToUpper())
                {
                    case "GDPR":
                        ValidateGDPRCompliance(policy, violations);
                        break;

                    case "HIPAA":
                        ValidateHIPAACompliance(policy, violations);
                        break;

                    case "SOC2":
                        ValidateSOC2Compliance(policy, violations);
                        break;

                    case "ISO27001":
                        ValidateISO27001Compliance(policy, violations);
                        break;

                    case "PCI_DSS":
                        ValidatePCIDSSCompliance(policy, violations);
                        break;
                }
            }

            return (violations.Count == 0, violations);
        }

        #endregion


    }
}
