using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Common;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using System.Text.Json;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 데이터 정책 Repository 구현체 - AuthHive v15
    /// 조직의 데이터 관리 정책(보존, 암호화, 개인정보 처리 등)을 관리
    /// BaseRepository를 상속받아 캐싱, 통계, 조직 스코프 기능 활용
    /// </summary>
    public class OrganizationDataPolicyRepository : 
        BaseRepository<OrganizationDataPolicy>, 
        IOrganizationDataPolicyRepository
    {
        // JSON 직렬화 옵션 (성능 최적화)
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        public OrganizationDataPolicyRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null) 
            : base(context, organizationContext, cache)
        {
        }

        #region 기본 조회 - 캐싱 최적화

        /// <summary>
        /// 조직의 데이터 정책 조회 (캐시 활용)
        /// API 권한 체크 및 정책 적용에서 빈번하게 호출
        /// </summary>
        public async Task<OrganizationDataPolicy?> GetByOrganizationAsync(Guid organizationId)
        {
            // 캐시 키 생성
            string cacheKey = $"DataPolicy:{organizationId}";
            
            if (_cache != null && _cache.TryGetValue(cacheKey, out OrganizationDataPolicy? cached))
            {
                return cached;
            }

            // QueryForOrganization 활용하여 조직 격리 보장
            var policy = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync();

            // 캐시 저장 (10분간 유지)
            if (policy != null && _cache != null)
            {
                _cache.Set(cacheKey, policy, TimeSpan.FromMinutes(10));
            }

            return policy;
        }

        /// <summary>
        /// 여러 조직의 데이터 정책 일괄 조회
        /// 배치 작업에서 사용
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByOrganizationsAsync(
            IEnumerable<Guid> organizationIds)
        {
            var orgIds = organizationIds.ToList();
            
            // 전체 조직 대상이므로 _dbSet 직접 사용
            return await _dbSet
                .Where(p => orgIds.Contains(p.OrganizationId) && !p.IsDeleted)
                .ToListAsync();
        }

        /// <summary>
        /// 조직의 정책 존재 여부 확인 (캐시 활용)
        /// 정책 생성 전 중복 체크
        /// </summary>
        public async Task<bool> PolicyExistsForOrganizationAsync(Guid organizationId)
        {
            // GetByOrganizationAsync가 캐시를 활용하므로 재사용
            var policy = await GetByOrganizationAsync(organizationId);
            return policy != null;
        }

        /// <summary>
        /// 정책 버전으로 조회
        /// 정책 이력 추적에 사용
        /// </summary>
        public async Task<OrganizationDataPolicy?> GetByVersionAsync(
            Guid organizationId,
            int version)
        {
            return await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(p => p.PolicyVersion == version);
        }

        #endregion

        #region 컴플라이언스 검증 - 최적화된 버전

        /// <summary>
        /// 컴플라이언스 표준별 정책 준수 확인 (캐시 활용)
        /// 규정 준수 대시보드에서 자주 호출
        /// </summary>
        public async Task<(bool IsCompliant, List<string> Violations)> CheckComplianceAsync(
            Guid organizationId,
            ComplianceReportType complianceType)
        {
            // 캐시 키 생성
            string cacheKey = $"Compliance:{organizationId}:{complianceType}";
            
            if (_cache != null && _cache.TryGetValue(cacheKey, out (bool, List<string>) cachedResult))
            {
                return cachedResult;
            }

            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return (false, new List<string> { "조직 데이터 정책이 없습니다" });

            var violations = new List<string>();

            // 컴플라이언스 타입별 검증
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

            var result = (violations.Count == 0, violations);
            
            // 캐시 저장 (5분간 유지)
            if (_cache != null)
            {
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(5));
            }

            return result;
        }

        /// <summary>
        /// 여러 컴플라이언스 표준 동시 검증
        /// 종합 컴플라이언스 리포트에서 사용
        /// </summary>
        public async Task<Dictionary<ComplianceReportType, (bool IsCompliant, List<string> Violations)>> 
            CheckMultipleComplianceAsync(
                Guid organizationId,
                IEnumerable<ComplianceReportType> complianceTypes)
        {
            var results = new Dictionary<ComplianceReportType, (bool, List<string>)>();
            
            // 병렬 처리로 성능 개선
            var tasks = complianceTypes.Select(async type =>
            {
                var result = await CheckComplianceAsync(organizationId, type);
                return new { Type = type, Result = result };
            });

            var completedTasks = await Task.WhenAll(tasks);
            
            foreach (var task in completedTasks)
            {
                results[task.Type] = task.Result;
            }
            
            return results;
        }

        #region 개별 컴플라이언스 검증 로직

        private void ValidateGDPRCompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            // GDPR Article 17 - Right to erasure
            if (!policy.EnableAutoAnonymization)
                violations.Add("GDPR requires data anonymization capability (Article 17)");
                
            // GDPR Article 5 - Data minimization
            if (policy.DataRetentionDays > 1095) // 3년
                violations.Add("GDPR recommends data retention period under 3 years (Article 5)");
                
            // GDPR Article 32 - Security of processing
            if (policy.EncryptionLevel == DataEncryptionLevel.None)
                violations.Add("GDPR requires appropriate security measures including encryption (Article 32)");
                
            // GDPR Article 20 - Data portability
            if (!policy.AllowDataExport)
                violations.Add("GDPR requires data portability capability (Article 20)");
        }

        private void ValidateHIPAACompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            // HIPAA Security Rule § 164.312(a)(2)(iv)
            if (policy.EncryptionLevel < DataEncryptionLevel.Enhanced)
                violations.Add("HIPAA requires enhanced encryption for PHI (§ 164.312(a)(2)(iv))");
                
            // HIPAA § 164.316(b)(2) - Documentation retention
            if (policy.AuditLogRetentionDays < 2190) // 6년
                violations.Add("HIPAA requires audit log retention for at least 6 years (§ 164.316(b)(2))");
                
            // PHI export restrictions
            if (policy.AllowDataExport && !IsHealthcareSystemOnly(policy))
                violations.Add("HIPAA restricts PHI export to authorized healthcare systems only");
        }

        private void ValidateSOC2Compliance(OrganizationDataPolicy policy, List<string> violations)
        {
            // SOC2 audit requirements
            if (policy.AuditLogRetentionDays < 365)
                violations.Add("SOC2 requires audit log retention for at least 1 year");
                
            // SOC2 policy review requirements
            if (policy.LastReviewedAt == null || policy.LastReviewedAt < DateTime.UtcNow.AddMonths(-6))
                violations.Add("SOC2 requires policy review at least every 6 months");
                
            // SOC2 encryption requirements
            if (policy.EncryptionLevel == DataEncryptionLevel.None)
                violations.Add("SOC2 requires data encryption at rest and in transit");
        }

        private void ValidateISO27001Compliance(OrganizationDataPolicy policy, List<string> violations)
        {
            // ISO27001 A.10.1 - Cryptographic controls
            if (policy.EncryptionLevel < DataEncryptionLevel.Standard)
                violations.Add("ISO27001 requires appropriate cryptographic controls (A.10.1)");
                
            // ISO27001 A.18.1.4 - Privacy and protection
            if (!policy.EnableAutoAnonymization)
                violations.Add("ISO27001 requires data minimization practices (A.18.1.4)");
                
            // ISO27001 A.5.1.1 - Policy review
            if (policy.LastReviewedAt == null || policy.LastReviewedAt < DateTime.UtcNow.AddYears(-1))
                violations.Add("ISO27001 requires annual policy review (A.5.1.1)");
        }

        private void ValidatePCIDSSCompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            // PCI DSS Requirement 3.4 - Strong cryptography
            if (policy.EncryptionLevel < DataEncryptionLevel.Enhanced)
                violations.Add("PCI DSS requires strong encryption for cardholder data (Requirement 3.4)");
                
            // PCI DSS Requirement 3.1 - Data retention
            if (policy.DataRetentionDays > 365)
                violations.Add("PCI DSS requires minimal data retention for cardholder data (Requirement 3.1)");
                
            // PCI DSS database export restrictions
            if (policy.AllowSqlDumpExport)
                violations.Add("PCI DSS prohibits unencrypted database exports (Requirement 3.4)");
        }

        private bool IsHealthcareSystemOnly(OrganizationDataPolicy policy)
        {
            if (string.IsNullOrEmpty(policy.AllowedExternalSystems))
                return false;
                
            try
            {
                var systems = JsonSerializer.Deserialize<List<string>>(
                    policy.AllowedExternalSystems, _jsonOptions);
                return systems?.All(s => 
                    s.Contains("Healthcare", StringComparison.OrdinalIgnoreCase) || 
                    s.Contains("Medical", StringComparison.OrdinalIgnoreCase)) ?? false;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #endregion

        #region 정책 생성 및 업데이트 - 캐시 무효화 포함

        /// <summary>
        /// 데이터 정책 생성 또는 업데이트
        /// 조직 온보딩 및 정책 변경 시 사용
        /// </summary>
        public async Task<OrganizationDataPolicy> UpsertAsync(OrganizationDataPolicy policy)
        {
            // 캐시 무효화
            InvalidatePolicyCache(policy.OrganizationId);

            // 정책 유효성 검증
            var (isValid, errors) = await ValidatePolicyAsync(policy);
            if (!isValid)
            {
                throw new ArgumentException($"Policy validation failed: {string.Join(", ", errors)}");
            }

            var existing = await GetByOrganizationAsync(policy.OrganizationId);
            
            if (existing == null)
            {
                // 새 정책 생성
                policy.PolicyVersion = 1;
                var newPolicy = await AddAsync(policy); // BaseRepository 메서드 활용
                await _context.SaveChangesAsync();
                return newPolicy;
            }
            else
            {
                // 기존 정책 업데이트
                UpdatePolicyFields(existing, policy);
                existing.PolicyVersion++;
                existing.UpdatedAt = DateTime.UtcNow;
                existing.UpdatedByConnectedId = policy.UpdatedByConnectedId;

                await UpdateAsync(existing); // BaseRepository 메서드 활용
                await _context.SaveChangesAsync();
                return existing;
            }
        }

        /// <summary>
        /// 정책 필드 업데이트 헬퍼
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
        /// 정책 유효성 검증
        /// 정책 저장 전 비즈니스 규칙 검증
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

            // 보존 기간 논리 검증
            if (policy.AnonymizationAfterDays > policy.DataRetentionDays)
                errors.Add("익명화 기간은 데이터 보존 기간보다 짧아야 합니다");

            return Task.FromResult((errors.Count == 0, errors));
        }

        #endregion

        #region 통계 및 분석 - BaseRepository 기능 활용

        /// <summary>
        /// 정책 사용 통계 (캐시 활용)
        /// 관리자 대시보드에서 사용
        /// </summary>
        public async Task<DataPolicyStatistics> GetDataPolicyStatisticsAsync()
        {
            // 캐시 키
            string cacheKey = "DataPolicyStatistics:Global";
            
            if (_cache != null && _cache.TryGetValue(cacheKey, out DataPolicyStatistics? cached))
            {
                return cached ?? new DataPolicyStatistics();
            }

            // BaseRepository의 Query() 활용
            var policies = await Query().ToListAsync();

            var stats = new DataPolicyStatistics
            {
                TotalOrganizations = policies.Count,
                OrganizationsWithPolicy = policies.Count,
                EncryptionLevelDist = policies
                    .GroupBy(p => p.EncryptionLevel)
                    .ToDictionary(g => g.Key.ToString(), g => g.Count()),
                MetadataModeDist = policies
                    .GroupBy(p => p.UserMetadataMode)
                    .ToDictionary(g => g.Key.ToString(), g => g.Count()),
                AllowDataExportCount = policies.Count(p => p.AllowDataExport),
                AutoAnonymizationEnabledCount = policies.Count(p => p.EnableAutoAnonymization),
                RegulationComplianceDist = await GetComplianceBreakdownAsync(policies)
            };

            // 캐시 저장 (15분간 유지)
            if (_cache != null)
            {
                _cache.Set(cacheKey, stats, TimeSpan.FromMinutes(15));
            }

            return stats;
        }

        /// <summary>
        /// 컴플라이언스별 분석 (비동기 최적화)
        /// </summary>
        private async Task<Dictionary<string, int>> GetComplianceBreakdownAsync(
            List<OrganizationDataPolicy> policies)
        {
            var breakdown = new Dictionary<string, int>();
            
            // 병렬 처리로 성능 개선
            var tasks = Enum.GetValues<ComplianceReportType>().Select(async complianceType =>
            {
                int compliantCount = 0;
                foreach (var policy in policies)
                {
                    var (isCompliant, _) = await CheckComplianceAsync(
                        policy.OrganizationId, complianceType);
                    if (isCompliant) compliantCount++;
                }
                return new { Type = complianceType.ToString(), Count = compliantCount };
            });

            var results = await Task.WhenAll(tasks);
            
            foreach (var result in results)
            {
                breakdown[result.Type] = result.Count;
            }
            
            return breakdown;
        }

        /// <summary>
        /// 조직별 정책 준수율 계산 (캐시 활용)
        /// 컴플라이언스 스코어카드에서 사용
        /// </summary>
        public async Task<double> GetComplianceScoreAsync(Guid organizationId)
        {
            // 캐시 키
            string cacheKey = $"ComplianceScore:{organizationId}";
            
            if (_cache != null && _cache.TryGetValue(cacheKey, out double cachedScore))
            {
                return cachedScore;
            }

            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return 0.0;

            var score = 0.0;
            var maxScore = 10.0;

            // 점수 계산 로직
            if (policy.EncryptionLevel != DataEncryptionLevel.None) 
                score += 2.0;

            if (policy.DataRetentionDays <= 1095) // 3년 이하
                score += 2.0;

            if (policy.AuditLogRetentionDays >= 365) // 1년 이상
                score += 2.0;

            if (policy.EnableAutoAnonymization) 
                score += 2.0;

            if (!string.IsNullOrEmpty(policy.AllowedExternalSystems)) 
                score += 1.0;

            if (policy.LastReviewedAt != null && 
                policy.LastReviewedAt > DateTime.UtcNow.AddMonths(-6)) 
                score += 1.0;

            var result = Math.Round((score / maxScore) * 100, 2);
            
            // 캐시 저장 (10분간 유지)
            if (_cache != null)
            {
                _cache.Set(cacheKey, result, TimeSpan.FromMinutes(10));
            }

            return result;
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// 정책 관련 캐시 무효화
        /// 정책 변경 시 관련 캐시 모두 제거
        /// </summary>
        private void InvalidatePolicyCache(Guid organizationId)
        {
            if (_cache == null) return;

            // 조직별 캐시 무효화
            _cache.Remove($"DataPolicy:{organizationId}");
            _cache.Remove($"ComplianceScore:{organizationId}");
            
            // 컴플라이언스 캐시 무효화
            foreach (ComplianceReportType type in Enum.GetValues(typeof(ComplianceReportType)))
            {
                _cache.Remove($"Compliance:{organizationId}:{type}");
            }
            
            // 전역 통계 캐시 무효화
            _cache.Remove("DataPolicyStatistics:Global");
        }

        #endregion

        #region 추가 구현 메서드들

        /// <summary>
        /// 정책 업데이트 (버전 자동 증가)
        /// 관리자의 정책 수정 시 사용
        /// </summary>
        public async Task<OrganizationDataPolicy?> UpdatePolicyAsync(
            Guid organizationId,
            Action<OrganizationDataPolicy> updates)
        {
            InvalidatePolicyCache(organizationId);
            
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return null;

            updates(policy);
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            await _context.SaveChangesAsync();
            return policy;
        }

        /// <summary>
        /// 정책 버전 증가
        /// 중요 변경사항 추적에 사용
        /// </summary>
        public async Task<int> IncrementVersionAsync(Guid organizationId)
        {
            InvalidatePolicyCache(organizationId);
            
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return -1;

            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            
            await UpdateAsync(policy);
            await _context.SaveChangesAsync();
            return policy.PolicyVersion;
        }

        /// <summary>
        /// 데이터 보존 기간 업데이트
        /// 컴플라이언스 요구사항 반영 시 사용
        /// </summary>
        public async Task<bool> UpdateRetentionPolicyAsync(
            Guid organizationId,
            int? dataRetentionDays = null,
            int? auditLogRetentionDays = null,
            int? pointTransactionRetentionDays = null)
        {
            InvalidatePolicyCache(organizationId);
            
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
                await _context.SaveChangesAsync();
            }

            return updated;
        }

        /// <summary>
        /// 보존 기간이 만료된 조직 조회
        /// 데이터 정리 배치 작업에서 사용
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetExpiredRetentionPoliciesAsync(
            string dataType)
        {
            var cutoffDate = DateTime.UtcNow;
            
            return dataType.ToLower() switch
            {
                "audit" => await Query()
                    .Where(p => p.AuditLogRetentionDays > 0 && 
                               p.CreatedAt.AddDays(p.AuditLogRetentionDays) < cutoffDate)
                    .ToListAsync(),
                
                "point" => await Query()
                    .Where(p => p.PointTransactionRetentionDays > 0 && 
                               p.CreatedAt.AddDays(p.PointTransactionRetentionDays) < cutoffDate)
                    .ToListAsync(),
                
                _ => await Query()
                    .Where(p => p.DataRetentionDays > 0 && 
                               p.CreatedAt.AddDays(p.DataRetentionDays) < cutoffDate)
                    .ToListAsync()
            };
        }

        /// <summary>
        /// 보존 정책별 조직 조회
        /// 정책 분석에 사용
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByRetentionRangeAsync(
            int minRetentionDays,
            int maxRetentionDays)
        {
            return await Query()
                .Where(p => p.DataRetentionDays >= minRetentionDays && 
                           p.DataRetentionDays <= maxRetentionDays)
                .OrderBy(p => p.DataRetentionDays)
                .ToListAsync();
        }

        /// <summary>
        /// 규정 준수 확인 (문자열 버전 - 하위 호환성)
        /// 레거시 시스템 호환용
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
                if (Enum.TryParse<ComplianceReportType>(regulation, true, out var complianceType))
                {
                    var (_, typeViolations) = await CheckComplianceAsync(organizationId, complianceType);
                    violations.AddRange(typeViolations);
                }
                else
                {
                    violations.Add($"Unknown regulation type: {regulation}");
                }
            }

            return (violations.Count == 0, violations);
        }

        /// <summary>
        /// 사용자 메타데이터 모드 업데이트
        /// 개인정보 수집 정책 변경 시 사용
        /// </summary>
        public async Task<bool> UpdateUserMetadataModeAsync(
            Guid organizationId,
            UserMetadataMode mode)
        {
            InvalidatePolicyCache(organizationId);
            
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            policy.UserMetadataMode = mode;
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 프로필 수집 설정 업데이트
        /// GDPR 등 규정 대응 시 사용
        /// </summary>
        public async Task<bool> UpdateProfileCollectionAsync(
            Guid organizationId,
            bool? collectMemberProfile = null,
            bool? collectUserProfile = null)
        {
            InvalidatePolicyCache(organizationId);
            
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
                await _context.SaveChangesAsync();
            }

            return updated;
        }

        /// <summary>
        /// 특정 메타데이터 모드를 사용하는 조직 조회
        /// 정책별 조직 분류 시 사용
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByMetadataModeAsync(
            UserMetadataMode mode)
        {
            return await Query()
                .Where(p => p.UserMetadataMode == mode)
                .ToListAsync();
        }

        /// <summary>
        /// 데이터 내보내기 권한 설정
        /// 데이터 이동성 정책 관리 시 사용
        /// </summary>
        public async Task<bool> UpdateExportPermissionsAsync(
            Guid organizationId,
            bool? allowDataExport = null,
            bool? allowSqlDumpExport = null,
            bool? allowBulkApiAccess = null)
        {
            InvalidatePolicyCache(organizationId);
            
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
                await _context.SaveChangesAsync();
            }

            return updated;
        }

        /// <summary>
        /// 암호화 수준 업데이트
        /// 보안 정책 강화 시 사용
        /// </summary>
        public async Task<bool> UpdateEncryptionLevelAsync(
            Guid organizationId,
            DataEncryptionLevel level)
        {
            InvalidatePolicyCache(organizationId);
            
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            policy.EncryptionLevel = level;
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 익명화 설정 업데이트
        /// 개인정보 보호 강화 시 사용
        /// </summary>
        public async Task<bool> UpdateAnonymizationSettingsAsync(
            Guid organizationId,
            bool? enableAutoAnonymization = null,
            int? anonymizationAfterDays = null)
        {
            InvalidatePolicyCache(organizationId);
            
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
                await _context.SaveChangesAsync();
            }

            return updated;
        }

        /// <summary>
        /// 익명화가 필요한 조직 조회
        /// 익명화 배치 작업에서 사용
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetOrganizationsNeedingAnonymizationAsync(
            DateTime asOfDate)
        {
            return await Query()
                .Where(p => p.EnableAutoAnonymization && 
                           p.CreatedAt.AddDays(p.AnonymizationAfterDays) <= asOfDate)
                .ToListAsync();
        }

        /// <summary>
        /// 외부 동기화 설정 업데이트
        /// 서드파티 통합 관리 시 사용
        /// </summary>
        public async Task<bool> UpdateExternalSyncSettingsAsync(
            Guid organizationId,
            bool? allowExternalSync = null,
            IEnumerable<string>? allowedSystems = null)
        {
            InvalidatePolicyCache(organizationId);
            
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
                policy.AllowedExternalSystems = JsonSerializer.Serialize(allowedSystems.ToList(), _jsonOptions);
                updated = true;
            }

            if (updated)
            {
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy);
                await _context.SaveChangesAsync();
            }

            return updated;
        }

        /// <summary>
        /// 허용된 외부 시스템 추가
        /// 새로운 통합 승인 시 사용
        /// </summary>
        public async Task<bool> AddAllowedExternalSystemAsync(
            Guid organizationId,
            string systemName)
        {
            InvalidatePolicyCache(organizationId);
            
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            var allowedSystems = new List<string>();
            
            if (!string.IsNullOrEmpty(policy.AllowedExternalSystems))
            {
                allowedSystems = JsonSerializer.Deserialize<List<string>>(
                    policy.AllowedExternalSystems, _jsonOptions) ?? new List<string>();
            }

            if (!allowedSystems.Contains(systemName))
            {
                allowedSystems.Add(systemName);
                policy.AllowedExternalSystems = JsonSerializer.Serialize(allowedSystems, _jsonOptions);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                
                await UpdateAsync(policy);
                await _context.SaveChangesAsync();
                return true;
            }

            return false;
        }

        /// <summary>
        /// 허용된 외부 시스템 제거
        /// 통합 해제 시 사용
        /// </summary>
        public async Task<bool> RemoveAllowedExternalSystemAsync(
            Guid organizationId,
            string systemName)
        {
            InvalidatePolicyCache(organizationId);
            
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null || string.IsNullOrEmpty(policy.AllowedExternalSystems))
                return false;

            var allowedSystems = JsonSerializer.Deserialize<List<string>>(
                policy.AllowedExternalSystems, _jsonOptions) ?? new List<string>();
            
            if (allowedSystems.Remove(systemName))
            {
                policy.AllowedExternalSystems = JsonSerializer.Serialize(allowedSystems, _jsonOptions);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                
                await UpdateAsync(policy);
                await _context.SaveChangesAsync();
                return true;
            }

            return false;
        }

        /// <summary>
        /// 정책 검토 날짜 업데이트
        /// 정기 정책 검토 프로세스에서 사용
        /// </summary>
        public async Task<bool> UpdateReviewDatesAsync(
            Guid organizationId,
            DateTime reviewedAt,
            DateTime? nextReviewDate = null)
        {
            InvalidatePolicyCache(organizationId);
            
            var policy = await GetByOrganizationAsync(organizationId);
            if (policy == null)
                return false;

            policy.LastReviewedAt = reviewedAt;
            policy.NextReviewDate = nextReviewDate ?? reviewedAt.AddDays(365); // 기본 1년 후
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 검토가 필요한 정책 조회
        /// 정책 검토 리마인더에서 사용
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetPoliciesNeedingReviewAsync(
            DateTime asOfDate)
        {
            return await Query()
                .Where(p => p.NextReviewDate == null || p.NextReviewDate <= asOfDate)
                .OrderBy(p => p.NextReviewDate ?? DateTime.MinValue)
                .ToListAsync();
        }

        /// <summary>
        /// 여러 조직에 기본 정책 적용
        /// 대량 온보딩 시 사용
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
                await _context.SaveChangesAsync();
            }

            return newPolicies.Count;
        }

        /// <summary>
        /// 플랜별 정책 자동 조정
        /// 구독 플랜 변경 시 사용
        /// </summary>
        public async Task<bool> AdjustPolicyForPlanAsync(
            Guid organizationId,
            string planType)
        {
            InvalidatePolicyCache(organizationId);
            
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
                    
                default:
                    return false;
            }

            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// 정책 트렌드 분석
        /// 정책 변화 추세 모니터링에 사용
        /// </summary>
        public async Task<IEnumerable<DataPolicyTrend>> GetDataPolicyTrendsAsync(int period = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            var policies = await Query()
                .Where(p => p.UpdatedAt >= startDate)
                .OrderBy(p => p.UpdatedAt)
                .ToListAsync();

            // 일별 트렌드 분석
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
    }
}