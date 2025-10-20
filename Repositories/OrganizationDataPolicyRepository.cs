using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Common;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using System.Text.Json;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Interfaces.Infra.Cache;
using System.Threading;
using System.Linq;
using System.Collections.Generic;
using System;
using System.Collections.Concurrent;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 컴플라이언스 검증 결과를 캐싱하기 위한 래퍼 클래스
    /// </summary>
    internal class ComplianceCacheItem
    {
        public bool IsCompliant { get; set; }
        public List<string> Violations { get; set; } = new List<string>();
    }

    /// <summary>
    /// Nullable double 값을 캐싱하기 위한 래퍼 클래스
    /// </summary>
    internal class NullableDoubleCacheItem
    {
        public double? Value { get; set; }
    }

    /// <summary>
    /// 조직 데이터 정책 Repository 구현체 - AuthHive v16 (int 오류 최종 수정 및 주석)
    /// </summary>
    public class OrganizationDataPolicyRepository :
        BaseRepository<OrganizationDataPolicy>,
        IOrganizationDataPolicyRepository
    {
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        /// <summary>
        /// 생성자: DbContext와 CacheService 의존성을 주입받습니다.
        /// </summary>
        public OrganizationDataPolicyRepository(
            AuthDbContext context,
            ICacheService? cacheService = null)
            : base(context, cacheService)
        {
        }

        /// <summary>
        /// 엔티티가 조직 범위인지 여부를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => true;

        #region 기본 조회

        /// <summary>
        /// 특정 조직 ID로 데이터 정책을 조회합니다. (캐시 우선)
        /// </summary>
        public async Task<OrganizationDataPolicy?> GetByOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            string cacheKey = $"DataPolicy:Org:{organizationId}";
            if (_cacheService != null)
            {
                var cachedPolicy = await _cacheService.GetAsync<OrganizationDataPolicy>(cacheKey, cancellationToken);
                if (cachedPolicy != null) return cachedPolicy;
            }

            var policyFromDb = await QueryForOrganization(organizationId)
                .AsNoTracking()
                .FirstOrDefaultAsync(cancellationToken);

            if (policyFromDb != null && _cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, policyFromDb, TimeSpan.FromMinutes(10), cancellationToken);
            }
            return policyFromDb;
        }

        /// <summary>
        /// 여러 조직 ID로 데이터 정책들을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByOrganizationsAsync(
            IEnumerable<Guid> organizationIds, CancellationToken cancellationToken = default)
        {
            var orgIdsList = organizationIds.ToList();
            return await _dbSet
                .Where(p => !p.IsDeleted && orgIdsList.Contains(p.OrganizationId))
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 조직에 정책이 존재하는지 확인합니다. (캐시 활용)
        /// </summary>
        public async Task<bool> PolicyExistsForOrganizationAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var policy = await GetByOrganizationAsync(organizationId, cancellationToken);
            return policy != null;
        }

        /// <summary>
        /// 특정 조직의 특정 버전 정책을 조회합니다.
        /// </summary>
        public async Task<OrganizationDataPolicy?> GetByVersionAsync(
            Guid organizationId, int version, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.PolicyVersion == version, cancellationToken);
        }

        #endregion

        #region 정책 생성 및 업데이트

        /// <summary>
        /// 데이터 정책을 생성하거나 업데이트합니다.
        /// </summary>
        public async Task<OrganizationDataPolicy> UpsertAsync(OrganizationDataPolicy policy, CancellationToken cancellationToken = default)
        {
            var (isValid, errors) = await ValidatePolicyAsync(policy, cancellationToken);
            if (!isValid) throw new ArgumentException($"Policy validation failed: {string.Join(", ", errors)}");

            await InvalidatePolicyCacheAsync(policy.OrganizationId, cancellationToken);
            var existing = await QueryForOrganization(policy.OrganizationId).FirstOrDefaultAsync(cancellationToken);

            if (existing == null)
            {
                policy.PolicyVersion = 1;
                await AddAsync(policy, cancellationToken);
                return policy;
            }
            else
            {
                UpdatePolicyFields(existing, policy);
                existing.PolicyVersion++;
                existing.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(existing, cancellationToken);
                return existing;
            }
        }

        /// <summary>
        /// Action을 통해 정책 필드를 업데이트합니다.
        /// </summary>
        public async Task<OrganizationDataPolicy?> UpdatePolicyAsync(
            Guid organizationId, Action<OrganizationDataPolicy> updates, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return null;

            await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
            updates(policy);
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy, cancellationToken);
            return policy;
        }

        /// <summary>
        /// 정책 버전 번호만 증가시킵니다.
        /// </summary>
        public async Task<int> IncrementVersionAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return -1;

            await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy, cancellationToken);
            return policy.PolicyVersion;
        }

        /// <summary>
        /// 엔티티 필드 값 복사 헬퍼.
        /// </summary>
        private void UpdatePolicyFields(OrganizationDataPolicy existing, OrganizationDataPolicy source)
        {
            existing.UserMetadataMode = source.UserMetadataMode;
            existing.CollectMemberProfile = source.CollectMemberProfile;
            existing.CollectUserProfile = source.CollectUserProfile;
            existing.ApiKeyManagement = source.ApiKeyManagement;
            existing.DataRetentionDays = source.DataRetentionDays;
            existing.AuditLogRetentionDays = source.AuditLogRetentionDays;
            existing.PointTransactionRetentionDays = source.PointTransactionRetentionDays;
            existing.AllowDataExport = source.AllowDataExport;
            existing.AllowSqlDumpExport = source.AllowSqlDumpExport;
            existing.AllowBulkApiAccess = source.AllowBulkApiAccess;
            existing.EnableAutoAnonymization = source.EnableAutoAnonymization;
            existing.AnonymizationAfterDays = source.AnonymizationAfterDays;
            existing.AllowExternalSync = source.AllowExternalSync;
            existing.AllowedExternalSystems = source.AllowedExternalSystems;
            existing.EncryptionLevel = source.EncryptionLevel;
        }

        #endregion

        #region 데이터 보존 정책 (int 타입 기준 수정)

        /// <summary>
        /// 데이터 보존 기간 설정을 업데이트합니다. (int 타입 처리)
        /// </summary>
        public async Task<bool> UpdateRetentionPolicyAsync(Guid organizationId, int? dataRetentionDays = null, int? auditLogRetentionDays = null, int? pointTransactionRetentionDays = null, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            bool updated = false;
            // int? 타입의 파라미터 값을 int 타입 필드에 적용
            if (dataRetentionDays.HasValue && policy.DataRetentionDays != dataRetentionDays.Value) { policy.DataRetentionDays = dataRetentionDays.Value; updated = true; }
            if (auditLogRetentionDays.HasValue && policy.AuditLogRetentionDays != auditLogRetentionDays.Value) { policy.AuditLogRetentionDays = auditLogRetentionDays.Value; updated = true; }
            if (pointTransactionRetentionDays.HasValue && policy.PointTransactionRetentionDays != pointTransactionRetentionDays.Value) { policy.PointTransactionRetentionDays = pointTransactionRetentionDays.Value; updated = true; }

            if (updated)
            {
                await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy, cancellationToken);
            }
            return updated;
        }

        /// <summary>
        /// 보존 기간이 만료된 정책 목록을 조회합니다. (int 타입 처리: > 0 체크)
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetExpiredRetentionPoliciesAsync(string dataType, CancellationToken cancellationToken = default)
        {
            var cutoffDate = DateTime.UtcNow;
            var query = Query().AsNoTracking();

            // .HasValue 제거, > 0 체크 사용, .Value 제거
            query = dataType.ToLowerInvariant() switch
            {
                "audit" => query.Where(p => p.AuditLogRetentionDays > 0 && p.CreatedAt.AddDays(p.AuditLogRetentionDays) < cutoffDate),
                "point" => query.Where(p => p.PointTransactionRetentionDays > 0 && p.CreatedAt.AddDays(p.PointTransactionRetentionDays) < cutoffDate),
                _ => query.Where(p => p.DataRetentionDays > 0 && p.CreatedAt.AddDays(p.DataRetentionDays) < cutoffDate)
            };
            return await query.ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 특정 보존 기간 범위 내 정책 목록을 조회합니다. (int 타입 처리)
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByRetentionRangeAsync(int minRetentionDays, int maxRetentionDays, CancellationToken cancellationToken = default)
        {
            return await Query()
                .AsNoTracking()
                 // .HasValue 제거, 직접 비교
                .Where(p => p.DataRetentionDays >= minRetentionDays && p.DataRetentionDays <= maxRetentionDays)
                .OrderBy(p => p.DataRetentionDays)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 컴플라이언스 검증

        /// <summary>
        /// 특정 컴플라이언스 표준 준수 여부를 확인합니다. (캐시 활용)
        /// </summary>
        public async Task<(bool IsCompliant, List<string> Violations)> CheckComplianceAsync(Guid organizationId, ComplianceReportType complianceType, CancellationToken cancellationToken = default)
        {
            string cacheKey = $"Compliance:{organizationId}:{complianceType}";
            if (_cacheService != null)
            {
                var cachedItem = await _cacheService.GetAsync<ComplianceCacheItem>(cacheKey, cancellationToken);
                if (cachedItem != null) return (cachedItem.IsCompliant, cachedItem.Violations);
            }

            var policy = await GetByOrganizationAsync(organizationId, cancellationToken);
            if (policy == null) return (false, new List<string> { "조직 데이터 정책이 없습니다." });

            var violations = new List<string>();
            switch (complianceType) // 검증 로직 호출 (내부에서 int 타입 처리 필요)
            {
                case ComplianceReportType.GDPR: ValidateGDPRCompliance(policy, violations); break;
                case ComplianceReportType.HIPAA: ValidateHIPAACompliance(policy, violations); break;
                case ComplianceReportType.SOC2: ValidateSOC2Compliance(policy, violations); break;
                case ComplianceReportType.ISO27001: ValidateISO27001Compliance(policy, violations); break;
                case ComplianceReportType.PCI_DSS: ValidatePCIDSSCompliance(policy, violations); break;
                default: violations.Add($"지원되지 않는 컴플라이언스 타입: {complianceType}"); break;
            }

            var result = (violations.Count == 0, violations);
            if (_cacheService != null)
            {
                var cacheItem = new ComplianceCacheItem { IsCompliant = result.Item1, Violations = result.Item2 };
                await _cacheService.SetAsync(cacheKey, cacheItem, TimeSpan.FromMinutes(5), cancellationToken);
            }
            return result;
        }

        /// <summary>
        /// 여러 컴플라이언스 표준 준수 여부를 동시에 확인합니다.
        /// </summary>
        public async Task<Dictionary<ComplianceReportType, (bool IsCompliant, List<string> Violations)>> CheckMultipleComplianceAsync(Guid organizationId, IEnumerable<ComplianceReportType> complianceTypes, CancellationToken cancellationToken = default)
        {
            var concurrentResults = new ConcurrentDictionary<ComplianceReportType, (bool, List<string>)>();
            var tasks = complianceTypes.Distinct().Select(async type =>
            {
                var result = await CheckComplianceAsync(organizationId, type, cancellationToken);
                concurrentResults[type] = result;
            });
            await Task.WhenAll(tasks);
            return concurrentResults.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        /// <summary>
        /// 문자열 규정 목록으로 컴플라이언스 준수 여부를 확인합니다.
        /// </summary>
        public async Task<(bool IsCompliant, List<string> Violations)> CheckComplianceAsync(Guid organizationId, IEnumerable<string> regulations, CancellationToken cancellationToken = default)
        {
            var complianceTypes = new List<ComplianceReportType>();
            var allViolations = new List<string>();
            foreach (var regulation in regulations.Distinct())
            {
                if (Enum.TryParse<ComplianceReportType>(regulation, true, out var type)) complianceTypes.Add(type);
                else allViolations.Add($"알 수 없는 규정 타입: {regulation}");
            }
            if (complianceTypes.Any())
            {
                try
                {
                    var results = await CheckMultipleComplianceAsync(organizationId, complianceTypes, cancellationToken);
                    allViolations.AddRange(results.SelectMany(kvp => kvp.Value.Violations));
                }
                catch (Exception ex) { Console.WriteLine($"Error checking multiple compliance: {ex.Message}"); allViolations.Add("컴플라이언스 검사 중 오류."); }
            }
            return (allViolations.Count == 0, allViolations);
        }

        /// <summary>
        /// 정책 유효성을 검증합니다. (int 타입 처리: > 0 체크)
        /// </summary>
        public Task<(bool IsValid, List<string> Errors)> ValidatePolicyAsync(OrganizationDataPolicy policy, CancellationToken cancellationToken = default)
        {
            var errors = new List<string>();
            // .HasValue 제거, > 0 체크 사용
            if (policy.DataRetentionDays <= 0) errors.Add("데이터 보존 기간은 0보다 커야 합니다.");
            if (policy.AuditLogRetentionDays <= 0) errors.Add("감사 로그 보존 기간은 0보다 커야 합니다.");
            // 0이 유효하지 않다고 가정
            if (policy.EnableAutoAnonymization && policy.AnonymizationAfterDays <= 0) errors.Add("자동 익명화 활성화 시, 익명화 기간은 0보다 커야 합니다.");
            if (policy.EnableAutoAnonymization && policy.AnonymizationAfterDays < 30) errors.Add("익명화 기간은 최소 30일 이상이어야 합니다.");
            if (policy.AllowDataExport && policy.EncryptionLevel == DataEncryptionLevel.None) errors.Add("데이터 내보내기를 허용하려면 암호화를 활성화해야 합니다.");
            if (policy.AllowSqlDumpExport && policy.EncryptionLevel < DataEncryptionLevel.Enhanced) errors.Add("SQL 덤프 내보내기를 허용하려면 'Enhanced' 암호화 이상이 필요합니다.");
            // .HasValue 제거, > 0 체크 후 직접 비교
            if (policy.EnableAutoAnonymization && policy.AnonymizationAfterDays > 0 && policy.DataRetentionDays > 0 && policy.AnonymizationAfterDays >= policy.DataRetentionDays) errors.Add("익명화 기간은 데이터 보존 기간보다 짧아야 합니다.");
            if (!string.IsNullOrWhiteSpace(policy.AllowedExternalSystems)) { try { JsonSerializer.Deserialize<List<string>>(policy.AllowedExternalSystems, _jsonOptions); } catch (JsonException) { errors.Add("허용된 외부 시스템 목록 형식이 JSON 배열이 아닙니다."); } }
            return Task.FromResult((errors.Count == 0, errors));
        }

        /// <summary>
        /// 컴플라이언스 준수 점수를 계산합니다. (int 타입 처리, 캐시 래퍼 사용)
        /// </summary>
        public async Task<double> GetComplianceScoreAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            string cacheKey = $"ComplianceScore:{organizationId}";
            if (_cacheService != null)
            {
                var cachedItem = await _cacheService.GetAsync<NullableDoubleCacheItem>(cacheKey, cancellationToken);
                if (cachedItem?.Value != null) return cachedItem.Value.Value;
            }

            var policy = await GetByOrganizationAsync(organizationId, cancellationToken);
            if (policy == null) return 0.0;

            double score = 0.0;
            const double maxScore = 10.0;
            if (policy.EncryptionLevel >= DataEncryptionLevel.Standard) score += 2.0;
            // .HasValue 제거, > 0 및 값 비교
            if (policy.DataRetentionDays > 0 && policy.DataRetentionDays <= 1095) score += 2.0;
            // 0은 미준수로 간주 (예: 1년 이상이어야 함)
            if (policy.AuditLogRetentionDays >= 365) score += 2.0;
            // .HasValue 제거, > 0 체크
            if (policy.EnableAutoAnonymization && policy.AnonymizationAfterDays > 0) score += 2.0;
            if (!string.IsNullOrWhiteSpace(policy.AllowedExternalSystems) && policy.AllowedExternalSystems != "[]") score += 1.0;
            if (policy.LastReviewedAt.HasValue && policy.LastReviewedAt > DateTime.UtcNow.AddMonths(-6)) score += 1.0;

            var result = Math.Round((score / maxScore) * 100.0, 2);

            if (_cacheService != null)
            {
                var cacheItem = new NullableDoubleCacheItem { Value = result };
                await _cacheService.SetAsync(cacheKey, cacheItem, TimeSpan.FromMinutes(10), cancellationToken);
            }
            return result;
        }

        #endregion

        #region 사용자 데이터 정책

        /// <summary>
        /// 사용자 메타데이터 수집 모드를 업데이트합니다.
        /// </summary>
        public async Task<bool> UpdateUserMetadataModeAsync(Guid organizationId, UserMetadataMode mode, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null || policy.UserMetadataMode == mode) return false;

            await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
            policy.UserMetadataMode = mode;
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy, cancellationToken);
            return true;
        }

        /// <summary>
        /// 프로필 수집 설정을 업데이트합니다.
        /// </summary>
        public async Task<bool> UpdateProfileCollectionAsync(Guid organizationId, bool? collectMemberProfile = null, bool? collectUserProfile = null, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            bool updated = false;
            if (collectMemberProfile.HasValue && policy.CollectMemberProfile != collectMemberProfile.Value) { policy.CollectMemberProfile = collectMemberProfile.Value; updated = true; }
            if (collectUserProfile.HasValue && policy.CollectUserProfile != collectUserProfile.Value) { policy.CollectUserProfile = collectUserProfile.Value; updated = true; }

            if (updated)
            {
                await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy, cancellationToken);
            }
            return updated;
        }

        /// <summary>
        /// 특정 메타데이터 모드를 사용하는 정책 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetByMetadataModeAsync(UserMetadataMode mode, CancellationToken cancellationToken = default)
        {
            return await Query()
                .AsNoTracking()
                .Where(p => p.UserMetadataMode == mode)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 데이터 내보내기 및 보안

        /// <summary>
        /// 데이터 내보내기 권한 설정을 업데이트합니다.
        /// </summary>
        public async Task<bool> UpdateExportPermissionsAsync(Guid organizationId, bool? allowDataExport = null, bool? allowSqlDumpExport = null, bool? allowBulkApiAccess = null, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            bool updated = false;
            if (allowDataExport.HasValue && policy.AllowDataExport != allowDataExport.Value) { policy.AllowDataExport = allowDataExport.Value; updated = true; }
            if (allowSqlDumpExport.HasValue && policy.AllowSqlDumpExport != allowSqlDumpExport.Value) { policy.AllowSqlDumpExport = allowSqlDumpExport.Value; updated = true; }
            if (allowBulkApiAccess.HasValue && policy.AllowBulkApiAccess != allowBulkApiAccess.Value) { policy.AllowBulkApiAccess = allowBulkApiAccess.Value; updated = true; }

            if (updated)
            {
                await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy, cancellationToken);
            }
            return updated;
        }

        /// <summary>
        /// 암호화 수준을 업데이트합니다.
        /// </summary>
        public async Task<bool> UpdateEncryptionLevelAsync(Guid organizationId, DataEncryptionLevel level, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null || policy.EncryptionLevel == level) return false;

            await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
            policy.EncryptionLevel = level;
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy, cancellationToken);
            return true;
        }

        /// <summary>
        /// 익명화 설정을 업데이트합니다. (int 타입 처리)
        /// </summary>
        public async Task<bool> UpdateAnonymizationSettingsAsync(Guid organizationId, bool? enableAutoAnonymization = null, int? anonymizationAfterDays = null, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            bool updated = false;
            if (enableAutoAnonymization.HasValue && policy.EnableAutoAnonymization != enableAutoAnonymization.Value) { policy.EnableAutoAnonymization = enableAutoAnonymization.Value; updated = true; }
            // int? 파라미터를 int 필드에 적용
            if (anonymizationAfterDays.HasValue && policy.AnonymizationAfterDays != anonymizationAfterDays.Value) { policy.AnonymizationAfterDays = anonymizationAfterDays.Value; updated = true; }

            if (updated)
            {
                 var (isValid, _) = await ValidatePolicyAsync(policy, cancellationToken);
                 if (!isValid) return false;

                await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy, cancellationToken);
            }
            return updated;
        }

        /// <summary>
        /// 익명화가 필요한 정책 목록을 조회합니다. (int 타입 처리: > 0 체크)
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetOrganizationsNeedingAnonymizationAsync(DateTime asOfDate, CancellationToken cancellationToken = default)
        {
             asOfDate = asOfDate.ToUniversalTime();
            return await Query()
                .AsNoTracking()
                // .HasValue 제거, > 0 체크, .Value 제거
                .Where(p => p.EnableAutoAnonymization &&
                            p.AnonymizationAfterDays > 0 &&
                            p.CreatedAt.AddDays(p.AnonymizationAfterDays) <= asOfDate)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 외부 시스템 동기화

        /// <summary>
        /// 외부 시스템 동기화 설정을 업데이트합니다.
        /// </summary>
        public async Task<bool> UpdateExternalSyncSettingsAsync(Guid organizationId, bool? allowExternalSync = null, IEnumerable<string>? allowedSystems = null, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            bool updated = false;
            string? newAllowedSystemsJson = null;

            if (allowExternalSync.HasValue && policy.AllowExternalSync != allowExternalSync.Value) { policy.AllowExternalSync = allowExternalSync.Value; updated = true; }
            if (allowedSystems != null)
            {
                var sortedSystems = allowedSystems.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().OrderBy(s => s).ToList();
                newAllowedSystemsJson = JsonSerializer.Serialize(sortedSystems, _jsonOptions);
                if (policy.AllowedExternalSystems != newAllowedSystemsJson) { policy.AllowedExternalSystems = newAllowedSystemsJson; updated = true; }
            }

            if (updated)
            {
                var (isValid, _) = await ValidatePolicyAsync(policy, cancellationToken);
                if (!isValid) return false;

                await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy, cancellationToken);
            }
            return updated;
        }

        /// <summary>
        /// 허용된 외부 시스템을 추가합니다.
        /// </summary>
        public async Task<bool> AddAllowedExternalSystemAsync(Guid organizationId, string systemName, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(systemName)) return false;
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            List<string> systems;
            try { systems = string.IsNullOrWhiteSpace(policy.AllowedExternalSystems) ? new List<string>() : JsonSerializer.Deserialize<List<string>>(policy.AllowedExternalSystems, _jsonOptions) ?? new List<string>(); }
            catch (JsonException) { return false; }

            if (systems.Contains(systemName, StringComparer.OrdinalIgnoreCase)) return false;

            systems.Add(systemName); systems.Sort();
            policy.AllowedExternalSystems = JsonSerializer.Serialize(systems, _jsonOptions);

            var (isValid, _) = await ValidatePolicyAsync(policy, cancellationToken);
            if (!isValid) return false;

            await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy, cancellationToken);
            return true;
        }

        /// <summary>
        /// 허용된 외부 시스템을 제거합니다.
        /// </summary>
        public async Task<bool> RemoveAllowedExternalSystemAsync(Guid organizationId, string systemName, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(systemName)) return false;
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null || string.IsNullOrWhiteSpace(policy.AllowedExternalSystems)) return false;

            List<string> systems;
            try { systems = JsonSerializer.Deserialize<List<string>>(policy.AllowedExternalSystems, _jsonOptions) ?? new List<string>(); }
            catch (JsonException) { return false; }

            int removedCount = systems.RemoveAll(s => s.Equals(systemName, StringComparison.OrdinalIgnoreCase));
            if (removedCount > 0)
            {
                systems.Sort();
                policy.AllowedExternalSystems = JsonSerializer.Serialize(systems, _jsonOptions);

                var (isValid, _) = await ValidatePolicyAsync(policy, cancellationToken);
                if (!isValid) return false;

                await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy, cancellationToken);
                return true;
            }
            return false;
        }

        #endregion

        #region 정책 검토 및 관리

        /// <summary>
        /// 정책 검토 날짜를 업데이트합니다.
        /// </summary>
        public async Task<bool> UpdateReviewDatesAsync(Guid organizationId, DateTime reviewedAt, DateTime? nextReviewDate = null, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            var reviewedAtUtc = reviewedAt.ToUniversalTime();
            var nextReviewDateUtc = (nextReviewDate ?? reviewedAtUtc.AddYears(1)).ToUniversalTime();

            if (policy.LastReviewedAt == reviewedAtUtc && policy.NextReviewDate == nextReviewDateUtc) return false;

            await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
            policy.LastReviewedAt = reviewedAtUtc;
            policy.NextReviewDate = nextReviewDateUtc;
            policy.PolicyVersion++;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy, cancellationToken);
            return true;
        }

        /// <summary>
        /// 검토가 필요한 정책 목록을 조회합니다.
        /// </summary>
        public async Task<IEnumerable<OrganizationDataPolicy>> GetPoliciesNeedingReviewAsync(DateTime asOfDate, CancellationToken cancellationToken = default)
        {
            var asOfDateUtc = asOfDate.ToUniversalTime();
            return await Query()
                .AsNoTracking()
                .Where(p => !p.NextReviewDate.HasValue || p.NextReviewDate <= asOfDateUtc)
                .OrderBy(p => p.NextReviewDate ?? DateTime.MinValue)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 여러 조직에 기본 정책을 적용합니다. (없는 경우에만 생성)
        /// </summary>
        public async Task<int> ApplyDefaultPolicyAsync(IEnumerable<Guid> organizationIds, OrganizationDataPolicy templatePolicy, CancellationToken cancellationToken = default)
        {
            var orgIdsList = organizationIds.Distinct().ToList();
            if (!orgIdsList.Any()) return 0;

            var (isTemplateValid, templateErrors) = await ValidatePolicyAsync(templatePolicy, cancellationToken);
            if (!isTemplateValid) throw new ArgumentException($"Default policy template is invalid: {string.Join(", ", templateErrors)}");

            var existingPoliciesList = await Query().Where(p => orgIdsList.Contains(p.OrganizationId)).Select(p => p.OrganizationId).ToListAsync(cancellationToken);
            var existingOrgIds = new HashSet<Guid>(existingPoliciesList);
            var orgIdsToCreate = orgIdsList.Except(existingOrgIds).ToList();
            if (!orgIdsToCreate.Any()) return 0;

            var now = DateTime.UtcNow;
            var creatorId = templatePolicy.CreatedByConnectedId;
            var newPolicies = orgIdsToCreate.Select(orgId => {
                var newPolicy = new OrganizationDataPolicy { OrganizationId = orgId, PolicyVersion = 1, CreatedAt = now, CreatedByConnectedId = creatorId };
                UpdatePolicyFields(newPolicy, templatePolicy);
                newPolicy.NextReviewDate = now.AddYears(1);
                return newPolicy;
            }).ToList();

            if (newPolicies.Any()) await AddRangeAsync(newPolicies, cancellationToken);
            return newPolicies.Count;
        }

        /// <summary>
        /// 플랜 유형에 따라 정책 설정을 자동 조정합니다.
        /// </summary>
        public async Task<bool> AdjustPolicyForPlanAsync(Guid organizationId, string planType, CancellationToken cancellationToken = default)
        {
            var policy = await QueryForOrganization(organizationId).FirstOrDefaultAsync(cancellationToken);
            if (policy == null) return false;

            bool updated = false;
            (DataEncryptionLevel EncLevel, bool AllowExport, bool AllowSql, bool AllowBulk) target;
            switch (planType.ToLowerInvariant())
            {
                case "basic": target = (DataEncryptionLevel.Standard, false, false, false); break;
                case "business": target = (DataEncryptionLevel.Enhanced, true, true, true); break;
                case "enterprise": target = (DataEncryptionLevel.Maximum, true, true, true); break;
                default: return false;
            }

            if (policy.EncryptionLevel != target.EncLevel) { policy.EncryptionLevel = target.EncLevel; updated = true; }
            if (policy.AllowDataExport != target.AllowExport) { policy.AllowDataExport = target.AllowExport; updated = true; }
            if (policy.AllowSqlDumpExport != target.AllowSql) { policy.AllowSqlDumpExport = target.AllowSql; updated = true; }
            if (policy.AllowBulkApiAccess != target.AllowBulk) { policy.AllowBulkApiAccess = target.AllowBulk; updated = true; }

            if (updated)
            {
                var (isValid, _) = await ValidatePolicyAsync(policy, cancellationToken);
                if (!isValid) return false;

                await InvalidatePolicyCacheAsync(organizationId, cancellationToken);
                policy.PolicyVersion++;
                policy.UpdatedAt = DateTime.UtcNow;
                await UpdateAsync(policy, cancellationToken);
            }
            return updated;
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 전체 데이터 정책 사용 통계를 집계합니다. (캐시 활용)
        /// </summary>
        public async Task<DataPolicyStatistics> GetDataPolicyStatisticsAsync(CancellationToken cancellationToken = default)
        {
            const string cacheKey = "DataPolicyStatistics:Global";
            if (_cacheService != null)
            {
                var cachedStats = await _cacheService.GetAsync<DataPolicyStatistics>(cacheKey, cancellationToken);
                if (cachedStats != null) return cachedStats;
            }

            var policies = await Query().AsNoTracking().ToListAsync(cancellationToken);
            var stats = new DataPolicyStatistics
            {
                TotalOrganizations = policies.Count, OrganizationsWithPolicy = policies.Count,
                EncryptionLevelDist = policies.GroupBy(p => p.EncryptionLevel).ToDictionary(g => g.Key.ToString(), g => g.Count()),
                MetadataModeDist = policies.GroupBy(p => p.UserMetadataMode).ToDictionary(g => g.Key.ToString(), g => g.Count()),
                AllowDataExportCount = policies.Count(p => p.AllowDataExport),
                AutoAnonymizationEnabledCount = policies.Count(p => p.EnableAutoAnonymization),
                RegulationComplianceDist = await GetGlobalComplianceBreakdownAsync(policies, cancellationToken)
            };

            if (_cacheService != null) await _cacheService.SetAsync(cacheKey, stats, TimeSpan.FromMinutes(15), cancellationToken);
            return stats;
        }

        /// <summary>
        /// 기간별 정책 변경 추세를 분석합니다.
        /// </summary>
        public async Task<IEnumerable<DataPolicyTrend>> GetDataPolicyTrendsAsync(int period = 30, CancellationToken cancellationToken = default)
        {
            var startDate = DateTime.UtcNow.AddDays(-period);
            var trendsData = await Query().AsNoTracking()
                .Where(p => (p.UpdatedAt ?? p.CreatedAt) >= startDate)
                .Select(p => new { Date = (p.UpdatedAt ?? p.CreatedAt).Date, p.EncryptionLevel })
                .ToListAsync(cancellationToken);

            var trends = trendsData.GroupBy(p => p.Date)
                .Select(g => new DataPolicyTrend { Period = g.Key, PolicyUpdates = g.Count(), EncryptionUpgrades = g.Count(p => p.EncryptionLevel > DataEncryptionLevel.Standard) })
                .OrderBy(t => t.Period).ToList();
            return trends;
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 관련 캐시 항목들을 무효화합니다.
        /// </summary>
        private async Task InvalidatePolicyCacheAsync(Guid organizationId, CancellationToken cancellationToken)
        {
            if (_cacheService == null) return;
            var tasks = new List<Task>
            {
                _cacheService.RemoveAsync($"DataPolicy:Org:{organizationId}", cancellationToken),
                _cacheService.RemoveAsync($"ComplianceScore:{organizationId}", cancellationToken),
                _cacheService.RemoveAsync("DataPolicyStatistics:Global", cancellationToken)
            };
            foreach (ComplianceReportType type in Enum.GetValues(typeof(ComplianceReportType))) tasks.Add(_cacheService.RemoveAsync($"Compliance:{organizationId}:{type}", cancellationToken));
            try { await Task.WhenAll(tasks); } catch (Exception ex) { Console.WriteLine($"Cache invalidation failed: {ex.Message}"); }
        }

        /// <summary>
        /// 전역 컴플라이언스 분포를 계산합니다. (병렬 처리)
        /// </summary>
        private async Task<Dictionary<string, int>> GetGlobalComplianceBreakdownAsync(List<OrganizationDataPolicy> policies, CancellationToken cancellationToken)
        {
            var breakdown = new ConcurrentDictionary<string, int>();
            await Parallel.ForEachAsync(Enum.GetValues<ComplianceReportType>(), cancellationToken, (type, ct) =>
            {
                int compliantCount = 0;
                foreach (var policy in policies)
                {
                    var violations = new List<string>();
                    switch (type) // 동기 검증 메서드 호출
                    {
                         case ComplianceReportType.GDPR: ValidateGDPRCompliance(policy, violations); break;
                         case ComplianceReportType.HIPAA: ValidateHIPAACompliance(policy, violations); break;
                         case ComplianceReportType.SOC2: ValidateSOC2Compliance(policy, violations); break;
                         case ComplianceReportType.ISO27001: ValidateISO27001Compliance(policy, violations); break;
                         case ComplianceReportType.PCI_DSS: ValidatePCIDSSCompliance(policy, violations); break;
                    }
                    if(violations.Count == 0) Interlocked.Increment(ref compliantCount);
                }
                breakdown[type.ToString()] = compliantCount;
                return ValueTask.CompletedTask;
            });
            return breakdown.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        // --- 개별 컴플라이언스 검증 메서드들 (int 타입 처리: > 0 체크, .HasValue 제거) ---
        private void ValidateGDPRCompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (!policy.EnableAutoAnonymization) violations.Add("GDPR requires data anonymization capability (Article 17)");
            // > 0 체크, 직접 비교
            if (policy.DataRetentionDays > 1095) violations.Add("GDPR recommends data retention period under 3 years (Article 5)");
            if (policy.EncryptionLevel == DataEncryptionLevel.None) violations.Add("GDPR requires appropriate security measures including encryption (Article 32)");
            if (!policy.AllowDataExport) violations.Add("GDPR requires data portability capability (Article 20)");
        }
        private void ValidateHIPAACompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (policy.EncryptionLevel < DataEncryptionLevel.Enhanced) violations.Add("HIPAA requires enhanced encryption for PHI (§ 164.312(a)(2)(iv))");
            // > 0 체크, 직접 비교 (6년 = 2190일)
            if (policy.AuditLogRetentionDays < 2190) violations.Add("HIPAA requires audit log retention for at least 6 years (§ 164.316(b)(2))");
            if (policy.AllowDataExport && !IsHealthcareSystemOnly(policy)) violations.Add("HIPAA restricts PHI export to authorized healthcare systems only");
        }
        private void ValidateSOC2Compliance(OrganizationDataPolicy policy, List<string> violations)
        {
            // > 0 체크, 직접 비교 (1년 = 365일)
            if (policy.AuditLogRetentionDays < 365) violations.Add("SOC2 requires audit log retention for at least 1 year");
            // Nullable DateTime? 는 HasValue 체크 유지
            if (!policy.LastReviewedAt.HasValue || policy.LastReviewedAt < DateTime.UtcNow.AddYears(-1)) violations.Add("SOC2 requires annual policy review");
            if (policy.EncryptionLevel == DataEncryptionLevel.None) violations.Add("SOC2 requires data encryption at rest and in transit");
        }
        private void ValidateISO27001Compliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (policy.EncryptionLevel < DataEncryptionLevel.Standard) violations.Add("ISO27001 requires appropriate cryptographic controls (A.10.1)");
            if (!policy.EnableAutoAnonymization) violations.Add("ISO27001 requires data minimization practices (A.18.1.4)");
            if (!policy.LastReviewedAt.HasValue || policy.LastReviewedAt < DateTime.UtcNow.AddYears(-1)) violations.Add("ISO27001 requires annual policy review (A.5.1.1)");
        }
        private void ValidatePCIDSSCompliance(OrganizationDataPolicy policy, List<string> violations)
        {
            if (policy.EncryptionLevel < DataEncryptionLevel.Enhanced) violations.Add("PCI DSS requires strong encryption for cardholder data (Requirement 3.4)");
            // > 0 체크, 직접 비교
            if (policy.DataRetentionDays > 365) violations.Add("PCI DSS requires minimal data retention for cardholder data (Requirement 3.1)");
            if (policy.AllowSqlDumpExport) violations.Add("PCI DSS prohibits unencrypted database exports (Requirement 3.4)");
            // > 0 체크, 직접 비교 (1년 = 365일)
            if (policy.AuditLogRetentionDays < 365) violations.Add("PCI DSS requires audit log retention for at least 1 year (Req 10.7)");
        }
        private bool IsHealthcareSystemOnly(OrganizationDataPolicy policy)
        {
            if (string.IsNullOrWhiteSpace(policy.AllowedExternalSystems)) return false;
            try { var systems = JsonSerializer.Deserialize<List<string>>(policy.AllowedExternalSystems, _jsonOptions); return systems?.All(s => !string.IsNullOrWhiteSpace(s) && (s.Contains("Healthcare", StringComparison.OrdinalIgnoreCase) || s.Contains("Medical", StringComparison.OrdinalIgnoreCase))) ?? false; } catch (JsonException) { return false; }
        }

        #endregion
    }
}