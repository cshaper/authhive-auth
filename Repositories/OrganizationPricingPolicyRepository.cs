using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Business.Commerce.Billing.Common;
using AuthHive.Core.Models.Business.Commerce.Common;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Enums.Business;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Business.Payment.Common;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직 가격 정책 리포지토리 구현체 - AuthHive v15
    /// 조직별 커스터마이징된 가격 정책 관리를 담당합니다.
    /// BaseRepository로 변경되어 자동 조직 필터링 및 캐싱 기능 활용
    /// </summary>
    public class OrganizationPricingPolicyRepository : BaseRepository<OrganizationPricingPolicy>, IOrganizationPricingPolicyRepository
    {
        public OrganizationPricingPolicyRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null) : base(context, organizationContext, cache)
        {
        }

        #region 기본 조회

        /// <summary>
        /// 정책 이름으로 조회
        /// </summary>
        public async Task<OrganizationPricingPolicy?> GetByNameAsync(
            Guid organizationId,
            string policyName,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(p =>
                    p.PolicyName == policyName &&
                    !p.IsDeleted,
                    cancellationToken);
        }

        /// <summary>
        /// 정책 타입별 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetByPolicyTypeAsync(
            Guid organizationId,
            PricingPolicyType policyType,
            bool activeOnly = true,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType && !p.IsDeleted);

            if (activeOnly)
            {
                query = query.Where(p => p.IsActive);
            }

            return await query
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.PolicyName)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 대상별 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetByTargetAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p =>
                    p.TargetType == targetType &&
                    p.IsActive &&
                    !p.IsDeleted);

            if (!string.IsNullOrEmpty(targetKey))
            {
                query = query.Where(p => p.TargetKey == targetKey);
            }

            return await query
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.PolicyName)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 정책 이름 중복 확인
        /// </summary>
        public async Task<bool> NameExistsAsync(
            Guid organizationId,
            string policyName,
            Guid? excludePolicyId = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p =>
                    p.PolicyName == policyName &&
                    !p.IsDeleted);

            if (excludePolicyId.HasValue)
            {
                query = query.Where(p => p.Id != excludePolicyId.Value);
            }

            return await query.AnyAsync(cancellationToken);
        }

        #endregion

        #region 정책 관리

        /// <summary>
        /// 가격 정책 생성
        /// </summary>
        public async Task<OrganizationPricingPolicy> CreatePolicyAsync(
            OrganizationPricingPolicy policy,
            bool validateConflicts = true,
            CancellationToken cancellationToken = default)
        {
            // 중복 이름 확인
            if (await NameExistsAsync(policy.OrganizationId, policy.PolicyName, null, cancellationToken))
            {
                throw new InvalidOperationException($"Policy name '{policy.PolicyName}' already exists");
            }

            // 충돌 검증
            if (validateConflicts)
            {
                var conflicts = await CheckPolicyConflictsAsync(policy, cancellationToken);
                if (conflicts.Any())
                {
                    throw new InvalidOperationException($"Policy conflicts with existing policies: {string.Join(", ", conflicts.Select(c => c.PolicyName))}");
                }
            }

            return await AddAsync(policy);
        }

        /// <summary>
        /// 정책 업데이트
        /// </summary>
        public async Task<OrganizationPricingPolicy?> UpdatePolicyAsync(
            Guid policyId,
            Action<OrganizationPricingPolicy> updates,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return null;

            updates(policy);
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            return policy;
        }

        /// <summary>
        /// 정책 활성화/비활성화
        /// </summary>
        public async Task<bool> SetActiveStatusAsync(
            Guid policyId,
            bool isActive,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.IsActive = isActive;
            policy.UpdatedAt = DateTime.UtcNow;

            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 정책 복제
        /// </summary>
        public async Task<OrganizationPricingPolicy> ClonePolicyAsync(
            Guid sourcePolicyId,
            string newName,
            Guid? targetOrganizationId = null,
            CancellationToken cancellationToken = default)
        {
            var sourcePolicy = await GetByIdAsync(sourcePolicyId);
            if (sourcePolicy == null)
                throw new InvalidOperationException("Source policy not found");

            var targetOrgId = targetOrganizationId ?? sourcePolicy.OrganizationId;

            // 새 이름 중복 확인
            if (await NameExistsAsync(targetOrgId, newName, null, cancellationToken))
            {
                throw new InvalidOperationException($"Policy name '{newName}' already exists in target organization");
            }

            var clonedPolicy = new OrganizationPricingPolicy
            {
                Id = Guid.NewGuid(),
                OrganizationId = targetOrgId,
                PolicyName = newName,
                Description = sourcePolicy.Description,
                PolicyType = sourcePolicy.PolicyType,
                TargetType = sourcePolicy.TargetType,
                TargetKey = sourcePolicy.TargetKey,
                DiscountRate = sourcePolicy.DiscountRate,
                DiscountAmount = sourcePolicy.DiscountAmount,
                CustomPrice = sourcePolicy.CustomPrice,
                PointBonusRate = sourcePolicy.PointBonusRate,
                Priority = sourcePolicy.Priority,
                ConditionRules = sourcePolicy.ConditionRules,
                IsActive = false, // 복제된 정책은 기본적으로 비활성
                CreatedAt = DateTime.UtcNow
            };

            return await AddAsync(clonedPolicy);
        }

        #endregion

        #region 할인 관리

        /// <summary>
        /// 할인 정책 업데이트
        /// </summary>
        public async Task<bool> UpdateDiscountAsync(
            Guid policyId,
            decimal? discountRate = null,
            decimal? discountAmount = null,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            if (discountRate.HasValue)
                policy.DiscountRate = discountRate.Value;

            if (discountAmount.HasValue)
                policy.DiscountAmount = discountAmount.Value;

            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 최대 할인 정책 조회
        /// </summary>
        public async Task<OrganizationPricingPolicy?> GetMaxDiscountPolicyAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p =>
                    p.TargetType == targetType &&
                    p.IsActive &&
                    !p.IsDeleted &&
                    (p.DiscountRate > 0 || p.DiscountAmount > 0));

            if (!string.IsNullOrEmpty(targetKey))
            {
                query = query.Where(p => p.TargetKey == targetKey);
            }

            // 할인율이 높은 것 우선, 그 다음 할인 금액이 높은 것
            return await query
                .OrderByDescending(p => p.DiscountRate)
                .ThenByDescending(p => p.DiscountAmount)
                .FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// 총 할인 금액 계산
        /// </summary>
        public async Task<decimal> CalculateDiscountedAmountAsync(
            Guid organizationId,
            decimal baseAmount,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            var policies = await GetByTargetAsync(organizationId, targetType, targetKey, cancellationToken);
            var activePolicies = policies.Where(p =>
                p.IsActive &&
                (p.EffectiveFrom <= DateTime.UtcNow) &&
                (p.EffectiveUntil == null || p.EffectiveUntil >= DateTime.UtcNow))
                .OrderBy(p => p.Priority)
                .ToList();

            decimal finalAmount = baseAmount;

            foreach (var policy in activePolicies)
            {
                if (policy.DiscountRate > 0)
                {
                    finalAmount = finalAmount * (1 - policy.DiscountRate);
                }

                if (policy.DiscountAmount > 0)
                {
                    finalAmount = Math.Max(0, finalAmount - policy.DiscountAmount);
                }
            }

            return finalAmount;
        }

        #endregion

        #region 맞춤 가격

        /// <summary>
        /// 맞춤 가격 설정
        /// </summary>
        public async Task<bool> SetCustomPriceAsync(
            Guid policyId,
            decimal customPrice,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.CustomPrice = customPrice;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 맞춤 요율 업데이트
        /// </summary>
        public async Task<bool> UpdateCustomRatesAsync(
            Guid policyId,
            decimal? mauOverageRate = null,
            decimal? apiUsageRate = null,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            if (mauOverageRate.HasValue)
                policy.CustomMAUOverageRate = mauOverageRate.Value;

            if (apiUsageRate.HasValue)
                policy.CustomApiUsageRate = apiUsageRate.Value;

            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 협상된 가격 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetNegotiatedPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p =>
                    p.PolicyType == PricingPolicyType.NegotiatedRate &&
                    p.IsActive &&
                    !p.IsDeleted)
                .OrderBy(p => p.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 포인트 보너스

        /// <summary>
        /// 포인트 보너스율 설정
        /// </summary>
        public async Task<bool> SetPointBonusRateAsync(
            Guid policyId,
            decimal bonusRate,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.PointBonusRate = bonusRate;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 포인트 보너스가 있는 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetPointBonusPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p =>
                    p.PointBonusRate > 0 &&
                    p.IsActive &&
                    !p.IsDeleted)
                .OrderBy(p => p.Priority)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 포인트 보너스 계산
        /// </summary>
        public async Task<decimal> CalculateTotalPointsWithBonusAsync(
            Guid organizationId,
            decimal basePoints,
            CancellationToken cancellationToken = default)
        {
            var bonusPolicies = await GetPointBonusPoliciesAsync(organizationId, cancellationToken);
            var totalBonusRate = bonusPolicies.Sum(p => p.PointBonusRate);

            return basePoints * (1 + totalBonusRate);
        }

        #endregion

        #region 유효 기간 관리

        /// <summary>
        /// 유효 기간 설정
        /// </summary>
        public async Task<bool> SetEffectivePeriodAsync(
            Guid policyId,
            DateTime effectiveFrom,
            DateTime? effectiveTo = null,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.EffectiveFrom = effectiveFrom;
            policy.EffectiveUntil = effectiveTo;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 현재 유효한 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetEffectivePoliciesAsync(
            Guid organizationId,
            DateTime? asOfDate = null,
            CancellationToken cancellationToken = default)
        {
            var checkDate = asOfDate ?? DateTime.UtcNow;

            return await QueryForOrganization(organizationId)
                .Where(p =>
                    p.IsActive &&
                    p.EffectiveFrom <= checkDate &&
                    (p.EffectiveUntil == null || p.EffectiveUntil >= checkDate) &&
                    !p.IsDeleted)
                .OrderBy(p => p.Priority)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 만료된 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetExpiredPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;

            return await QueryForOrganization(organizationId)
                .Where(p =>
                    p.EffectiveUntil.HasValue &&
                    p.EffectiveUntil < now &&
                    !p.IsDeleted)
                .OrderByDescending(p => p.EffectiveUntil)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 임시 정책 생성
        /// </summary>
        public async Task<OrganizationPricingPolicy> CreateTemporaryPolicyAsync(
            OrganizationPricingPolicy policy,
            TimeSpan duration,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            policy.EffectiveFrom = now;
            policy.EffectiveUntil = now.Add(duration);
            policy.PolicyName = $"TEMP-{policy.PolicyName}-{now:yyyyMMddHHmmss}";

            return await CreatePolicyAsync(policy, true, cancellationToken);
        }

        #endregion

        #region 우선순위 관리

        /// <summary>
        /// 우선순위 업데이트
        /// </summary>
        public async Task<bool> UpdatePriorityAsync(
            Guid policyId,
            int priority,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.Priority = priority;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 우선순위별 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetByPriorityAsync(
            Guid organizationId,
            PricingTargetType? targetType = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.IsActive && !p.IsDeleted);

            if (targetType.HasValue)
            {
                query = query.Where(p => p.TargetType == targetType.Value);
            }

            return await query
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.PolicyName)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 최고 우선순위 정책 조회
        /// </summary>
        public async Task<OrganizationPricingPolicy?> GetHighestPriorityPolicyAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p =>
                    p.TargetType == targetType &&
                    p.IsActive &&
                    !p.IsDeleted);

            if (!string.IsNullOrEmpty(targetKey))
            {
                query = query.Where(p => p.TargetKey == targetKey);
            }

            return await query
                .OrderBy(p => p.Priority)
                .FirstOrDefaultAsync(cancellationToken);
        }

        #endregion

        #region 승인 관리

        /// <summary>
        /// 정책 승인
        /// </summary>
        public async Task<bool> ApprovePolicyAsync(
            Guid policyId,
            Guid approvedBy,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.IsApproved = true;
            policy.ApprovedAt = DateTime.UtcNow;
            policy.ApprovedByConnectedId = approvedBy;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 미승인 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetUnapprovedPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p =>
                    !p.IsApproved &&
                    p.IsActive &&
                    !p.IsDeleted)
                .OrderBy(p => p.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 승인 취소
        /// </summary>
        public async Task<bool> RevokeApprovalAsync(
            Guid policyId,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.IsApproved = false;
            policy.ApprovedAt = null;
            policy.ApprovedByConnectedId = null;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 승인 이력 조회
        /// </summary>
        public async Task<IEnumerable<PricingPolicyApprovalHistoryDto>> GetApprovalHistoryAsync(
            Guid policyId,
            CancellationToken cancellationToken = default)
        {
            // 실제로는 별도의 ApprovalHistory 테이블에서 조회해야 함
            // 현재는 기본 구현만 제공
            var policy = await GetByIdAsync(policyId);
            if (policy?.IsApproved == true && policy.ApprovedAt.HasValue && policy.ApprovedByConnectedId.HasValue)
            {
                return new List<PricingPolicyApprovalHistoryDto>
                {
                    new PricingPolicyApprovalHistoryDto
                    {
                        PolicyId = policyId,
                        ApprovedAt = policy.ApprovedAt.Value,
                        ApprovedByConnectedId = policy.ApprovedByConnectedId.Value,
                        Action = "Approved"
                    }
                };
            }

            return Enumerable.Empty<PricingPolicyApprovalHistoryDto>();
        }

        #endregion

        #region 조건 규칙

        /// <summary>
        /// 조건 규칙 업데이트
        /// </summary>
        public async Task<bool> UpdateConditionRulesAsync(
            Guid policyId,
            string conditionRules,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null) return false;

            policy.ConditionRules = conditionRules;
            policy.UpdatedAt = DateTime.UtcNow;
            await UpdateAsync(policy);
            return true;
        }

        /// <summary>
        /// 조건 평가 (기본 구현)
        /// </summary>
        public async Task<bool> EvaluateConditionsAsync(
            Guid policyId,
            Dictionary<string, object> context,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null || string.IsNullOrEmpty(policy.ConditionRules))
                return true; // 조건이 없으면 항상 true

            // TODO: 실제로는 JSON 규칙 엔진이나 표현식 평가기를 사용해야 함
            // 현재는 간단한 구현만 제공
            try
            {
                var rules = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(policy.ConditionRules);

                // 기본적인 조건 평가 로직
                foreach (var rule in rules ?? new Dictionary<string, object>())
                {
                    if (context.ContainsKey(rule.Key))
                    {
                        // 간단한 동등성 비교
                        if (!context[rule.Key].Equals(rule.Value))
                            return false;
                    }
                }

                return true;
            }
            catch
            {
                // JSON 파싱 실패 시 false 반환
                return false;
            }
        }

        /// <summary>
        /// 조건을 충족하는 정책 조회
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> GetPoliciesMeetingConditionsAsync(
            Guid organizationId,
            Dictionary<string, object> context,
            CancellationToken cancellationToken = default)
        {
            var policies = await GetEffectivePoliciesAsync(organizationId, null, cancellationToken);
            var validPolicies = new List<OrganizationPricingPolicy>();

            foreach (var policy in policies)
            {
                if (await EvaluateConditionsAsync(policy.Id, context, cancellationToken))
                {
                    validPolicies.Add(policy);
                }
            }

            return validPolicies.OrderBy(p => p.Priority);
        }

        #endregion

        #region 충돌 검증

        /// <summary>
        /// 정책 충돌 확인
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> CheckPolicyConflictsAsync(
            OrganizationPricingPolicy policy,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(policy.OrganizationId)
                .Where(p =>
                    p.TargetType == policy.TargetType &&
                    p.TargetKey == policy.TargetKey &&
                    p.PolicyType == policy.PolicyType &&
                    p.Priority == policy.Priority &&
                    p.Id != policy.Id &&
                    p.IsActive &&
                    !p.IsDeleted)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 대상별 중복 정책 확인
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> FindDuplicatePoliciesAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p =>
                    p.TargetType == targetType &&
                    p.IsActive &&
                    !p.IsDeleted);

            if (!string.IsNullOrEmpty(targetKey))
            {
                query = query.Where(p => p.TargetKey == targetKey);
            }

            return await query
                .GroupBy(p => new { p.TargetType, p.TargetKey, p.PolicyType })
                .Where(g => g.Count() > 1)
                .SelectMany(g => g)
                .ToListAsync(cancellationToken);
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 정책 일괄 생성
        /// </summary>
        public async Task<int> BulkCreateAsync(
            IEnumerable<OrganizationPricingPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            var policyList = policies.ToList();

            foreach (var policy in policyList)
            {
                policy.CreatedAt = DateTime.UtcNow;
                policy.UpdatedAt = DateTime.UtcNow;
            }

            await _dbSet.AddRangeAsync(policyList, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            return policyList.Count;
        }

        /// <summary>
        /// 정책 타입별 일괄 업데이트
        /// </summary>
        public async Task<int> BulkUpdateByTypeAsync(
            Guid organizationId,
            PricingPolicyType policyType,
            Action<OrganizationPricingPolicy> updates,
            CancellationToken cancellationToken = default)
        {
            var policies = await QueryForOrganization(organizationId)
                .Where(p =>
                    p.PolicyType == policyType &&
                    !p.IsDeleted)
                .ToListAsync(cancellationToken);

            var timestamp = DateTime.UtcNow;
            foreach (var policy in policies)
            {
                updates(policy);
                policy.UpdatedAt = timestamp;
            }

            _dbSet.UpdateRange(policies);
            await _context.SaveChangesAsync(cancellationToken);
            return policies.Count;
        }

        /// <summary>
        /// 만료된 정책 일괄 삭제
        /// </summary>
        public async Task<int> BulkDeleteExpiredAsync(
            Guid organizationId,
            DateTime olderThan,
            CancellationToken cancellationToken = default)
        {
            var expiredPolicies = await QueryForOrganization(organizationId)
                .Where(p =>
                    p.EffectiveUntil.HasValue &&
                    p.EffectiveUntil < olderThan &&
                    !p.IsDeleted)
                .ToListAsync(cancellationToken);

            var timestamp = DateTime.UtcNow;
            foreach (var policy in expiredPolicies)
            {
                policy.IsDeleted = true;
                policy.DeletedAt = timestamp;
                policy.UpdatedAt = timestamp;
            }

            _dbSet.UpdateRange(expiredPolicies);
            await _context.SaveChangesAsync(cancellationToken);
            return expiredPolicies.Count;
        }

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 가격 정책 통계
        /// </summary>
        public async Task<PricingPolicyStatistics> GetStatisticsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var policies = await QueryForOrganization(organizationId)
                .Where(p => !p.IsDeleted)
                .ToListAsync(cancellationToken);

            var activePolicies = policies.Where(p => p.IsActive).ToList();
            var expiredPolicies = policies.Where(p =>
                p.EffectiveUntil.HasValue && p.EffectiveUntil < DateTime.UtcNow).ToList();
            var pendingPolicies = policies.Where(p => !p.IsApproved).ToList();

            // 정책 타입별 분포
            var policiesByType = policies
                .GroupBy(p => p.PolicyType.ToString())
                .ToDictionary(g => g.Key, g => g.Count());

            // 할인 관련 통계
            var discountPolicies = activePolicies.Where(p => p.DiscountRate > 0).ToList();
            var averageDiscountRate = discountPolicies.Any() ?
                (double)discountPolicies.Average(p => p.DiscountRate) : 0;
            var maxDiscountRate = discountPolicies.Any() ?
                (double)discountPolicies.Max(p => p.DiscountRate) : 0;
            var totalDiscountAmount = activePolicies.Sum(p => p.DiscountAmount);

            // 사용 통계 (타겟 타입별)
            var usageByTargetType = activePolicies
                .GroupBy(p => p.TargetType.ToString())
                .ToDictionary(g => g.Key, g => g.Count());

            return new PricingPolicyStatistics
            {
                // 기본 통계
                TotalPolicies = policies.Count,
                ActivePolicies = activePolicies.Count,
                ExpiredPolicies = expiredPolicies.Count,
                PendingApprovalPolicies = pendingPolicies.Count,

                // 정책 타입별 분포
                PoliciesByType = policiesByType,

                // 할인 통계
                AverageDiscountRate = (decimal)averageDiscountRate,
                MaxDiscountRate = (decimal)maxDiscountRate,
                TotalDiscountAmount = totalDiscountAmount,
                TotalSavedAmount = 0, // 실제로는 거래 데이터와 연계하여 계산

                // 사용 통계
                TotalApplicationCount = 0, // 실제 적용된 정책 수 (별도 집계 필요)
                UniqueCustomerCount = 0, // 정책을 적용받은 고유 고객 수 (별도 집계 필요)
                UsageByTargetType = usageByTargetType,

                // 효과 분석 (실제로는 별도 분석 로직 필요)
                RevenueImpact = 0,
                ConversionRateChange = 0,
                CustomerRetentionImpact = 0,

                // 기간 정보
                PeriodStart = policies.Any() ? policies.Min(p => p.CreatedAt) : DateTime.UtcNow,
                PeriodEnd = DateTime.UtcNow,
                GeneratedAt = DateTime.UtcNow,

                // 상위 정책 (실제로는 사용 빈도나 효과를 기준으로 정렬)
                TopPolicies = activePolicies
                    .OrderByDescending(p => p.DiscountRate + p.DiscountAmount)
                    .Take(5)
                    .Select(p => new TopPerformingPolicy
                    {
                        PolicyId = p.Id,
                        PolicyName = p.PolicyName,
                        UsageCount = 0, // 실제 사용 횟수 (별도 집계 필요)
                        TotalImpact = p.DiscountAmount + (p.DiscountRate * 1000) // 임시 계산
                    })
                    .ToList()
            };
        }

        /// <summary>
        /// 할인 영향 분석
        /// </summary>
        public async Task<DiscountImpactAnalysis> AnalyzeDiscountImpactAsync(
            Guid organizationId,
            int period = 30,
            CancellationToken cancellationToken = default)
        {
            var fromDate = DateTime.UtcNow.AddDays(-period);

            var policies = await QueryForOrganization(organizationId)
                .Where(p =>
                    p.CreatedAt >= fromDate &&
                    (p.DiscountRate > 0 || p.DiscountAmount > 0) &&
                    !p.IsDeleted)
                .ToListAsync(cancellationToken);

            return new DiscountImpactAnalysis
            {
                OrganizationId = organizationId,
                AnalysisPeriodDays = period,
                AverageDiscountRate = (decimal)(policies.Where(p => p.DiscountRate > 0).Average(p => (double?)p.DiscountRate) ?? 0),
                TotalDiscountAmount = policies.Sum(p => p.DiscountAmount),
                EstimatedCustomerSavings = 0m, // 실제로는 거래 데이터와 연계하여 계산
                AnalyzedAt = DateTime.UtcNow
            };
        }

        /// <summary>
        /// 정책 사용 메트릭스
        /// </summary>
        public async Task<PolicyUsageMetrics> GetUsageMetricsAsync(
            Guid policyId,
            CancellationToken cancellationToken = default)
        {
            var policy = await GetByIdAsync(policyId);
            if (policy == null)
                throw new InvalidOperationException("Policy not found");

            // 실제로는 별도의 사용량 추적 테이블에서 조회해야 함
            return new PolicyUsageMetrics
            {
                PolicyId = policyId,
                TotalUsageCount = 0, // 실제 총 사용량 조회 필요
                DailyUsageCount = 0, // 실제 일일 사용량 조회 필요
                WeeklyUsageCount = 0, // 실제 주간 사용량 조회 필요
                MonthlyUsageCount = 0, // 실제 월간 사용량 조회 필요
                TotalDiscountGiven = 0m, // 실제 절감액 계산 필요
                LastUsedAt = DateTime.UtcNow // 마지막 사용 시점
            };
        }

        /// <summary>
        /// 가격 정책 추이 조회
        /// </summary>
        public async Task<List<PricingPolicyTrend>> GetPolicyTrendsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            TrendInterval interval = TrendInterval.Monthly,
            CancellationToken cancellationToken = default)
        {
            var policies = await QueryForOrganization(organizationId)
                .Where(p =>
                    p.CreatedAt >= startDate &&
                    p.CreatedAt <= endDate &&
                    !p.IsDeleted)
                .OrderBy(p => p.CreatedAt)
                .ToListAsync(cancellationToken);

            var trends = new List<PricingPolicyTrend>();

            // 간격에 따른 그룹핑 (월별 예시)
            var groups = policies.GroupBy(p => new { p.CreatedAt.Year, p.CreatedAt.Month });

            foreach (var group in groups)
            {
                trends.Add(new PricingPolicyTrend
                {
                    Period = new DateTime(group.Key.Year, group.Key.Month, 1),
                    PeriodLabel = $"{group.Key.Year}-{group.Key.Month:00}",
                    TotalDiscountAmount = group.Where(p => p.DiscountAmount > 0).Sum(p => p.DiscountAmount),
                    ActivePolicyCount = group.Count(p => p.IsActive),
                    AverageDiscountRate = (decimal)(group.Where(p => p.DiscountRate > 0).Average(p => (double?)p.DiscountRate) ?? 0)
                });
            }

            return trends;
        }

        #endregion

        #region 검색 및 필터링

        /// <summary>
        /// 키워드로 정책 검색
        /// </summary>
        public async Task<IEnumerable<OrganizationPricingPolicy>> SearchAsync(
            Guid organizationId,
            string keyword,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p =>
                    (p.PolicyName.Contains(keyword) ||
                     (p.Description != null && p.Description.Contains(keyword))) &&
                    !p.IsDeleted)
                .OrderBy(p => p.PolicyName)
                .ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 고급 검색
        /// </summary>
        public async Task<PagedResult<OrganizationPricingPolicy>> AdvancedSearchAsync(
            Expression<Func<OrganizationPricingPolicy, bool>> criteria,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            var query = _dbSet.Where(p => !p.IsDeleted).Where(criteria);

            var totalCount = await query.CountAsync(cancellationToken);
            var items = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .OrderBy(p => p.PolicyName)
                .ToListAsync(cancellationToken);

            return new PagedResult<OrganizationPricingPolicy>
            {
                Items = items,
                TotalCount = totalCount,
                PageNumber = pageNumber,
                PageSize = pageSize,
            };
        }

        #endregion
    }
}