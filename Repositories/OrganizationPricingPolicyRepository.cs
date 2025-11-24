using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Infra.Cache;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using AuthHive.Core.Models.Business.Commerce.Billing.Common;
using AuthHive.Core.Models.Business.Commerce.Common;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Business.Payment.Common;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직 가격 정책 리포지토리 구현체 - AuthHive v16
    /// BaseRepository<T>를 상속받아 공통 CRUD, 캐싱, 조직 필터링 기능을 재사용합니다.
    /// </summary>
    public class OrganizationPricingPolicyRepository : BaseRepository<OrganizationPricingPolicy>, IOrganizationPricingPolicyRepository
    {
        private readonly ILogger<OrganizationPricingPolicyRepository> _logger;

        /// <summary>
        /// [FIXED] 생성자: v16 BaseRepository 원칙에 따라 AuthDbContext, ICacheService, ILogger를 주입받습니다.
        /// IOrganizationContext 의존성을 제거합니다.
        /// </summary>
        public OrganizationPricingPolicyRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<OrganizationPricingPolicyRepository> logger)
            : base(context, cacheService) // [FIXED] CS1729: BaseRepository 생성자 시그니처 수정 (3개 -> 2개)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// [FIXED] CS0534: 이 리포지토리가 다루는 엔티티(OrganizationPricingPolicy)가
        /// 조직 범위에 속하는지(조직 ID로 필터링되어야 하는지) 여부를 결정합니다.
        /// 가격 정책은 조직별로 관리되므로 true를 반환합니다.
        /// </summary>
        protected override bool IsOrganizationBaseEntity() => true;

        #region 기본 조회

        public async Task<OrganizationPricingPolicy?> GetByNameAsync(
            Guid organizationId,
            string policyName,
            CancellationToken cancellationToken = default)
        {
            // 캐시 키는 조직별로 고유해야 함
            string cacheKey = $"OrgPricingPolicy:Name:{organizationId}:{policyName.ToLowerInvariant()}";
            if (_cacheService != null)
            {
                var cachedPolicy = await _cacheService.GetAsync<OrganizationPricingPolicy>(cacheKey, cancellationToken);
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

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetByPolicyTypeAsync(
            Guid organizationId,
            PricingPolicyType policyType,
            bool activeOnly = true,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType);

            if (activeOnly)
            {
                query = query.Where(p => p.IsActive);
            }

            return await query
                .AsNoTracking()
                .OrderBy(p => p.Priority)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetByTargetAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.TargetType == targetType && p.IsActive);

            if (!string.IsNullOrEmpty(targetKey))
            {
                query = query.Where(p => p.TargetKey == targetKey);
            }

            return await query
                .AsNoTracking()
                .OrderBy(p => p.Priority)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> NameExistsAsync(
            Guid organizationId,
            string policyName,
            Guid? excludePolicyId = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.PolicyName == policyName);

            if (excludePolicyId.HasValue)
            {
                query = query.Where(p => p.Id != excludePolicyId.Value);
            }

            return await query.AnyAsync(cancellationToken);
        }

        #endregion

        #region 정책 관리

        public async Task<OrganizationPricingPolicy> CreatePolicyAsync(
            OrganizationPricingPolicy policy,
            bool validateConflicts = true,
            CancellationToken cancellationToken = default)
        {
            if (validateConflicts)
            {
                // TODO: 정책 충돌 검증 로직은 복잡한 비즈니스 규칙이므로
                // IOrganizationPricingService 같은 서비스 계층에서 처리해야 합니다.
                // var conflicts = await CheckPolicyConflictsAsync(policy, cancellationToken);
                // if (conflicts.Any())
                // {
                //    throw new InvalidOperationException("Policy conflicts detected.");
                // }
            }
            // BaseRepository의 AddAsync 사용
            return await base.AddAsync(policy, cancellationToken);
        }

        public async Task<OrganizationPricingPolicy?> UpdatePolicyAsync(
            Guid policyId,
            Action<OrganizationPricingPolicy> updates,
            CancellationToken cancellationToken = default)
        {
            var policy = await Query() // IsDeleted = false 필터 포함
                .FirstOrDefaultAsync(p => p.Id == policyId, cancellationToken);

            if (policy == null)
            {
                return null;
            }

            updates(policy); // 전달된 Action을 실행하여 엔티티 변경
            
            // BaseRepository의 UpdateAsync 사용 (캐시 무효화 포함)
            await base.UpdateAsync(policy, cancellationToken);
            return policy;
        }

        public async Task<bool> SetActiveStatusAsync(
            Guid policyId, 
            bool isActive,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.IsActive = isActive;
            }, cancellationToken);

            return policy != null;
        }

        public async Task<OrganizationPricingPolicy> ClonePolicyAsync(
            Guid sourcePolicyId,
            string newName,
            Guid? targetOrganizationId = null,
            CancellationToken cancellationToken = default)
        {
            var sourcePolicy = await Query()
                .AsNoTracking() // 원본은 추적할 필요 없음
                .FirstOrDefaultAsync(p => p.Id == sourcePolicyId, cancellationToken);

            if (sourcePolicy == null)
            {
                throw new KeyNotFoundException($"Source policy with ID {sourcePolicyId} not found.");
            }

            // 새 엔티티 생성
            var newPolicy = new OrganizationPricingPolicy
            {
                // 속성 복사
                OrganizationId = targetOrganizationId ?? sourcePolicy.OrganizationId,
                PolicyName = newName,
                PolicyType = sourcePolicy.PolicyType,
                Description = sourcePolicy.Description,
                Priority = sourcePolicy.Priority,
                IsActive = false, // 복제본은 기본적으로 비활성 상태로 생성
                IsApproved = false,
                EffectiveFrom = sourcePolicy.EffectiveFrom,
                EffectiveUntil = sourcePolicy.EffectiveUntil, // [FIXED] EffectiveTo -> EffectiveUntil
                TargetType = sourcePolicy.TargetType,
                TargetKey = sourcePolicy.TargetKey,
                DiscountRate = sourcePolicy.DiscountRate,
                DiscountAmount = sourcePolicy.DiscountAmount,
                CustomPrice = sourcePolicy.CustomPrice,
                CustomMAUOverageRate = sourcePolicy.CustomMAUOverageRate, // [FIXED] CustomMauOverageRate -> CustomMAUOverageRate
                CustomApiUsageRate = sourcePolicy.CustomApiUsageRate,
                PointBonusRate = sourcePolicy.PointBonusRate,
                ConditionRules = sourcePolicy.ConditionRules
                // Id, CreatedAt, UpdatedAt 등은 자동 생성됨
            };

            return await base.AddAsync(newPolicy, cancellationToken);
        }

        #endregion

        #region 할인 관리

        public async Task<bool> UpdateDiscountAsync(
            Guid policyId,
            decimal? discountRate = null,
            decimal? discountAmount = null,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                // [FIXED] CS0266: decimal?을 decimal에 할당할 수 없음. .HasValue로 확인
                if (discountRate.HasValue)
                    p.DiscountRate = discountRate.Value;
                if (discountAmount.HasValue)
                    p.DiscountAmount = discountAmount.Value;
            }, cancellationToken);

            return policy != null;
        }

        public async Task<OrganizationPricingPolicy?> GetMaxDiscountPolicyAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            // TODO: '최대 할인'을 결정하는 로직(비율 vs 금액)은 비즈니스 규칙입니다.
            // 이 로직은 서비스 계층(IOrganizationPricingService)으로 이동해야 합니다.
            // 여기서는 우선순위가 가장 높은 정책을 반환하는 것으로 단순화합니다.
            _logger.LogWarning("GetMaxDiscountPolicyAsync is using simplified logic. Move complex discount calculation to Service Layer.");

            return await GetHighestPriorityPolicyAsync(organizationId, targetType, targetKey, cancellationToken);
        }

        public async Task<decimal> CalculateDiscountedAmountAsync(
            Guid organizationId,
            decimal baseAmount,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            // !경고: 이것은 리포지토리의 책임을 벗어나는 순수 비즈니스 로직입니다.
            // TODO: 이 로직 전체를 IOrganizationPricingService.CalculateFinalPriceAsync()로 이동해야 합니다.
            _logger.LogError("CalculateDiscountedAmountAsync MUST be moved to a Service Layer. This violates SRP.");

            var policy = await GetMaxDiscountPolicyAsync(organizationId, targetType, targetKey, cancellationToken);
            if (policy == null)
            {
                return baseAmount;
            }

            // 서비스 계층에서 수행해야 할 로직 (임시 구현)
            decimal finalAmount = baseAmount;

            // [FIXED] CS1061: decimal(non-nullable)은 .HasValue, .Value를 가질 수 없음
            if (policy.DiscountRate > 0)
            {
                finalAmount = finalAmount * (1 - policy.DiscountRate);
            }
            if (policy.DiscountAmount > 0)
            {
                finalAmount = finalAmount - policy.DiscountAmount;
            }
            return Math.Max(0, finalAmount); // 가격은 0 미만이 될 수 없음
        }

        #endregion

        #region 맞춤 가격

        public async Task<bool> SetCustomPriceAsync(
            Guid policyId, 
            decimal customPrice,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.PolicyType = PricingPolicyType.Negotiated; // 맞춤 가격은 '협상가' 타입
                p.CustomPrice = customPrice;
            }, cancellationToken);
            return policy != null;
        }

        public async Task<bool> UpdateCustomRatesAsync(
            Guid policyId,
            decimal? mauOverageRate = null,
            decimal? apiUsageRate = null,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.PolicyType = PricingPolicyType.Negotiated;
                // [FIXED] CS0117: 속성 이름 오타 수정
                if(mauOverageRate.HasValue) p.CustomMAUOverageRate = mauOverageRate.Value;
                if(apiUsageRate.HasValue) p.CustomApiUsageRate = apiUsageRate.Value;
            }, cancellationToken);
            return policy != null;
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetNegotiatedPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // GetByPolicyTypeAsync 메서드 재사용
            return await GetByPolicyTypeAsync(
                organizationId,
                PricingPolicyType.Negotiated,
                activeOnly: true,
                cancellationToken);
        }

        #endregion

        #region 포인트 보너스

        public async Task<bool> SetPointBonusRateAsync(
            Guid policyId, 
            decimal bonusRate,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.PointBonusRate = bonusRate;
            }, cancellationToken);
            return policy != null;
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetPointBonusPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // [FIXED] CS1061: PointBonusRate는 non-nullable이므로 .HasValue 제거
            return await QueryForOrganization(organizationId)
                .Where(p => p.IsActive && p.PointBonusRate > 0)
                .AsNoTracking()
                .OrderBy(p => p.Priority)
                .ToListAsync(cancellationToken);
        }

        public async Task<decimal> CalculateTotalPointsWithBonusAsync(
            Guid organizationId,
            decimal basePoints,
            CancellationToken cancellationToken = default)
        {
            // !경고: 이것 또한 리포지토리의 책임을 벗어나는 비즈니스 로직입니다.
            // TODO: 이 로직 전체를 IPointService.CalculatePointsAsync() 같은 서비스로 이동해야 합니다.
            _logger.LogError("CalculateTotalPointsWithBonusAsync MUST be moved to a Service Layer.");
            
            var policies = await GetPointBonusPoliciesAsync(organizationId, cancellationToken);
            // .Max()는 0을 반환할 수 있으므로, 보너스가 없는 경우(1.0m)와 구분
            var bestBonusRate = policies.Any() ? policies.Max(p => p.PointBonusRate) : 0m; 
            
            // 보너스율이 0보다 클 때만 적용, 아니면 1(100%)을 곱함
            return basePoints * (bestBonusRate > 0 ? bestBonusRate : 1.0m);
        }

        #endregion

        #region 유효 기간 관리

        public async Task<bool> SetEffectivePeriodAsync(
            Guid policyId,
            DateTime effectiveFrom,
            DateTime? effectiveTo = null,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.EffectiveFrom = effectiveFrom;
                // [FIXED] CS0117: 속성 이름 오타 수정
                p.EffectiveUntil = effectiveTo;
            }, cancellationToken);
            return policy != null;
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetEffectivePoliciesAsync(
            Guid organizationId,
            DateTime? asOfDate = null,
            CancellationToken cancellationToken = default)
        {
            var now = asOfDate ?? DateTime.UtcNow;
            return await QueryForOrganization(organizationId)
                .Where(p => p.IsActive &&
                            p.EffectiveFrom <= now &&
                            // [FIXED] CS0117: 속성 이름 오타 수정
                            (p.EffectiveUntil == null || p.EffectiveUntil >= now))
                .AsNoTracking()
                .OrderBy(p => p.Priority)
                .ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetExpiredPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            // [FIXED] CS0117: 속성 이름 오타 수정
            return await QueryForOrganization(organizationId)
                .Where(p => p.EffectiveUntil != null && p.EffectiveUntil < now)
                .AsNoTracking()
                .OrderByDescending(p => p.EffectiveUntil)
                .ToListAsync(cancellationToken);
        }

        public async Task<OrganizationPricingPolicy> CreateTemporaryPolicyAsync(
            OrganizationPricingPolicy policy,
            TimeSpan duration,
            CancellationToken cancellationToken = default)
        {
            policy.EffectiveFrom = DateTime.UtcNow;
            // [FIXED] CS0117: 속성 이름 오타 수정
            policy.EffectiveUntil = DateTime.UtcNow.Add(duration);
            policy.IsActive = true;
            return await base.AddAsync(policy, cancellationToken);
        }

        #endregion

        #region 우선순위 관리

        public async Task<bool> UpdatePriorityAsync(
            Guid policyId, 
            int priority,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.Priority = priority;
            }, cancellationToken);
            return policy != null;
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetByPriorityAsync(
            Guid organizationId,
            PricingTargetType? targetType = null,
            CancellationToken cancellationToken = default)
        {
            var query = QueryForOrganization(organizationId)
                .Where(p => p.IsActive);

            if (targetType.HasValue)
            {
                query = query.Where(p => p.TargetType == targetType.Value);
            }

            return await query
                .AsNoTracking()
                .OrderBy(p => p.Priority)
                .ToListAsync(cancellationToken);
        }

        public async Task<OrganizationPricingPolicy?> GetHighestPriorityPolicyAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey = null,
            CancellationToken cancellationToken = default)
        {
            var now = DateTime.UtcNow;
            var query = QueryForOrganization(organizationId)
                .Where(p => p.IsActive &&
                            p.TargetType == targetType &&
                            p.EffectiveFrom <= now &&
                            // [FIXED] CS0117: 속성 이름 오타 수정
                            (p.EffectiveUntil == null || p.EffectiveUntil >= now));

            if (!string.IsNullOrEmpty(targetKey))
            {
                // 특정 대상(targetKey)에 대한 정책과, 모든 대상('All' 또는 null)에 대한 정책을 모두 고려
                query = query.Where(p => p.TargetKey == targetKey || string.IsNullOrEmpty(p.TargetKey));
            }

            return await query
                .AsNoTracking()
                .OrderBy(p => p.Priority) // 우선순위 숫자가 낮은 것이 높음
                .FirstOrDefaultAsync(cancellationToken);
        }

        #endregion

        #region 승인 관리

        public async Task<bool> ApprovePolicyAsync(
            Guid policyId, 
            Guid approvedBy,
            CancellationToken cancellationToken = default)
        {
            var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.IsApproved = true;
                p.ApprovedByConnectedId = approvedBy;
                p.ApprovedAt = DateTime.UtcNow;
            }, cancellationToken);

            // TODO: IAuditLogRepository를 사용하여 승인 이력(ApprovalHistory)을 별도 테이블에 기록해야 합니다.
            // _auditLogRepo.LogApproval(policyId, approvedBy);

            return policy != null;
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> GetUnapprovedPoliciesAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .Where(p => !p.IsApproved)
                .AsNoTracking()
                .OrderBy(p => p.CreatedAt)
                .ToListAsync(cancellationToken);
        }

        public async Task<bool> RevokeApprovalAsync(
            Guid policyId,
            CancellationToken cancellationToken = default)
        {
             var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.IsApproved = false;
                p.ApprovedByConnectedId = null;
                p.ApprovedAt = null;
            }, cancellationToken);

            // TODO: IAuditLogRepository를 사용하여 승인 취소 이력을 기록해야 합니다.
            return policy != null;
        }

        public Task<IEnumerable<PricingPolicyApprovalHistoryDto>> GetApprovalHistoryAsync(
            Guid policyId,
            CancellationToken cancellationToken = default)
        {
            // TODO: 이 기능은 별도의 'ApprovalHistory' 테이블 또는 'AuditLog' 테이블을
            // IAuditLogRepository를 통해 조회해야 합니다.
            _logger.LogWarning("GetApprovalHistoryAsync is not implemented. Requires IAuditLogRepository.");
            return Task.FromResult(Enumerable.Empty<PricingPolicyApprovalHistoryDto>());
        }

        #endregion

        #region 조건 규칙

        public async Task<bool> UpdateConditionRulesAsync(
            Guid policyId, 
            string conditionRules,
            CancellationToken cancellationToken = default)
        {
             var policy = await UpdatePolicyAsync(policyId, p =>
            {
                p.ConditionRules = conditionRules; // JSON 문자열 저장
            }, cancellationToken);
            return policy != null;
        }

        public Task<bool> EvaluateConditionsAsync(
            Guid policyId, 
            Dictionary<string, object> context,
            CancellationToken cancellationToken = default)
        {
            // !경고: 이것은 리포지토리의 책임을 벗어나는 순수 비즈니스 로직(규칙 엔진)입니다.
            // TODO: 이 로직 전체를 IOrganizationPricingService 또는 별도의 IRuleEngine 서비스로 이동해야 합니다.
            _logger.LogError("EvaluateConditionsAsync MUST be moved to a Service Layer/Rule Engine.");
            return Task.FromResult(false); // 리포지토리에서는 항상 false 반환
        }

        public Task<IEnumerable<OrganizationPricingPolicy>> GetPoliciesMeetingConditionsAsync(
            Guid organizationId,
            Dictionary<string, object> context,
            CancellationToken cancellationToken = default)
        {
            // !경고: 이것 또한 규칙 엔진이 필요한 비즈니스 로직입니다.
            // TODO: 이 로직은 서비스 계층에서 구현되어야 합니다.
             _logger.LogError("GetPoliciesMeetingConditionsAsync MUST be moved to a Service Layer/Rule Engine.");
            return Task.FromResult(Enumerable.Empty<OrganizationPricingPolicy>());
        }

        #endregion

        #region 충돌 검증

        public Task<IEnumerable<OrganizationPricingPolicy>> CheckPolicyConflictsAsync(
            OrganizationPricingPolicy policy,
            CancellationToken cancellationToken = default)
        {
            // !경고: '충돌'을 정의하는 것(기간 겹침, 대상 겹침 등)은 복잡한 비즈니스 로직입니다.
            // TODO: 이 로직은 서비스 계층(IOrganizationPricingService)으로 이동해야 합니다.
            _logger.LogError("CheckPolicyConflictsAsync MUST be moved to a Service Layer.");
            return Task.FromResult(Enumerable.Empty<OrganizationPricingPolicy>());
        }

        public async Task<IEnumerable<OrganizationPricingPolicy>> FindDuplicatePoliciesAsync(
            Guid organizationId,
            PricingTargetType targetType,
            string? targetKey,
            CancellationToken cancellationToken = default)
        {
            // 이 쿼리는 '동일 대상'을 가진 정책을 찾는 단순 조회이므로 리포지토리에 적합합니다.
            var query = QueryForOrganization(organizationId)
                .Where(p => p.TargetType == targetType && p.TargetKey == targetKey);
                
            return await query.AsNoTracking().ToListAsync(cancellationToken);
        }

        #endregion

        #region 일괄 작업

        public async Task<int> BulkCreateAsync(
            IEnumerable<OrganizationPricingPolicy> policies,
            CancellationToken cancellationToken = default)
        {
            await base.AddRangeAsync(policies, cancellationToken);
            return policies.Count();
        }

        public async Task<int> BulkUpdateByTypeAsync(
            Guid organizationId,
            PricingPolicyType policyType,
            Action<OrganizationPricingPolicy> updates,
            CancellationToken cancellationToken = default)
        {
            // ExecuteUpdateAsync는 Action<T>를 지원하지 않으므로,
            // 데이터를 로드하여 변경해야 합니다. (데이터가 많을 시 성능 저하 가능)
            var policiesToUpdate = await QueryForOrganization(organizationId)
                .Where(p => p.PolicyType == policyType)
                .ToListAsync(cancellationToken);

            foreach (var policy in policiesToUpdate)
            {
                updates(policy);
            }

            await base.UpdateRangeAsync(policiesToUpdate, cancellationToken);
            return policiesToUpdate.Count;
        }

        public async Task<int> BulkDeleteExpiredAsync(
            Guid organizationId, 
            DateTime olderThan,
            CancellationToken cancellationToken = default)
        {
            // [FIXED] CS0117: 속성 이름 오타 수정
            var policiesToDelete = await QueryForOrganization(organizationId)
                .Where(p => p.EffectiveUntil != null && p.EffectiveUntil < olderThan)
                .ToListAsync(cancellationToken);

            if (policiesToDelete.Any())
            {
                // BaseRepository의 Soft Delete 사용
                await base.DeleteRangeAsync(policiesToDelete, cancellationToken);
            }
            return policiesToDelete.Count;
        }

        #endregion

        #region 통계 및 분석 (TODO)

        // !경고: 아래 메서드들은 리포지토리의 기본 책임을 벗어나는 복잡한 분석/통계 쿼리입니다.
        // TODO: 이러한 기능은 성능을 위해 별도의 읽기 전용 리포지토리(CQRS)나
        // 분석 서비스(IAnalyticsService)로 분리하는 것을 강력히 권장합니다.

        public Task<PricingPolicyStatistics> GetStatisticsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("GetStatisticsAsync is not implemented. This is complex analytics logic and should be in a separate Analytics/Reporting service.");
            // TODO: 이 쿼리는 DB에 큰 부하를 줄 수 있습니다.
            // var stats = await QueryForOrganization(organizationId)
            //     .GroupBy(p => 1) // 전체 통계
            //     .Select(g => new PricingPolicyStatistics {
            //         ActivePolicies = g.Count(p => p.IsActive),
            //         TotalPolicies = g.Count(),
            //         AverageDiscountRate = g.Average(p => p.DiscountRate),
            //         // ...
            //     }).FirstOrDefaultAsync(cancellationToken);
            return Task.FromResult(new PricingPolicyStatistics());
        }

        public Task<DiscountImpactAnalysis> AnalyzeDiscountImpactAsync(
            Guid organizationId,
            int period = 30,
            CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("AnalyzeDiscountImpactAsync is not implemented. Move to Analytics Service.");
            return Task.FromResult(new DiscountImpactAnalysis());
        }

        public Task<PolicyUsageMetrics> GetUsageMetricsAsync(
            Guid policyId,
            CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("GetUsageMetricsAsync is not implemented. Move to Analytics Service.");
            return Task.FromResult(new PolicyUsageMetrics());
        }

        public Task<List<PricingPolicyTrend>> GetPolicyTrendsAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            TrendInterval interval = TrendInterval.Monthly,
            CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("GetPolicyTrendsAsync is not implemented. Move to Analytics Service.");
            return Task.FromResult(new List<PricingPolicyTrend>());
        }


        #endregion

        #region 검색 및 필터링

        public async Task<IEnumerable<OrganizationPricingPolicy>> SearchAsync(
            Guid organizationId,
            string keyword,
            CancellationToken cancellationToken = default)
        {
            var lowerKeyword = keyword.ToLower();
            return await QueryForOrganization(organizationId)
                .Where(p => (p.PolicyName != null && p.PolicyName.ToLower().Contains(lowerKeyword)) ||
                            (p.Description != null && p.Description.ToLower().Contains(lowerKeyword)))
                .AsNoTracking()
                .Take(50) // 너무 많은 결과 방지
                .ToListAsync(cancellationToken);
        }

        public async Task<PagedResult<OrganizationPricingPolicy>> AdvancedSearchAsync(
            Expression<Func<OrganizationPricingPolicy, bool>> criteria,
            int pageNumber = 1,
            int pageSize = 50,
            CancellationToken cancellationToken = default)
        {
            // BaseRepository의 GetPagedAsync 메서드를 재사용합니다.
            // 단, 이 criteria는 OrganizationId 필터링을 포함해야 하므로,
            // 서비스 계층에서 criteria를 조합할 때 주의해야 합니다.
            // 예: criteria = criteria.And(p => p.OrganizationId == currentOrgId);
            _logger.LogWarning("AdvancedSearchAsync criteria must be combined with OrganizationId filter in the Service Layer.");

            var (items, totalCount) = await base.GetPagedAsync(
                pageNumber,
                pageSize,
                criteria,
                orderBy: p => p.Priority,
                isDescending: false,
                cancellationToken);

            return new PagedResult<OrganizationPricingPolicy>(items, totalCount, pageNumber, pageSize);
        }

        #endregion
    }
}