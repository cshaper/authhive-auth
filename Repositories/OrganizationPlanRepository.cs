using AuthHive.Core.Entities.Business.Platform;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Interfaces.Repositories.Business.Platform;
using AuthHive.Core.Models.Business.Platform;
using AuthHive.Core.Models.Business.Platform.Common;
using AuthHive.Core.Interfaces.Base; // IOrganizationContext namespace
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory; // IMemoryCache namespace
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Organization.Service;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직의 구독 요금제(SaaS Plan) 데이터에 접근하기 위한 리포지토리의 구체적인 구현체입니다.
    /// </summary>
    public class OrganizationPlanRepository : BaseRepository<OrganizationPlan>, IOrganizationPlanRepository
    {
        /// <summary>
        /// 생성자: 필요한 모든 의존성을 주입받아 BaseRepository에 전달합니다.
        /// </summary>
        /// <param name="context">데이터베이스 컨텍스트</param>
        /// <param name="organizationContext">현재 조직 컨텍스트</param>
        /// <param name="cache">메모리 캐시 (선택적)</param>
        public OrganizationPlanRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext, // <-- Dependency added
            IMemoryCache? cache = null)               // <-- Dependency added
            : base(context, organizationContext, cache) // <-- All arguments passed to base
        {
            // The base constructor handles initialization.
        }

        /// <summary>
        /// 특정 조직의 현재 활성화된 플랜 정보를 조회합니다.
        /// 이 메서드는 조직에 연결된 여러 구독(Subscription) 기록 중에서
        /// 현재 날짜를 기준으로 유효하고 활성화된 단 하나의 플랜을 반환합니다.
        /// </summary>
        public async Task<OrganizationPlan?> GetActivePlanByOrganizationIdAsync(Guid organizationId)
        {
            var now = DateTime.UtcNow;

            // PlanSubscription 엔티티를 통해 현재 활성 구독을 찾고, 그 구독과 연결된 OrganizationPlan을 반환합니다.
            // PlanSubscription 엔티티에 StartDate, EndDate, IsActive와 같은 속성이 있다고 가정합니다.
            // TODO: PlanSubscription 엔티티의 실제 속성명(예: ValidFrom, ValidTo)에 맞게 쿼리를 수정해야 합니다.
            var activeSubscription = await _context.Set<PlanSubscription>()
                .Include(s => s.Plan) // OrganizationPlan 정보를 함께 로드합니다.
                .Where(s => s.OrganizationId == organizationId && s.IsActive)
                .OrderByDescending(s => s.StartDate) // 가장 최근에 시작된 구독을 우선으로 합니다.
                .FirstOrDefaultAsync(s => s.StartDate <= now && (s.EndDate == null || s.EndDate >= now));

            // 활성 구독(Subscription)에 연결된 플랜(Plan)을 반환합니다.
            return activeSubscription?.Plan;
        }

        public async Task<OrganizationPlan?> GetByPlanKeyAsync(string planKey, CancellationToken cancellationToken = default)
        {
            return await _dbSet.FirstOrDefaultAsync(p => p.PlanKey == planKey, cancellationToken);
        }

        public async Task<OrganizationPlan?> GetByPlanTypeAsync(PlanType planType, CancellationToken cancellationToken = default)
        {
            return await _dbSet.FirstOrDefaultAsync(p => p.PlanType == planType, cancellationToken);
        }

        public async Task<IEnumerable<OrganizationPlan>> GetAvailablePlansAsync(bool includeCustom = false, bool includeHidden = false, CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsQueryable();

            if (!includeHidden)
            {
                query = query.Where(p => p.IsAvailable);
            }

            if (!includeCustom)
            {
                query = query.Where(p => p.PlanType != PlanType.Custom);
            }

            return await query.OrderBy(p => p.DisplayOrder).ToListAsync(cancellationToken);
        }

        public async Task<IEnumerable<PlanFeature>> GetPlanFeaturesAsync(Guid planId, bool? isEnabled = null, CancellationToken cancellationToken = default)
        {
            var query = _context.Set<PlanFeature>().Where(f => f.PlanId == planId);

            if (isEnabled.HasValue)
            {
                query = query.Where(f => f.IsEnabled == isEnabled.Value);
            }

            return await query.ToListAsync(cancellationToken);
        }

        // --- Other method implementations (NotImplemented) ---

        public Task<IEnumerable<AddonCompatibility>> GetAddonCompatibilityAsync(PlanType planType, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<PlanComparisonMatrix> GetComparisonMatrixAsync(IEnumerable<PlanType>? planTypes = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<PlanLimits> GetPlanLimitsAsync(PlanType planType, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<PlanPricing> GetPlanPricingAsync(PlanType planType, BillingCycle billingCycle = BillingCycle.Monthly, string currencyCode = "USD", CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<bool> IsUpgradePathValidAsync(PlanType fromPlan, PlanType toPlan, CancellationToken cancellationToken = default)
        {
            if (toPlan < fromPlan) return Task.FromResult(false);
            return Task.FromResult(true);
        }
    }
}