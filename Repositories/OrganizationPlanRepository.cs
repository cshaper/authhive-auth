using AuthHive.Core.Entities.Business.Platform;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Interfaces.Repositories.Business.Platform;
using AuthHive.Core.Models.Business.Platform;
using AuthHive.Core.Models.Business.Platform.Common;
using AuthHive.Core.Interfaces.Base;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Constants.Business;
// REFACTORED: ICacheService를 사용하므로 IMemoryCache 네임스페이스는 제거합니다.
// using Microsoft.Extensions.Caching.Memory;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// 조직의 구독 요금제(SaaS Plan) 데이터에 접근하기 위한 리포지토리의 구체적인 구현체입니다.
    /// v16 원칙에 따라 ICacheService를 사용하여 캐싱 전략을 캡슐화합니다.
    /// </summary>
    public class OrganizationPlanRepository : BaseRepository<OrganizationPlan>, IOrganizationPlanRepository
    {

        /// <summary>
        /// 생성자: IMemoryCache 의존성을 제거하고 ICacheService를 받도록 수정합니다.
        /// </summary>
        /// <param name="context">데이터베이스 컨텍스트</param>
        /// <param name="organizationContext">현재 조직 컨텍스트</param>
        /// <param name="cacheService">캐시 서비스 추상화</param>
        public OrganizationPlanRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            ICacheService cacheService) // REFACTORED: IMemoryCache 대신 ICacheService를 주입받습니다.
            : base(context, organizationContext, cacheService) // REFACTORED: cacheService를 base 생성자에 전달합니다.
        {
            // BaseRepository 생성자가 모든 초기화를 처리합니다.
        }


        /// <summary>
        /// 특정 조직의 현재 활성화된 플랜 정보를 조회합니다. (캐시 적용)
        /// 이 메서드는 조직에 연결된 여러 구독(Subscription) 기록 중에서
        /// 현재 날짜를 기준으로 유효하고 활성화된 단 하나의 플랜을 반환합니다.
        /// </summary>
        /// <summary>
        /// 특정 조직의 현재 활성화된 플랜 정보를 조회합니다. (Cache-Aside 패턴 적용)
        /// </summary>
        public async Task<OrganizationPlan?> GetActivePlanByOrganizationIdAsync(Guid organizationId)
        {
            // 캐시 서비스가 주입되지 않은 경우, DB로 직접 조회합니다.
            if (_cacheService == null)
            {
                var now = DateTime.UtcNow;
                var activeSubscription = await _context.Set<PlanSubscription>()
                    .Include(s => s.Plan)
                    .Where(s => s.OrganizationId == organizationId && s.Status == SubscriptionStatus.Active)
                    .OrderByDescending(s => s.StartDate)
                    .FirstOrDefaultAsync(s => s.StartDate <= now && (s.EndDate == null || s.EndDate >= now));
                return activeSubscription?.Plan;
            }

            // 캐시 서비스가 존재하면, Cache-Aside 패턴을 수행합니다.
            string cacheKey = $"active_plan_for_org:{organizationId}";

            // 1. 캐시에서 조회
            var cachedPlan = await _cacheService.GetAsync<OrganizationPlan>(cacheKey);
            if (cachedPlan != null)
            {
                return cachedPlan;
            }

            // 2. DB에서 조회
            var nowDb = DateTime.UtcNow;
            var activeSubscriptionDb = await _context.Set<PlanSubscription>()
                .Include(s => s.Plan)
                .Where(s => s.OrganizationId == organizationId && s.Status == SubscriptionStatus.Active)
                .OrderByDescending(s => s.StartDate)
                .FirstOrDefaultAsync(s => s.StartDate <= nowDb && (s.EndDate == null || s.EndDate >= nowDb));

            var planFromDb = activeSubscriptionDb?.Plan;

            // 3. 캐시에 저장
            if (planFromDb != null)
            {
                await _cacheService.SetAsync(cacheKey, planFromDb);
            }

            return planFromDb;
        }
        public async Task<OrganizationPlan?> GetByPlanKeyAsync(string planKey, CancellationToken cancellationToken = default)
        {
            // 캐시 서비스가 없으면 DB로 직접 조회합니다.
            if (_cacheService == null)
            {
                return await _dbSet.FirstOrDefaultAsync(p => p.PlanKey == planKey, cancellationToken);
            }

            // 캐시 서비스가 있으면 Cache-Aside 패턴을 적용합니다.
            string cacheKey = $"plan_by_key:{planKey}";

            // 1. 캐시에서 조회
            var cachedPlan = await _cacheService.GetAsync<OrganizationPlan>(cacheKey);
            if (cachedPlan != null)
            {
                return cachedPlan;
            }

            // 2. DB에서 조회
            var planFromDb = await _dbSet.AsNoTracking()
                                         .FirstOrDefaultAsync(p => p.PlanKey == planKey, cancellationToken);

            // 3. DB 결과가 있으면 캐시에 저장
            if (planFromDb != null)
            {
                await _cacheService.SetAsync(cacheKey, planFromDb);
            }

            return planFromDb;
        }

        /// <summary>
        /// 특정 플랜의 모든 기능 제한 목록을 PricingConstants에서 직접 조회합니다.
        /// 이 메서드는 데이터베이스를 조회하지 않아 매우 빠르고 비용 효율적입니다.
        /// </summary>
        /// <param name="planKey">플랜의 고유 키 (예: "plan.pro")</param>
        /// <returns>플랜의 상세 기능 명세</returns>
        public Task<ServiceResult<PlanDetails>> GetPlanFeaturesAsync(string planKey)
        {
            // PricingConstants는 모든 플랜 정보의 '진실 공급원'입니다.
            // 데이터베이스를 조회할 필요 없이 이 중앙 상수 클래스에서 모든 정보를 가져옵니다.
            var planDetails = PricingConstants.GetPlan(planKey);

            if (planDetails == null)
            {
                return Task.FromResult(
                    ServiceResult<PlanDetails>.Failure("Plan not found in PricingConstants.")
                );
            }

            return Task.FromResult(ServiceResult<PlanDetails>.Success(planDetails));
        }

    }
}