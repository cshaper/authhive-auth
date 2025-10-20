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
// REFACTORED: IOrganizationContextService는 더 이상 리포지토리 생성자에서 직접 사용되지 않습니다.
// using AuthHive.Core.Interfaces.Organization.Service; 
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
        /// [FIXED] 생성자: BaseRepository v16 원칙에 따라 IOrganizationContext 의존성을 제거하고
        /// AuthDbContext와 ICacheService만 주입받도록 수정합니다.
        /// </summary>
        /// <param name="context">데이터베이스 컨텍스트</param>
        /// <param name="cacheService">캐시 서비스 추상화 (null일 수 있음)</param>
        public OrganizationPlanRepository(
            AuthDbContext context,
            ICacheService? cacheService) // REFACTORED: IOrganizationContext 제거, ICacheService를 nullable(?)로 변경
            : base(context, cacheService) // REFACTORED: base(context, cacheService) 시그니처로 변경
        {
            // BaseRepository 생성자가 모든 초기화를 처리합니다.
        }

        /// <summary>
        /// [FIXED] OrganizationPlan 엔티티는 "Pro Plan", "Free Plan" 등 플랫폼 전역의
        /// '정의' 데이터이므로 특정 조직에 종속되지 않습니다.
        /// BaseRepository의 추상 메서드를 구현합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => false;


        /// <summary>
        /// 특정 조직의 현재 활성화된 플랜 정보를 조회합니다. (캐시 적용)
        /// 이 메서드는 조직에 연결된 여러 구독(Subscription) 기록 중에서
        /// 현재 날짜를 기준으로 유효하고 활성화된 단 하나의 플랜을 반환합니다.
        /// </summary>
        /// <summary>
        /// 특정 조직의 현재 활성화된 플랜 정보를 조회합니다. (Cache-Aside 패턴 적용)
        /// </summary>
        public async Task<OrganizationPlan?> GetActivePlanByOrganizationIdAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            // 캐시 서비스가 주입되지 않은 경우, DB로 직접 조회합니다.
            // (BaseRepository의 _cacheService 필드를 사용)
            if (_cacheService == null)
            {
                var now = DateTime.UtcNow;
                var activeSubscription = await _context.Set<PlanSubscription>()
                    .Include(s => s.Plan)
                    .Where(s => s.OrganizationId == organizationId && s.Status == SubscriptionStatus.Active)
                    .OrderByDescending(s => s.StartDate)
                    .FirstOrDefaultAsync(s => s.StartDate <= now && (s.EndDate == null || s.EndDate >= now), cancellationToken); // cancellationToken 전달
                return activeSubscription?.Plan;
            }

            // 캐시 서비스가 존재하면, Cache-Aside 패턴을 수행합니다.
            string cacheKey = $"active_plan_for_org:{organizationId}";

            // 1. 캐시에서 조회
            var cachedPlan = await _cacheService.GetAsync<OrganizationPlan>(cacheKey, cancellationToken);
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
                .FirstOrDefaultAsync(s => s.StartDate <= nowDb && (s.EndDate == null || s.EndDate >= nowDb), cancellationToken); // cancellationToken 전달

            var planFromDb = activeSubscriptionDb?.Plan;

            // 3. 캐시에 저장
            if (planFromDb != null)
            {
                // 플랜 정보는 자주 바뀌지 않으므로 적절한 만료 시간(예: 15분) 설정
                await _cacheService.SetAsync(cacheKey, planFromDb, TimeSpan.FromMinutes(15), cancellationToken);
            }

            return planFromDb;
        }

        /// <summary>
        /// 플랜 키(예: "plan.pro")를 기준으로 플랜 정의를 조회합니다. (Cache-Aside 패턴 적용)
        /// </summary>
        public async Task<OrganizationPlan?> GetByPlanKeyAsync(string planKey, CancellationToken cancellationToken = default)
        {
            // 캐시 서비스가 없으면 DB로 직접 조회합니다.
            if (_cacheService == null)
            {
                // AsNoTracking()을 사용하여 조회 성능 최적화
                return await _dbSet.AsNoTracking().FirstOrDefaultAsync(p => p.PlanKey == planKey, cancellationToken);
            }

            // 캐시 서비스가 있으면 Cache-Aside 패턴을 적용합니다.
            string cacheKey = $"plan_by_key:{planKey}";

            // 1. 캐시에서 조회
            var cachedPlan = await _cacheService.GetAsync<OrganizationPlan>(cacheKey, cancellationToken);
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
                // 플랜 정의는 거의 변경되지 않으므로 비교적 긴 만료 시간(예: 1시간) 설정
                await _cacheService.SetAsync(cacheKey, planFromDb, TimeSpan.FromHours(1), cancellationToken);
            }

            return planFromDb;
        }

        /// <summary>
        /// 특정 플랜의 모든 기능 제한 목록을 PricingConstants에서 직접 조회합니다.
        /// 이 메서드는 데이터베이스를 조회하지 않아 매우 빠르고 비용 효율적입니다.
        /// (SaaS 원칙: 3. Strict Pricing Enforcement 적용)
        /// </summary>
        /// <param name="planKey">플랜의 고유 키 (예: "plan.pro")</param>
        /// <returns>플랜의 상세 기능 명세</returns>
        public Task<ServiceResult<PlanDetails>> GetPlanFeaturesAsync(string planKey)
        {
            // PricingConstants는 모든 플랜 정보의 '진실 공급원(Source of Truth)'입니다.
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