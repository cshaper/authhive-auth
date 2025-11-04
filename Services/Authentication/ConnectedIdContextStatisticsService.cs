// [Correction] Added necessary using statements for new services and models.
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Core;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Auth.Context;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Services.Authentication
{

    /// <summary>
    /// ConnectedId 컨텍스트 통계 서비스 구현체
    /// </summary>
    public class ConnectedIdContextStatisticsService : IConnectedIdContextStatisticsService
    {
        private readonly IConnectedIdContextRepository _contextRepository;
        private readonly ILogger<ConnectedIdContextStatisticsService> _logger;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IOrganizationSettingsRepository _orgSettingsRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IRoleService _roleService;
        private readonly IDateTimeProvider _dateTimeProvider;

        public ConnectedIdContextStatisticsService(
            IConnectedIdContextRepository contextRepository,
            ILogger<ConnectedIdContextStatisticsService> logger,
            ICacheService cacheService,
            IAuditService auditService,
            IOrganizationSettingsRepository orgSettingsRepository,
            IConnectedIdRepository connectedIdRepository,
            IRoleService roleService,
            IDateTimeProvider dateTimeProvider)
        {
            _contextRepository = contextRepository;
            _logger = logger;
            _cacheService = cacheService;
            _auditService = auditService;
            _orgSettingsRepository = orgSettingsRepository;
            _connectedIdRepository = connectedIdRepository;
            _roleService = roleService;
            _dateTimeProvider = dateTimeProvider;
        }

        #region IService Implementation

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdContextStatisticsService initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        #endregion


        #region Interface Implementation

        public Task<ServiceResult<ConnectedIdContextStatisticsDto>> GetOverallStatisticsReadModelAsync(string period = "Last24Hours")
        {
            _logger.LogWarning("Accessing GetOverallStatisticsReadModelAsync(string) without explicit ConnectedId. Using System ID.");
            return GetOverallStatisticsReadModelAsync(Guid.Empty, period);
        }

        /// <summary>
        /// 전반적인 통계 정보를 비동기로 가져옵니다. (시스템 관리자 역할로 제한되어야 함)
        /// </summary>
        public async Task<ServiceResult<ConnectedIdContextStatisticsDto>> GetOverallStatisticsReadModelAsync(
            Guid currentConnectedId,
            string period = "Last24Hours")
        {
            // 1. 시스템 관리자 역할 권한 검사 및 접근 제어
            bool isSystemAdmin = await _roleService.IsConnectedIdInRoleAsync(
                currentConnectedId,
                RoleConstants.SystemReservedKeys.SUPER_ADMIN);

            if (!isSystemAdmin)
            {
                await _auditService.LogActionAsync(
                    performedByConnectedId: currentConnectedId,
                    action: "Attempted Get Overall Statistics (Unauthorized)",
                    actionType: AuditActionType.UnauthorizedAccess,
                    resourceType: "ConnectedIdContextStatistics",
                    resourceId: null,
                    success: false,
                    metadata: $"Access Denied: User {currentConnectedId} is not a System Administrator for period {period}.");

                return ServiceResult<ConnectedIdContextStatisticsDto>.Failure(
                    "Access Denied. Required role: System Administrator.",
                    "Unauthorized");
            }

            // 2. 통계 로직
            var cacheKey = $"stats:overall:{period}";
            var cachedResult = await _cacheService.GetAsync<ConnectedIdContextStatisticsDto>(cacheKey);
            if (cachedResult != null) return ServiceResult<ConnectedIdContextStatisticsDto>.Success(cachedResult);

            var since = ParsePeriodToDateTime(period);
            var filter = (Expression<Func<ConnectedIdContext, bool>>)(c => c.CreatedAt >= since);

            var statisticsResult = await GenerateStatisticsAsync(filter, period);

            if (statisticsResult.IsSuccess)
            {
                await _cacheService.SetAsync<ConnectedIdContextStatisticsDto>(
                    cacheKey,
                    statisticsResult.Data!,
                    TimeSpan.FromMinutes(5));

                await _auditService.LogActionAsync(
                    performedByConnectedId: currentConnectedId,
                    action: "Get Overall Statistics",
                    actionType: AuditActionType.Read,
                    resourceType: "ConnectedIdContextStatistics",
                    resourceId: null,
                    success: true,
                    metadata: $"Period: {period}");
            }

            return statisticsResult;
        }

        public async Task<ServiceResult<ConnectedIdContextStatisticsDto>> GetStatisticsForOrganizationAsync(Guid organizationId, string period = "Last24Hours")
        {
            var planCheckResult = await CheckFeatureAvailabilityAsync(organizationId, "Statistics");
            if (!planCheckResult.IsSuccess)
            {
                return ServiceResult<ConnectedIdContextStatisticsDto>.Failure(planCheckResult.ErrorMessage!, planCheckResult.ErrorCode);
            }

            var cacheKey = $"stats:org:{organizationId}:{period}";
            var cachedResult = await _cacheService.GetAsync<ConnectedIdContextStatisticsDto>(cacheKey);
            if (cachedResult != null) return ServiceResult<ConnectedIdContextStatisticsDto>.Success(cachedResult);

            var since = ParsePeriodToDateTime(period);
            var filter = (Expression<Func<ConnectedIdContext, bool>>)(c => c.OrganizationId == organizationId && c.CreatedAt >= since);

            var statisticsResult = await GenerateStatisticsAsync(filter, period);

            if (statisticsResult.IsSuccess)
            {
                await _cacheService.SetAsync<ConnectedIdContextStatisticsDto>(cacheKey, statisticsResult.Data!, TimeSpan.FromMinutes(5));
                await LogAuditEventAsync(organizationId, "Get Organization Statistics", $"Period: {period}");
            }
            return statisticsResult;
        }

        public async Task<ServiceResult<ConnectedIdContextStatisticsDto>> GetStatisticsForUserAsync(Guid userId, string period = "Last24Hours")
        {
            var connectedId = await _connectedIdRepository.Query().FirstOrDefaultAsync(c => c.UserId == userId);
            if (connectedId == null) return ServiceResult<ConnectedIdContextStatisticsDto>.NotFound("User context not found.");

            var planCheckResult = await CheckFeatureAvailabilityAsync(connectedId.OrganizationId, "Statistics");
            if (!planCheckResult.IsSuccess)
            {
                return ServiceResult<ConnectedIdContextStatisticsDto>.Failure(planCheckResult.ErrorMessage!, planCheckResult.ErrorCode);
            }

            var cacheKey = $"stats:user:{userId}:{period}";
            var cachedResult = await _cacheService.GetAsync<ConnectedIdContextStatisticsDto>(cacheKey);
            if (cachedResult != null) return ServiceResult<ConnectedIdContextStatisticsDto>.Success(cachedResult);

            var since = ParsePeriodToDateTime(period);
            var filter = (Expression<Func<ConnectedIdContext, bool>>)(c => c.CreatedByConnectedId == userId && c.CreatedAt >= since);

            var statisticsResult = await GenerateStatisticsAsync(filter, period);

            if (statisticsResult.IsSuccess)
            {
                await _cacheService.SetAsync<ConnectedIdContextStatisticsDto>(cacheKey, statisticsResult.Data!, TimeSpan.FromMinutes(5));
                await LogAuditEventAsync(connectedId.OrganizationId, "Get User Statistics", $"Target User: {userId}, Period: {period}");
            }
            return statisticsResult;
        }

        public async Task<ServiceResult<TimeSeriesData<long>>> GetContextCreationTrendsAsync(Guid currentConnectedId, DateTime startDate, DateTime endDate, string granularity = "Daily")
        {
            // 1. 시스템 관리자 역할 권한 검사 및 접근 제어
            bool isSystemAdmin = await _roleService.IsConnectedIdInRoleAsync(
                currentConnectedId,
                RoleConstants.SystemReservedKeys.SUPER_ADMIN);

            if (!isSystemAdmin)
            {
                await _auditService.LogActionAsync(
                    performedByConnectedId: currentConnectedId,
                    action: "Attempted Get Overall Trends (Unauthorized)",
                    actionType: AuditActionType.UnauthorizedAccess,
                    resourceType: "ContextCreationTrends",
                    resourceId: null,
                    success: false,
                    metadata: $"Access Denied: User {currentConnectedId} is not a System Administrator for range {startDate:d} to {endDate:d}.");

                return ServiceResult<TimeSeriesData<long>>.Failure(
                    "Access Denied. Required role: System Administrator.",
                    "Unauthorized");
            }

            // 2. 캐시 키 및 로직
            var cacheKey = $"stats:trends:overall:{startDate:yyyyMMdd}-{endDate:yyyyMMdd}:{granularity}";
            var cachedResult = await _cacheService.GetAsync<TimeSeriesData<long>>(cacheKey);
            if (cachedResult != null) return ServiceResult<TimeSeriesData<long>>.Success(cachedResult);

            try
            {
                var query = _contextRepository.Query().Where(c => c.CreatedAt >= startDate && c.CreatedAt <= endDate);
                List<TimeSeriesData<long>.DataPoint> dataPoints;

                if (granularity.Equals("hourly", StringComparison.OrdinalIgnoreCase))
                {
                    dataPoints = await query.GroupBy(c => new { c.CreatedAt.Date, c.CreatedAt.Hour })
                        .Select(g => new TimeSeriesData<long>.DataPoint { Timestamp = g.Key.Date.AddHours(g.Key.Hour), Value = g.Count() })
                        .OrderBy(dp => dp.Timestamp).ToListAsync();
                }
                else
                {
                    dataPoints = await query.GroupBy(c => c.CreatedAt.Date)
                        .Select(g => new TimeSeriesData<long>.DataPoint { Timestamp = g.Key, Value = g.Count() })
                        .OrderBy(dp => dp.Timestamp).ToListAsync();
                }

                var timeSeriesData = new TimeSeriesData<long> { StartDate = startDate, EndDate = endDate, Granularity = granularity, DataPoints = dataPoints };
                await _cacheService.SetAsync<TimeSeriesData<long>>(cacheKey, timeSeriesData, TimeSpan.FromMinutes(10));
                await LogAuditEventAsync(null, "Get Overall Creation Trends", $"Range: {startDate:d} to {endDate:d}, Granularity: {granularity}");
                return ServiceResult<TimeSeriesData<long>>.Success(timeSeriesData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get overall context creation trends.");
                return ServiceResult<TimeSeriesData<long>>.Failure("Failed to retrieve context creation trends.");
            }
        }
        #endregion

        #region Private Helper Methods

        private async Task<ServiceResult<ConnectedIdContextStatisticsDto>> GenerateStatisticsAsync(Expression<Func<ConnectedIdContext, bool>> filter, string period)
        {
            try
            {
                var query = _contextRepository.Query().Where(filter);
                var now = DateTime.UtcNow;

                var totalContextsTask = query.CountAsync();
                var activeContextsTask = query.CountAsync(c => c.ExpiresAt > now);
                var hotPathContextsTask = query.CountAsync(c => c.IsHotPath);
                var contextsByTypeTask = query.GroupBy(c => c.ContextType)
                    .Select(g => new { Type = g.Key, Count = g.Count() })
                    .ToDictionaryAsync(x => x.Type.ToString(), x => (long)x.Count);

                var avgLifetimeTask = query.Where(c => c.ExpiresAt > c.CreatedAt)
                    .Select(c => (double?)EF.Functions.DateDiffSecond(c.CreatedAt, c.ExpiresAt)).AverageAsync();

                await Task.WhenAll(totalContextsTask, activeContextsTask, hotPathContextsTask, contextsByTypeTask, avgLifetimeTask);

                var statisticsDto = new ConnectedIdContextStatisticsDto
                {
                    Id = Guid.NewGuid(),
                    Period = period,
                    TotalContextsCreated = totalContextsTask.Result,
                    ActiveContexts = activeContextsTask.Result,
                    HotPathContexts = hotPathContextsTask.Result,
                    ContextsByType = contextsByTypeTask.Result,
                    AverageContextLifetimeSeconds = avgLifetimeTask.Result ?? 0.0,
                    CacheHitRatio = 0.0, // TODO: Implement cache hit ratio tracking
                    GeneratedAt = DateTime.UtcNow
                };

                return ServiceResult<ConnectedIdContextStatisticsDto>.Success(statisticsDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate ConnectedId context statistics.");
                return ServiceResult<ConnectedIdContextStatisticsDto>.Failure("An error occurred while generating statistics.");
            }
        }

        private async Task<ServiceResult> CheckFeatureAvailabilityAsync(Guid organizationId, string featureName)
        {
            var settings = await _orgSettingsRepository.GetSettingAsync(organizationId, "Pricing", "PlanKey");

            var planKey = settings?.SettingValue ?? PricingConstants.DefaultPlanKey;

            if (planKey == PricingConstants.SubscriptionPlans.BASIC_KEY)
            {
                // ⭐️ PricingConstants에 정의된 에러 코드 사용 (BusinessErrors 대체)
                return ServiceResult.Failure(
                    errorMessage: $"The '{featureName}' feature is not available on your current plan ('{planKey}'). Please upgrade your plan to access advanced statistics.",
                    errorCode: PricingConstants.BusinessErrorCodes.UpgradeRequired
                );
            }
            return ServiceResult.Success();
        }

        private async Task LogAuditEventAsync(Guid? organizationId, string action, string details)
        {
            var connectedId = Guid.Empty; // Placeholder: 실제 요청자의 ConnectedId로 대체되어야 합니다.

            await _auditService.LogActionAsync(
                actionType: AuditActionType.Read,
                action: action,
                connectedId: connectedId,
                success: true,
                errorMessage: null,
                resourceType: "ContextStatistics",
                resourceId: organizationId?.ToString(),
                metadata: new Dictionary<string, object> { { "Details", details } }
            );
        }

        private DateTime ParsePeriodToDateTime(string period)
        {
            return period.ToLower() switch
            {
                "last7days" => DateTime.UtcNow.AddDays(-7),
                "last30days" => DateTime.UtcNow.AddDays(-30),
                "last24hours" => DateTime.UtcNow.AddHours(-24),
                _ => DateTime.UtcNow.AddHours(-24),
            };
        }
        #endregion
    }
}