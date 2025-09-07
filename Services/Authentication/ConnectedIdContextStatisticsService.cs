using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Context;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace AuthHive.Auth.Services.Auth
{
    /// <summary>
    /// ConnectedId 컨텍스트 통계 서비스 구현체
    /// </summary>
    public class ConnectedIdContextStatisticsService : IConnectedIdContextStatisticsService
    {
        private readonly IConnectedIdContextRepository _contextRepository;
        private readonly ILogger<ConnectedIdContextStatisticsService> _logger;

        public ConnectedIdContextStatisticsService(
            IConnectedIdContextRepository contextRepository,
            ILogger<ConnectedIdContextStatisticsService> logger)
        {
            _contextRepository = contextRepository;
            _logger = logger;
        }

        #region IService Implementation
        public Task<bool> IsHealthyAsync()
        {
            // DB 연결 상태 등을 확인하는 로직 추가 가능
            return Task.FromResult(true);
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdContextStatisticsService initialized.");
            return Task.CompletedTask;
        }
        #endregion

        #region Public Statistics Methods
        public Task<ServiceResult<ConnectedIdContextStatisticsDto>> GetOverallStatisticsAsync(string period = "Last24Hours")
        {
            var since = ParsePeriodToDateTime(period);
            var filter = (Expression<Func<ConnectedIdContext, bool>>)(c => c.CreatedAt >= since);
            return GenerateStatisticsAsync(filter, period);
        }

        public Task<ServiceResult<ConnectedIdContextStatisticsDto>> GetStatisticsForOrganizationAsync(Guid organizationId, string period = "Last24Hours")
        {
            var since = ParsePeriodToDateTime(period);
            var filter = (Expression<Func<ConnectedIdContext, bool>>)(c => c.OrganizationId == organizationId && c.CreatedAt >= since);
            return GenerateStatisticsAsync(filter, period);
        }

        public Task<ServiceResult<ConnectedIdContextStatisticsDto>> GetStatisticsForUserAsync(Guid userId, string period = "Last24Hours")
        {
            // ConnectedIdContext에는 UserId가 없으므로, ConnectedId를 통해 조회해야 합니다.
            // 실제 구현에서는 IConnectedIdRepository 등을 통해 UserId -> ConnectedId[] 변환이 필요할 수 있습니다.
            // 여기서는 CreatedByConnectedId를 기준으로 조회합니다.
            var since = ParsePeriodToDateTime(period);
            var filter = (Expression<Func<ConnectedIdContext, bool>>)(c => c.CreatedByConnectedId == userId && c.CreatedAt >= since);
            return GenerateStatisticsAsync(filter, period);
        }
        public async Task<ServiceResult<TimeSeriesData<long>>> GetContextCreationTrendsAsync(DateTime startDate, DateTime endDate, string granularity = "Daily")
        {
            try
            {
                var query = _contextRepository.Query()
                    .Where(c => c.CreatedAt >= startDate && c.CreatedAt <= endDate);

                // 👇 [수정됨] if/else 구문으로 변경하여 각 케이스를 명확하게 분리
                List<TimeSeriesData<long>.DataPoint> dataPoints;

                if (granularity.Equals("hourly", StringComparison.OrdinalIgnoreCase))
                {
                    dataPoints = await query
                        .GroupBy(c => new { c.CreatedAt.Date, c.CreatedAt.Hour })
                        .Select(g => new TimeSeriesData<long>.DataPoint
                        {
                            Timestamp = g.Key.Date.AddHours(g.Key.Hour),
                            Value = g.Count()
                        })
                        .OrderBy(dp => dp.Timestamp)
                        .ToListAsync();
                }
                else // "daily" 또는 기본값
                {
                    dataPoints = await query
                        .GroupBy(c => c.CreatedAt.Date)
                        .Select(g => new TimeSeriesData<long>.DataPoint
                        {
                            Timestamp = g.Key,
                            Value = g.Count()
                        })
                        .OrderBy(dp => dp.Timestamp)
                        .ToListAsync();
                }

                var timeSeriesData = new TimeSeriesData<long>
                {
                    StartDate = startDate,
                    EndDate = endDate,
                    Granularity = granularity,
                    DataPoints = dataPoints
                };

                return ServiceResult<TimeSeriesData<long>>.Success(timeSeriesData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get context creation trends.");
                return ServiceResult<TimeSeriesData<long>>.Failure("Failed to retrieve context creation trends.");
            }
        }
        #endregion

        #region Private Helper Methods
        /// <summary>
        /// 지정된 필터를 기반으로 통계 DTO를 생성하는 공통 헬퍼 메서드
        /// </summary>

        private async Task<ServiceResult<ConnectedIdContextStatisticsDto>> GenerateStatisticsAsync(Expression<Func<ConnectedIdContext, bool>> filter, string period)
        {
            try
            {
                var query = _contextRepository.Query().Where(filter);
                var now = DateTime.UtcNow;

                var totalContextsTask = query.CountAsync();
                var activeContextsTask = query.CountAsync(c => c.ExpiresAt > now);
                var hotPathContextsTask = query.CountAsync(c => c.IsHotPath);

                var contextsByTypeTask = query
                    .GroupBy(c => c.ContextType)
                    .Select(g => new { Type = g.Key, Count = g.Count() })
                    .ToDictionaryAsync(x => x.Type.ToString(), x => (long)x.Count);

                // 👇 [수정 1] AverageAsync가 Task<double?>를 반환하도록 Select 구문으로 명시적 캐스팅
                var avgLifetimeTask = query
                    .Where(c => c.ExpiresAt > c.CreatedAt)
                    .Select(c => (double?)EF.Functions.DateDiffSecond(c.CreatedAt, c.ExpiresAt))
                    .AverageAsync();

                await Task.WhenAll(totalContextsTask, activeContextsTask, hotPathContextsTask, contextsByTypeTask, avgLifetimeTask);

                var statisticsDto = new ConnectedIdContextStatisticsDto
                {
                    Id = Guid.NewGuid(),
                    Period = period,
                    TotalContextsCreated = totalContextsTask.Result,
                    ActiveContexts = activeContextsTask.Result,
                    HotPathContexts = hotPathContextsTask.Result,
                    ContextsByType = contextsByTypeTask.Result,
                    // 👇 [수정 2] avgLifetimeTask.Result가 double? 이므로 ?? 연산자로 기본값 처리
                    AverageContextLifetimeSeconds = avgLifetimeTask.Result ?? 0.0,
                    CacheHitRatio = 0.0,
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
        /// <summary>
        /// 기간 문자열을 DateTime으로 변환합니다.
        /// </summary>
        private DateTime ParsePeriodToDateTime(string period)
        {
            return period.ToLower() switch
            {
                "last7days" => DateTime.UtcNow.AddDays(-7),
                "last30days" => DateTime.UtcNow.AddDays(-30),
                "last24hours" => DateTime.UtcNow.AddHours(-24),
                _ => DateTime.UtcNow.AddHours(-24), // Default
            };
        }
        #endregion
    }
}
