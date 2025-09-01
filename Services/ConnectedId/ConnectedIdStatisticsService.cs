using System;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// ConnectedId 관련 통계를 표준화된 방식으로 제공합니다.
    /// </summary>
    public class ConnectedIdStatisticsService : IConnectedIdStatisticsService
    {
        private readonly IConnectedIdRepository _repository;
        private readonly ILogger<ConnectedIdStatisticsService> _logger;

        public ConnectedIdStatisticsService(
            IConnectedIdRepository repository,
            ILogger<ConnectedIdStatisticsService> logger)
        {
            _repository = repository;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Repository가 정상적으로 동작하는지 간단히 확인
                return await _repository.CountAsync() >= 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConnectedIdStatisticsService health check failed.");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdStatisticsService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region IStatisticsService Implementation

        public async Task<ServiceResult<ConnectedIdStatistics>> GetStatisticsAsync(StatisticsQuery query)
        {
            try
            {
                // TODO: 현재 요청을 보낸 사용자가 해당 조직(query.OrganizationId)의
                // 통계를 볼 권한이 있는지 확인하는 권한 검증 로직이 필요합니다.
                
                var stats = await _repository.GetStatisticsAsync(query);
                
                if (stats == null)
                {
                    _logger.LogWarning("Statistics could not be generated for organization {OrgId}", query.OrganizationId);
                    return ServiceResult<ConnectedIdStatistics>.Failure("Statistics could not be generated.");
                }

                return ServiceResult<ConnectedIdStatistics>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get ConnectedId statistics for organization {OrgId}", query.OrganizationId);
                return ServiceResult<ConnectedIdStatistics>.Failure("An error occurred while fetching statistics.");
            }
        }

        #endregion
    }
}