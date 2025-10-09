using System;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Core.Models.Business.Platform.Common;
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

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 🚨 수정된 코드: 첫 번째 인수에 null을 명시적으로 전달하여 predicate를 생략하고,
                // cancellationToken을 두 번째 인수로 전달합니다.
                return await _repository.CountAsync(null, cancellationToken) >= 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConnectedIdStatisticsService health check failed.");
                return false;
            }
        }
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdStatisticsService initialized.");
            return Task.CompletedTask;
        }


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