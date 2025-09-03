using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// ConnectedId 컨텍스트의 관리, 유지보수, 진단 작업을 담당하는 서비스 구현체입니다.
    /// </summary>
    public class ConnectedIdContextAdminService : IConnectedIdContextAdminService
    {
        private readonly IConnectedIdContextRepository _contextRepository;
        private readonly ILogger<ConnectedIdContextAdminService> _logger;

        public ConnectedIdContextAdminService(
            IConnectedIdContextRepository contextRepository,
            ILogger<ConnectedIdContextAdminService> logger)
        {
            _contextRepository = contextRepository;
            _logger = logger;
        }

        public Task<bool> IsHealthyAsync()
        {
            return Task.FromResult(_contextRepository != null);
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdContextAdminService initialized.");
            return Task.CompletedTask;
        }

        #region 데이터 정리 (Cleanup)

        public async Task<ServiceResult<int>> CleanupExpiredContextsAsync(int retentionDays = 7)
        {
            _logger.LogInformation("Starting cleanup of expired contexts older than {RetentionDays} days.", retentionDays);
            try
            {
                var deletedCount = await _contextRepository.CleanupExpiredContextsAsync(retentionDays);
                _logger.LogInformation("Successfully cleaned up {DeletedCount} expired contexts.", deletedCount);
                return ServiceResult<int>.Success(deletedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup expired contexts.");
                return ServiceResult<int>.Failure("An error occurred during expired context cleanup.");
            }
        }

        public async Task<ServiceResult<int>> CleanupInactiveContextsAsync(int inactiveDays = 30)
        {
            _logger.LogInformation("Starting cleanup of inactive contexts older than {InactiveDays} days.", inactiveDays);
            try
            {
                var deletedCount = await _contextRepository.CleanupInactiveContextsAsync(inactiveDays);
                _logger.LogInformation("Successfully cleaned up {DeletedCount} inactive contexts.", deletedCount);
                return ServiceResult<int>.Success(deletedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup inactive contexts.");
                return ServiceResult<int>.Failure("An error occurred during inactive context cleanup.");
            }
        }

        public async Task<ServiceResult<int>> InvalidateContextsBySessionIdAsync(Guid sessionId)
        {
            if (sessionId == Guid.Empty)
                return ServiceResult<int>.Failure("SessionId cannot be empty.");

            _logger.LogInformation("Invalidating all contexts for SessionId: {SessionId}", sessionId);
            try
            {
                var invalidatedCount = await _contextRepository.DeleteBySessionIdAsync(sessionId);
                _logger.LogInformation("Successfully invalidated {InvalidatedCount} contexts for SessionId: {SessionId}", invalidatedCount, sessionId);
                return ServiceResult<int>.Success(invalidatedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate contexts for SessionId: {SessionId}", sessionId);
                return ServiceResult<int>.Failure("An error occurred while invalidating session contexts.");
            }
        }

        #endregion

        #region 유지보수 및 최적화 (Maintenance & Optimization)

        public async Task<ServiceResult<int>> UpdateHotPathStatusAsync(int threshold, int timeWindowHours)
        {
            _logger.LogInformation("Starting batch update for Hot Path status with threshold {Threshold} in the last {TimeWindowHours} hours.", threshold, timeWindowHours);
            try
            {
                var updatedCount = await _contextRepository.UpdateHotPathStatusAsync(threshold, timeWindowHours);
                _logger.LogInformation("Successfully updated Hot Path status for {UpdatedCount} contexts.", updatedCount);
                return ServiceResult<int>.Success(updatedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to batch update Hot Path status.");
                return ServiceResult<int>.Failure("An error occurred during Hot Path status update.");
            }
        }

        public async Task<ServiceResult<IEnumerable<Guid>>> TriggerContextRefreshJobsAsync(int expiryThresholdMinutes = 5)
        {
            _logger.LogInformation("Finding contexts that need refresh within the next {ExpiryThresholdMinutes} minutes.", expiryThresholdMinutes);
            try
            {
                var contextsToRefresh = await _contextRepository.GetContextsNeedingRefreshAsync(expiryThresholdMinutes);
                var contextIds = contextsToRefresh.Select(c => c.Id).ToList();
                _logger.LogInformation("Found {ContextCount} contexts that need to be refreshed.", contextIds.Count);
                return ServiceResult<IEnumerable<Guid>>.Success(contextIds);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to find contexts needing refresh.");
                return ServiceResult<IEnumerable<Guid>>.Failure("An error occurred while fetching contexts for refresh jobs.");
            }
        }

        #endregion

        #region 무결성 및 진단 (Integrity & Diagnostics)

        public async Task<ServiceResult<(bool IsValid, string? ErrorMessage)>> ValidateContextIntegrityAsync(Guid contextId)
        {
            if (contextId == Guid.Empty)
                return ServiceResult<(bool, string?)>.Failure("ContextId cannot be empty.");

            _logger.LogDebug("Validating integrity for context: {ContextId}", contextId);
            try
            {
                var result = await _contextRepository.ValidateContextIntegrityAsync(contextId);
                return ServiceResult<(bool, string?)>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating integrity for context: {ContextId}", contextId);
                return ServiceResult<(bool, string?)>.Failure("An error occurred during integrity validation.");
            }
        }

        public async Task<ServiceResult<string>> RecalculateChecksumAsync(Guid contextId)
        {
            if (contextId == Guid.Empty)
                return ServiceResult<string>.Failure("ContextId cannot be empty.");

            _logger.LogInformation("Recalculating checksum for context: {ContextId}", contextId);
            try
            {
                var newChecksum = await _contextRepository.RecalculateChecksumAsync(contextId);
                _logger.LogInformation("Successfully recalculated checksum for context {ContextId}. New checksum: {NewChecksum}", contextId, newChecksum);
                return ServiceResult<string>.Success(newChecksum);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to recalculate checksum for context: {ContextId}", contextId);
                return ServiceResult<string>.Failure("An error occurred during checksum recalculation.");
            }
        }

        #endregion

        #region 데이터 마이그레이션 (Import/Export)

        public async Task<ServiceResult<string>> ExportContextsAsync(Guid connectedId)
        {
             if (connectedId == Guid.Empty)
                return ServiceResult<string>.Failure("ConnectedId cannot be empty.");

            _logger.LogInformation("Exporting contexts for ConnectedId: {ConnectedId}", connectedId);
            try
            {
                var json_data = await _contextRepository.ExportContextsAsJsonAsync(connectedId);
                return ServiceResult<string>.Success(json_data);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export contexts for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<string>.Failure("An error occurred during context export.");
            }
        }

        public async Task<ServiceResult<int>> ImportContextsAsync(string jsonData, bool overwrite = false)
        {
            if (string.IsNullOrWhiteSpace(jsonData))
                return ServiceResult<int>.Failure("JSON data cannot be empty.");

            _logger.LogInformation("Importing contexts from JSON data. Overwrite mode: {Overwrite}", overwrite);
            try
            {
                var importedCount = await _contextRepository.ImportContextsFromJsonAsync(jsonData, overwrite);
                _logger.LogInformation("Successfully imported {ImportedCount} contexts.", importedCount);
                return ServiceResult<int>.Success(importedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to import contexts from JSON data.");
                return ServiceResult<int>.Failure("An error occurred during context import.");
            }
        }

        #endregion
    }
}