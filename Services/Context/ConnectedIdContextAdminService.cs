using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Services.Context
{
    /// <summary>
    /// ConnectedId 컨텍스트의 관리, 유지보수, 진단 작업을 담당하는 서비스 구현체입니다. (v16 최종본)
    /// </summary>
    public class ConnectedIdContextAdminService : IConnectedIdContextAdminService
    {
        private readonly IConnectedIdContextRepository _contextRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuditService _auditService;
        private readonly ILogger<ConnectedIdContextAdminService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        public ConnectedIdContextAdminService(
            IConnectedIdContextRepository contextRepository,
            IUnitOfWork unitOfWork,
            IAuditService auditService,
            ILogger<ConnectedIdContextAdminService> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _contextRepository = contextRepository;
            _unitOfWork = unitOfWork;
            _auditService = auditService;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }
public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // Repository가 null이 아니고, 데이터베이스에 연결할 수 있는지 확인하는 것이 가장 확실합니다.
            // 여기서는 간단하게 null 체크만 수행합니다.
            var isHealthy = _contextRepository != null && _unitOfWork != null;
            if (!isHealthy)
            {
                _logger.LogCritical("ConnectedIdContextAdminService is unhealthy due to missing dependencies.");
            }
            return Task.FromResult(isHealthy);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdContextAdminService has been initialized successfully.");
            // 이 서비스는 특별한 초기화 로직이 없으므로 완료된 Task를 반환합니다.
            return Task.CompletedTask;
        }
        
        #region 데이터 정리 (Cleanup)

        public async Task<ServiceResult<int>> CleanupExpiredContextsAsync(int retentionDays = 7, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting cleanup of expired contexts older than {RetentionDays} days.", retentionDays);
            try
            {
                var cutoffDate = _dateTimeProvider.UtcNow.AddDays(-retentionDays);
                var deletedCount = await _contextRepository.DeleteExpiredBeforeAsync(cutoffDate, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Successfully cleaned up {DeletedCount} expired contexts.", deletedCount);
                return ServiceResult<int>.Success(deletedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup expired contexts.");
                return ServiceResult<int>.Failure("An error occurred during expired context cleanup.");
            }
        }

        public async Task<ServiceResult<int>> CleanupInactiveContextsAsync(int inactiveDays = 30, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting cleanup of inactive contexts older than {InactiveDays} days.", inactiveDays);
            try
            {
                var cutoffDate = _dateTimeProvider.UtcNow.AddDays(-inactiveDays);
                var deletedCount = await _contextRepository.DeleteInactiveBeforeAsync(cutoffDate, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation("Successfully cleaned up {DeletedCount} inactive contexts.", deletedCount);
                return ServiceResult<int>.Success(deletedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup inactive contexts.");
                return ServiceResult<int>.Failure("An error occurred during inactive context cleanup.");
            }
        }

        public async Task<ServiceResult<int>> InvalidateContextsBySessionIdAsync(Guid sessionId, string reason, Guid? invalidatedBy, CancellationToken cancellationToken = default)
        {
            if (sessionId == Guid.Empty)
                return ServiceResult<int>.Failure("SessionId cannot be empty.");

            _logger.LogInformation("Invalidating all contexts for SessionId: {SessionId}. Reason: {Reason}", sessionId, reason);
            try
            {
                var invalidatedCount = await _contextRepository.DeleteBySessionIdAsync(sessionId, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Delete,
                    action: "Contexts.InvalidatedBySession",
                    connectedId: invalidatedBy ?? Guid.Empty, // 작업 주체
                    success: true,
                    resourceType: "Session",
                    resourceId: sessionId.ToString(),
                    metadata: new Dictionary<string, object> { { "Reason", reason }, { "InvalidatedCount", invalidatedCount } },
                    cancellationToken: cancellationToken
                );

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

        public async Task<ServiceResult<int>> UpdateHotPathStatusAsync(int threshold, int timeWindowHours, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Starting batch update for Hot Path status with threshold {Threshold} in the last {TimeWindowHours} hours.", threshold, timeWindowHours);
            try
            {
                var timeWindow = TimeSpan.FromHours(timeWindowHours);
                var updatedCount = await _contextRepository.UpdateHotPathStatusAsync(threshold, timeWindow, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                
                _logger.LogInformation("Successfully updated Hot Path status for {UpdatedCount} contexts.", updatedCount);
                return ServiceResult<int>.Success(updatedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to batch update Hot Path status.");
                return ServiceResult<int>.Failure("An error occurred during Hot Path status update.");
            }
        }

        public async Task<ServiceResult<IEnumerable<Guid>>> TriggerContextRefreshJobsAsync(int expiryThresholdMinutes = 5, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Finding contexts that need refresh within the next {ExpiryThresholdMinutes} minutes.", expiryThresholdMinutes);
            try
            {
                var timeWindow = TimeSpan.FromMinutes(expiryThresholdMinutes);
                var contextsToRefresh = await _contextRepository.GetContextsNeedingRefreshAsync(timeWindow, cancellationToken);
                var contextIds = contextsToRefresh.Select(c => c.Id).ToList();

                _logger.LogInformation("Found {ContextCount} contexts that need to be refreshed.", contextIds.Count);
                
                // TODO: 여기서 실제 잡 큐(Hangfire, RabbitMQ 등)에 작업을 등록하는 로직이 추가될 수 있습니다.
                
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

        public async Task<ServiceResult<(bool IsValid, string? ErrorMessage)>> ValidateContextIntegrityAsync(Guid contextId, CancellationToken cancellationToken = default)
        {
            if (contextId == Guid.Empty)
                return ServiceResult<(bool, string?)>.Failure("ContextId cannot be empty.");

            _logger.LogDebug("Validating integrity for context: {ContextId}", contextId);
            try
            {
                var result = await _contextRepository.ValidateContextIntegrityAsync(contextId, cancellationToken);
                return ServiceResult<(bool, string?)>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating integrity for context: {ContextId}", contextId);
                return ServiceResult<(bool, string?)>.Failure("An error occurred during integrity validation.");
            }
        }

        public async Task<ServiceResult<string>> RecalculateChecksumAsync(Guid contextId, CancellationToken cancellationToken = default)
        {
            if (contextId == Guid.Empty)
                return ServiceResult<string>.Failure("ContextId cannot be empty.");

            _logger.LogInformation("Recalculating checksum for context: {ContextId}", contextId);
            try
            {
                var newChecksum = await _contextRepository.RecalculateChecksumAsync(contextId, cancellationToken);
                 if (newChecksum == null)
                    return ServiceResult<string>.NotFound("Context not found.");

                await _unitOfWork.SaveChangesAsync(cancellationToken);
                
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

        public async Task<ServiceResult<string>> ExportContextsAsync(Guid connectedId, CancellationToken cancellationToken = default)
        {
            if (connectedId == Guid.Empty)
                return ServiceResult<string>.Failure("ConnectedId cannot be empty.");

            _logger.LogInformation("Exporting contexts for ConnectedId: {ConnectedId}", connectedId);
            try
            {
                var jsonData = await _contextRepository.ExportContextsAsJsonAsync(connectedId, cancellationToken);
                return ServiceResult<string>.Success(jsonData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export contexts for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult<string>.Failure("An error occurred during context export.");
            }
        }

        public async Task<ServiceResult<int>> ImportContextsAsync(string jsonData, bool overwrite, Guid importedBy, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(jsonData))
                return ServiceResult<int>.Failure("JSON data cannot be empty.");

            _logger.LogInformation("Importing contexts from JSON data. Overwrite mode: {Overwrite}. Imported by: {ImportedBy}", overwrite, importedBy);
            try
            {
                var importedCount = await _contextRepository.ImportContextsFromJsonAsync(jsonData, overwrite, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Create,
                    action: "Contexts.Imported",
                    connectedId: importedBy,
                    success: true,
                    resourceType: "System",
                    metadata: new Dictionary<string, object> { { "ImportedCount", importedCount }, { "Overwrite", overwrite } },
                    cancellationToken: cancellationToken
                );

                _logger.LogInformation("Successfully imported {ImportedCount} contexts.", importedCount);
                return ServiceResult<int>.Success(importedCount);
            }
            catch (JsonException jsonEx)
            {
                _logger.LogError(jsonEx, "Failed to import contexts due to invalid JSON format.");
                return ServiceResult<int>.Failure("Invalid JSON format.");
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

