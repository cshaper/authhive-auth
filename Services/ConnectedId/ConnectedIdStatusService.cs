using System;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// ConnectedId의 상태(활성, 비활성, 정지 등) 관리 비즈니스 로직을 구현합니다.
    /// </summary>
    public class ConnectedIdStatusService : IConnectedIdStatusService
    {
        private readonly IConnectedIdRepository _repository;
        private readonly ILogger<ConnectedIdStatusService> _logger;

        public ConnectedIdStatusService(
            IConnectedIdRepository repository,
            ILogger<ConnectedIdStatusService> logger)
        {
            _repository = repository;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 🚨 수정: 첫 번째 인수로 null을 전달하여 predicate를 생략하고,
                // CancellationToken을 두 번째 인수로 올바르게 전달합니다.
                return await _repository.CountAsync(null, cancellationToken) >= 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConnectedIdStatusService health check failed.");
                return false;
            }
        }
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("ConnectedIdStatusService initialized.");
            return Task.CompletedTask;
        }

        #endregion


        #region Status Management

        public async Task<ServiceResult<StatusChangeResponse>> ChangeStatusAsync(Guid id, ChangeConnectedIdStatusRequest request)
        {
            try
            {
                var connectedId = await _repository.GetByIdAsync(id);
                if (connectedId == null)
                {
                    return ServiceResult<StatusChangeResponse>.Failure("ConnectedId not found");
                }

                var oldStatus = connectedId.Status;
                if (oldStatus == request.NewStatus)
                {
                    var noChangeResponse = new StatusChangeResponse
                    {
                        ConnectedId = id,
                        PreviousStatus = oldStatus,
                        CurrentStatus = request.NewStatus,
                        ChangedAt = connectedId.UpdatedAt ?? DateTime.UtcNow,
                        Reason = "Status is already the same."
                    };
                    return ServiceResult<StatusChangeResponse>.Success(noChangeResponse);
                }

                connectedId.Status = request.NewStatus;
                await _repository.UpdateAsync(connectedId);
                _logger.LogInformation("Status of ConnectedId {ConnectedId} changed from {OldStatus} to {NewStatus}. Reason: {Reason}",
                    id, oldStatus, request.NewStatus, request.Reason);

                var response = new StatusChangeResponse
                {
                    ConnectedId = id,
                    PreviousStatus = oldStatus,
                    CurrentStatus = request.NewStatus,
                    ChangedAt = DateTime.UtcNow,
                    Reason = request.Reason
                };
                return ServiceResult<StatusChangeResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change status for ConnectedId {ConnectedId}", id);
                return ServiceResult<StatusChangeResponse>.Failure("An error occurred while changing status.");
            }
        }

        public async Task<ServiceResult> ActivateAsync(Guid id)
        {
            var result = await ChangeStatusAsync(id, new ChangeConnectedIdStatusRequest
            {
                NewStatus = ConnectedIdStatus.Active,
                Reason = "Activated by system request."
            });

            return result.IsSuccess
                ? ServiceResult.Success("ConnectedId activated")
                : ServiceResult.Failure(result.ErrorMessage ?? "Failed to activate ConnectedId.");
        }

        public async Task<ServiceResult> DeactivateAsync(Guid id)
        {
            var result = await ChangeStatusAsync(id, new ChangeConnectedIdStatusRequest
            {
                NewStatus = ConnectedIdStatus.Inactive,
                Reason = "Deactivated by system request."
            });
            // ✨ [수정] null 병합 연산자(??)를 사용하여 null 가능성을 제거합니다.
            return result.IsSuccess
                ? ServiceResult.Success("ConnectedId deactivated")
                : ServiceResult.Failure(result.ErrorMessage ?? "Failed to deactivate ConnectedId.");
        }

        public async Task<ServiceResult> SuspendAsync(Guid id, string reason)
        {
            var result = await ChangeStatusAsync(id, new ChangeConnectedIdStatusRequest
            {
                NewStatus = ConnectedIdStatus.Suspended,
                Reason = reason
            });
            // ✨ [수정] null 병합 연산자(??)를 사용하여 null 가능성을 제거합니다.
            return result.IsSuccess
                ? ServiceResult.Success("ConnectedId suspended")
                : ServiceResult.Failure(result.ErrorMessage ?? "Failed to suspend ConnectedId.");
        }

        public async Task<ServiceResult<int>> CleanupInactiveAsync(Guid organizationId, DateTime inactiveSince, CancellationToken cancellationToken = default)
        {
            try
            {
                var inactiveList = await _repository.GetInactiveConnectedIdsAsync(organizationId, inactiveSince, cancellationToken);
                int count = 0;
                // TODO: 일괄 업데이트(Bulk Update)로 성능 최적화 필요
                foreach (var connectedId in inactiveList)
                {
                    connectedId.Status = ConnectedIdStatus.Inactive;
                    await _repository.UpdateAsync(connectedId);
                    count++;
                }

                if (count > 0)
                {
                    _logger.LogInformation("Cleaned up {Count} inactive ConnectedIds for organization {OrganizationId}", count, organizationId);
                }

                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup inactive ConnectedIds for organization {OrganizationId}", organizationId);
                return ServiceResult<int>.Failure("An error occurred during cleanup.");
            }
        }
        #endregion
    }
}