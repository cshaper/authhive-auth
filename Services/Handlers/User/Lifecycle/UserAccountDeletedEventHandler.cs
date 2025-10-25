// File: AuthHive.Auth/Services/Handlers/User/Lifecycle/UserAccountDeletedEventHandler.cs
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions; // (필요 시) 확장 메서드용
using AuthHive.Core.Enums.Core; // AuditActionType
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Service; // IAuthenticationCacheService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.User.Events.Lifecycle; // 처리할 이벤트
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// UserAccountDeletedEvent를 처리하여 감사 로그를 남기고 모든 관련 캐시를 삭제합니다.
    /// </summary>
    public class UserAccountDeletedEventHandler : IDomainEventHandler<UserAccountDeletedEvent>
    {
        private readonly ILogger<UserAccountDeletedEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuthenticationCacheService _authenticationCacheService;

        // 계정 삭제는 중요한 이벤트이므로 우선순위를 높게 설정할 수 있습니다. (예: 1)
        public int Priority => 1;
        public bool IsEnabled => true;

        public UserAccountDeletedEventHandler(
            ILogger<UserAccountDeletedEventHandler> logger,
            IAuditService auditService,
            IUnitOfWork unitOfWork,
            IAuthenticationCacheService authenticationCacheService)
        {
            _logger = logger;
            _auditService = auditService;
            _unitOfWork = unitOfWork;
            _authenticationCacheService = authenticationCacheService;
        }

        /// <summary>
        /// 사용자 계정 삭제 이벤트 처리
        /// </summary>
        public async Task HandleAsync(UserAccountDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation(
                "Processing UserAccountDeletedEvent for UserId: {UserId} (IsSoftDelete: {IsSoftDelete})",
                @event.UserId, @event.IsSoftDelete);

            try
            {
                // 1. 감사 로그 기록 (트랜잭션으로 묶음)
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["DeletedAt"] = @event.DeletedAt,
                    ["IsSoftDelete"] = @event.IsSoftDelete,
                    ["DataRetained"] = @event.DataRetained,
                    ["DeletionReason"] = @event.DeletionReason ?? "N/A",
                    ["RetentionDays"] = @event.RetentionDays?.ToString() ?? "N/A",
                    ["OrganizationId"] = @event.OrganizationId?.ToString() ?? "N/A",
                    ["Source"] = @event.Source
                };

                // (필요 시) @event.Metadata가 있다면 병합
                // auditMetadata.Merge(@event.Metadata);
                // 삭제 주체가 명확하지 않으면(null), 삭제된 사용자 본인(UserId)을 주체로 기록
                Guid auditActorConnectedId = @event.DeletedByConnectedId ?? @event.UserId;
                await _auditService.LogActionAsync(
                      AuditActionType.UserAccountDeleted, // "계정 삭제" 감사 유형
                      "User Account Deleted",
                      auditActorConnectedId, // (수정됨) Nullable이 아닌 Guid 전달
                      resourceType: "User",
                      resourceId: @event.UserId.ToString(), // 삭제된 대상
                      metadata: auditMetadata,
                      cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 2. 캐시 무효화 (가장 중요)
                // 계정이 삭제되었으므로, 이 사용자와 관련된 모든 인증/세션/프로필 캐시를 즉시 제거합니다.
                var cacheResult = await _authenticationCacheService.ClearAuthenticationCacheAsync(
                    @event.UserId
                );

                if (!cacheResult.IsSuccess)
                {
                    // 캐시 삭제 실패는 심각한 문제는 아니지만(만료됨), 경고 로그는 남깁니다.
                    _logger.LogWarning("Failed to clear authentication cache for deleted user {UserId}. Reason: {Reason}",
                        @event.UserId, cacheResult.ErrorMessage);
                }

                _logger.LogInformation("Successfully processed UserAccountDeletedEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountDeletedEvent for UserId: {UserId}", @event.UserId);
                // throw; // 필요 시 재시도
            }
        }
    }
}