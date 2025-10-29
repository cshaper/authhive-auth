// File: AuthHive.Auth/Services/Handlers/User/Lifecycle/UserAccountSuspendedEventHandler.cs
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
 // (필요 시) 확장 메서드용
using AuthHive.Core.Enums.Core; // AuditActionType
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Service; // IAuthenticationCacheService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.User.Events.Lifecycle; // 처리할 이벤트
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// UserAccountSuspendedEvent를 처리하여 감사 로그를 남기고
    /// 사용자의 모든 인증/세션 캐시를 즉시 무효화합니다. (액세스 차단)
    /// </summary>
    public class UserAccountSuspendedEventHandler : IDomainEventHandler<UserAccountSuspendedEvent>
    {
        private readonly ILogger<UserAccountSuspendedEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuthenticationCacheService _authenticationCacheService;

        // 계정 정지는 매우 높은 우선순위
        public int Priority => 1;
        public bool IsEnabled => true;

        public UserAccountSuspendedEventHandler(
            ILogger<UserAccountSuspendedEventHandler> logger,
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
        /// 사용자 계정 정지 이벤트 처리
        /// </summary>
        public async Task HandleAsync(UserAccountSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning(
                "Processing UserAccountSuspendedEvent for UserId: {UserId}, Reason: {Reason}, Type: {Type}",
                @event.UserId, @event.SuspensionReason, @event.SuspensionType);

            try
            {
                // 1. 감사 로그 기록 (트랜잭션)
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["SuspendedAt"] = @event.SuspendedAt,
                    ["SuspensionReason"] = @event.SuspensionReason,
                    ["SuspensionType"] = @event.SuspensionType,
                    ["SuspensionEndsAt"] = @event.SuspensionEndsAt?.ToString() ?? "N/A",
                    ["AppealProcess"] = @event.AppealProcess ?? "N/A",
                    ["OrganizationId"] = @event.OrganizationId?.ToString() ?? "N/A",
                    ["Source"] = @event.Source
                };
                
                // (필요 시) @event.Metadata가 있다면 병합
                // auditMetadata.Merge(@event.Metadata);

                // 정지를 수행한 주체(관리자)가 없으면(null), 정지된 사용자 본인을 주체로 기록
                Guid auditActorConnectedId = @event.SuspendedByConnectedId ?? @event.UserId;

                await _auditService.LogActionAsync(
                    AuditActionType.UserAccountSuspended, // "계정 정지" 감사 유형
                    "User Account Suspended",
                    auditActorConnectedId, // (non-nullable Guid)
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(), // 정지된 대상
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 2. 캐시 무효화 (필수)
                // 계정이 정지되어 즉시 액세스를 차단해야 하므로, 모든 관련 캐시를 제거합니다.
                var cacheResult = await _authenticationCacheService.ClearAuthenticationCacheAsync(
                    @event.UserId
                );

                // (수정) IsSuccess 및 ErrorMessage 속성 사용
                if (!cacheResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to clear authentication cache for suspended user {UserId}. Reason: {Reason}",
                        @event.UserId, cacheResult.ErrorMessage);
                }

                _logger.LogInformation("Successfully processed UserAccountSuspendedEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountSuspendedEvent for UserId: {UserId}", @event.UserId);
                // throw; // 필요 시 재시도
            }
        }
    }
}