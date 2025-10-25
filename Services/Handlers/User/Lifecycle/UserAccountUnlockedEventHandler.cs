// File: AuthHive.Auth/Services/Handlers/User/Lifecycle/UserAccountUnlockedEventHandler.cs
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core; // AuditActionType
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Service; // IAuthenticationCacheService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.User.Events.Lifecycle; // 처리할 이벤트
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// UserAccountUnlockedEvent를 처리하여 감사 로그를 남기고
    /// 사용자의 잠금 상태와 관련된 인증 캐시를 정리합니다.
    /// </summary>
    public class UserAccountUnlockedEventHandler : IDomainEventHandler<UserAccountUnlockedEvent>
    {
        private readonly ILogger<UserAccountUnlockedEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuthenticationCacheService _authenticationCacheService;

        public int Priority => 1;
        public bool IsEnabled => true;

        public UserAccountUnlockedEventHandler(
            ILogger<UserAccountUnlockedEventHandler> logger,
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
        /// 사용자 계정 잠금 해제 이벤트 처리
        /// </summary>
        public async Task HandleAsync(UserAccountUnlockedEvent @event, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation(
                "Processing UserAccountUnlockedEvent for UserId: {UserId}, Method: {Method}",
                @event.UserId, @event.UnlockMethod);

            try
            {
                // 1. 감사 로그 기록 (트랜잭션)
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["UnlockedAt"] = @event.UnlockedAt,
                    ["UnlockMethod"] = @event.UnlockMethod,
                    ["OrganizationId"] = @event.OrganizationId?.ToString() ?? "N/A",
                    ["Source"] = @event.Source,
                    ["ClientIpAddress"] = @event.ClientIpAddress ?? "N/A"
                };

                // 잠금 해제 주체(관리자, 시스템)가 없으면(null), 잠금 해제된 사용자 본인을 주체로 기록
                Guid auditActorConnectedId = @event.UnlockedByConnectedId ?? @event.UserId;

                await _auditService.LogActionAsync(
                    AuditActionType.UserAccountUnlocked, // "계정 잠금 해제" 감사 유형
                    "User Account Unlocked",
                    auditActorConnectedId, // (non-nullable Guid)
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(), // 잠금 해제된 대상
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 2. 캐시 무효화 (필수)
                // 계정 잠금이 해제되어 로그인 시도 횟수 등 관련 캐시를 초기화해야 합니다.
                var cacheResult = await _authenticationCacheService.ClearAuthenticationCacheAsync(
                    @event.UserId
                );

                // (수정) IsSuccess 및 ErrorMessage 속성 사용
                if (!cacheResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to clear authentication cache for unlocked user {UserId}. Reason: {Reason}",
                        @event.UserId, cacheResult.ErrorMessage);
                }

                _logger.LogInformation("Successfully processed UserAccountUnlockedEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountUnlockedEvent for UserId: {UserId}", @event.UserId);
                // throw; // 필요 시 재시도
            }
        }
    }
}