// File: AuthHive.Auth/Services/Handlers/User/Lifecycle/UserAccountRecoveredEventHandler.cs
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
    /// UserAccountRecoveredEvent를 처리하여 감사 로그를 남기고
    /// 보안을 위해 사용자의 모든 인증/세션 캐시를 무효화합니다.
    /// </summary>
    public class UserAccountRecoveredEventHandler : IDomainEventHandler<UserAccountRecoveredEvent>
    {
        private readonly ILogger<UserAccountRecoveredEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuthenticationCacheService _authenticationCacheService;

        public int Priority => 1;
        public bool IsEnabled => true;

        public UserAccountRecoveredEventHandler(
            ILogger<UserAccountRecoveredEventHandler> logger,
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
        /// 사용자 계정 복구 이벤트 처리
        /// </summary>
        public async Task HandleAsync(UserAccountRecoveredEvent @event, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation(
                "Processing UserAccountRecoveredEvent for UserId: {UserId}, Method: {Method}",
                @event.UserId, @event.RecoveryMethod);

            try
            {
                // 1. 감사 로그 기록 (트랜잭션)
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["RecoveredAt"] = @event.RecoveredAt,
                    ["RecoveryMethod"] = @event.RecoveryMethod,
                    // (보안) 토큰 값 자체를 기록하지 않고, 사용 여부만 기록
                    ["RecoveryTokenUsed"] = !string.IsNullOrEmpty(@event.RecoveryToken),
                    ["OrganizationId"] = @event.OrganizationId?.ToString() ?? "N/A",
                    ["ClientIpAddress"] = @event.ClientIpAddress ?? "N/A",
                    ["UserAgent"] = @event.UserAgent ?? "N/A",
                    ["Source"] = @event.Source
                };

                // 복구 주체(관리자)가 없으면(null), 복구한 사용자 본인을 주체로 기록
                Guid auditActorConnectedId = @event.RecoveredByConnectedId ?? @event.UserId;

                await _auditService.LogActionAsync(
                    AuditActionType.UserAccountRecovered, // "계정 복구" 감사 유형
                    "User Account Recovered",
                    auditActorConnectedId, // (non-nullable Guid)
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(), // 복구된 대상
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 2. 캐시 무효화 (필수)
                // 계정 복구(비밀번호 재설정 등)가 완료되면 기존 세션을 무효화해야 합니다.
                var cacheResult = await _authenticationCacheService.ClearAuthenticationCacheAsync(
                    @event.UserId
                );

                // (수정) IsSuccess 및 ErrorMessage 속성 사용
                if (!cacheResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to clear authentication cache for recovered user {UserId}. Reason: {Reason}",
                        @event.UserId, cacheResult.ErrorMessage);
                }

                _logger.LogInformation("Successfully processed UserAccountRecoveredEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountRecoveredEvent for UserId: {UserId}", @event.UserId);
                // throw; // 필요 시 재시도
            }
        }
    }
}