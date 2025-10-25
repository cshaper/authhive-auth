// File: AuthHive.Auth/Services/Handlers/User/Lifecycle/UserAccountActivatedEventHandler.cs
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
    /// UserAccountActivatedEvent를 처리하여 감사 로그를 남기고 캐시를 갱신합니다.
    /// </summary>
    public class UserAccountActivatedEventHandler : IDomainEventHandler<UserAccountActivatedEvent>
    {
        private readonly ILogger<UserAccountActivatedEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuthenticationCacheService _authenticationCacheService;

        public int Priority => 1;
        public bool IsEnabled => true;

        public UserAccountActivatedEventHandler(
            ILogger<UserAccountActivatedEventHandler> logger,
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
        /// 사용자 계정 활성화 이벤트 처리
        /// </summary>
        public async Task HandleAsync(UserAccountActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Processing UserAccountActivatedEvent for UserId: {UserId}, Method: {Method}",
                @event.UserId, @event.ActivationMethod);

            try
            {
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                // 감사 로그 메타데이터 구성
                var auditMetadata = new Dictionary<string, object>
                {
                    ["ActivationMethod"] = @event.ActivationMethod,
                    ["ActivatedAt"] = @event.ActivatedAt,
                    ["Source"] = @event.Source,
                    ["OrganizationId"] = @event.OrganizationId?.ToString() ?? "N/A"
                };
                
                // (필요 시) @event.Metadata가 있다면 병합
                // auditMetadata.Merge(@event.Metadata);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.UserAccountActivated, // "계정 활성화" 감사 유형
                    "User Account Activated",
                    // 활성화를 수행한 주체(관리자 등) 또는 본인
                    @event.ActivatedByConnectedId ?? @event.UserId, 
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 계정 상태가 변경되었으므로 관련 캐시 무효화
                var cacheResult = await _authenticationCacheService.ClearAuthenticationCacheAsync(
                    @event.UserId
                );

                if (!cacheResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to clear authentication cache for activated user {UserId}. Reason: {Reason}",
                        @event.UserId, cacheResult.ErrorMessage);
                }

                _logger.LogInformation("Successfully processed UserAccountActivatedEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountActivatedEvent for UserId: {UserId}", @event.UserId);
                // throw; // 필요 시 재시도
            }
        }
    }
}