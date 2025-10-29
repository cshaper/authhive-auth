// File: AuthHive.Auth/Services/Handlers/User/Profile/LogProfileDeletedAuditHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// ProfileDeletedEvent 발생 시 감사 로그를 기록합니다.
// (캐시 무효화는 InvalidateProfileCacheHandler가 별도로 처리)
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService
using AuthHive.Core.Models.User.Events.Profile; // The Event
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
 // 확장 메서드 사용

namespace AuthHive.Auth.Handlers.User.Profile
{
    /// <summary>
    /// (한글 주석) 사용자 프로필 삭제 시 감사 로그를 기록하는 핸들러입니다.
    /// </summary>
    public class LogProfileDeletedAuditHandler :
        IDomainEventHandler<ProfileDeletedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogProfileDeletedAuditHandler> _logger;

        // --- IDomainEventHandler 구현 ---
        public int Priority => 10; // 캐시 무효화 핸들러보다 먼저 실행될 수 있음 (순서 중요치 않다면 기본값)
        public bool IsEnabled => true;

        public LogProfileDeletedAuditHandler(
            IAuditService auditService,
            ILogger<LogProfileDeletedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 프로필 삭제 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(ProfileDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogWarning("Recording audit log for ProfileDeleted event. User: {UserId}, ProfileId: {ProfileId}, DeletedBy: {DeletedBy}",
                    @event.UserId, @event.ProfileId, @event.DeletedByConnectedId); // 삭제는 Warning 레벨로 로깅

                // (한글 주석) 감사 로그 메타데이터 준비
                var deleteData = new Dictionary<string, object>
                {
                    ["user_id"] = @event.UserId,
                    ["profile_id"] = @event.ProfileId,
                    ["deleted_at"] = @event.DeletedAt,
                    ["deleted_by"] = @event.DeletedByConnectedId
                };

                // (한글 주석) 필요 시 BaseEvent의 Metadata 병합 (확장 메서드 사용)
                deleteData.MergeMetadata(@event.Metadata, _logger);

                // (한글 주석) 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Delete, // 삭제 액션
                    "USER_PROFILE_DELETED",
                    @event.DeletedByConnectedId, // 행위자
                    resourceType: "UserProfile",
                    resourceId: @event.ProfileId.ToString(), // 삭제된 프로필 ID
                    metadata: deleteData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ProfileDeletedEvent: {EventId}", @event.EventId);
            }
        }

        #region IService Implementation
        // --- IService 구현 (InitializeAsync, IsHealthyAsync) ---
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
             _logger.LogInformation("LogProfileDeletedAuditHandler initialized.");
             return Task.CompletedTask;
        }

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             return Task.FromResult(IsEnabled); // AuditService 헬스 체크 구현 전까지 임시
        }
        #endregion
    }
}