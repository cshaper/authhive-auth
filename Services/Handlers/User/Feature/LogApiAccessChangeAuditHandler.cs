// File: authhive.auth/services/handlers/User/Features/LogApiAccessChangeAuditHandler.cs
// ----------------------------------------------------------------------
// [Refactored Handler - 최종]
// ❗️ IDomainEventHandler와 IService를 구현합니다.
// 목적: API 접근 권한 변경 시, 감사 로그를 기록합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // ❗️ IDomainEventHandler
using AuthHive.Core.Models.User.Events.Features;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User.Features
{
    /// <summary>
    /// API 접근 권한 변경 시 감사 로그를 기록합니다. (IAuditService 사용)
    /// </summary>
    public class LogApiAccessChangeAuditHandler : 
        IDomainEventHandler<ApiAccessChangedEvent>, // ❗️ 수정됨
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogApiAccessChangeAuditHandler> _logger;

        // ❗️ IDomainEventHandler 계약 구현
        public int Priority => 10;
        public bool IsEnabled => true;

        public LogApiAccessChangeAuditHandler(
            IAuditService auditService,
            ILogger<LogApiAccessChangeAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) API 접근 권한 변경 이벤트를 처리하여 감사 로그를 기록합니다.
        /// </summary>
        public async Task HandleAsync(ApiAccessChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // (한글 주석) 관리자 권한, 삭제 권한 등 '중요 권한'이 변경될 때만 로그를 기록합니다.
                if (@event.AddedPermissions.Any(IsHighValuePermission) ||
                    @event.RemovedPermissions.Any(IsHighValuePermission))
                {
                    var metadata = new Dictionary<string, object>
                    {
                        ["added"] = @event.AddedPermissions,
                        ["removed"] = @event.RemovedPermissions,
                        ["current_count"] = @event.CurrentPermissions.Length
                    };

                    await _auditService.LogActionAsync(
                        AuditActionType.Update,
                        "API_ACCESS_CHANGED",
                        @event.ChangedByConnectedId ?? @event.UserId,
                        resourceId: @event.UserId.ToString(),
                        metadata: metadata);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for ApiAccessChangedEvent: {EventId}", @event.EventId);
            }
        }

        // (한글 주석) 감사 로그를 기록할 가치가 있는 중요 권한인지 판단합니다.
        private bool IsHighValuePermission(string permission)
        {
            var highValuePatterns = new[] { "admin", "delete", "export", "billing", "security", "audit" };
            var permLower = permission.ToLowerInvariant();
            return highValuePatterns.Any(pattern => permLower.Contains(pattern));
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}