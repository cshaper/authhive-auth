// File: AuthHive.Auth/Services/Handlers/Permission/LogPermissionModifiedAuditHandler.cs
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions.Events; // PermissionModifiedEvent
using AuthHive.Auth.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // For ToDictionary, string.Join
using System.Text.Json; // For serialization if needed
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Permission
{
    /// <summary>
    /// 권한 정의 수정 시 감사 로그를 기록합니다.
    /// </summary>
    public class LogPermissionModifiedAuditHandler :
        IDomainEventHandler<PermissionModifiedEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly ILogger<LogPermissionModifiedAuditHandler> _logger;

        public int Priority => 10; // 로깅 핸들러
        public bool IsEnabled => true;

        public LogPermissionModifiedAuditHandler(
            IAuditService auditService,
            ILogger<LogPermissionModifiedAuditHandler> logger)
        {
            _auditService = auditService;
            _logger = logger;
        }

        public async Task HandleAsync(PermissionModifiedEvent @event, CancellationToken cancellationToken = default)
        {
            var permissionId = @event.AggregateId; // PermissionId
            var initiator = @event.ModifiedByUserId; // 작업을 수행한 주체 (ConnectedId 가정)

            try
            {
                _logger.LogInformation(
                    "Recording audit log for PermissionModified event. PermissionId: {PermissionId}, Scope: {Scope}",
                    permissionId, @event.PermissionScope);

                // 변경 사항을 보기 쉬운 형식으로 변환 (예: "Name: 'Read Users' -> 'View Users'")
                var changesDescription = BuildChangeDescription(@event.OldValues, @event.NewValues);

                var auditData = new Dictionary<string, object>
                {
                    ["permission_id"] = permissionId,
                    ["permission_scope"] = @event.PermissionScope,
                    ["modified_by_user_id"] = initiator, // ConnectedId 가정
                    ["reason"] = @event.Reason ?? "N/A",
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["occurred_at"] = @event.OccurredAt,
                    ["severity"] = AuditEventSeverity.Info.ToString(),
                    ["changes_summary"] = changesDescription, // 변경 요약
                    // 상세 변경 내역 (필요시)
                    // ["old_values"] = @event.OldValues,
                    // ["new_values"] = @event.NewValues
                };
                auditData.MergeMetadata(@event.Metadata, _logger);

                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    "PERMISSION_DEFINITION_MODIFIED",
                    initiator,
                    success: true,
                    errorMessage: null,
                    resourceType: "PermissionDefinition",
                    resourceId: permissionId.ToString(),
                    metadata: auditData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit for PermissionModifiedEvent: {EventId}", @event.EventId);
            }
        }

        /// <summary>
        /// 변경 전/후 값을 비교하여 문자열 설명을 만듭니다.
        /// </summary>
        private string BuildChangeDescription(Dictionary<string, object?> oldValues, Dictionary<string, object?> newValues)
        {
            var changes = new List<string>();
            if (newValues == null) return "No changes detected.";

            foreach (var key in newValues.Keys)
            {
                var newValue = newValues[key];
                if (oldValues == null || !oldValues.TryGetValue(key, out var oldValue))
                {
                    changes.Add($"{key}: set to '{newValue}'");
                }
                else if (!Equals(oldValue, newValue))
                {
                    changes.Add($"{key}: changed from '{oldValue}' to '{newValue}'");
                }
            }
            // 이전 값에만 있던 속성 (삭제된 속성) 처리 (필요시)
            // if (oldValues != null) { ... }

            return changes.Any() ? string.Join("; ", changes) : "No effective changes detected.";
        }


        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}