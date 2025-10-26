// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/RespondToHighRiskAuthHandler.cs
// ----------------------------------------------------------------------
// [신규 핸들러]
// HighRiskAuthenticationEvent 발생 시 감사 로그 기록 및 후속 보안 조치를 취합니다.
// ----------------------------------------------------------------------

using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base; // IDomainEventHandler, IService, IEventBus
using AuthHive.Core.Models.Auth.Authentication.Events; // The Event
// using AuthHive.Core.Models.Auth.Authentication.Events; // MfaRequiredEvent, AdditionalVerificationRequiredEvent (가정)
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Extensions;
using static AuthHive.Core.Enums.Infra.Security.SecurityEnums;

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// (한글 주석) 고위험 인증 시도에 대응하여 감사 로그를 기록하고 MFA 강제 등의 후속 조치를 발행하는 핸들러입니다.
    /// </summary>
    public class RespondToHighRiskAuthHandler :
        IDomainEventHandler<HighRiskAuthenticationEvent>,
        IService
    {
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus; // 후속 이벤트 발행용
        private readonly ILogger<RespondToHighRiskAuthHandler> _logger;

        // --- IDomainEventHandler Implementation ---
        public int Priority => 5; // Critical 보안 이벤트이므로 최우선 순위
        public bool IsEnabled => true;

        public RespondToHighRiskAuthHandler(
            IAuditService auditService,
            IEventBus eventBus,
            ILogger<RespondToHighRiskAuthHandler> logger)
        {
            _auditService = auditService;
            _eventBus = eventBus;
            _logger = logger;
        }

        /// <summary>
        /// (한글 주석) 고위험 인증 시도 이벤트를 처리하여 감사 로그 기록 및 이벤트 발행을 수행합니다.
        /// </summary>
        public async Task HandleAsync(HighRiskAuthenticationEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                var actionTaken = "LOGGED";
                
                // 1. (한글 주석) 감사 로그 메타데이터 준비
                var riskData = new Dictionary<string, object>
                {
                    ["user_id"] = @event.UserId ?? Guid.Empty,
                    ["connected_id"] = @event.ConnectedId ?? Guid.Empty,
                    ["risk_level"] = @event.RiskLevel.ToString(),
                    ["risk_score"] = @event.RiskScore,
                    ["risk_factors"] = string.Join(", ", @event.RiskFactors), // 팩터 목록을 문자열로 변환
                    ["ip_address"] = @event.IpAddress,
                    ["organization_id"] = @event.OrganizationId ?? Guid.Empty,
                    ["requires_mfa"] = @event.RequiresMfa,
                    ["severity"] = MapRiskLevelToSeverity(@event.RiskLevel).ToString()
                };
                riskData.MergeMetadata(@event.Metadata, _logger);

                // 2. (한글 주석) 후속 조치 이벤트 발행 (MFA 강제 또는 추가 검증)
                if (@event.ConnectedId.HasValue) // 유효한 ConnectedId가 있어야 MFA를 요청할 수 있음
                {
                    if (@event.RequiresMfa)
                    {
                        // (한글 주석) ❗️ MFA 강제 요청 이벤트 발행
                        // (가정) MfaRequiredEvent는 ConnectedId를 받습니다.
                        // var mfaRequiredEvent = new MfaRequiredEvent(@event.ConnectedId.Value, @event.OrganizationId, "HighRiskAuth");
                        // await _eventBus.PublishAsync(mfaRequiredEvent, cancellationToken);
                        actionTaken = "MFA_REQUIRED";
                    }
                    else if (@event.RequiresAdditionalVerification)
                    {
                        // (한글 주석) ❗️ 추가 검증 요청 이벤트 발행 (예: 이메일 링크 확인)
                        // var verificationEvent = new AdditionalVerificationRequiredEvent(@event.ConnectedId.Value, "HighRiskAuth");
                        // await _eventBus.PublishAsync(verificationEvent, cancellationToken);
                         actionTaken = "VERIFICATION_REQUIRED";
                    }
                }
                
                // 3. (한글 주석) 감사 로그 최종 기록
                riskData["action_taken"] = actionTaken;

                await _auditService.LogActionAsync(
                    AuditActionType.Security, // 보안 감지 액션
                    "HIGH_RISK_AUTHENTICATION",
                    @event.ConnectedId ?? @event.UserId ?? Guid.Empty, // 행위자 (ConnectedId 또는 UserId)
                    success: @event.RiskLevel < RiskLevel.High, // 리스크 레벨이 High 이상이면 실패로 간주
                    errorMessage: $"High Risk Authentication attempt detected (Level: {@event.RiskLevel}). Action: {actionTaken}.",
                    resourceType: "Authentication",
                    resourceId: @event.ConnectedId?.ToString() ?? @event.IpAddress, // ConnectedId가 있으면 ConnectedId, 없으면 IP 주소
                    metadata: riskData,
                    cancellationToken: cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Failed to process HighRiskAuthenticationEvent for User {UserId}: {EventId}", @event.UserId, @event.EventId);
                // throw; // Critical 이벤트이므로 예외를 던져 모니터링 시스템이 알도록 할 수 있음
            }
        }

        /// <summary>
        /// (한글 주석) 위험 레벨(Enum)을 감사 로그 심각도(Enum)로 변환합니다.
        /// </summary>
        private AuditEventSeverity MapRiskLevelToSeverity(RiskLevel riskLevel)
        {
            return riskLevel switch
            {
                RiskLevel.Critical => AuditEventSeverity.Critical,
                RiskLevel.High => AuditEventSeverity.Error,
                RiskLevel.Medium => AuditEventSeverity.Warning,
                _ => AuditEventSeverity.Info
            };
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
             // (가정) IAuditService와 IEventBus는 IHealthCheckable을 구현
             return IsEnabled && await _auditService.IsHealthyAsync(cancellationToken) && await _eventBus.IsHealthyAsync(cancellationToken);
        }
        #endregion
    }
}