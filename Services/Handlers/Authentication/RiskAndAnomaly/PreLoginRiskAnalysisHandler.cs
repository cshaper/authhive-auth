// File: AuthHive.Auth/Services/Handlers/Authentication/RiskAndAnomaly/PreLoginRiskAnalysisHandler.cs
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Security; // ❗️ [수정] IRiskAssessmentService 사용
using AuthHive.Core.Models.Auth.Authentication.Events; // PreLoginEvent
using AuthHive.Core.Models.Auth.Authentication.Requests; // AuthenticationRequest
using AuthHive.Core.Models.Auth.Authentication.Common; // DeviceInfo
using AuthHive.Core.Models.Infra.Security; // RiskEvent
using AuthHive.Core.Enums.Auth; // AuthenticationMethod
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq; // for RiskFactors select
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Session.Common;

namespace AuthHive.Auth.Handlers.Authentication.RiskAndAnomaly
{
    /// <summary>
    /// 로그인 시도 전(PreLogin) 이벤트를 받아 실시간 위험 분석을 수행하고,
    /// 그 결과를 RiskAssessmentService에 다시 기록하여 후속 조치를 트리거합니다.
    /// </summary>
    public class PreLoginRiskAnalysisHandler :
        IDomainEventHandler<PreLoginEvent>,
        IService
    {
        // ❗️ [수정] IRiskAnalysisService -> IRiskAssessmentService
        private readonly IRiskAssessmentService _riskAssessmentService; 
        private readonly ILogger<PreLoginRiskAnalysisHandler> _logger;
        // ❗️ [삭제] IEventBus (_riskAssessmentService.LogRiskEventAsync가 이벤트 발행 담당)

        public int Priority => 5; 
        public bool IsEnabled => true;

        public PreLoginRiskAnalysisHandler(
            // ❗️ [수정] riskAnalysisService -> riskAssessmentService
            IRiskAssessmentService riskAssessmentService,
            ILogger<PreLoginRiskAnalysisHandler> logger)
            // ❗️ [삭제] IEventBus eventBus
        {
            _riskAssessmentService = riskAssessmentService;
            _logger = logger;
        }

        public async Task HandleAsync(PreLoginEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. PreLoginEvent를 AuthenticationRequest DTO로 변환
                var authRequest = new AuthenticationRequest
                {
                    Username = @event.Username,
                    IpAddress = @event.IpAddress,
                    Method = ConvertToAuthMethod(@event.LoginMethod), 
                    DeviceInfo = new DeviceInfo 
                    {
                        DeviceId = @event.UserAgent ?? "unknown_ua", 
                        UserAgent = @event.UserAgent ?? string.Empty
                    } 
                };

                // 2. IRiskAssessmentService를 호출하여 위험도 "평가"
                var assessmentResult = await _riskAssessmentService.AssessAuthenticationRiskAsync(
                    authRequest, 
                    cancellationToken
                );

                if (!assessmentResult.IsSuccess || assessmentResult.Data == null)
                {
                    _logger.LogWarning(
                        "Risk assessment failed for Username {Username} from IP {IpAddress}.",
                        @event.Username, @event.IpAddress);
                    return;
                }

                var assessment = assessmentResult.Data;

                // 3. 평가 결과를 RiskEvent로 변환하여 "기록" 요청
                // (LogRiskEventAsync가 내부적으로 HighRiskAuthenticationEvent 발행 여부 결정)
                var riskEvent = new RiskEvent
                {
                    Id = @event.AggregateId, // PreLogin 시도 ID
                    EventType = "AuthenticationAttempt", // 위험 이벤트 타입
                    RiskScore = (int)(assessment.RiskScore * 100), // double(0.0~1.0) -> int(0~100)
                    UserId = null, // PreLogin 단계에서는 UserId를 알 수 없음
                    OccurredAt = @event.OccurredAt,
                    EventData = new Dictionary<string, object>
                    {
                        { "Username", @event.Username },
                        { "IpAddress", @event.IpAddress },
                        { "UserAgent", @event.UserAgent ?? "N/A" },
                        { "LoginMethod", @event.LoginMethod },
                        { "RiskLevel", assessment.RiskLevel.ToString() }, // Enum -> string
                        { "RequiresMfa", assessment.RequiresMfa },
                        { "RiskFactors", assessment.RiskFactors.Select(f => f.Name).ToList() },
                        // ❗️ [추가] LogRiskEventAsync에서 ConnectedId를 찾기 위한 정보 전달
                        // PreLogin 단계에서는 ConnectedId가 없으므로 null 전달
                        { "ConnectedId", (object?)null ?? DBNull.Value } 
                    }
                };

                // ❗️ [수정] _eventBus.PublishAsync 대신 _riskAssessmentService.LogRiskEventAsync 호출
                await _riskAssessmentService.LogRiskEventAsync(riskEvent, cancellationToken);
                
                // ❗️ [삭제] 기존 위험 이벤트 직접 발행 로직 제거
                /*
                if (!riskResult.IsSafe)
                { ... }
                */
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during pre-login risk analysis for {Username}: {EventId}", 
                    @event.Username, @event.EventId);
            }
        }

        // string을 AuthenticationMethod Enum으로 변환하는 헬퍼
        private AuthenticationMethod ConvertToAuthMethod(string method)
        {
            if (Enum.TryParse<AuthenticationMethod>(method, true, out var authMethod))
            {
                return authMethod;
            }
            if (method.StartsWith("Social", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticationMethod.SocialLogin;
            }
            return AuthenticationMethod.Other;
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(IsEnabled);
        #endregion
    }
}