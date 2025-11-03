// 파일 경로: AuthHive.Auth/Validator/SessionValidator.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading; // CancellationToken
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth; // SessionEnums
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Business.Platform.Service; // IPlanService (IPlanRestrictionService로 대체 고려)
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Base; // IUnitOfWork, IConnectedIdContext
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService
// ✨ 분리된 모델 및 Enum 네임스페이스 추가
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Auth.Security;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Audit; // AuditEvent (Class)
using AuthHive.Core.Models.Audit.Common; // ComplianceStatus
using AuthHive.Core.Enums.Infra.Security; // RiskLevel, ThreatType
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult; // IValidator용
// ✨ PricingConstants 사용
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Auth.Service;
using static AuthHive.Core.Enums.Infra.Monitoring.ThreatAssessmentEnums;
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Infra.Security.SecurityEnums;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Models;

namespace AuthHive.Auth.Validator
{
    public class SessionValidator : ISessionValidator
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        // TODO: IPlanService 대신 IPlanRestrictionService 사용 고려
        private readonly IPlanService _planService;
        private readonly IAuditService _auditService;
        private readonly ILogger<SessionValidator> _logger;
        private readonly IDateTimeProvider _dateTimeProvider; 
        private readonly IPlanRestrictionService _planRestrictionService; // ✅ 추가

        public SessionValidator(
            ISessionRepository sessionRepository,
            IConnectedIdRepository connectedIdRepository,
            IPlanService planService,
            IAuditService auditService,
            ILogger<SessionValidator> logger,
            IDateTimeProvider dateTimeProvider, // ✅ 주입
            IPlanRestrictionService planRestrictionService // ✅ 주입
            )
        {
            _sessionRepository = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _planService = planService ?? throw new ArgumentNullException(nameof(planService));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _planRestrictionService = planRestrictionService ?? throw new ArgumentNullException(nameof(planRestrictionService));
        }

        #region IValidator<SessionEntity> Implementation (CancellationToken 추가)

        public Task<ValidationResult> ValidateCreateAsync(SessionEntity entity, CancellationToken cancellationToken = default)
        {
            var result = ValidationResult.Success();
            if (entity.UserId == Guid.Empty)
                result.AddError(nameof(entity.UserId), "UserId is required.", "USER_ID_REQUIRED");
            if (entity.ExpiresAt <= _dateTimeProvider.UtcNow) // ✅ 수정
                result.AddError(nameof(entity.ExpiresAt), "Expiration date must be in the future.", "EXPIRATION_IN_PAST");
            
            return Task.FromResult(result);
        }

        public Task<ValidationResult> ValidateUpdateAsync(SessionEntity entity, SessionEntity? existingEntity = null, CancellationToken cancellationToken = default)
        {
            var result = ValidationResult.Success();
            if (existingEntity != null)
            {
                if (entity.UserId != existingEntity.UserId)
                    result.AddError(nameof(entity.UserId), "UserId cannot be changed after session creation.", "USER_ID_IMMUTABLE");
                if (entity.SessionType != existingEntity.SessionType)
                    result.AddError(nameof(entity.SessionType), "SessionType cannot be changed.", "SESSION_TYPE_IMMUTABLE");
            }
            return Task.FromResult(result);
        }

        public Task<ValidationResult> ValidateDeleteAsync(SessionEntity entity, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ValidationResult.Success());
        }

        #endregion

        #region ISessionValidator Implementation (CancellationToken 추가)

        // ValidateCreateAsync(CreateSessionRequest...)
        public async Task<ServiceResult> ValidateCreateAsync(CreateSessionRequest request, Guid connectedId, CancellationToken cancellationToken = default)
        {
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken); // ✅ Token 전달
            if (connectedIdEntity == null || !connectedIdEntity.IsActive)
            {
                return ServiceResult.Failure("User connection is not active.", "CONNECTION_INACTIVE");
            }

            var sessionLimitResult = await ValidateSessionLimitAsync(connectedId, request.SessionType, cancellationToken); // ✅ Token 전달
            if (!sessionLimitResult.IsSuccess || (sessionLimitResult.Data != null && !sessionLimitResult.Data.IsAllowed))
            {
              
                return ServiceResult.Failure("Session limit exceeded.", ServiceErrorReason.PlanRestriction); // ✅ ErrorCode 사용
            }

            _logger.LogInformation("Session creation validation passed for ConnectedId: {ConnectedId}", connectedId);
            return ServiceResult.Success();
        }

        // ValidateDeviceTrustAsync (Enum 수정)
        public Task<ServiceResult<SessionEnums.DeviceTrustLevel>> ValidateDeviceTrustAsync(string deviceFingerprint, string userAgent, Guid connectedId, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Device trust validation for ConnectedId: {ConnectedId}. Returning 'Known' as default.", connectedId);
            // TODO: 실제 디바이스 신뢰도 검증 로직 (TrustedDeviceRepository 사용)
            return Task.FromResult(ServiceResult<SessionEnums.DeviceTrustLevel>.Success(SessionEnums.DeviceTrustLevel.Trusted)); // ✅ 수정
        }

        // ValidateSessionAsync
        public async Task<ServiceResult> ValidateSessionAsync(Guid sessionId, string currentIp, string? userAgent = null, CancellationToken cancellationToken = default)
        {
            var session = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken); // ✅ Token 전달

            if (session == null)
                return ServiceResult.Failure("Session not found.", ServiceErrorReason.NotFound);
            if (session.Status != SessionEnums.SessionStatus.Active) // ✅ 수정
                return ServiceResult.Failure($"Session is not active. Status: {session.Status}", "SESSION_INACTIVE");
            if (session.ExpiresAt <= _dateTimeProvider.UtcNow) // ✅ 수정
                return ServiceResult.Failure("Session has expired.", "SESSION_EXPIRED");
            
            // TODO: IP, UserAgent 변경 감지 로직 (보안 강화)

            return ServiceResult.Success();
        }

        // ValidateRefreshAsync
        public Task<ServiceResult> ValidateRefreshAsync(Guid sessionId, string refreshToken, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateRefreshAsync is not fully implemented.");
            // TODO: RefreshTokenRepository/ITokenService를 통해 리프레시 토큰 유효성 검증
            return Task.FromResult(ServiceResult.Success());
        }

        // AnalyzeActivityPatternAsync
        public Task<ServiceResult<ActivityAnalysis>> AnalyzeActivityPatternAsync(Guid sessionId, TimeSpan window, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("AnalyzeActivityPatternAsync is not fully implemented.");
            // TODO: ISessionActivityLogRepository에서 로그 조회 및 분석 (별도 Risk/Security 서비스 위임 권장)
            var analysis = new ActivityAnalysis { IsNormal = true };
            return Task.FromResult(ServiceResult<ActivityAnalysis>.Success(analysis));
        }

        // ValidateTerminationAsync (Enum 수정)
        public Task<ServiceResult> ValidateTerminationAsync(Guid sessionId, SessionEnums.SessionEndReason reason, Guid? terminatedBy = null, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Validating termination for session {SessionId} with reason: {Reason}", sessionId, reason);
            // TODO: 종료 권한 검증 (예: terminatedBy가 sessionId의 소유자 또는 관리자인지)
            return Task.FromResult(ServiceResult.Success());
        }

        // ValidateBulkTerminationAsync (Enum 수정)
        public Task<ServiceResult> ValidateBulkTerminationAsync(List<Guid> sessionIds, SessionEnums.SessionEndReason reason, Guid terminatedBy, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateBulkTerminationAsync is not fully implemented.");
            // TODO: 대량 종료 권한 검증
            return Task.FromResult(ServiceResult.Success());
        }

        // ValidateSessionLimitAsync (Enum 수정, PricingConstants 사용)
        public async Task<ServiceResult<SessionLimitAction>> ValidateSessionLimitAsync(Guid connectedId, SessionEnums.SessionType sessionType, CancellationToken cancellationToken = default)
        {
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
            if (connectedIdEntity?.OrganizationId == null)
                return ServiceResult<SessionLimitAction>.Failure("Organization context is required to check session limits.", "ORG_CONTEXT_REQUIRED");

            // TODO: IPlanService 대신 IPlanRestrictionService 또는 PricingConstants 직접 사용
            // var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(connectedIdEntity.OrganizationId, cancellationToken);
            // var planKey = subscription?.PlanKey ?? PricingConstants.DefaultPlanKey;
            // var planKey = PricingConstants.DefaultPlanKey; // 임시

            // TODO: 세션 제한은 PricingConstants에 없음. [AuthConstants.Session] 사용
            var limit = AuthConstants.Session.MaxConcurrentGlobalSessions; // 임시 값
          

            var activeSessions = await _sessionRepository.GetActiveSessionsAsync(connectedId, cancellationToken); // ✅ Token 전달
            
            if (activeSessions.Count() >= limit)
            {
              
                var action = new SessionLimitAction { IsAllowed = false, Action = "Block" }; // 정책에 따라 "ReplaceOldest" 등
                return ServiceResult<SessionLimitAction>.Success(action);
            }

            return ServiceResult<SessionLimitAction>.Success(new SessionLimitAction { IsAllowed = true });
        }

        // ValidateCrossDeviceSessionAsync
        public Task<ServiceResult> ValidateCrossDeviceSessionAsync(Guid connectedId, List<Guid> sessionIds, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateCrossDeviceSessionAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        // DetectSessionHijackingAsync
        public Task<ServiceResult<ThreatDetection>> DetectSessionHijackingAsync(Guid sessionId, SessionContext context, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetectSessionHijackingAsync is not fully implemented.");
            // TODO: ISessionSecurityService 위임
            var detection = new ThreatDetection { ThreatDetected = false, Type = ThreatType.None };
            return Task.FromResult(ServiceResult<ThreatDetection>.Success(detection));
        }

        // DetectAutomationAsync
        public Task<ServiceResult<BotDetection>> DetectAutomationAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetectAutomationAsync is not fully implemented.");
            // TODO: ISecurityService 또는 IRiskAssessmentService 위임
            var detection = new BotDetection { IsBot = false };
            return Task.FromResult(ServiceResult<BotDetection>.Success(detection));
        }

        // DetectPrivilegeEscalationAsync
        public Task<ServiceResult> DetectPrivilegeEscalationAsync(Guid sessionId, string attemptedAction, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetectPrivilegeEscalationAsync is not fully implemented.");
            // TODO: IAuditService/IAuthorizationService와 연계
            return Task.FromResult(ServiceResult.Success());
        }

        // DetermineAuthRequirementAsync
        public Task<ServiceResult<AuthenticationRequirement>> DetermineAuthRequirementAsync(Guid sessionId, RiskScore riskScore, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetermineAuthRequirementAsync is not fully implemented.");
            // TODO: IRiskAssessmentService/IPolicyService 위임
            var requirement = new AuthenticationRequirement { RequiresReauth = false };
            if (riskScore.Level >= RiskLevel.High) {
                requirement.RequiresReauth = true;
                requirement.Method = "MFA"; // 예시
            }
            return Task.FromResult(ServiceResult<AuthenticationRequirement>.Success(requirement));
        }

        // CalculateDynamicTimeoutAsync
        public Task<ServiceResult<TimeSpan>> CalculateDynamicTimeoutAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("CalculateDynamicTimeoutAsync is not fully implemented.");
            // TODO: IPolicyService 위임 (사용자 역할, 디바이스 신뢰도 등 기반)
            var timeout = TimeSpan.FromHours(2);
            return Task.FromResult(ServiceResult<TimeSpan>.Success(timeout));
        }

        // ValidateComplianceAsync
        public Task<ServiceResult<ComplianceStatus>> ValidateComplianceAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateComplianceAsync is not fully implemented.");
            // TODO: IComplianceService 위임
            var status = new ComplianceStatus { IsCompliant = true };
            return Task.FromResult(ServiceResult<ComplianceStatus>.Success(status));
        }

        // ValidateAuditTrailAsync
        public Task<ServiceResult> ValidateAuditTrailAsync(Guid sessionId, AuditLogResponse auditEvent, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateAuditTrailAsync is not fully implemented.");
            // TODO: IAuditService와 연계
            return Task.FromResult(ServiceResult.Success());
        }

        #endregion
    }
}