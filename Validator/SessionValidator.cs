// [AuthHive.Auth] SessionValidator.cs
// v17 CQRS "본보기": 'ISessionValidator' (SOP 1.5)의 v17 구현체입니다.
// [v17.3 수정] v16 DTO(CS0246) 및 v17 불변 DTO 생성자(CS7036, CS0200) 오류를 "수정"합니다.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Session.Commands; // [CS0246] CreateSessionCommand
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Auth.Security.ReadModels; // [CS0246] SecurityRiskScoreReadModel
using AuthHive.Core.Models.Audit.Responses; // [CS0246] AuditLogResponse
using AuthHive.Core.Models.Auth.Session.ReadModels; // [CS0246] SessionActivityAnalysisReadModel
using AuthHive.Core.Models.Audit.ReadModels; // [CS0246] ComplianceStatusReadModel
using AuthHive.Core.Models.Auth.Security;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Enums.Infra.Security;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Auth.Service;
using static AuthHive.Core.Enums.Infra.Monitoring.ThreatAssessmentEnums; // [CS7036] ThreatType
using AuthHive.Core.Constants.Auth;
using static AuthHive.Core.Enums.Infra.Security.SecurityEnums;
using AuthHive.Core.Enums.Audit;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Models.Auth.ConnectedId.ReadModels;

namespace AuthHive.Auth.Validator
{
    /// <summary>
    /// [v17 수정] 세션 검증 구현체 (v17 "본보기" 적용)
    /// </summary>
    public class SessionValidator : ISessionValidator
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IPlanService _planService;
        private readonly IAuditService _auditService;
        private readonly ILogger<SessionValidator> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IPlanRestrictionService _planRestrictionService;

        public SessionValidator(
            ISessionRepository sessionRepository,
            IConnectedIdRepository connectedIdRepository,
            IPlanService planService,
            IAuditService auditService,
            ILogger<SessionValidator> logger,
            IDateTimeProvider dateTimeProvider,
            IPlanRestrictionService planRestrictionService)
        {
            _sessionRepository = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _planService = planService ?? throw new ArgumentNullException(nameof(planService));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _planRestrictionService = planRestrictionService ?? throw new ArgumentNullException(nameof(planRestrictionService));
        }

        #region IValidator<SessionEntity> Implementation

        public Task<ValidationResult> ValidateCreateAsync(SessionEntity entity, CancellationToken cancellationToken = default)
        {
            var result = ValidationResult.Success();
            if (entity.UserId == Guid.Empty)
                result.AddError(nameof(entity.UserId), "UserId is required.", "USER_ID_REQUIRED");
            if (entity.ExpiresAt <= _dateTimeProvider.UtcNow)
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

        #region ISessionValidator Implementation

        public async Task<ServiceResult> ValidateCreateAsync(CreateSessionCommand command, Guid connectedId, CancellationToken cancellationToken = default)
        {
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
            if (connectedIdEntity == null || !connectedIdEntity.IsActive)
            {
                return ServiceResult.Failure("User connection is not active.", "CONNECTION_INACTIVE");
            }

            var sessionLimitResult = await ValidateSessionLimitAsync(connectedId, command.SessionType, cancellationToken);
            if (!sessionLimitResult.IsSuccess || (sessionLimitResult.Data != null && !sessionLimitResult.Data.IsAllowed))
            {
                return ServiceResult.Failure("Session limit exceeded.", ServiceErrorReason.PlanRestriction);
            }

            _logger.LogInformation("Session creation validation passed for ConnectedId: {ConnectedId}", connectedId);
            return ServiceResult.Success();
        }

        // ValidateDeviceTrustAsync (Enum 수정)
        public Task<ServiceResult<SessionEnums.DeviceTrustLevel>> ValidateDeviceTrustAsync(string deviceFingerprint, string userAgent, Guid connectedId, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Device trust validation for ConnectedId: {ConnectedId}. Returning 'Trusted' as default.", connectedId);
            return Task.FromResult(ServiceResult<SessionEnums.DeviceTrustLevel>.Success(SessionEnums.DeviceTrustLevel.Trusted));
        }

        // ValidateSessionAsync
        public async Task<ServiceResult> ValidateSessionAsync(Guid sessionId, string currentIp, string? userAgent = null, CancellationToken cancellationToken = default)
        {
            var session = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken);

            if (session == null)
                return ServiceResult.Failure("Session not found.", ServiceErrorReason.NotFound);
            if (session.Status != SessionEnums.SessionStatus.Active)
                return ServiceResult.Failure($"Session is not active. Status: {session.Status}", "SESSION_INACTIVE");
            if (session.ExpiresAt <= _dateTimeProvider.UtcNow)
                return ServiceResult.Failure("Session has expired.", "SESSION_EXPIRED");

            return ServiceResult.Success();
        }

        // ValidateRefreshAsync
        public async Task<ServiceResult> ValidateRefreshAsync(Guid sessionId, string? refreshToken, CancellationToken cancellationToken = default)
        {
            // 시나리오 2: 토큰 재발급 (RefreshToken이 제공된 경우)
            if (!string.IsNullOrEmpty(refreshToken))
            {
                // TODO: RefreshToken 검증 로직 구현 (현재 v16에는 없음)
                // 예: var isValid = await _refreshTokenRepository.ValidateAsync(refreshToken, sessionId);
                // if (!isValid) return ServiceResult.Failure("Invalid refresh token.", "INVALID_REFRESH_TOKEN");

                _logger.LogWarning("ValidateRefreshAsync is not fully implemented for RefreshToken (Scenario 2)");
                // 임시로 성공 처리
                return ServiceResult.Success();
            }

            // 시나리오 1: 슬라이딩 세션 (RefreshToken이 없는 경우 - v16 로직 이관)
            // v16 SessionService.RefreshSessionAsync 로직 
            var session = await _sessionRepository.GetByIdAsync(sessionId, cancellationToken);

            if (session == null)
            {
                // (이 코드는 핸들러에서도 중복 검사하지만, Validator의 책임으로도 맞음)
                return ServiceResult.Failure($"Session {sessionId} not found", "SESSION_NOT_FOUND");
            }

            if (session.Status != SessionStatus.Active)
            {
                return ServiceResult.Failure($"Cannot refresh inactive session. Current status: {session.Status}", "SESSION_INACTIVE");
            }

            if (session.ExpiresAt < _dateTimeProvider.UtcNow)
            {
                return ServiceResult.Failure("Session has already expired", "SESSION_EXPIRED");
            }

            // 슬라이딩 세션(시나리오 1) 검증 통과
            return ServiceResult.Success();
        }

        // [v17 "본보기" 수정] AnalyzeActivityPatternAsync
        public Task<ServiceResult<SessionActivityAnalysisReadModel>> AnalyzeActivityPatternAsync(Guid sessionId, TimeSpan window, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("AnalyzeActivityPatternAsync is not fully implemented.");
            var analysis = new SessionActivityAnalysisReadModel(sessionId, window); // v17 DTO
            return Task.FromResult(ServiceResult<SessionActivityAnalysisReadModel>.Success(analysis));
        }

        // ValidateTerminationAsync (Enum 수정)
        public Task<ServiceResult> ValidateTerminationAsync(Guid sessionId, SessionEnums.SessionEndReason reason, Guid? terminatedBy = null, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Validating termination for session {SessionId} with reason: {Reason}", sessionId, reason);
            return Task.FromResult(ServiceResult.Success());
        }

        // ValidateBulkTerminationAsync (Enum 수정)
        public Task<ServiceResult> ValidateBulkTerminationAsync(List<Guid> sessionIds, SessionEnums.SessionEndReason reason, Guid terminatedBy, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateBulkTerminationAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        // ValidateSessionLimitAsync (Enum 수정, PricingConstants 사용)
        public async Task<ServiceResult<SessionLimitAction>> ValidateSessionLimitAsync(Guid connectedId, SessionEnums.SessionType sessionType, CancellationToken cancellationToken = default)
        {
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
            if (connectedIdEntity?.OrganizationId == null)
                return ServiceResult<SessionLimitAction>.Failure("Organization context is required to check session limits.", "ORG_CONTEXT_REQUIRED");

            var limit = AuthConstants.Session.MaxConcurrentGlobalSessions; // 임시 값

            var activeSessions = await _sessionRepository.GetActiveSessionsAsync(connectedId, cancellationToken);

            if (activeSessions.Count() >= limit)
            {
                // [v17 "본보기" 수정] CS7036/CS0200 오류 해결: 불변 DTO의 생성자 사용
                var action = new SessionLimitAction(isAllowed: false, action: "Block");
                return ServiceResult<SessionLimitAction>.Success(action);
            }

            return ServiceResult<SessionLimitAction>.Success(new SessionLimitAction(isAllowed: true, action: "Allow"));
        }

        // DetectSessionHijackingAsync
        public Task<ServiceResult<ThreatDetectionReadModel>> DetectSessionHijackingAsync(Guid sessionId, SessionContext context, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetectSessionHijackingAsync is not fully implemented.");
            // [v17 "본보기" 수정] CS7036 오류 해결: 불변 DTO의 생성자 사용
            var detection = new ThreatDetectionReadModel(
                threatDetected: false,
                type: ThreatType.None,
                confidence: 0.0,
                evidence: "N/A",
                recommendedAction: "None");
            return Task.FromResult(ServiceResult<ThreatDetectionReadModel>.Success(detection));
        }

        // DetectAutomationAsync
        public Task<ServiceResult<BotDetectionReadModel>> DetectAutomationAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetectAutomationAsync is not fully implemented.");

            // [v17 "본보기" 수정] CS7036/CS0200 오류 해결: 불변 DTO의 생성자 사용
            // v17 DTO 생성자 (v6.48): new BotDetectionReadModel(bool isBot, double probability, ...)
            var detection = new BotDetectionReadModel(
                isBot: false,
                probability: 0.0,
                indicators: null);

            return Task.FromResult(ServiceResult<BotDetectionReadModel>.Success(detection));
        }

        // DetectPrivilegeEscalationAsync
        public Task<ServiceResult> DetectPrivilegeEscalationAsync(Guid sessionId, string attemptedAction, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetectPrivilegeEscalationAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }


        public Task<ServiceResult<AuthenticationRequirement>> DetermineAuthRequirementAsync(
            Guid sessionId,
            RiskScoreReadModel riskScore, // [v17] v6.32에서 "확인"한 DTO
            CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("DetermineAuthRequirementAsync is not fully implemented.");

            // [v17 "본보기" 수정] CS7036/CS0200 오류 해결: 불변 DTO의 생성자 사용
            if (riskScore.RiskLevel >= RiskLevel.High)
            {
                // v17 DTO 생성자 (v6.48): new AuthenticationRequirement(bool requiresReauth, string method, ...)
                var requirement = new AuthenticationRequirement(
                    requiresReauth: true,
                    method: "MFA", // v16 '추론' 로직 이관
                    validFor: TimeSpan.FromMinutes(15) // (임시)
                );
                return Task.FromResult(ServiceResult<AuthenticationRequirement>.Success(requirement));
            }

            // 기본값 (인증 불필요)
            var defaultRequirement = new AuthenticationRequirement(
                requiresReauth: false,
                method: "None",
                validFor: null
            );
            return Task.FromResult(ServiceResult<AuthenticationRequirement>.Success(defaultRequirement));
        }
        // CalculateDynamicTimeoutAsync
        public Task<ServiceResult<TimeSpan>> CalculateDynamicTimeoutAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("CalculateDynamicTimeoutAsync is not fully implemented.");
            var timeout = TimeSpan.FromHours(2);
            return Task.FromResult(ServiceResult<TimeSpan>.Success(timeout));
        }

        // [v17 "본보기" 수정] ValidateComplianceAsync
        public Task<ServiceResult<ComplianceStatusReadModel>> ValidateComplianceAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateComplianceAsync is not fully implemented.");
            var status = new ComplianceStatusReadModel { IsCompliant = true };
            return Task.FromResult(ServiceResult<ComplianceStatusReadModel>.Success(status));
        }

        // [v17 "본보기" 수정] ValidateAuditTrailAsync
        public Task<ServiceResult> ValidateAuditTrailAsync(Guid sessionId, AuditLogResponse auditEvent, CancellationToken cancellationToken = default)
        {
            _logger.LogWarning("ValidateAuditTrailAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        #endregion
    }
}