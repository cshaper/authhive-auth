using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Validator;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Business.Platform.Service;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;

// --- 오류 수정을 위한 using 지시문 정리 ---
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult; // IValidator용
using DeviceTrustLevel = AuthHive.Core.Interfaces.Auth.Validator.DeviceTrustLevel; // ISessionValidator 내 정의된 enum
using SessionTerminationReason = AuthHive.Core.Interfaces.Auth.Validator.SessionTerminationReason; // ISessionValidator 내 정의된 enum
using static AuthHive.Core.Enums.Auth.SessionEnums; // SessionStatus 등 공용 enum

namespace AuthHive.Auth.Validator
{
    public class SessionValidator : ISessionValidator
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IPlanService _planService;
        private readonly IAuditService _auditService;
        private readonly ILogger<SessionValidator> _logger;

        public SessionValidator(
            ISessionRepository sessionRepository,
            IConnectedIdRepository connectedIdRepository,
            IPlanService planService,
            IAuditService auditService,
            ILogger<SessionValidator> logger)
        {
            _sessionRepository = sessionRepository;
            _connectedIdRepository = connectedIdRepository;
            _planService = planService;
            _auditService = auditService;
            _logger = logger;
        }

        #region IValidator<SessionEntity> Implementation

        public Task<ValidationResult> ValidateCreateAsync(SessionEntity entity)
        {
            var result = ValidationResult.Success();
            if (entity.UserId == Guid.Empty)
                result.AddError(nameof(entity.UserId), "UserId is required.", "USER_ID_REQUIRED");
            if (entity.ExpiresAt <= DateTime.UtcNow)
                result.AddError(nameof(entity.ExpiresAt), "Expiration date must be in the future.", "EXPIRATION_IN_PAST");
            
            return Task.FromResult(result);
        }

        public Task<ValidationResult> ValidateUpdateAsync(SessionEntity entity, SessionEntity? existingEntity = null)
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

        public Task<ValidationResult> ValidateDeleteAsync(SessionEntity entity)
        {
            return Task.FromResult(ValidationResult.Success());
        }

        #endregion

        #region ISessionValidator Implementation

        // [FIXED] 불필요한 명시적 구현을 제거하고 public으로 변경하여 구문 오류 해결
        public async Task<ServiceResult> ValidateCreateAsync(CreateSessionRequest request, Guid connectedId)
        {
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
            if (connectedIdEntity == null || !connectedIdEntity.IsActive)
            {
                return ServiceResult.Failure("User connection is not active.", "CONNECTION_INACTIVE");
            }

            var sessionLimitResult = await ValidateSessionLimitAsync(connectedId, request.SessionType);
            if (!sessionLimitResult.IsSuccess || (sessionLimitResult.Data != null && !sessionLimitResult.Data.IsAllowed))
            {
                return ServiceResult.Failure("Session limit exceeded.", "SESSION_LIMIT_EXCEEDED");
            }

            _logger.LogInformation("Session creation validation passed for ConnectedId: {ConnectedId}", connectedId);
            return ServiceResult.Success();
        }

        public Task<ServiceResult<DeviceTrustLevel>> ValidateDeviceTrustAsync(string deviceFingerprint, string userAgent, Guid connectedId)
        {
            _logger.LogInformation("Device trust validation for ConnectedId: {ConnectedId}. Returning 'Known' as default.", connectedId);
            return Task.FromResult(ServiceResult<DeviceTrustLevel>.Success(DeviceTrustLevel.Known));
        }

        public async Task<ServiceResult> ValidateSessionAsync(Guid sessionId, string currentIp, string? userAgent = null)
        {
            var session = await _sessionRepository.GetByIdAsync(sessionId);

            if (session == null)
                return ServiceResult.Failure("Session not found.", "SESSION_NOT_FOUND");
            if (session.Status != SessionStatus.Active)
                return ServiceResult.Failure($"Session is not active. Status: {session.Status}", "SESSION_INACTIVE");
            if (session.ExpiresAt <= DateTime.UtcNow)
                return ServiceResult.Failure("Session has expired.", "SESSION_EXPIRED");

            return ServiceResult.Success();
        }

        public Task<ServiceResult> ValidateRefreshAsync(Guid sessionId, string refreshToken)
        {
            _logger.LogWarning("ValidateRefreshAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult<ActivityAnalysis>> AnalyzeActivityPatternAsync(Guid sessionId, TimeSpan window)
        {
            _logger.LogWarning("AnalyzeActivityPatternAsync is not fully implemented.");
            var analysis = new ActivityAnalysis { IsNormal = true };
            return Task.FromResult(ServiceResult<ActivityAnalysis>.Success(analysis));
        }

        public Task<ServiceResult> ValidateTerminationAsync(Guid sessionId, SessionTerminationReason reason, Guid? terminatedBy = null)
        {
            _logger.LogInformation("Validating termination for session {SessionId} with reason: {Reason}", sessionId, reason);
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult> ValidateBulkTerminationAsync(List<Guid> sessionIds, SessionTerminationReason reason, Guid terminatedBy)
        {
            _logger.LogWarning("ValidateBulkTerminationAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<SessionLimitAction>> ValidateSessionLimitAsync(Guid connectedId, SessionType sessionType)
        {
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId); // 조직 정보는 PlanService에서 조회하므로 기본 GetByIdAsync 사용
            if (connectedIdEntity?.OrganizationId == null)
                return ServiceResult<SessionLimitAction>.Failure("Organization context is required to check session limits.", "ORG_CONTEXT_REQUIRED");

            var subscription = await _planService.GetCurrentSubscriptionForOrgAsync(connectedIdEntity.OrganizationId);
            var planKey = subscription?.PlanKey ?? "Free";

            var limit = planKey switch
            {
                "Enterprise" => 10,
                "Business" => 5,
                "Pro" => 3,
                _ => 1
            };
            
            // [FIXED] ISessionRepository에 정의된 정확한 메서드 이름으로 수정
            var activeSessions = await _sessionRepository.GetActiveSessionsAsync(connectedId);
            
            if (activeSessions.Count() >= limit)
            {
                var action = new SessionLimitAction { IsAllowed = false, Action = "Block" };
                return ServiceResult<SessionLimitAction>.Success(action);
            }

            return ServiceResult<SessionLimitAction>.Success(new SessionLimitAction { IsAllowed = true });
        }

        public Task<ServiceResult> ValidateCrossDeviceSessionAsync(Guid connectedId, List<Guid> sessionIds)
        {
            _logger.LogWarning("ValidateCrossDeviceSessionAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult<ThreatDetection>> DetectSessionHijackingAsync(Guid sessionId, SessionContext context)
        {
            _logger.LogWarning("DetectSessionHijackingAsync is not fully implemented.");
            var detection = new ThreatDetection { ThreatDetected = false, Type = ThreatType.None };
            return Task.FromResult(ServiceResult<ThreatDetection>.Success(detection));
        }

        public Task<ServiceResult<BotDetection>> DetectAutomationAsync(Guid sessionId, List<ApiCallPattern> patterns)
        {
            _logger.LogWarning("DetectAutomationAsync is not fully implemented.");
            var detection = new BotDetection { IsBot = false };
            return Task.FromResult(ServiceResult<BotDetection>.Success(detection));
        }

        public Task<ServiceResult> DetectPrivilegeEscalationAsync(Guid sessionId, string attemptedAction)
        {
            _logger.LogWarning("DetectPrivilegeEscalationAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult<AuthenticationRequirement>> DetermineAuthRequirementAsync(Guid sessionId, RiskScore riskScore)
        {
            _logger.LogWarning("DetermineAuthRequirementAsync is not fully implemented.");
            var requirement = new AuthenticationRequirement { RequiresReauth = false };
            return Task.FromResult(ServiceResult<AuthenticationRequirement>.Success(requirement));
        }

        public Task<ServiceResult<TimeSpan>> CalculateDynamicTimeoutAsync(Guid sessionId, SessionContext context)
        {
            _logger.LogWarning("CalculateDynamicTimeoutAsync is not fully implemented.");
            var timeout = TimeSpan.FromHours(2);
            return Task.FromResult(ServiceResult<TimeSpan>.Success(timeout));
        }

        public Task<ServiceResult<ComplianceStatus>> ValidateComplianceAsync(Guid organizationId, SessionPolicy policy)
        {
            _logger.LogWarning("ValidateComplianceAsync is not fully implemented.");
            var status = new ComplianceStatus { IsCompliant = true };
            return Task.FromResult(ServiceResult<ComplianceStatus>.Success(status));
        }

        public Task<ServiceResult> ValidateAuditTrailAsync(Guid sessionId, AuditEvent auditEvent)
        {
            _logger.LogWarning("ValidateAuditTrailAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        #endregion
    }
}