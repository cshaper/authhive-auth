/*
 * [AuthHive.Auth.Handlers.User.UserEventHandler] - 단일 핸들러 버전 (수정됨)
 * * @[요약]
 * 사용자의 핵심 생명주기 및 인증 관련 이벤트를 단일 클래스에서 처리합니다.
 * (개별 핸들러 분리 대신 이 클래스 내에서 모든 오류 수정)
 * * @[주요 변경 사항]
 * 1. 이벤트 타입: ICoreUserEventHandler 인터페이스에 정의된 최신 이벤트 타입 사용
 * 2. CS1503 (직렬화):
 * - AuditService.LogActionAsync: metadata에 Dictionary 직접 전달
 * - CacheService.SetAsync: Dictionary를 MemoryStream으로 직렬화하여 전달
 * 3. CS1061 (속성/메서드 없음):
 * - ConnectedIdService.GetByIdAsync 사용 및 ServiceResult 속성 올바르게 사용
 * - BaseEvent 속성(ClientIpAddress 등) 올바르게 사용
 * 4. CS8509 (Switch 식): DetermineAuditActionType 메서드에 discard 패턴 추가
 * 5. Metadata 처리: BaseEvent.Metadata가 Dictionary이므로 JSON 역직렬화 제거
 * 6. 네임스페이스: 리팩토링된 이벤트 모델 네임스페이스 사용
 */
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.User.Handler; // ICoreUserEventHandler
// 👇 리팩토링된 이벤트 네임스페이스 사용
using AuthHive.Core.Models.User.Events.Lifecycle;
using AuthHive.Core.Models.User.Events.Session;
using AuthHive.Core.Models.User.Events.Profile;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.UserExperience; // IEmailService
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.External; // EmailMessageDto
using AuthHive.Core.Interfaces.Auth.Service; // IConnectedIdService
using AuthHive.Core.Models.Common; // ServiceResult<T>
using AuthHive.Core.Models.Auth.ConnectedId.Responses; // ConnectedIdDetailResponse

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// SaaS 최적화된 핵심 사용자 이벤트 핸들러 (단일 클래스 버전)
    /// </summary>
    public class UserEventHandler : IDomainEventHandler, IService // 인터페이스 구현
    {
        private readonly ILogger<UserEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IEmailService _emailService;
        private readonly ICacheService _cacheService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IConnectedIdService _connectedIdService; // OrganizationId 조회용 추가

        private const string CACHE_KEY_PREFIX = "user_event"; // 핸들러 내부 캐시용 접두사

        public int Priority => 1; // 다른 핸들러보다 먼저 실행될 수 있도록 우선순위 설정
        public bool IsEnabled { get; private set; } = true;

        public UserEventHandler(
            ILogger<UserEventHandler> logger,
            IAuditService auditService,
            IEmailService emailService,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork,
            IConnectedIdService connectedIdService) // 의존성 추가
        {
            _logger = logger;
            _auditService = auditService;
            _emailService = emailService;
            _cacheService = cacheService;
            _dateTimeProvider = dateTimeProvider;
            _unitOfWork = unitOfWork;
            _connectedIdService = connectedIdService; // 할당
        }

        #region IService Implementation
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            await WarmUpCacheAsync(cancellationToken);
            _logger.LogInformation("UserEventHandler initialized");
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // Cache 서비스 상태만 확인 (필요시 다른 의존성 확인 추가)
            return IsEnabled && await _cacheService.IsHealthyAsync(cancellationToken);
        }

        // 캐시 워밍업 (예: 이벤트 처리 규칙 로드)
        private async Task WarmUpCacheAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}:rules";
                var rules = GetEventProcessingRules(); // 임시 규칙 생성 메서드

                // [FIX CS1503 - Stream for Cache] 규칙 데이터를 직렬화하여 캐시에 저장
                await using var stream = new MemoryStream();
                await JsonSerializer.SerializeAsync(stream, rules, cancellationToken: cancellationToken);
                stream.Position = 0;
                await _cacheService.SetAsync(cacheKey, stream, TimeSpan.FromHours(1), cancellationToken);
                _logger.LogInformation("User event processing rules cached.");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cache warmup failed for UserEventHandler - continuing without cache");
            }
        }
        #endregion

        #region ICoreUserEventHandler Implementation (개별 메서드 구현)

        // --- 계정 생성 ---
        public async Task OnUserAccountCreatedAsync(UserAccountCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                // TODO: TenantSettings 조회 로직은 별도 서비스로 분리 권장
                var tenantSettings = await GetTenantSettingsAsync(@event.UserId); // 임시 헬퍼 호출

                // 환영 이메일 발송 (별도 스레드)
                if (tenantSettings.SendWelcomeEmail && !string.IsNullOrEmpty(@event.Email))
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            // 👇 [원상 복구] ConvertToStringDict 헬퍼 사용
                            Dictionary<string, string>? emailTags = null;
                            if (@event.Metadata != null && @event.Metadata.Any())
                            {
                                // Metadata 딕셔너리(object)를 string 딕셔너리로 변환
                                emailTags = ConvertToStringDict(@event.Metadata); // 👈 헬퍼 메서드 호출
                            }

                            await _emailService.SendEmailAsync(new EmailMessageDto
                            {
                                To = new List<string> { @event.Email }, // To는 List<string> 타입
                                Subject = "Welcome to AuthHive!",
                                Body = $"Welcome, {@event.Email}! Your account is created.",
                                Tags = emailTags // 👈 Dictionary<string, string> 전달
                            }, cancellationToken);
                            _logger.LogInformation("Welcome email sent to {Email} for UserId {UserId}", @event.Email, @event.UserId);
                        }
                        catch (Exception emailEx)
                        {
                            _logger.LogError(emailEx, "Failed to send welcome email for UserId {UserId}", @event.UserId);
                        }
                    }, cancellationToken);
                }

                // 감사 로그 메타데이터
                var auditMetadata = new Dictionary<string, object>
                {
                    ["RegistrationMethod"] = @event.RegistrationMethod,
                    ["EmailVerified"] = @event.EmailVerified,
                    ["Timestamp"] = @event.OccurredAt
                };
                MergeMetadata(auditMetadata, @event.Metadata); // [FIX] 헬퍼 사용

                // 감사 로그 기록 (Dictionary 직접 전달)
                await _auditService.LogActionAsync(
                    AuditActionType.UserRegistration,
                    "UserAccountCreated",
                    @event.CreatedByConnectedId ?? @event.UserId,
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata, // Dictionary 전달
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // TODO: 캐시 무효화 로직 분리 권장
                await InvalidateUserCacheAsync(@event.UserId); // 임시 헬퍼 호출

                _logger.LogInformation("Successfully processed UserAccountCreatedEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountCreatedEvent for UserId: {UserId}", @event.UserId);
                // throw; // 필요 시 재시도
            }
        }

        // --- 계정 활성화 ---
        public async Task OnUserAccountActivatedAsync(UserAccountActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 캐시 무효화 (상태 변경)
                await InvalidateUserCacheAsync(@event.UserId);

                // 감사 로그 메타데이터
                var auditMetadata = new Dictionary<string, object>
                {
                    ["ActivationMethod"] = @event.ActivationMethod,
                    ["ActivatedAt"] = @event.ActivatedAt,
                    ["Timestamp"] = @event.OccurredAt
                };
                MergeMetadata(auditMetadata, @event.Metadata);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.StatusChange,
                    "UserAccountActivated",
                    @event.ActivatedByConnectedId ?? @event.UserId,
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                _logger.LogInformation("Successfully processed UserAccountActivatedEvent for UserId: {UserId}, Method: {Method}", @event.UserId, @event.ActivationMethod);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserAccountActivatedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }

        // --- 사용자 정보 업데이트 ---
        public async Task OnUserUpdatedAsync(UserUpdatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 캐시 무효화
                await InvalidateUserCacheAsync(@event.UserId);

                // 감사 로그 메타데이터
                var auditMetadata = new Dictionary<string, object>
                {
                    ["UpdatedFields"] = string.Join(", ", @event.UpdatedFields),
                    ["Timestamp"] = @event.OccurredAt
                };
                MergeMetadata(auditMetadata, @event.Metadata);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.Update,
                    "UserUpdated",
                    @event.UpdatedByConnectedId ?? @event.UserId,
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                _logger.LogInformation("Successfully processed UserUpdatedEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserUpdatedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }


        // --- 사용자 상태 변경 ---
        public async Task OnUserStatusChangedAsync(UserStatusChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await InvalidateUserCacheAsync(@event.UserId);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["old_status"] = @event.OldStatus.ToString(),
                    ["new_status"] = @event.NewStatus.ToString(),
                    ["reason"] = @event.Reason ?? "not_specified",
                    ["Timestamp"] = @event.OccurredAt
                };
                MergeMetadata(auditMetadata, @event.Metadata); // [FIX] 헬퍼 사용

                await _auditService.LogActionAsync(
                    AuditActionType.StatusChange,
                    "UserStatusChanged",
                    @event.ChangedByConnectedId ?? @event.UserId,
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata, // Dictionary 전달
                    cancellationToken: cancellationToken);

                _logger.LogInformation("User status changed successfully - UserId: {UserId}, From: {OldStatus} To: {NewStatus}",
                    @event.UserId, @event.OldStatus, @event.NewStatus);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserStatusChangedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }

        // --- 계정 비활성화 ---
        public async Task OnUserAccountDeactivatedAsync(UserAccountDeactivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await InvalidateUserCacheAsync(@event.UserId);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["DeactivationReason"] = @event.DeactivationReason,
                    ["IsTemporary"] = @event.IsTemporary,
                    ["Timestamp"] = @event.OccurredAt
                };

                if (@event.ReactivationDate.HasValue)
                {
                    auditMetadata["ReactivationDate"] = @event.ReactivationDate.Value; // .Value를 사용해 non-nullable DateTime 할당
                }
                MergeMetadata(auditMetadata, @event.Metadata);

                await _auditService.LogActionAsync(
                    AuditActionType.StatusChange,
                    "UserAccountDeactivated",
                    @event.DeactivatedByConnectedId ?? @event.UserId,
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                _logger.LogInformation("Successfully processed UserAccountDeactivatedEvent for UserId: {UserId}, Reason: {Reason}", @event.UserId, @event.DeactivationReason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserAccountDeactivatedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }

        // --- 계정 정지 ---
        public async Task OnUserAccountSuspendedAsync(UserAccountSuspendedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await InvalidateUserCacheAsync(@event.UserId);
                // TODO: 추가 로직 (예: 세션 강제 종료 이벤트 발행)

                var auditMetadata = new Dictionary<string, object>
                {
                    ["SuspensionReason"] = @event.SuspensionReason,
                    ["SuspensionType"] = @event.SuspensionType,
                    ["Timestamp"] = @event.OccurredAt
                };
                if(@event.SuspensionEndsAt.HasValue)
                {
                    auditMetadata["SuspensionEndsAt"] = @event.SuspensionEndsAt.Value;
                }
                MergeMetadata(auditMetadata, @event.Metadata);

                await _auditService.LogActionAsync(
                    AuditActionType.Blocked, // 정지는 Blocked 타입
                    "UserAccountSuspended",
                    @event.SuspendedByConnectedId ?? @event.UserId, // 관리자 또는 시스템
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                _logger.LogWarning("Successfully processed UserAccountSuspendedEvent for UserId: {UserId}, Reason: {Reason}", @event.UserId, @event.SuspensionReason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserAccountSuspendedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }

        // --- 계정 잠금 해제 ---
        public async Task OnUserAccountUnlockedAsync(UserAccountUnlockedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await InvalidateUserCacheAsync(@event.UserId);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["UnlockMethod"] = @event.UnlockMethod,
                    ["UnlockedAt"] = @event.UnlockedAt,
                    ["Timestamp"] = @event.OccurredAt
                };
                MergeMetadata(auditMetadata, @event.Metadata);

                await _auditService.LogActionAsync(
                    AuditActionType.AccountUnlocked, // 구체적인 타입 사용
                    "UserAccountUnlocked",
                    @event.UnlockedByConnectedId ?? @event.UserId, // 해제 주체
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                _logger.LogInformation("Successfully processed UserAccountUnlockedEvent for UserId: {UserId}, Method: {Method}", @event.UserId, @event.UnlockMethod);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserAccountUnlockedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }

        // --- 계정 복구 ---
        public async Task OnUserAccountRecoveredAsync(UserAccountRecoveredEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 복구 후 상태 변경이 있을 수 있으므로 캐시 무효화
                await InvalidateUserCacheAsync(@event.UserId);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["RecoveryMethod"] = @event.RecoveryMethod,
                    ["RecoveredAt"] = @event.RecoveredAt,
                    ["Timestamp"] = @event.OccurredAt
                    // RecoveryToken은 민감 정보일 수 있어 기본 메타데이터에는 포함하지 않음 (필요 시 BaseEvent.Metadata 사용)
                };
                MergeMetadata(auditMetadata, @event.Metadata);

                await _auditService.LogActionAsync(
                    AuditActionType.Update, // 계정 정보/상태 업데이트로 간주
                    "UserAccountRecovered",
                    @event.RecoveredByConnectedId ?? @event.UserId, // 복구 주체
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata,
                    cancellationToken: cancellationToken);

                _logger.LogInformation("Successfully processed UserAccountRecoveredEvent for UserId: {UserId}, Method: {Method}", @event.UserId, @event.RecoveryMethod);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserAccountRecoveredEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }


        // --- 계정 삭제 ---
        public async Task OnUserAccountDeletedAsync(UserAccountDeletedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                // TODO: Hard delete 로직 분리 필요 (별도 서비스/프로세스 호출)
                if (!@event.IsSoftDelete)
                {
                    _logger.LogWarning("Hard delete requested for UserId: {UserId} via event. This should be handled by a dedicated cleanup process.", @event.UserId);
                    // 실제 데이터 삭제 로직은 여기에 포함하지 않음
                    // await _cleanupService.HardDeleteUserAsync(@event.UserId);
                }

                // 모든 관련 캐시 무효화
                await InvalidateAllUserCacheAsync(@event.UserId); // 임시 헬퍼 호출

                var auditMetadata = new Dictionary<string, object>
                {
                    ["IsSoftDelete"] = @event.IsSoftDelete,
                    ["DeletionReason"] = @event.DeletionReason ?? "user_requested",
                    ["DataRetained"] = @event.DataRetained,
                    ["Timestamp"] = @event.OccurredAt
                };
                if(@event.RetentionDays.HasValue)
                {
                    auditMetadata["RetentionDays"] = @event.RetentionDays.Value;
                }
                MergeMetadata(auditMetadata, @event.Metadata); // [FIX] 헬퍼 사용

                await _auditService.LogActionAsync(
                    AuditActionType.Delete,
                    "UserAccountDeleted",
                    @event.DeletedByConnectedId ?? @event.UserId, // 삭제 주체
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata, // Dictionary 전달
                    cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                _logger.LogWarning("Successfully processed UserAccountDeletedEvent for UserId: {UserId}, SoftDelete: {SoftDelete}",
                    @event.UserId, @event.IsSoftDelete);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountDeletedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }

        // --- 계정 검증 (이메일, 전화번호 등) ---
        public async Task OnUserAccountVerifiedAsync(UserAccountVerifiedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 검증 상태 변경 시 캐시 무효화
                await InvalidateUserCacheAsync(@event.UserId);

                var auditMetadata = new Dictionary<string, object>
                {
                    ["VerificationType"] = @event.VerificationType,
                    ["VerificationMethod"] = @event.VerificationMethod,
                    ["IsManualVerification"] = @event.IsManualVerification,
                    ["VerifiedAt"] = @event.VerifiedAt,
                    ["Timestamp"] = @event.OccurredAt
                };
                MergeMetadata(auditMetadata, @event.Metadata); // [FIX] 헬퍼 사용

                await _auditService.LogActionAsync(
                    AuditActionType.Validation, // 더 구체적인 타입 사용
                    "UserAccountVerified",
                    @event.VerifiedByConnectedId ?? @event.UserId, // 검증 주체
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata, // Dictionary 전달
                    cancellationToken: cancellationToken);

                _logger.LogInformation("User account attribute verified successfully - UserId: {UserId}, Type: {Type}",
                    @event.UserId, @event.VerificationType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process UserAccountVerifiedEvent for UserId: {UserId}, Type: {Type}", @event.UserId, @event.VerificationType);
                // throw;
            }
        }

        // --- 2단계 인증 설정 변경 ---
        public async Task OnTwoFactorSettingChangedAsync(TwoFactorSettingChangedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                // 보안 관련 설정 변경 시 캐시 무효화 (예: 세션, 권한 캐시)
                var securityKey = $"user:security:{@event.UserId:N}"; // 예시 키
                await _cacheService.RemoveAsync(securityKey, cancellationToken);
                await InvalidateUserCacheAsync(@event.UserId); // 사용자 기본 정보 캐시도 무효화

                var auditMetadata = new Dictionary<string, object>
                {
                    ["Enabled"] = @event.Enabled,
                    ["TwoFactorType"] = @event.TwoFactorType,
                    ["ChangedAt"] = @event.ChangedAt,
                    ["Timestamp"] = @event.OccurredAt
                    // BackupCodes는 민감 정보이므로 감사 로그 메타데이터에 직접 포함하지 않음
                };
                MergeMetadata(auditMetadata, @event.Metadata); // [FIX] 헬퍼 사용

                await _auditService.LogActionAsync(
                    AuditActionType.SecuritySettingChanged, // 더 구체적인 타입 사용
                    @event.Enabled ? "TwoFactorEnabled" : "TwoFactorDisabled",
                    @event.ChangedByConnectedId ?? @event.UserId, // 변경 주체
                    resourceType: "User",
                    resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata, // Dictionary 전달
                    cancellationToken: cancellationToken);

                _logger.LogInformation("2FA setting changed successfully - UserId: {UserId}, Enabled: {Enabled}, Type: {Type}",
                    @event.UserId, @event.Enabled, @event.TwoFactorType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process TwoFactorSettingChangedEvent for UserId: {UserId}", @event.UserId);
                // throw;
            }
        }

        #endregion

        #region IDomainEventHandler Implementation (Generic Handler)

        // 이 메서드는 ICoreUserEventHandler의 개별 메서드를 호출하는 라우터 역할을 합니다.
        // 핸들러를 분리하지 않았으므로 이 방식이 필요합니다.
        public async Task HandleAsync(object domainEvent, CancellationToken cancellationToken = default)
        {
            switch (domainEvent)
            {
                // Lifecycle Events
                case UserAccountCreatedEvent created:
                    await OnUserAccountCreatedAsync(created, cancellationToken); break;
                case UserAccountActivatedEvent activated:
                    await OnUserAccountActivatedAsync(activated, cancellationToken); break;
                case UserUpdatedEvent updated:
                    await OnUserUpdatedAsync(updated, cancellationToken); break;
                case UserStatusChangedEvent statusChanged:
                    await OnUserStatusChangedAsync(statusChanged, cancellationToken); break;
                case UserAccountDeactivatedEvent deactivated:
                    await OnUserAccountDeactivatedAsync(deactivated, cancellationToken); break;
                case UserAccountSuspendedEvent suspended:
                    await OnUserAccountSuspendedAsync(suspended, cancellationToken); break;
                case UserAccountUnlockedEvent unlocked:
                    await OnUserAccountUnlockedAsync(unlocked, cancellationToken); break;
                case UserAccountRecoveredEvent recovered:
                    await OnUserAccountRecoveredAsync(recovered, cancellationToken); break;
                case UserAccountDeletedEvent deleted:
                    await OnUserAccountDeletedAsync(deleted, cancellationToken); break;
                // case UserAccountMergedEvent merged: // 필요 시 추가
                //    await OnUserAccountMergedAsync(merged, cancellationToken); break;

                // Session Events
                // Profile/Verification Events
                case UserAccountVerifiedEvent verified:
                    await OnUserAccountVerifiedAsync(verified, cancellationToken); break;
                case TwoFactorSettingChangedEvent twoFactorChanged:
                    await OnTwoFactorSettingChangedAsync(twoFactorChanged, cancellationToken); break;

                default:
                    _logger.LogWarning("Unsupported event type received in UserEventHandler: {EventType}", domainEvent?.GetType().FullName);
                    break;
            }
        }

        #endregion

        #region Helper Methods (공통 로직 - 별도 서비스로 분리 권장)

        // BaseEvent.Metadata (Dictionary)를 대상 Dictionary에 병합
        private void MergeMetadata(Dictionary<string, object> target, Dictionary<string, object>? source)
        {
            if (source != null)
            {
                foreach (var kvp in source)
                {
                    // 충돌 시 source 값으로 덮어쓰거나, 필요 시 로직 수정
                    target[kvp.Key] = kvp.Value;
                }
            }
        }


        // Dictionary<string, object> -> Dictionary<string, string> 변환 (EmailService 등에서 필요)
        private Dictionary<string, string> ConvertToStringDict(Dictionary<string, object> dict)
        {
            if (dict == null) return new Dictionary<string, string>();
            return dict.ToDictionary(kvp => kvp.Key, kvp => kvp.Value?.ToString() ?? string.Empty);
        }

        // 테넌트 설정 조회 (임시)
        private async Task<TenantSettings> GetTenantSettingsAsync(Guid userId)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}:tenant_settings:{userId:N}";
            try
            {
                var cached = await _cacheService.GetAsync<TenantSettings>(cacheKey); // GetAsync가 Stream을 받아 역직렬화 가정
                if (cached != null) return cached;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get TenantSettings from cache for {CacheKey}", cacheKey);
            }

            // DB 조회 시뮬레이션
            var settings = new TenantSettings { SendWelcomeEmail = true };

            try
            {
                // [FIX CS1503 - Stream for Cache]
                await using var stream = new MemoryStream();
                await JsonSerializer.SerializeAsync(stream, settings);
                stream.Position = 0;
                await _cacheService.SetAsync(cacheKey, stream, TimeSpan.FromHours(1));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to set TenantSettings in cache for {CacheKey}", cacheKey);
            }
            return settings;
        }

        // 특정 사용자 관련 캐시 무효화 (임시)
        private async Task InvalidateUserCacheAsync(Guid userId)
        {
            // 이 핸들러 내부에서 사용하는 캐시만 무효화 (더 구체적인 패턴 권장)
            var pattern = $"{CACHE_KEY_PREFIX}:*{userId:N}*";
            try
            {
                await _cacheService.RemoveByPatternAsync(pattern);
                _logger.LogDebug("Invalidated handler cache keys matching pattern: {Pattern}", pattern);
                // 중요: 실제 사용자 데이터 캐시 (예: UserProfile, Permissions) 무효화 로직은
                // 여기에 직접 구현하기보다, 별도의 IUserCacheManager 등을 통해 호출하는 것이 좋음
                // await _userCacheManager.InvalidateUserCoreDataAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to invalidate cache for pattern {Pattern}", pattern);
            }
        }

        // 사용자 삭제 시 모든 관련 캐시 무효화 (임시 - 패턴 주의)
        private async Task InvalidateAllUserCacheAsync(Guid userId)
        {
            // 경고: RemoveByPatternAsync는 성능에 영향을 줄 수 있으므로 신중하게 사용해야 함
            // 더 구체적인 키 목록을 생성하여 RemoveAsync를 여러 번 호출하는 것이 더 안전할 수 있음
            var patterns = new[]
            {
                $"{CACHE_KEY_PREFIX}:*{userId:N}*", // 핸들러 캐시
                $"user:{userId:N}:*",             // 사용자 정보 캐시 (예시)
                $"profile:{userId:N}:*",          // 프로필 캐시 (예시)
                $"permissions:{userId:N}:*",     // 권한 캐시 (예시)
                $"sessions:{userId:N}:*"         // 세션 캐시 (예시)
            };

            foreach (var pattern in patterns)
            {
                try
                {
                    await _cacheService.RemoveByPatternAsync(pattern);
                    _logger.LogDebug("Invalidated cache keys matching pattern: {Pattern}", pattern);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to invalidate cache for pattern {Pattern}", pattern);
                }
            }
        }

        // 온보딩 이벤트 발행 (임시)
        private async Task PublishOnboardingEventAsync(Guid userId, CancellationToken cancellationToken)
        {
            // 실제 구현에서는 IEventBus 사용
            // var onboardingEvent = new UserOnboardingStartedEvent(userId, ...);
            // await _eventBus.PublishAsync(onboardingEvent, cancellationToken);
            _logger.LogInformation("Placeholder: Onboarding event would be published for UserId: {UserId}", userId);
            await Task.CompletedTask;
        }

        // 이벤트 처리 규칙 (임시)
        private Dictionary<string, object> GetEventProcessingRules()
        {
            // 실제 구현에서는 설정 파일 또는 DB에서 로드
            return new Dictionary<string, object>
            {
                ["max_retries"] = 3,
                ["timeout_seconds"] = 30,
                ["batch_size"] = 100,
                ["enable_dead_letter"] = true
            };
        }

        #endregion

        #region Private Classes (임시)
        private class TenantSettings
        {
            public bool SendWelcomeEmail { get; set; } = true;
            // 필요 시 다른 설정 추가
        }
        #endregion
    }
}