// File: AuthHive.Auth/Handlers/User/Lifecycle/UserAccountCreatedEventHandler.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.User.Events.Lifecycle; // 처리할 이벤트
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.UserExperience; // IEmailService
using AuthHive.Core.Models.External; // EmailMessageDto
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService (공통 서비스 분리 필요)
using Microsoft.Extensions.Logging;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Auth.Extensions; // 필요시 사용 (BaseEvent 등)

namespace AuthHive.Auth.Handlers.User.Lifecycle // 하위 네임스페이스 사용 추천
{
    /// <summary>
    /// UserAccountCreatedEvent를 처리하는 전용 핸들러입니다.
    /// </summary>
    public class UserAccountCreatedEventHandler : IDomainEventHandler<UserAccountCreatedEvent>
    {
        // 필요한 의존성만 주입
        private readonly ILogger<UserAccountCreatedEventHandler> _logger;
        private readonly IAuditService _auditService;
        private readonly IEmailService _emailService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IAuthenticationCacheService _authenticationCacheService;
        private readonly IOrganizationSettingsService _organizationSettingsService;


        public int Priority => 1; // 우선순위 설정
        public bool IsEnabled => true; // 활성화 여부

        public UserAccountCreatedEventHandler(
            ILogger<UserAccountCreatedEventHandler> logger,
            IAuditService auditService,
            IEmailService emailService,
            IUnitOfWork unitOfWork,
            IAuthenticationCacheService authenticationCacheService,
            IOrganizationSettingsService organizationSettingsService
            )
        {
            _logger = logger;
            _auditService = auditService;
            _emailService = emailService;
            _unitOfWork = unitOfWork;
            _authenticationCacheService = authenticationCacheService;
            _organizationSettingsService = organizationSettingsService;
        }


        /// <summary>
        /// UserAccountCreatedEvent 처리 로직
        /// </summary>
        public async Task HandleAsync(UserAccountCreatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync(cancellationToken);

                bool sendWelcomeEmail = true; // 기본값: true

                // --- 1. TenantSettings 조회 로직 (오류 수정) ---

                // (오류 수정) @event.OrganizationId가 null이 아닌지 확인
               if (@event.OrganizationId.HasValue)
                {
                    Guid organizationId = @event.OrganizationId.Value; 

                    // (오류 수정) <bool> 대신 <string>으로 호출
                    var settingsResult = await _organizationSettingsService.GetSettingValueAsync<string>(
                        organizationId,
                        OrganizationSettingCategory.Notification, // 이 부분은 올바르게 수정하셨습니다.
                        "SendWelcomeEmail", // 설정 키
                        cancellationToken
                    );

                    // (오류 수정) string 결과를 bool로 변환
                    if (settingsResult.IsSuccess && !string.IsNullOrEmpty(settingsResult.Data))
                    {
                        // "true"(대소문자 무관) 문자열을 bool로 변환
                        bool.TryParse(settingsResult.Data, out sendWelcomeEmail);
                    }
                    else if (!settingsResult.IsSuccess)
                    {
                        _logger.LogWarning(
                            "Failed to retrieve 'SendWelcomeEmail' setting for OrgId {OrganizationId} (UserId {UserId}). Using default value (true). Reason: {Reason}",
                            organizationId, @event.UserId, settingsResult.ErrorMessage);
                    }
                    // else (Succeeded지만 Data가 null이거나 empty인 경우) -> sendWelcomeEmail은 기본값(true) 유지
                }
                else
                {
                    _logger.LogInformation(
                        "OrganizationId is null for UserAccountCreatedEvent (UserId {UserId}). Using default 'SendWelcomeEmail = true'.", 
                        @event.UserId);
                }
                // --- 1. 수정 완료 ---


                // 환영 이메일 발송
                if (sendWelcomeEmail && !string.IsNullOrEmpty(@event.Email))
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            Dictionary<string, string>? emailTags = null;
                            if (@event.Metadata != null && @event.Metadata.Any())
                            {
                                // --- 확장 메서드로 변경됨 ---
                                emailTags = @event.Metadata.ToStringDictionary();
                            }
                            await _emailService.SendEmailAsync(new EmailMessageDto
                            {
                                To = new List<string> { @event.Email },
                                Subject = "Welcome to AuthHive!",
                                Body = $"Welcome, {@event.Email}! Your account is created.",
                                Tags = emailTags
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

                // --- 확장 메서드로 변경됨 ---
                auditMetadata.Merge(@event.Metadata);

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    AuditActionType.UserRegistration, "UserAccountCreated",
                    @event.CreatedByConnectedId ?? @event.UserId,
                    resourceType: "User", resourceId: @event.UserId.ToString(),
                    metadata: auditMetadata, cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // --- 캐시 무효화 로직 (서비스 호출로 변경됨) ---
                var cacheResult = await _authenticationCacheService.ClearAuthenticationCacheAsync(
                    @event.UserId
                );

                if (!cacheResult.IsSuccess)
                {
                    _logger.LogWarning("Failed to clear authentication cache for UserId {UserId}. Reason: {Reason}",
                        @event.UserId, cacheResult.ErrorMessage);
                }

                _logger.LogInformation("Successfully processed UserAccountCreatedEvent for UserId: {UserId}", @event.UserId);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to process UserAccountCreatedEvent for UserId: {UserId}", @event.UserId);
                // throw; // 필요 시 재시도
            }
        }

        #region --- 임시 헬퍼 메서드 (별도 서비스로 분리 권장) ---
        // private void MergeMetadata(Dictionary<string, object> target, Dictionary<string, object>? source) { /* ... */ }
        // private Dictionary<string, string> ConvertToStringDict(Dictionary<string, object> dict) { /* ... */ }

        #endregion
    }
}