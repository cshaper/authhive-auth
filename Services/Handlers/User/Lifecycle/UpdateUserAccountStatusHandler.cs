// File: d:/Works/Projects/Auth_V2/AuthHive/AuthHive.Auth/Services/Handlers/User/Lifecycle/UpdateUserAccountStatusHandler.cs
// ----------------------------------------------------------------------
// [Event Handler]
// UserAccountActivatedEvent를 처리하는 핸들러입니다.
// 목적: 사용자의 Write Model (User 엔티티) 상태를 Active로 업데이트하고, 이메일 검증 상태를 설정합니다.
// ----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Models.User.Events.Lifecycle; // The Event
using AuthHive.Core.Interfaces.Base;               // For IDomainEventHandler
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Core.UserEnums;


namespace AuthHive.Auth.Services.Handlers.User.Lifecycle
{
    /// <summary>
    /// <see cref="UserAccountActivatedEvent"/>를 처리하는 상태 업데이트 핸들러입니다.
    /// User 엔티티의 상태를 'Active'로 변경합니다.
    /// </summary>
    public class UpdateUserAccountStatusHandler
        : IDomainEventHandler<UserAccountActivatedEvent>
    {
        // Write Model 상태 변경은 최우선 순위
        public int Priority => 100;
        public bool IsEnabled => true;

        private readonly IUserRepository _userRepository;
        private readonly ILogger<UpdateUserAccountStatusHandler> _logger;

        public UpdateUserAccountStatusHandler(
            IUserRepository userRepository,
            ILogger<UpdateUserAccountStatusHandler> logger)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 계정 활성화 이벤트를 처리하여 User 엔티티의 상태를 업데이트합니다.
        /// </summary>
        public async Task HandleAsync(UserAccountActivatedEvent @event, CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation(
                    "Starting User account status and email verification update for UserId: {UserId}",
                    @event.UserId);

                // 1. User 엔티티를 조회합니다. (상태 확인 및 이후 로직을 위해)
                var user = await _userRepository.GetByIdAsync(@event.UserId, cancellationToken);

                if (user == null)
                {
                    _logger.LogError("User not found for activation event. Skipping status update. (UserId: {UserId})", @event.UserId);
                    return;
                }
                
                // --- 2. 상태를 업데이트하고 이메일 검증을 저장합니다. ---
                
                // 2a. 메인 상태를 Active로 변경합니다.
                // (수정) UpdateStatusAsync -> UpdateUserStatusAsync로 변경하고 TriggeredBy를 추가
                var statusUpdateResult = await _userRepository.UpdateUserStatusAsync(@event.UserId, UserStatus.Active, @event.TriggeredBy, cancellationToken);

                // 2b. 이메일 검증 상태를 'Verified'로 변경합니다.
                // (가정) UpdateUserEmailVerificationAsync가 IUserRepository에 존재합니다.
                var verificationUpdateResult = await _userRepository.UpdateUserEmailVerificationAsync(
                    @event.UserId,
                    true, // isVerified = true
                    DateTime.UtcNow, // verifiedAt = 현재 시각
                    cancellationToken
                );
                
                // 3. 결과 확인
                if (statusUpdateResult && verificationUpdateResult) // UpdateStatusAsync와 VerificationAsync 모두 성공했다고 가정
                {
                     _logger.LogInformation(
                        "User account successfully Activated and Email Verified. (UserId: {UserId})",
                        @event.UserId);
                }
                else
                {
                    // 상태 업데이트 또는 검증 업데이트 중 하나라도 실패하면 오류 처리
                    _logger.LogError(
                        "Failed to fully process activation (Status: {StatusSuccess}, Verification: {VerificationSuccess}). (UserId: {UserId})",
                        statusUpdateResult, verificationUpdateResult, @event.UserId);
                    throw new InvalidOperationException($"Failed to fully activate User account and verify email for UserId: {@event.UserId}");
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("User status and verification update cancelled. (UserId: {UserId})", @event.UserId);
                throw;
            }
            catch (Exception ex)
            {
                // Write Model 업데이트 실패는 심각하므로 재시도를 위해 예외를 다시 던집니다.
                _logger.LogError(ex,
                    "Fatal error updating User account status and verification for activation. (UserId: {UserId})",
                    @event.UserId);
                throw;
            }
        }
    }
}
