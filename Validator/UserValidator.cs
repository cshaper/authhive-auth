using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;

// --- v17 수정: using Commands ---
using AuthHive.Core.Models.User.Commands;
// using AuthHive.Core.Models.User.Requests; // [v17 제거]

// --- v17 수정: using 별칭(Alias) ---
using UserEntity = AuthHive.Core.Entities.User.User;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Validator
{
    /// <summary>
    /// UserValidator 구현체 (v17 CQRS 표준)
    /// "본보기" 역할을 하며, Command 유효성 검사를 담당합니다.
    /// </summary>
    public class UserValidator : IUserValidator
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserProfileRepository _userProfileRepository;
        // [tree 검토] IAuditService는 현재 사용되지 않으므로 제거 (YAGNI 원칙)
        private readonly ILogger<UserValidator> _logger;

        public UserValidator(
            IUserRepository userRepository,
            IUserProfileRepository userProfileRepository,
            ILogger<UserValidator> logger)
        {
            _userRepository = userRepository;
            _userProfileRepository = userProfileRepository;
            _logger = logger;
        }

        #region Entity Validation (Delete 시 사용)

        public Task<ValidationResult> ValidateDeleteAsync(UserEntity entity)
        {
            // [v16 로직 유지] 시스템 관리자 삭제 방지
            if (entity.Email.EndsWith("@authhive.com", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(ValidationResult.Failure("User", "System administrator account cannot be deleted.", "DELETE_SYSTEM_ADMIN_FORBIDDEN"));
            }
            return Task.FromResult(ValidationResult.Success());
        }

        #endregion

        #region IUserValidator Implementation (Command Validation)

        /// <summary>
        /// [v17 수정] CreateUserCommand를 검증합니다.
        /// </summary>
        public async Task<ServiceResult> ValidateCreateAsync(CreateUserCommand command)
        {
            // 1. 형식 검사
            var emailValidation = await ValidateEmailAsync(command.Email);
            if (!emailValidation.IsSuccess) return emailValidation;

            if (!string.IsNullOrWhiteSpace(command.Username))
            {
                var usernameValidation = await ValidateUsernameAsync(command.Username);
                if (!usernameValidation.IsSuccess) return usernameValidation;
            }

            // 2. 인증 수단 검사 (v17 Command DTO의 로직)
            if (string.IsNullOrEmpty(command.Password) && string.IsNullOrEmpty(command.ExternalUserId))
            {
                return ServiceResult.Failure("Either a password or an external user ID must be provided.", "AUTH_METHOD_REQUIRED");
            }

            // 3. 중복 검사 (비밀번호 검사는 핸들러의 책임이 아님)
            var emailDuplication = await ValidateEmailDuplicationAsync(command.Email);
            if (!emailDuplication.IsSuccess) return emailDuplication;

            if (!string.IsNullOrWhiteSpace(command.Username))
            {
                var usernameDuplication = await ValidateUsernameDuplicationAsync(command.Username);
                if (!usernameDuplication.IsSuccess) return usernameDuplication;
            }

            return ServiceResult.Success("User creation data is valid.");
        }


        /// <summary>
        /// [v17 수정] UpdateUserCommand를 검증합니다. v16 로직을 이관합니다.
        /// [v17.2 수정] SRP 원칙에 따라 Status 관련 로직 제거
        /// </summary>
        public async Task<ServiceResult> ValidateUpdateAsync(UpdateUserCommand command)
        {
            var userId = command.UserId; // AggregateId

            // 1. User 존재 여부 검사 (v16 UserValidator.ValidateUpdateAsync 로직)
            var user = await _userRepository.GetByIdAsync(userId, CancellationToken.None);
            if (user == null)
            {
                return ServiceResult.NotFound($"User not found: {userId}");
            }

            // 2. 사용자명 변경 시 중복 검사 (v16 UserValidator.ValidateUpdateAsync 로직)
            if (!string.IsNullOrWhiteSpace(command.Username) && command.Username != user.Username)
            {
                // 2a. 형식 검사
                var usernameValidation = await ValidateUsernameAsync(command.Username);
                if (!usernameValidation.IsSuccess) return usernameValidation;

                // 2b. 중복 검사 (CheckUsernameExistsAsync 사용)
                var usernameDuplication = await ValidateUsernameDuplicationAsync(command.Username, userId);
                if (!usernameDuplication.IsSuccess) return usernameDuplication;
            }

            // 3. [v17 수정] Status 변경 유효성 검사 로직 "제거"
            // (이 로직은 'SuspendUserCommandHandler'의 Validator가 담당)
            /*
            if (command.Status.HasValue && command.Status.Value != user.Status)
            {
                var changedBy = command.TriggeredBy ?? command.UserId; 
                var statusTransition = await ValidateStatusTransitionAsync(userId, user.Status, command.Status.Value, changedBy);
                if (!statusTransition.IsSuccess) return statusTransition;
            }
            */

            _logger.LogWarning("ValidateUpdateAsync(UpdateUserCommand) logic migrated (General Info only).");
            return ServiceResult.Success();
        }
        public async Task<ServiceResult> ValidateDeleteAsync(Guid userId, Guid deletedByConnectedId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult.NotFound("User not found.");
            }

            var entityValidationResult = await ValidateDeleteAsync(user);
            if (!entityValidationResult.IsValid)
            {
                var error = entityValidationResult.Errors.First();
                return ServiceResult.Failure(error.Message, error.ErrorCode);
            }

            return ServiceResult.Success("User can be deleted.");
        }

        // [v17 수정] CreateUserProfileCommand를 검증합니다.
        public async Task<ServiceResult> ValidateProfileCreationAsync(CreateUserProfileCommand command)
        {

            var userId = command.UserId;
            if (!await _userRepository.ExistsAsync(userId, CancellationToken.None))
            {
                return ServiceResult.NotFound($"User not found: {userId}");
            }
            if (await _userProfileRepository.ExistsAsync(userId, CancellationToken.None))
            {
                return ServiceResult.Failure($"Profile already exists for user: {userId}", "PROFILE_ALREADY_EXISTS");
            }
            if (!string.IsNullOrWhiteSpace(command.PhoneNumber))
            {
                var phoneExists = await _userProfileRepository.GetByPhoneNumberAsync(command.PhoneNumber, CancellationToken.None);
                if (phoneExists != null)
                {
                    return ServiceResult.Failure("Phone number already in use", "PHONE_NUMBER_DUPLICATE");
                }
            }
            _logger.LogWarning("ValidateProfileCreationAsync logic from UserProfileService migrated.");
            return ServiceResult.Success();
        }

        // [v17 수정] UpdateUserProfileCommand를 받도록 시그니처 수정
        public async Task<ServiceResult> ValidateProfileUpdateAsync(UpdateUserProfileCommand command)
        {
            var userId = command.UserId; // AggregateId

            // 1. Profile 존재 여부 검사
            var profile = await _userProfileRepository.GetByIdAsync(userId);
            if (profile == null)
            {
                return ServiceResult.NotFound($"Profile not found for user: {userId}");
            }

            // 2. 전화번호 중복 검사 (v16 UserProfileService.ApplyProfileChanges 로직 이관)
            if (!string.IsNullOrWhiteSpace(command.PhoneNumber) && command.PhoneNumber != profile.PhoneNumber)
            {
                var phoneExists = await _userProfileRepository.GetByPhoneNumberAsync(command.PhoneNumber);
                if (phoneExists != null && phoneExists.UserId != userId) // 다른 사람의 것인지 확인
                {
                    return ServiceResult.Failure("Phone number already in use by another user", "PHONE_NUMBER_DUPLICATE");
                }
            }

            // [v16 UserValidator.ValidateProfileUpdateAsync 로직 유지]
            _logger.LogWarning("ValidateProfileUpdateAsync logic (partial) migrated.");
            return ServiceResult.Success();
        }

        /// <summary>
        /// [v17] SuspendUserCommand를 검증합니다.
        /// </summary>
        public async Task<ServiceResult> ValidateSuspendAsync(SuspendUserCommand command)
        {
            var userId = command.UserId;

            // 1. User 존재 여부 검사
            var user = await _userRepository.GetByIdAsync(userId, CancellationToken.None);
            if (user == null)
            {
                return ServiceResult.NotFound($"User not found: {userId}");
            }

            // 2. 상태 변경 유효성 검사 (v16 로직 재활용)
            var changedBy = command.TriggeredBy ?? command.UserId;
            var statusTransition = await ValidateStatusTransitionAsync(
                userId,
                user.Status,
                UserStatus.Suspended, // 목표 상태
                changedBy
            );
            if (!statusTransition.IsSuccess) return statusTransition;

            _logger.LogWarning("ValidateSuspendAsync(SuspendUserCommand) logic migrated.");
            return ServiceResult.Success();
        }

        /// <summary>
        /// [v17] ChangeTwoFactorCommand를 검증합니다.
        /// </summary>
        public async Task<ServiceResult> ValidateTwoFactorChangeAsync(ChangeTwoFactorCommand command)
        {
            var userId = command.UserId;

            // 1. User 존재 여부 검사
            var user = await _userRepository.GetByIdAsync(userId, CancellationToken.None);
            if (user == null)
            {
                return ServiceResult.NotFound($"User not found: {userId}");
            }

            // TODO: v16의 ValidateTwoFactorSetupAsync 로직 (현재는 비어있음 )
            // (예: "SMS 타입인데 UserProfile에 전화번호가 등록되어 있는가?")
            _logger.LogWarning("ValidateTwoFactorChangeAsync (ValidateTwoFactorSetupAsync) is not fully implemented.");

            return ServiceResult.Success();
        }

        #endregion

        #region --- 유틸리티 메서드 (v17 로직 수정) ---

        public Task<ServiceResult> ValidateEmailAsync(string email, bool checkMxRecord = false, bool blockDisposable = true)
        {
            if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase))
            {
                return Task.FromResult(ServiceResult.Failure("Invalid email format.", "EMAIL_INVALID_FORMAT"));
            }
            // TODO: MX 레코드, 일회용 이메일 검사 로직 (Infra 서비스 호출)
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult> ValidateUsernameAsync(string username)
        {
            if (!Regex.IsMatch(username, "^[a-zA-Z0-9_]{3,50}$"))
            {
                return Task.FromResult(ServiceResult.Failure("Username must be 3-50 characters long and contain only letters, numbers, and underscores.", "USERNAME_INVALID_FORMAT"));
            }
            return Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> ValidateEmailDuplicationAsync(string email, Guid? excludeUserId = null)
        {
            // [v17 로직 수정] GetByEmailAsync -> CheckEmailExistsAsync (효율성, CS1061 해결)
            var isTaken = await _userRepository.CheckEmailExistsAsync(email, excludeUserId);
            if (isTaken)
            {
                return ServiceResult.Failure("Email address is already in use.", "EMAIL_DUPLICATE");
            }
            return ServiceResult.Success();
        }

        public async Task<ServiceResult> ValidateUsernameDuplicationAsync(string username, Guid? excludeUserId = null)
        {
            // [v17 로직 수정] GetByUsernameAsync -> CheckUsernameExistsAsync (효율성, CS1061 해결)
            var isTaken = await _userRepository.CheckUsernameExistsAsync(username, excludeUserId);
            if (isTaken)
            {
                return ServiceResult.Failure("Username is already taken.", "USERNAME_DUPLICATE");
            }
            return ServiceResult.Success();
        }

        public Task<ServiceResult> ValidateStatusTransitionAsync(Guid userId, UserStatus currentStatus, UserStatus newStatus, Guid changedByConnectedId)
        {
            // [v16 로직 유지]
            var validTransitions = new Dictionary<UserStatus, List<UserStatus>>
            {
                { UserStatus.PendingVerification, new List<UserStatus> { UserStatus.Active, UserStatus.Deleted } },
                { UserStatus.Active, new List<UserStatus> { UserStatus.Inactive, UserStatus.Suspended, UserStatus.Deleted } },
                { UserStatus.Inactive, new List<UserStatus> { UserStatus.Active, UserStatus.Deleted } },
                { UserStatus.Suspended, new List<UserStatus> { UserStatus.Active, UserStatus.Deleted } },
                { UserStatus.IsLocked, new List<UserStatus> { UserStatus.Active } }
            };

            if (currentStatus == newStatus) return Task.FromResult(ServiceResult.Success());

            if (!validTransitions.ContainsKey(currentStatus) || !validTransitions[currentStatus].Contains(newStatus))
            {
                return Task.FromResult(ServiceResult.Failure($"Cannot transition user from {currentStatus} to {newStatus}.", "INVALID_STATUS_TRANSITION"));
            }

            return Task.FromResult(ServiceResult.Success());
        }

        // --- v16의 나머지 메서드 스텁 (향후 구현) ---
        // ... (ValidateSuspensionAsync, ValidateExternalUserMappingAsync 등)

        #endregion
    }
}