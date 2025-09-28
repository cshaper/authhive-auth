using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using Microsoft.Extensions.Logging;

// --- 올바른 using 지시문 및 별칭(Alias) 설정 ---
using UserEntity = AuthHive.Core.Entities.User.User;
using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Validator
{
    public class UserValidator : IUserValidator
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserProfileRepository _userProfileRepository;
        private readonly IAuditService _auditService;
        private readonly ILogger<UserValidator> _logger;

        public UserValidator(
            IUserRepository userRepository,
            IUserProfileRepository userProfileRepository,
            IAuditService auditService,
            ILogger<UserValidator> logger)
        {
            _userRepository = userRepository;
            _userProfileRepository = userProfileRepository;
            _auditService = auditService;
            _logger = logger;
        }

        #region IValidator<UserEntity> Implementation
        
        public Task<ValidationResult> ValidateCreateAsync(UserEntity entity)
        {
            var result = ValidationResult.Success();
            if (string.IsNullOrWhiteSpace(entity.Email))
                result.AddError(nameof(entity.Email), "Email is required.", "EMAIL_REQUIRED");
            
            return Task.FromResult(result);
        }

        public Task<ValidationResult> ValidateUpdateAsync(UserEntity entity, UserEntity? existingEntity = null)
        {
            var result = ValidationResult.Success();
            if (existingEntity != null && entity.Email != existingEntity.Email)
            {
                result.AddError(nameof(entity.Email), "Email address cannot be changed directly.", "EMAIL_IMMUTABLE");
            }
            return Task.FromResult(result);
        }
        
        public Task<ValidationResult> ValidateDeleteAsync(UserEntity entity)
        {
            // [FIXED] 'IsSystemAdmin' property does not exist.
            // Check for a system user by a convention, such as a reserved email domain.
            if (entity.Email.EndsWith("@authhive.com", StringComparison.OrdinalIgnoreCase))
            {
                 return Task.FromResult(ValidationResult.Failure("User", "System administrator account cannot be deleted.", "DELETE_SYSTEM_ADMIN_FORBIDDEN"));
            }
            return Task.FromResult(ValidationResult.Success());
        }

        #endregion

        #region IUserValidator Implementation

        public async Task<ServiceResult> ValidateCreateAsync(CreateUserRequest request)
        {
            var emailValidation = await ValidateEmailAsync(request.Email);
            if (!emailValidation.IsSuccess) return emailValidation;

            var emailDuplication = await ValidateEmailDuplicationAsync(request.Email);
            if (!emailDuplication.IsSuccess) return emailDuplication;

            if (!string.IsNullOrWhiteSpace(request.Username))
            {
                var usernameValidation = await ValidateUsernameAsync(request.Username);
                if (!usernameValidation.IsSuccess) return usernameValidation;

                var usernameDuplication = await ValidateUsernameDuplicationAsync(request.Username);
                if (!usernameDuplication.IsSuccess) return usernameDuplication;
            }
            
            if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 8)
            {
                return ServiceResult.Failure("Password must be at least 8 characters long.", "PASSWORD_TOO_SHORT");
            }

            return ServiceResult.Success("User creation data is valid.");
        }

        public async Task<ServiceResult> ValidateUpdateAsync(Guid userId, UpdateUserRequest request, Guid updatedByConnectedId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult.NotFound("User not found.");
            }
            
            if (!string.IsNullOrWhiteSpace(request.Username) && user.Username != request.Username)
            {
                var usernameValidation = await ValidateUsernameAsync(request.Username);
                if (!usernameValidation.IsSuccess) return usernameValidation;

                var usernameDuplication = await ValidateUsernameDuplicationAsync(request.Username, userId);
                if (!usernameDuplication.IsSuccess) return usernameDuplication;
            }
            
            if (request.Status.HasValue && user.Status != request.Status.Value)
            {
                var statusTransition = await ValidateStatusTransitionAsync(userId, user.Status, request.Status.Value, updatedByConnectedId);
                if (!statusTransition.IsSuccess) return statusTransition;
            }

            return ServiceResult.Success("User update data is valid.");
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
        
        public Task<ServiceResult> ValidateProfileCreationAsync(Guid userId, CreateUserProfileRequest request)
        {
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult> ValidateProfileUpdateAsync(Guid userId, UpdateUserProfileRequest request)
        {
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult> ValidateEmailAsync(string email, bool checkMxRecord = false, bool blockDisposable = true)
        {
            if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase))
            {
                return Task.FromResult(ServiceResult.Failure("Invalid email format.", "EMAIL_INVALID_FORMAT"));
            }
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
            var existingUser = await _userRepository.GetByEmailAsync(email);
            if (existingUser != null && existingUser.Id != excludeUserId)
            {
                return ServiceResult.Failure("Email address is already in use.", "EMAIL_DUPLICATE");
            }
            return ServiceResult.Success();
        }

        public async Task<ServiceResult> ValidateUsernameDuplicationAsync(string username, Guid? excludeUserId = null)
        {
            var existingUser = await _userRepository.GetByUsernameAsync(username);
            if (existingUser != null && existingUser.Id != excludeUserId)
            {
                return ServiceResult.Failure("Username is already taken.", "USERNAME_DUPLICATE");
            }
            return ServiceResult.Success();
        }
        
        public Task<ServiceResult> ValidateStatusTransitionAsync(Guid userId, UserStatus currentStatus, UserStatus newStatus, Guid changedByConnectedId)
        {
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

        public Task<ServiceResult> ValidateActivationAsync(Guid userId)
        {
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult> ValidateSuspensionAsync(Guid userId, string reason)
        {
            if (string.IsNullOrWhiteSpace(reason))
            {
                return Task.FromResult(ServiceResult.Failure("A reason is required to suspend a user.", "SUSPENSION_REASON_REQUIRED"));
            }
            return Task.FromResult(ServiceResult.Success());
        }
        
        public Task<ServiceResult> ValidateExternalUserMappingAsync(string externalSystemType, string externalUserId, Guid? existingUserId = null)
        {
             _logger.LogWarning("ValidateExternalUserMappingAsync is not fully implemented.");
             return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult> ValidateTwoFactorSetupAsync(Guid userId)
        {
            _logger.LogWarning("ValidateTwoFactorSetupAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        public Task<ServiceResult> ValidateLoginActivityAsync(Guid userId, DateTime? lastLoginAt)
        {
            _logger.LogWarning("ValidateLoginActivityAsync is not fully implemented.");
            return Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<BulkValidationResult>> ValidateBulkCreateAsync(List<CreateUserRequest> requests)
        {
            var result = new BulkValidationResult { TotalCount = requests.Count };
            var uniqueEmails = new HashSet<string>();
            var uniqueUsernames = new HashSet<string>();

            for (int i = 0; i < requests.Count; i++)
            {
                var request = requests[i];
                var itemResult = new ItemValidationResult { Index = i, Identifier = request.Email, IsValid = true };
                var validation = await ValidateCreateAsync(request);
                if (!validation.IsSuccess)
                {
                    itemResult.IsValid = false;
                    itemResult.Errors.Add(validation.ErrorMessage ?? "Validation failed");
                }
                if (!uniqueEmails.Add(request.Email.ToLower()))
                {
                    itemResult.IsValid = false;
                    itemResult.Errors.Add("Email is duplicated within the request batch.");
                }
                if (!string.IsNullOrWhiteSpace(request.Username) && !uniqueUsernames.Add(request.Username.ToLower()))
                {
                    itemResult.IsValid = false;
                    itemResult.Errors.Add("Username is duplicated within the request batch.");
                }
                result.ItemResults.Add(itemResult);
            }
            
            result.ValidCount = result.ItemResults.Count(r => r.IsValid);
            result.InvalidCount = result.TotalCount - result.ValidCount;
            result.IsValid = result.InvalidCount == 0;
            
            return result.ToServiceResult();
        }

        public Task<ServiceResult<BulkValidationResult>> ValidateBulkUpdateAsync(List<(Guid UserId, UpdateUserRequest Request)> updates)
        {
             _logger.LogWarning("ValidateBulkUpdateAsync is not fully implemented.");
             var result = new BulkValidationResult { IsValid = true };
             return Task.FromResult(result.ToServiceResult());
        }

        #endregion
    }
}