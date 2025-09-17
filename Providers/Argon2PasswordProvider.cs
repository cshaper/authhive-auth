using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Models.Common;
using Isopoh.Cryptography.Argon2;
using System.Security.Cryptography;
using System.Text;
using AuthHive.Core.Interfaces.User.Repository; // IUserRepository 사용
using AuthHive.Core.Interfaces.Base; // IUnitOfWork 사용
using AuthHive.Core.Entities.User;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Models.Infra.Security; // User 엔티티 사용

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// Argon2 알고리즘을 사용한 IPasswordProvider 구현체
    /// </summary>
    public class Argon2PasswordProvider : IPasswordProvider
    {
        private readonly IUserRepository _userRepository;
        // private readonly IPasswordHistoryRepository _passwordHistoryRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<Argon2PasswordProvider> _logger;

        public Argon2PasswordProvider(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ILogger<Argon2PasswordProvider> logger)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        #region Hashing and Verification

        public Task<string> HashPasswordAsync(string password)
        {
            var hash = Argon2.Hash(password);
            return Task.FromResult(hash);
        }

        public Task<bool> VerifyPasswordAsync(string password, string passwordHash)
        {
            var isValid = Argon2.Verify(passwordHash, password);
            return Task.FromResult(isValid);
        }

        #endregion

        #region Strength and Policy Validation

        public Task<ServiceResult<PasswordStrengthResult>> ValidatePasswordStrengthAsync(string password)
        {
            var result = Zxcvbn.Core.EvaluatePassword(password);
            var strength = new PasswordStrengthResult
            {
                Score = (result.Score + 1) * 25,
                Suggestions = result.Feedback.Suggestions.ToList(),
                MeetsRequirements = result.Score >= 2
            };

            strength.Level = result.Score switch
            {
                0 => "Weak", 1 => "Fair", 2 => "Good", _ => "Strong"
            };

            return Task.FromResult(ServiceResult<PasswordStrengthResult>.Success(strength));
        }

        public Task<ServiceResult<bool>> ValidatePasswordPolicyAsync(string password, Guid? organizationId = null)
        {
            if (password.Length < 8)
                return Task.FromResult(ServiceResult<bool>.Failure("Password must be at least 8 characters long."));
            if (!password.Any(char.IsUpper))
                return Task.FromResult(ServiceResult<bool>.Failure("Password must contain at least one uppercase letter."));
            if (!password.Any(char.IsDigit))
                return Task.FromResult(ServiceResult<bool>.Failure("Password must contain at least one number."));

            return Task.FromResult(ServiceResult<bool>.Success(true));
        }

        #endregion

        #region Password Management

        public async Task<ServiceResult> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword)
        {
            // 수정된 부분: FindByIdAsync -> GetByIdAsync
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null || string.IsNullOrEmpty(user.PasswordHash))
            {
                return ServiceResult.Failure("User not found or no password set.");
            }

            if (!await VerifyPasswordAsync(currentPassword, user.PasswordHash))
            {
                return ServiceResult.Failure("Incorrect current password.");
            }

            var historyCheck = await CheckPasswordHistoryAsync(userId, newPassword);
            if (historyCheck.IsSuccess && historyCheck.Data)
            {
                return ServiceResult.Failure("New password cannot be the same as recent passwords.");
            }

            var policyResult = await ValidatePasswordPolicyAsync(newPassword);
            if (!policyResult.IsSuccess)
            {
                return ServiceResult.Failure(policyResult.ErrorMessage ?? "New password does not meet the policy requirements.");
            }

            user.PasswordHash = await HashPasswordAsync(newPassword);
            await _userRepository.UpdateAsync(user); // IUnitOfWork 대신 Repository의 Update 사용

            return ServiceResult.Success();
        }

        public async Task<ServiceResult<string>> GeneratePasswordResetTokenAsync(Guid userId)
        {
            // 수정된 부분: FindByIdAsync -> GetByIdAsync
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null)
            {
                return ServiceResult<string>.Failure("User not found.");
            }

            var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var hashedToken = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));

            user.PasswordResetToken = hashedToken;
            user.PasswordResetTokenExpiresAt = DateTime.UtcNow.AddHours(1);
            await _userRepository.UpdateAsync(user);

            _logger.LogInformation("Generated password reset token for user {UserId}", userId);
            return ServiceResult<string>.Success(rawToken);
        }

        public async Task<ServiceResult> ResetPasswordAsync(string resetToken, string newPassword)
        {
            var hashedToken = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(resetToken)));
            
            // 이 부분은 IUserRepository에 FindByPasswordResetTokenAsync가 추가되어야 합니다.
            var user = await _userRepository.FindByPasswordResetTokenAsync(hashedToken);

            if (user == null || user.PasswordResetTokenExpiresAt < DateTime.UtcNow)
            {
                return ServiceResult.Failure("Invalid or expired password reset token.");
            }

            var policyResult = await ValidatePasswordPolicyAsync(newPassword);
            if (!policyResult.IsSuccess)
            {
                return ServiceResult.Failure(policyResult.ErrorMessage ?? "New password does not meet the policy requirements.");
            }

            user.PasswordHash = await HashPasswordAsync(newPassword);
            user.PasswordResetToken = null;
            user.PasswordResetTokenExpiresAt = null;
            await _userRepository.UpdateAsync(user);
            
            _logger.LogInformation("Password has been reset for user {UserId}", user.Id);
            return ServiceResult.Success();
        }

        public async Task<ServiceResult<bool>> CheckPasswordHistoryAsync(Guid userId, string newPassword, int historyCount = 5)
        {
            // IPasswordHistoryRepository 구현 전까지 임시로 false 반환
            await Task.CompletedTask;
            return ServiceResult<bool>.Success(false);
        }

        #endregion
    }
}