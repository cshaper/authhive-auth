// Path: AuthHive.Auth/Services/Authentication/BasicAuthenticationService.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.User;
using System.Security.Cryptography;
using System.Text;
using static AuthHive.Core.Enums.Core.UserEnums;

namespace AuthHive.Auth.Services.Authentication
{
    public class BasicAuthenticationService : IBasicAuthenticationService
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<BasicAuthenticationService> _logger;
        private readonly Dictionary<string, (Guid userId, DateTime expiry)> _resetTokens = new();
        private readonly Dictionary<string, (Guid userId, DateTime expiry)> _emailTokens = new();
        
        public BasicAuthenticationService(
            AuthDbContext context,
            ILogger<BasicAuthenticationService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<ServiceResult<User>> AuthenticatePasswordAsync(
            string username, 
            string password)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == username);
                
            if (user == null || !VerifyPassword(password, user.PasswordHash!))
            {
                return ServiceResult<User>.Failure("Invalid credentials.");
            }

            if (user.Status != UserStatus.Active)
            {
                return ServiceResult<User>.Failure($"Account is {user.Status}");
            }

            return ServiceResult<User>.Success(user);
        }

        public async Task<ServiceResult<User>> RegisterUserAsync(
            string email, 
            string password, 
            string displayName)
        {
            if (await _context.Users.AnyAsync(u => u.Email == email))
            {
                return ServiceResult<User>.Failure("User with this email already exists.");
            }

            var user = new User
            {
                Email = email,
                DisplayName = displayName,
                PasswordHash = HashPassword(password),
                Status = UserStatus.Active,
                EmailVerified = false
            };
            
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            return ServiceResult<User>.Success(user);
        }

        public async Task<ServiceResult<PasswordResetToken>> GeneratePasswordResetTokenAsync(
            string email, 
            Guid? organizationId = null)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null)
                {
                    // 보안상 사용자 존재 여부 노출하지 않음
                    return ServiceResult<PasswordResetToken>.Success(new PasswordResetToken 
                    { 
                        Email = email,
                        Message = "If the email exists, a reset link has been sent." 
                    });
                }

                var token = GenerateSecureToken();
                var expiry = DateTime.UtcNow.AddHours(1);
                
                _resetTokens[token] = (user.Id, expiry);

                var resetToken = new PasswordResetToken
                {
                    Token = token,
                    Email = email,
                    UserId = user.Id,
                    ExpiresAt = expiry,
                    Message = "Password reset token generated",
                    ResetUrl = $"/reset-password?token={token}"
                };

                return ServiceResult<PasswordResetToken>.Success(resetToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate password reset token for {Email}", email);
                return ServiceResult<PasswordResetToken>.Failure("Failed to process request");
            }
        }

        public async Task<ServiceResult<PasswordResetResult>> ResetPasswordWithTokenAsync(
            string token, 
            string newPassword)
        {
            try
            {
                if (!_resetTokens.TryGetValue(token, out var tokenData))
                {
                    return ServiceResult<PasswordResetResult>.Failure("Invalid or expired token");
                }

                if (tokenData.expiry < DateTime.UtcNow)
                {
                    _resetTokens.Remove(token);
                    return ServiceResult<PasswordResetResult>.Failure("Token has expired");
                }

                var user = await _context.Users.FindAsync(tokenData.userId);
                if (user == null)
                {
                    return ServiceResult<PasswordResetResult>.Failure("User not found");
                }

                user.PasswordHash = HashPassword(newPassword);
                user.PasswordChangedAt = DateTime.UtcNow;
                
                await _context.SaveChangesAsync();
                _resetTokens.Remove(token);

                var result = new PasswordResetResult
                {
                    Success = true,
                    UserId = user.Id,
                    Email = user.Email?? string.Empty,
                    ResetAt = DateTime.UtcNow
                };

                return ServiceResult<PasswordResetResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reset password with token");
                return ServiceResult<PasswordResetResult>.Failure("Failed to reset password");
            }
        }

        public async Task<ServiceResult<bool>> VerifyPasswordAsync(
            Guid userId, 
            string password)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return ServiceResult<bool>.Failure("User not found");
                }

                var isValid = VerifyPassword(password, user.PasswordHash!);
                return ServiceResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify password for user {UserId}", userId);
                return ServiceResult<bool>.Failure("Failed to verify password");
            }
        }

        public async Task<ServiceResult> ChangePasswordAsync(
            Guid userId, 
            string newPassword)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found");
                }

                user.PasswordHash = HashPassword(newPassword);
                user.PasswordChangedAt = DateTime.UtcNow;
                
                await _context.SaveChangesAsync();
                
                return ServiceResult.Success("Password changed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change password for user {UserId}", userId);
                return ServiceResult.Failure("Failed to change password");
            }
        }

        public async Task<ServiceResult<string>> GenerateEmailVerificationTokenAsync(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return ServiceResult<string>.Failure("User not found");
                }

                if (user.EmailVerified)
                {
                    return ServiceResult<string>.Failure("Email already verified");
                }

                var token = GenerateSecureToken();
                var expiry = DateTime.UtcNow.AddHours(24);
                
                _emailTokens[token] = (userId, expiry);

                return ServiceResult<string>.Success(token);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate email verification token for user {UserId}", userId);
                return ServiceResult<string>.Failure("Failed to generate token");
            }
        }

        public async Task<ServiceResult> VerifyEmailAsync(string token)
        {
            try
            {
                if (!_emailTokens.TryGetValue(token, out var tokenData))
                {
                    return ServiceResult.Failure("Invalid or expired token");
                }

                if (tokenData.expiry < DateTime.UtcNow)
                {
                    _emailTokens.Remove(token);
                    return ServiceResult.Failure("Token has expired");
                }

                var user = await _context.Users.FindAsync(tokenData.userId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found");
                }

                user.EmailVerified = true;
                user.EmailVerifiedAt = DateTime.UtcNow;
                
                await _context.SaveChangesAsync();
                _emailTokens.Remove(token);

                return ServiceResult.Success("Email verified successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify email with token");
                return ServiceResult.Failure("Failed to verify email");
            }
        }

        // IService implementation
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                return await _context.Database.CanConnectAsync();
            }
            catch
            {
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("BasicAuthenticationService initialized");
            return Task.CompletedTask;
        }

        #region Private Helper Methods

        private bool VerifyPassword(string password, string hash) 
            => HashPassword(password) == hash;

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        private string GenerateSecureToken(int byteLength = 32)
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(byteLength))
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }

        #endregion
    }
}