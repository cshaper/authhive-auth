// Path: AuthHive.Auth/Services/Authentication/PasswordAuthenticationService.cs
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Auth.Data.Context;
using System.Security.Cryptography;
using System.Text;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Core;
using Microsoft.Extensions.Logging;
// PasswordAuthenticationService.cs 상단에 추가


namespace AuthHive.Auth.Services.Authentication
{
    public class PasswordService : IPasswordService
    {
        private readonly AuthDbContext _context;
        private readonly IConnectedIdService _connectedIdService;
        private readonly ISessionService _sessionService;
        private readonly ITokenService _tokenService;
        private readonly ILogger<PasswordService> _logger;

        public PasswordService(
            AuthDbContext context,
            IConnectedIdService connectedIdService,
            ISessionService sessionService,
            ITokenService tokenService,
            ILogger<PasswordService> logger)
        {
            _context = context;
            _connectedIdService = connectedIdService;
            _sessionService = sessionService;
            _tokenService = tokenService;
            _logger = logger;
        }

        // IService 구현
        public Task<bool> IsHealthyAsync() => Task.FromResult(true);
        public Task InitializeAsync() => Task.CompletedTask;

        // 회원가입
        public async Task<ServiceResult<AuthenticationResponse>> RegisterAsync(
            string email, 
            string password, 
            string displayName,
            Guid? organizationId = null)
        {
            try
            {
                // 이메일 중복 확인
                if (await _context.Users.AnyAsync(u => u.Email == email))
                {
                    return ServiceResult<AuthenticationResponse>.Failure("User with this email already exists.");
                }

                // 패스워드 검증
                var validationResult = await ValidatePasswordAsync(password, organizationId);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<AuthenticationResponse>.Failure(validationResult.ErrorMessage ?? "Invalid password");
                }

                // 사용자 생성
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

                // ConnectedId 생성 (조직이 없으면 개인 조직 생성)
                var targetOrgId = organizationId ?? await GetOrCreatePersonalOrganizationId(user.Id);
                
                var connectedIdRequest = new CreateConnectedIdRequest
                {
                    UserId = user.Id,
                    OrganizationId = targetOrgId,
                    Provider = "local"
                };

                var connectedIdResult = await _connectedIdService.CreateAsync(connectedIdRequest);
                if (!connectedIdResult.IsSuccess || connectedIdResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to create ConnectedId");
                }

                // 세션 생성
                var sessionRequest = new CreateSessionRequest
                {
                    ConnectedId = connectedIdResult.Data.Id,
                    OrganizationId = targetOrgId,
                    IPAddress = "127.0.0.1", // TODO: 실제 IP 가져오기
                    UserAgent = "registration"
                };

                var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest);
                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to create session");
                }

                // 토큰 발급
                var tokenResult = await _tokenService.IssueTokensAsync(sessionResult.Data.SessionDto);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to issue tokens");
                }

                return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedIdResult.Data.Id,
                    SessionId = sessionResult.Data.SessionDto.Id,
                    AccessToken = tokenResult.Data.AccessToken,
                    RefreshToken = tokenResult.Data.RefreshToken,
                    ExpiresAt = tokenResult.Data.ExpiresAt,
                    OrganizationId = targetOrgId,
                    AuthenticationMethod = "Password",
                    IsFirstLogin = true
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register user {Email}", email);
                return ServiceResult<AuthenticationResponse>.Failure("Registration failed");
            }
        }

        // 패스워드로 인증
        public async Task<ServiceResult<AuthenticationResponse>> AuthenticateWithPasswordAsync(
            string username,
            string password,
            Guid? organizationId = null)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == username);
                if (user == null || !VerifyPassword(password, user.PasswordHash!))
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Invalid credentials.");
                }

                if (user.Status != UserStatus.Active)
                {
                    return ServiceResult<AuthenticationResponse>.Failure($"Account is {user.Status}");
                }

                // ConnectedId 가져오거나 생성
                var targetOrgId = organizationId ?? await GetOrCreatePersonalOrganizationId(user.Id);
                var connectedId = await GetOrCreateConnectedIdAsync(user.Id, targetOrgId);

                // 세션 생성
                var sessionRequest = new CreateSessionRequest
                {
                    ConnectedId = connectedId.Id,
                    OrganizationId = targetOrgId,
                    IPAddress = "127.0.0.1", // TODO: 실제 IP
                    UserAgent = "password-auth"
                };

                var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest);
                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to create session");
                }

                // 토큰 발급
                var tokenResult = await _tokenService.IssueTokensAsync(sessionResult.Data.SessionDto);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to issue tokens");
                }

                return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedId.Id,
                    SessionId = sessionResult.Data.SessionDto.Id,
                    AccessToken = tokenResult.Data.AccessToken,
                    RefreshToken = tokenResult.Data.RefreshToken,
                    ExpiresAt = tokenResult.Data.ExpiresAt,
                    OrganizationId = targetOrgId,
                    AuthenticationMethod = "Password"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed for {Username}", username);
                return ServiceResult<AuthenticationResponse>.Failure("Authentication failed");
            }
        }

        // IPasswordService 메서드들
        public async Task<ServiceResult<PasswordResetToken>> RequestPasswordResetAsync(
            string email, 
            Guid? organizationId = null)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null)
                {
                    // 보안상 사용자 없어도 성공 반환
                    return ServiceResult<PasswordResetToken>.Success(new PasswordResetToken { Message = "If the email exists, a reset link has been sent." });
                }

                var token = GenerateSecureToken();
                var resetToken = new PasswordResetToken
                {
                    Token = token,
                    UserId = user.Id,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    Message = "Password reset token generated"
                };

                // TODO: 토큰 저장 및 이메일 발송

                return ServiceResult<PasswordResetToken>.Success(resetToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to request password reset for {Email}", email);
                return ServiceResult<PasswordResetToken>.Failure("Failed to process request");
            }
        }

        public async Task<ServiceResult> ResetPasswordAsync(string token, string newPassword)
        {
            // TODO: 토큰 검증 및 패스워드 변경 구현
            return await Task.FromResult(ServiceResult.Failure("Not implemented"));
        }

        public async Task<ServiceResult> ChangePasswordAsync(
            Guid userId, 
            string currentPassword, 
            string newPassword)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return ServiceResult.Failure("User not found");
                }

                if (!VerifyPassword(currentPassword, user.PasswordHash!))
                {
                    return ServiceResult.Failure("Current password is incorrect");
                }

                var validationResult = await ValidatePasswordAsync(newPassword, null);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult.Failure(validationResult.ErrorMessage ?? "Invalid password");
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

        public async Task<ServiceResult<PasswordValidationResult>> ValidatePasswordAsync(
            string password, 
            Guid? organizationId = null)
        {
            var result = new PasswordValidationResult
            {
                IsValid = true,
                Errors = new List<string>()
            };

            // TODO: 조직별 정책 가져오기
            var policy = await GetPasswordPolicyAsync(organizationId);

            if (password.Length < 8)
                result.Errors.Add("Password must be at least 8 characters");

            if (!password.Any(char.IsUpper))
                result.Errors.Add("Password must contain at least one uppercase letter");

            if (!password.Any(char.IsLower))
                result.Errors.Add("Password must contain at least one lowercase letter");

            if (!password.Any(char.IsDigit))
                result.Errors.Add("Password must contain at least one number");

            result.IsValid = result.Errors.Count == 0;

            return result.IsValid 
                ? ServiceResult<PasswordValidationResult>.Success(result)
                : ServiceResult<PasswordValidationResult>.Failure(string.Join(", ", result.Errors));
        }

        public async Task<ServiceResult<PasswordPolicy>> GetPasswordPolicyAsync(Guid? organizationId = null)
        {
            // TODO: 조직별 정책 구현
            var policy = new PasswordPolicy
            {
                MinimumLength = 8,
                RequireUppercase = true,
                RequireLowercase = true,
                RequireNumbers = true,
                RequireSpecialCharacters = false,
                ExpirationDays = 90
            };

            return await Task.FromResult(ServiceResult<PasswordPolicy>.Success(policy));
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

        private async Task<Guid> GetOrCreatePersonalOrganizationId(Guid userId)
        {
            var orgKey = $"personal_{userId}";
            var org = await _context.Organizations
                .FirstOrDefaultAsync(o => o.OrganizationKey == orgKey);

            if (org == null)
            {
                var user = await _context.Users.FindAsync(userId);
                org = new Organization
                {
                    OrganizationKey = orgKey,
                    Name = $"{user!.DisplayName}'s Personal Space",
                    Type = OrganizationType.Personal,
                    Status = OrganizationStatus.Active
                };
                _context.Organizations.Add(org);
                await _context.SaveChangesAsync();
            }

            return org.Id;
        }

        private async Task<ConnectedId> GetOrCreateConnectedIdAsync(Guid userId, Guid organizationId)
        {
            var connectedId = await _context.ConnectedIds
                .FirstOrDefaultAsync(c => c.UserId == userId && c.OrganizationId == organizationId);

            if (connectedId == null)
            {
                var request = new CreateConnectedIdRequest
                {
                    UserId = userId,
                    OrganizationId = organizationId,
                    Provider = "local"
                };

                var result = await _connectedIdService.CreateAsync(request);
                connectedId = await _context.ConnectedIds.FindAsync(result.Data!.Id);
            }

            return connectedId!;
        }

        #endregion
    }
}