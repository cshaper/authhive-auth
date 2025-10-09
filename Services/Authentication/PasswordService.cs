// Path: AuthHive.Auth/Services/Authentication/PasswordService.cs
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
using AuthHive.Core.Entities.Organization;
using System.Text;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Enums.Core;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Auth;
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Services.Authentication
{
    public class PasswordService : IPasswordService
    {
        private readonly AuthDbContext _context;
        private readonly IConnectedIdService _connectedIdService;
        private readonly ISessionService _sessionService;
        private readonly ITokenService _tokenService;
        private readonly IAccountSecurityService _accountSecurityService; // 추가된 의존성
        private readonly ILogger<PasswordService> _logger;

        public PasswordService(
            AuthDbContext context,
            IConnectedIdService connectedIdService,
            ISessionService sessionService,
            ITokenService tokenService,
            IAccountSecurityService accountSecurityService, // 추가된 매개변수
            ILogger<PasswordService> logger)
        {
            _context = context;
            _connectedIdService = connectedIdService;
            _sessionService = sessionService;
            _tokenService = tokenService;
            _accountSecurityService = accountSecurityService; // 할당
            _logger = logger;
        }

        // IService 구현
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken을 Database.CanConnectAsync()에 전달합니다.
                return await _context.Database.CanConnectAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "PasswordService health check failed");
                return false;
            }
        }

        // CancellationToken을 추가하고, 효율적인 Task.CompletedTask 반환을 유지합니다.
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

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

                // AccountSecurityService를 통한 패스워드 검증
                var validationResult = await ValidatePasswordAsync(password, organizationId);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<AuthenticationResponse>.Failure(validationResult.ErrorMessage ?? "Invalid password");
                }

                // 사용자 생성
                var user = new UserEntity
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
                    IpAddress = CommonDefaults.DefaultLocalIpV4,
                    UserAgent = CommonDefaults.RegistrationUserAgent
                };

                var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest);
                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to create session");
                }

                // SessionDto null 체크 추가
                if (sessionResult.Data.SessionDto == null)
                {
                    _logger.LogError("SessionDto is null after session creation for user {Email}", email);
                    return ServiceResult<AuthenticationResponse>.Failure("Session data is incomplete");
                }

                // SessionDto를 변수에 저장하여 안전하게 사용
                var sessionDto = sessionResult.Data.SessionDto;

                // 토큰 발급
                var tokenResult = await _tokenService.IssueTokensAsync(sessionDto);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to issue tokens");
                }

                return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedIdResult.Data.Id,
                    SessionId = sessionDto.Id,  // 안전하게 접근
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
                    IpAddress = CommonDefaults.DefaultLocalIpV4, // TODO: 실제 IP
                    UserAgent = CommonDefaults.PasswordAuthUserAgent
                };

                var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest);
                if (!sessionResult.IsSuccess || sessionResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to create session");
                }

                // SessionDto null 체크 추가
                if (sessionResult.Data.SessionDto == null)
                {
                    _logger.LogError("SessionDto is null after session creation for user {Username}", username);
                    return ServiceResult<AuthenticationResponse>.Failure("Session data is incomplete");
                }

                // SessionDto를 변수에 저장
                var sessionDto = sessionResult.Data.SessionDto;

                // 토큰 발급
                var tokenResult = await _tokenService.IssueTokensAsync(sessionDto);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Failed to issue tokens");
                }

                return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedId.Id,
                    SessionId = sessionDto.Id,  // 안전하게 접근
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

                // AccountSecurityService를 통한 패스워드 검증
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

        /// <summary>
        /// AccountSecurityService를 통한 패스워드 검증 (위임)
        /// </summary>
        public async Task<ServiceResult<PasswordValidationResult>> ValidatePasswordAsync(
            string password,
            Guid? organizationId = null)
        {
            try
            {
                _logger.LogDebug("Delegating password validation to AccountSecurityService for organization {OrganizationId}", organizationId);

                // AccountSecurityService의 패스워드 정책 조회
                var policyResult = await _accountSecurityService.GetPasswordPolicyAsync(organizationId);
                if (!policyResult.IsSuccess || policyResult.Data == null)
                {
                    _logger.LogWarning("Failed to get password policy from AccountSecurityService, using fallback validation");
                    return await FallbackPasswordValidation(password);
                }

                var policy = policyResult.Data;
                var result = new PasswordValidationResult
                {
                    IsValid = true,
                    Errors = new List<string>()
                };

                // 정책 기반 검증
                if (password.Length < policy.MinimumLength)
                    result.Errors.Add($"Password must be at least {policy.MinimumLength} characters");

                if (password.Length > policy.MaximumLength)
                    result.Errors.Add($"Password must not exceed {policy.MaximumLength} characters");

                if (policy.RequireUppercase && !password.Any(char.IsUpper))
                    result.Errors.Add("Password must contain at least one uppercase letter");

                if (policy.RequireLowercase && !password.Any(char.IsLower))
                    result.Errors.Add("Password must contain at least one lowercase letter");

                if (policy.RequireNumbers && !password.Any(char.IsDigit))
                    result.Errors.Add("Password must contain at least one number");

                if (policy.RequireSpecialCharacters && !password.Any(c => !char.IsLetterOrDigit(c)))
                    result.Errors.Add("Password must contain at least one special character");

                // 고유 문자 수 검증
                if (policy.MinimumUniqueCharacters > 0)
                {
                    var uniqueChars = password.Distinct().Count();
                    if (uniqueChars < policy.MinimumUniqueCharacters)
                        result.Errors.Add($"Password must contain at least {policy.MinimumUniqueCharacters} unique characters");
                }

                // 일반적인 패스워드 방지
                if (policy.PreventCommonPasswords && IsCommonPassword(password))
                    result.Errors.Add("Password is too common. Please choose a more secure password");

                result.IsValid = result.Errors.Count == 0;

                return result.IsValid
                    ? ServiceResult<PasswordValidationResult>.Success(result)
                    : ServiceResult<PasswordValidationResult>.Failure(string.Join(", ", result.Errors));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Password validation failed, falling back to basic validation");
                return await FallbackPasswordValidation(password);
            }
        }

        /// <summary>
        /// AccountSecurityService를 통한 패스워드 정책 조회 (위임)
        /// </summary>
        public async Task<ServiceResult<PasswordPolicyDto>> GetPasswordPolicyAsync(Guid? organizationId = null)
        {
            try
            {
                _logger.LogDebug("Delegating password policy retrieval to AccountSecurityService for organization {OrganizationId}", organizationId);

                // AccountSecurityService로 완전히 위임
                var result = await _accountSecurityService.GetPasswordPolicyAsync(organizationId);

                if (result.IsSuccess)
                {
                    _logger.LogDebug("Successfully retrieved password policy from AccountSecurityService");
                }
                else
                {
                    _logger.LogWarning("Failed to get password policy from AccountSecurityService: {Error}", result.ErrorMessage);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delegate password policy retrieval to AccountSecurityService");
                return ServiceResult<PasswordPolicyDto>.Failure("Failed to retrieve password policy");
            }
        }

        #region Private Helper Methods

        /// <summary>
        /// 폴백 패스워드 검증 (AccountSecurityService 사용 불가시)
        /// </summary>
        private async Task<ServiceResult<PasswordValidationResult>> FallbackPasswordValidation(string password)
        {
            await Task.CompletedTask; // 비동기 시그니처 유지

            var result = new PasswordValidationResult
            {
                IsValid = true,
                Errors = new List<string>()
            };

            // 기본 검증 규칙
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

        /// <summary>
        /// 일반적인 패스워드 확인
        /// </summary>
        private bool IsCommonPassword(string password)
        {
            var commonPasswords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "password", "123456", "password123", "admin", "qwerty",
                "letmein", "welcome", "monkey", "dragon", "master"
            };

            return commonPasswords.Contains(password);
        }

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

                // null 체크 추가
                if (user == null)
                {
                    throw new InvalidOperationException($"User with ID {userId} not found");
                    // 또는 기본값 사용
                    // throw new NotFoundException($"User with ID {userId} not found");
                }

                org = new AuthHive.Core.Entities.Organization.Organization
                {
                    OrganizationKey = orgKey,
                    Name = $"{user.DisplayName ?? user.Username}'s Personal Space",  // DisplayName이 null일 수도 있음
                    Type = OrganizationType.Personal,
                    Status = OrganizationStatus.Active
                };

                _context.Organizations.Add(org);
                await _context.SaveChangesAsync();
            }

            return org.Id;
        }
        private async Task<Core.Entities.Auth.ConnectedId> GetOrCreateConnectedIdAsync(Guid userId, Guid organizationId)
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