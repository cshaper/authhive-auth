using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Providers.Authentication;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Constants.Auth;
using System.Collections.Generic;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Models.Organization.Common;

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// 패스워드 인증 제공자 - AuthHive v15
    /// BaseAuthenticationProvider를 상속받아 구현
    /// Argon2PasswordProvider를 내부적으로 사용하여 패스워드 처리
    /// </summary>
    public class PasswordAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly Argon2PasswordProvider _argon2Provider;
        private readonly IPasswordService _passwordService;
        private readonly ITokenService _tokenService;
        private readonly PasswordPolicySettings _passwordPolicy;

        #region Constructor

        public PasswordAuthenticationProvider(
            ILogger<PasswordAuthenticationProvider> logger,
            IDistributedCache cache,
            IAuthenticationAttemptLogRepository attemptLogRepository,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            AuthDbContext context,
            Argon2PasswordProvider argon2Provider,
            IPasswordService passwordService,
            ITokenService tokenService,
            IOptions<PasswordPolicySettings> passwordPolicy)
            : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
        {
            _argon2Provider = argon2Provider ?? throw new ArgumentNullException(nameof(argon2Provider));
            _passwordService = passwordService ?? throw new ArgumentNullException(nameof(passwordService));
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
            _passwordPolicy = passwordPolicy?.Value ?? new PasswordPolicySettings();
        }

        #endregion

        #region Properties

        public override string ProviderName => "Password";
        public override string ProviderType => "Credential";

        #endregion

        #region BaseAuthenticationProvider Implementation

        /// <summary>
        /// 실제 패스워드 인증 수행 - SaaS 멀티테넌시 지원
        /// </summary>
        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request)
        {
            try
            {
                // 1. 입력 검증
                if (string.IsNullOrWhiteSpace(request.Username) && string.IsNullOrWhiteSpace(request.Email))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        "Username or email is required",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                if (string.IsNullOrWhiteSpace(request.Password))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        "Password is required",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 2. 사용자 찾기 (조직 컨텍스트 고려)
                var userProfile = await FindUserProfileAsync(request);
                if (userProfile == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        "Invalid credentials",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                var user = userProfile.User;

                // 3. SaaS: 조직 접근 권한 확인
                if (request.OrganizationId.HasValue)
                {
                    var hasOrgAccess = user.ConnectedIds?
                        .Any(c => c.OrganizationId == request.OrganizationId.Value
                            && c.Status == ConnectedIdStatus.Active) ?? false;

                    if (!hasOrgAccess)
                    {
                        return ServiceResult<AuthenticationOutcome>.Failure(
                            "You do not have access to this organization",
                            "ORG_ACCESS_DENIED");
                    }
                }

                // 4. 계정 상태 확인
                var statusCheck = await ValidateAccountStatusAsync(user);
                if (!statusCheck.IsSuccess)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        statusCheck.Message ?? "Account status invalid",
                        statusCheck.ErrorCode);
                }
                // 4. 패스워드 해시 존재 확인
                if (string.IsNullOrWhiteSpace(user.PasswordHash))
                {
                    // 패스워드가 설정되지 않은 계정 (예: 소셜 로그인 전용 계정)
                    await HandleFailedPasswordAttemptAsync(user);
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        "Password authentication is not available for this account",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }
                // 5. 패스워드 검증 (Argon2Provider 사용)
                var isPasswordValid = await _argon2Provider.VerifyPasswordAsync(
                    request.Password,
                    user.PasswordHash);

                if (!isPasswordValid)
                {
                    await HandleFailedPasswordAttemptAsync(user);
                    return ServiceResult<AuthenticationOutcome>.Failure(
                        "Invalid credentials",
                        AuthConstants.ErrorCodes.InvalidCredentials);
                }

                // 6. 패스워드 만료 확인
                if (IsPasswordExpired(user))
                {
                    return CreatePasswordChangeRequiredOutcome(user);
                }

                // 7. SaaS: 조직별 ConnectedId 가져오기 또는 생성
                var connectedId = await GetOrCreateConnectedIdAsync(user, request.OrganizationId);

                // 8. 성공 처리
                await HandleSuccessfulAuthenticationAsync(user);

                // 9. SaaS: ConnectedId 활동 업데이트
                await UpdateConnectedIdActivityAsync(connectedId);

                // 10. 인증 결과 생성 (조직 컨텍스트 포함)
                var outcome = await CreateAuthenticationOutcomeAsync(user, connectedId, request);

                // 11. MFA 확인 (조직별 정책 적용 가능)
                if (user.IsTwoFactorEnabled || await IsOrganizationMfaRequiredAsync(request.OrganizationId))
                {
                    outcome.RequiresMfa = true;
                    outcome.MfaMethods = GetAvailableMfaMethods(user);
                    outcome.Success = false; // MFA 완료 전까지는 부분 성공
                    outcome.Message = "MFA verification required";
                }

                return ServiceResult<AuthenticationOutcome>.Success(outcome);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password authentication");
                return ServiceResult<AuthenticationOutcome>.Failure(
                    "Authentication failed",
                    "INTERNAL_ERROR");
            }
        }

        /// <summary>
        /// ConnectedId 활동 시간 업데이트
        /// </summary>
        private async Task UpdateConnectedIdActivityAsync(Guid connectedId)
        {
            var entity = await _context.ConnectedIds.FindAsync(connectedId);
            if (entity != null)
            {
                entity.UpdateLastActivity();
                await _context.SaveChangesAsync();
            }
        }

        /// <summary>
        /// 조직의 MFA 정책 확인
        /// </summary>
        private async Task<bool> IsOrganizationMfaRequiredAsync(Guid? organizationId)
        {
            if (!organizationId.HasValue)
                return false;

            var org = await _context.Organizations
                .FirstOrDefaultAsync(o => o.Id == organizationId.Value);

            // 조직의 보안 정책에 따라 MFA 요구 (실제 구현 시 정책 테이블 참조)
            return org?.IsMFARequired ?? false;
        }

        /// <summary>
        /// 사용자 프로필 찾기
        /// </summary>
        protected override async Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request)
        {
            // Username 또는 Email로 검색
            var identifier = request.Username ?? request.Email;
            if (string.IsNullOrWhiteSpace(identifier))
                return null;

            var query = _context.UserProfiles
                .Include(p => p.User)
                    .ThenInclude(u => u.ConnectedIds)
                .AsQueryable();

            // 조직 컨텍스트가 있는 경우
            if (request.OrganizationId.HasValue)
            {
                query = query.Where(p => p.User.OrganizationId == request.OrganizationId);
            }

            // Email 형식인지 확인
            if (identifier.Contains("@"))
            {
                return await query.FirstOrDefaultAsync(p =>
                    p.User.Email == identifier);
            }
            else
            {
                // Username 또는 DisplayName으로 검색
                return await query.FirstOrDefaultAsync(p =>
                    p.User.Username == identifier ||
                    p.User.DisplayName == identifier ||
                    p.User.Email == identifier);
            }
        }

        #endregion

        #region IAuthenticationProvider Implementation

        public override async Task<ServiceResult<bool>> ValidateAsync(string token)
        {
            // 패스워드 인증은 토큰 검증 미지원
            return await Task.FromResult(
                ServiceResult<bool>.Failure("Token validation not supported for password authentication"));
        }

        public override async Task<ServiceResult> RevokeAsync(string token)
        {
            // 패스워드 인증은 토큰 취소 미지원
            return await Task.FromResult(
                ServiceResult.Failure("Token revocation not supported for password authentication"));
        }

        public override async Task<bool> IsEnabledAsync()
        {
            return await Task.FromResult(_passwordPolicy.IsEnabled);
        }

        #endregion

        #region Private Methods

        private async Task<ServiceResult> ValidateAccountStatusAsync(User user)
        {
            // 계정 상태 확인 - UserStatus enum 사용
            switch (user.Status)
            {
                case UserStatus.Active:
                    // Active 상태는 통과
                    break;

                case UserStatus.PendingVerification:
                    // 이메일 인증 대기 중인 경우, 정책에 따라 허용 또는 차단
                    if (_passwordPolicy.RequireEmailVerification)
                    {
                        return ServiceResult.Failure(
                            "Please verify your email before signing in",
                            "EMAIL_NOT_VERIFIED");
                    }
                    break;

                case UserStatus.Inactive:
                    return ServiceResult.Failure(
                        "Account is inactive. Please contact support.",
                        "ACCOUNT_INACTIVE");

                case UserStatus.Suspended:
                    return ServiceResult.Failure(
                        "Account has been suspended",
                        "ACCOUNT_SUSPENDED");

                case UserStatus.Deleted:
                    return ServiceResult.Failure(
                        "Account has been deleted",
                        "ACCOUNT_DELETED");

                case UserStatus.IsLocked:
                    // Locked 상태는 계정 잠금과는 별개로 관리자가 설정한 영구 잠금
                    return ServiceResult.Failure(
                        "Account is locked by administrator",
                        AuthConstants.ErrorCodes.AccountLocked);

                default:
                    return ServiceResult.Failure(
                        "Account status is invalid",
                        "INVALID_STATUS");
            }

            // 임시 계정 잠금 확인 (IsAccountLocked 필드)
            if (user.IsAccountLocked)
            {
                if (user.AccountLockedUntil.HasValue && user.AccountLockedUntil > DateTime.UtcNow)
                {
                    var remainingTime = user.AccountLockedUntil.Value - DateTime.UtcNow;
                    return ServiceResult.Failure(
                        $"Account is temporarily locked. Try again in {Math.Ceiling(remainingTime.TotalMinutes)} minutes",
                        AuthConstants.ErrorCodes.AccountLocked);
                }

                // 잠금 기간 만료 - 자동 해제
                user.IsAccountLocked = false;
                user.AccountLockedUntil = null;
                await _context.SaveChangesAsync();
            }

            // 이메일 인증 확인 (PendingVerification이 아닌 경우에도)
            if (_passwordPolicy.RequireEmailVerification && !user.IsEmailVerified)
            {
                return ServiceResult.Failure(
                    "Email verification required",
                    "EMAIL_NOT_VERIFIED");
            }

            return ServiceResult.Success();
        }

        private async Task HandleFailedPasswordAttemptAsync(User user)
        {
            // User 엔티티에 FailedLoginAttempts 필드가 없으므로
            // AuthenticationAttemptLog를 통해 실패 횟수를 추적
            var failureCount = await _attemptLogRepository.GetConsecutiveFailureCountAsync(user.Id);

            // 계정 임시 잠금 확인
            if (failureCount >= _passwordPolicy.MaxFailedAttempts - 1)
            {
                user.IsAccountLocked = true;
                user.AccountLockedUntil = DateTime.UtcNow.AddMinutes(_passwordPolicy.LockoutDurationMinutes);
                // Status는 변경하지 않음 - 임시 잠금과 영구 잠금(Status.Locked)은 별개
            }

            await _context.SaveChangesAsync();
        }

        private async Task HandleSuccessfulAuthenticationAsync(User user)
        {
            user.LastLoginAt = DateTime.UtcNow;
            user.IsAccountLocked = false;
            user.AccountLockedUntil = null;

            if (!user.FirstLoginAt.HasValue)
            {
                user.FirstLoginAt = DateTime.UtcNow;
            }

            // Status 변경 제거 - Locked 상태는 관리자가 수동으로 해제해야 함
            // PendingVerification 상태도 이메일 인증 후에만 Active로 변경되어야 함

            // LoginCount 증가
            user.LoginCount = (user.LoginCount ?? 0) + 1;

            // LastActivity 업데이트
            user.LastActivity = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        private bool IsPasswordExpired(User user)
        {
            // PasswordChangedAt이 User 엔티티에 있다면 사용
            if (user.PasswordChangedAt.HasValue && _passwordPolicy.PasswordExpiryDays > 0)
            {
                var expiryDate = user.PasswordChangedAt.Value.AddDays(_passwordPolicy.PasswordExpiryDays);
                return expiryDate < DateTime.UtcNow;
            }

            return false;
        }

        private ServiceResult<AuthenticationOutcome> CreatePasswordChangeRequiredOutcome(User user)
        {
            var outcome = new AuthenticationOutcome
            {
                Success = false,
                UserId = user.Id,
                RequiresPasswordChange = true,
                Message = "Password has expired and needs to be changed"
            };

            return ServiceResult<AuthenticationOutcome>.Success(outcome);
        }

        private async Task<Guid> GetOrCreateConnectedIdAsync(User user, Guid? organizationId)
        {
            // SaaS 멀티테넌시: 조직별 ConnectedId 처리

            // 1. 조직 컨텍스트가 없는 경우 (전역 인증)
            if (!organizationId.HasValue)
            {
                // 사용자의 기본 조직 사용
                organizationId = user.OrganizationId;
                if (!organizationId.HasValue)
                {
                    // 조직이 없으면 첫 번째 활성 ConnectedId 반환
                    var activeConnectedId = user.ConnectedIds?
                        .FirstOrDefault(c => c.Status == ConnectedIdStatus.Active);
                    if (activeConnectedId != null)
                        return activeConnectedId.Id;

                    // ConnectedId가 없으면 오류
                    throw new InvalidOperationException("User has no organization context and no active ConnectedId");
                }
            }

            // 2. 특정 조직의 ConnectedId 찾기
            var connectedId = user.ConnectedIds?
                .FirstOrDefault(c => c.OrganizationId == organizationId.Value
                    && c.Status == ConnectedIdStatus.Active);

            if (connectedId != null)
                return connectedId.Id;

            // 3. 해당 조직의 ConnectedId가 없으면 생성
            var createRequest = new CreateConnectedIdRequest
            {
                UserId = user.Id,
                OrganizationId = organizationId.Value,
                Provider = "Internal",
                DisplayName = user.DisplayName ?? user.Email,
                MembershipType = MembershipType.Member, // 기본 멤버십 타입
                InitialStatus = ConnectedIdStatus.Active
            };

            var newConnectedId = await _connectedIdService.CreateAsync(createRequest);

            if (!newConnectedId.IsSuccess)
            {
                throw new InvalidOperationException($"Failed to create ConnectedId: {newConnectedId.Message}");
            }

            return newConnectedId.Data?.Id ?? throw new InvalidOperationException("ConnectedId data is null");
        }

        private async Task<AuthenticationOutcome> CreateAuthenticationOutcomeAsync(
            User user,
            Guid connectedId,
            AuthenticationRequest request)
        {
            // SaaS 멀티테넌시: 조직 컨텍스트 확인
            var organizationId = request.OrganizationId ?? user.OrganizationId;

            var outcome = new AuthenticationOutcome
            {
                Success = true,
                UserId = user.Id,
                ConnectedId = connectedId,
                OrganizationId = organizationId,
                ApplicationId = request.ApplicationId,
                Provider = ProviderName,
                AuthenticationMethod = "Password",
                AuthenticationStrength = AuthenticationStrength.Medium,
                IsFirstLogin = !user.LastLoginAt.HasValue || user.FirstLoginAt == user.LastLoginAt,
                RequiresPasswordChange = user.RequiresPasswordChange,
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = connectedId.ToString(), // SaaS: ConnectedId를 subject로 사용
                    ["user_id"] = user.Id.ToString(),
                    ["email"] = user.Email,
                    ["email_verified"] = user.IsEmailVerified,
                    ["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    ["auth_provider"] = "Internal"
                }
            };

            // 조직 정보 추가
            if (organizationId.HasValue)
            {
                outcome.Claims["org_id"] = organizationId.Value.ToString();

                // ConnectedId의 조직 내 역할 조회
                var connectedEntity = await _context.ConnectedIds
                    .Include(c => c.RoleAssignments)
                    .FirstOrDefaultAsync(c => c.Id == connectedId);

                if (connectedEntity != null)
                {
                    outcome.Claims["membership_type"] = connectedEntity.MembershipType.ToString();
                    outcome.Claims["connected_status"] = connectedEntity.Status.ToString();

                    // 역할 정보
                    if (connectedEntity.RoleAssignments?.Any() == true)
                    {
                        var roles = connectedEntity.RoleAssignments
                            .Select(r => r.RoleId.ToString())
                            .ToList();
                        outcome.Claims["roles"] = string.Join(",", roles);
                    }
                }
            }

            // 사용자 표시 이름 추가
            if (!string.IsNullOrEmpty(user.DisplayName))
            {
                outcome.Claims["name"] = user.DisplayName;
            }
            else if (!string.IsNullOrEmpty(user.Username))
            {
                outcome.Claims["name"] = user.Username;
            }

            // 세션 생성 - ConnectedId 기반
            // ConnectedId로부터 UserId 가져오기
            var connectedIdEntity = await _context.ConnectedIds
                .FirstOrDefaultAsync(c => c.Id == connectedId);

            var sessionRequest = new CreateSessionRequest
            {
                UserId = connectedIdEntity?.UserId ?? user.Id, // UserId 필수 필드
                ConnectedId = connectedId, // ConnectedId 설정
                OrganizationId = organizationId,
                ApplicationId = request.ApplicationId,
                SessionType = SessionType.Web,
                Level = organizationId.HasValue ? SessionLevel.Organization : SessionLevel.Global,
                IPAddress = request.IpAddress,
                UserAgent = request.UserAgent,
                DeviceInfo = request.DeviceInfo,
                Browser = request.DeviceInfo?.Browser,
                OperatingSystem = request.DeviceInfo?.OperatingSystem,
                Location = request.DeviceInfo?.Location,
                ExpiresAt = DateTime.UtcNow.AddHours(24),
                InitialStatus = SessionStatus.Active,
                InitialRiskScore = 0,
                Provider = "Internal",
                AuthenticationMethod = AuthenticationMethod.Password,
                IsBiometric = false,
                SecurityLevel = SessionSecurityLevel.Enhanced,
                EnableGrpc = false,
                EnablePubSubNotifications = true,
                EnablePermissionCache = true
            };

            var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest);

            if (sessionResult.IsSuccess && sessionResult.Data != null)
            {
                outcome.SessionId = sessionResult.Data.SessionId;
                // SessionToken은 내부 세션 관리용이므로 outcome에 포함하지 않음
                // JWT AccessToken이 실제 인증 토큰 역할

                // SessionDto로부터 JWT 토큰 발급
                if (sessionResult.Data?.SessionDto != null)
                {
                    var tokenResult = await _tokenService.IssueTokensAsync(sessionResult.Data.SessionDto);
                    if (tokenResult.IsSuccess && tokenResult.Data != null)
                    {
                        outcome.AccessToken = tokenResult.Data.AccessToken;
                        outcome.RefreshToken = tokenResult.Data.RefreshToken;
                        // ExpiresAt은 토큰 만료 시간으로 업데이트
                        outcome.ExpiresAt = tokenResult.Data.ExpiresAt;
                    }
                }
                else
                {
                    // SessionDto가 없는 경우 기본 만료 시간 설정
                    // SessionDto가 없는 경우 기본 만료 시간 설정
                    outcome.ExpiresAt = sessionResult.Data?.ExpiresAt;
                }
            }

            return outcome;
        }

        private List<string> GetAvailableMfaMethods(User user)
        {
            var methods = new List<string>();

            if (user.IsTwoFactorEnabled)
            {
                methods.Add("TOTP");

                // TwoFactorMethod 필드 확인
                if (!string.IsNullOrEmpty(user.TwoFactorMethod))
                {
                    methods.Add(user.TwoFactorMethod);
                }
            }

            if (user.BackupCodes?.Any() == true)
                methods.Add("BackupCode");

            return methods;
        }

        #endregion
    }
}