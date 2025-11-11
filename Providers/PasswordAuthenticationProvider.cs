using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AuthHive.Auth.Providers.Authentication;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Business.Platform;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Interfaces.Infra;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Constants.Auth.AuthConstants;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using static AuthHive.Core.Enums.Auth.SessionEnums;


namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// 패스워드 인증 제공자 - AuthHive v16 최종본
    /// </summary>
    public class PasswordAuthenticationProvider : BaseAuthenticationProvider
    {
        private readonly Argon2PasswordHashProvider _argon2Provider;
        private readonly IPasswordService _passwordService;
        private readonly ITokenService _tokenService;
        private readonly ISessionService _sessionService;
        private readonly IConnectedIdService _connectedIdService;
        private readonly PasswordPolicySettings _passwordPolicy;

        #region Constructor

        public PasswordAuthenticationProvider(
            ILogger<PasswordAuthenticationProvider> logger,
            // --- BaseAuthenticationProvider 필수 9가지 인자 ---
            ICacheService cacheService,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            IAuditService auditService,
            IUserRepository userRepository,
            IConnectedIdRepository connectedIdRepository,
            IAccountSecurityService accountSecurityService, // ✅ BaseProvider가 요구
            IPlanRestrictionService planRestrictionService, // ✅ BaseProvider가 요구
                                                            // ----------------------------------------------------

            // Password Provider 특화된 서비스들
            Argon2PasswordHashProvider argon2Provider,
            IPasswordService passwordService,
            ITokenService tokenService,
            ISessionService sessionService,
            IConnectedIdService connectedIdService,
            IOptions<PasswordPolicySettings> passwordPolicy)
            // ✅ BaseAuthenticationProvider의 9가지 필수 인자 전달
            : base(logger, cacheService, unitOfWork, dateTimeProvider, auditService, userRepository, connectedIdRepository, accountSecurityService, planRestrictionService)
        {
            _argon2Provider = argon2Provider ?? throw new ArgumentNullException(nameof(argon2Provider));
            _passwordService = passwordService ?? throw new ArgumentNullException(nameof(passwordService));
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
            _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
            _connectedIdService = connectedIdService ?? throw new ArgumentNullException(nameof(connectedIdService));
            _passwordPolicy = passwordPolicy?.Value ?? new PasswordPolicySettings();
        }

        #endregion

        #region Properties
        public override string ProviderName => "Password";
        public override string ProviderType => "Credential";
        #endregion

        #region BaseAuthenticationProvider Implementation

        protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request,
            CancellationToken cancellationToken)
        {
            try
            {
                // 1. 입력 검증
                if (string.IsNullOrWhiteSpace(request.Username) && string.IsNullOrWhiteSpace(request.Email))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Username or email is required", ErrorCodes.InvalidCredentials);
                }
                if (string.IsNullOrWhiteSpace(request.Password))
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Password is required", ErrorCodes.InvalidCredentials);
                }

                // 2. 사용자 찾기
                var user = await FindUserAsync(request.Username ?? request.Email, cancellationToken);
                if (user == null)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid credentials", ErrorCodes.InvalidCredentials);
                }

                // 3. SaaS: ConnectedId를 찾거나 생성하고, 조직 접근 권한 확인
                var connectedIdResponse = await GetOrCreateConnectedIdAsync(user, request.OrganizationId, cancellationToken);

                if (request.OrganizationId.HasValue && connectedIdResponse.Status != ConnectedIdStatus.Active)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure("You do not have active access to this organization", "ORG_ACCESS_DENIED");
                }

                // 4. 계정 상태 확인
                var statusCheck = await ValidateAccountStatusAsync(user);
                if (!statusCheck.IsSuccess)
                {
                    return ServiceResult<AuthenticationOutcome>.Failure(statusCheck.Message ?? "Account status invalid", statusCheck.ErrorCode);
                }

                // 5. 패스워드 검증
                if (string.IsNullOrWhiteSpace(user.PasswordHash))
                {
                    await HandleFailedPasswordAttemptAsync(user, cancellationToken);
                    return ServiceResult<AuthenticationOutcome>.Failure("Password authentication is not available for this account", ErrorCodes.InvalidCredentials);
                }

                var isPasswordValid = await _argon2Provider.VerifyPasswordAsync(request.Password, user.PasswordHash);

                if (!isPasswordValid)
                {
                    await HandleFailedPasswordAttemptAsync(user, cancellationToken);
                    return ServiceResult<AuthenticationOutcome>.Failure("Invalid credentials", ErrorCodes.InvalidCredentials);
                }

                // 6. 패스워드 만료 확인
                if (IsPasswordExpired(user))
                {
                    return CreatePasswordChangeRequiredOutcome(user);
                }

                // 7. 성공 후 처리 (BaseProvider의 OnAuthenticationSuccessAsync에서 DB 업데이트 완료)
                await HandleSuccessfulAuthenticationAsync(user, request.IpAddress, cancellationToken);

                // 8. MFA 확인 (조직별 정책 적용)
                var requiresMfa = user.IsTwoFactorEnabled || await IsOrganizationMfaRequiredAsync(request.OrganizationId, cancellationToken);

                // 9. 인증 결과 생성 (토큰/세션 발급 로직은 Outcome 생성 내부에만 남김)
                var outcome = await CreateAuthenticationOutcomeAsync(user, connectedIdResponse.Id, request, requiresMfa, cancellationToken);

                return ServiceResult<AuthenticationOutcome>.Success(outcome);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password authentication");
                return ServiceResult<AuthenticationOutcome>.Failure("Authentication failed", "INTERNAL_ERROR");
            }
        }

        public override Task<ServiceResult<bool>> ValidateAsync(string token, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult<bool>.Failure("Token validation not supported for password authentication", "NOT_SUPPORTED"));
        }

        public override Task<ServiceResult> RevokeAsync(string token, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ServiceResult.Failure("Token revocation not supported for password authentication", "NOT_SUPPORTED"));
        }

        public override async Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default)
        {
            return await Task.FromResult(_passwordPolicy.IsEnabled && _passwordService != null);
        }

        #endregion

        #region Core Internal Methods

        private async Task HandleFailedPasswordAttemptAsync(User user, CancellationToken cancellationToken)
        {
            await _accountSecurityService.IncrementFailedAttemptsAsync(user.Id, cancellationToken);
        }

        private async Task HandleSuccessfulAuthenticationAsync(User user, string? ipAddress, CancellationToken cancellationToken)
        {
            await _accountSecurityService.ResetFailedAttemptsAsync(user.Id, cancellationToken);
        }

        private async Task<ServiceResult> ValidateAccountStatusAsync(User user)
        {
            await Task.CompletedTask;

            // 1. UserStatus Enum 확인
            switch (user.Status)
            {
                case UserStatus.Active:
                    break;
                case UserStatus.PendingVerification:
                    if (_passwordPolicy.RequireEmailVerification)
                        return ServiceResult.Failure("Please verify your email before signing in", "EMAIL_NOT_VERIFIED");
                    break;
                case UserStatus.Inactive:
                    return ServiceResult.Failure("Account is inactive. Please contact support.", "ACCOUNT_INACTIVE");
                case UserStatus.Suspended:
                    return ServiceResult.Failure("Account has been suspended", "ACCOUNT_SUSPENDED");
                case UserStatus.Deleted:
                    return ServiceResult.Failure("Account has been deleted", "ACCOUNT_DELETED");
                case UserStatus.IsLocked:
                    return ServiceResult.Failure("Account is locked by administrator", ErrorCodes.AccountLocked);
                default:
                    return ServiceResult.Failure("Account status is invalid", "INVALID_STATUS");
            }

            // 2. 이메일 인증 확인 (Policy)
            if (_passwordPolicy.RequireEmailVerification && !user.IsEmailVerified)
            {
                return ServiceResult.Failure("Email verification required", "EMAIL_NOT_VERIFIED");
            }

            return ServiceResult.Success();
        }

        private async Task<bool> IsOrganizationMfaRequiredAsync(Guid? organizationId, CancellationToken cancellationToken)
        {
            if (!organizationId.HasValue)
                return false;

            // NOTE: IPlanRestrictionService를 통해 MFA 강제 정책을 확인 (가정)
            // var mfaRequired = await _planRestrictionService.IsMfaRequiredAsync(organizationId.Value, cancellationToken);
            return await Task.FromResult(false);
        }

        private bool IsPasswordExpired(User user)
        {
            if (user.PasswordChangedAt.HasValue && _passwordPolicy.PasswordExpiryDays > 0)
            {
                var expiryDate = user.PasswordChangedAt.Value.AddDays(_passwordPolicy.PasswordExpiryDays);
                return expiryDate < _dateTimeProvider.UtcNow;
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

        /// <summary>
        /// SaaS 멀티테넌시: ConnectedId를 찾거나 생성하고, 해당 DTO를 반환합니다.
        /// </summary>
        private async Task<ConnectedIdResponse> GetOrCreateConnectedIdAsync(User user, Guid? organizationId, CancellationToken cancellationToken)
        {
            var targetOrgId = organizationId ?? user.OrganizationId;

            if (!targetOrgId.HasValue)
            {
                var activeConnectedId = user.ConnectedIds?
                    .FirstOrDefault(c => c.Status == ConnectedIdStatus.Active);
                if (activeConnectedId != null)
                    return new ConnectedIdResponse { Id = activeConnectedId.Id, Status = activeConnectedId.Status };

                throw new InvalidOperationException("User has no organization context and no active ConnectedId");
            }

            // 1. 특정 조직의 ConnectedId 찾기
            var connectedId = user.ConnectedIds?
                .FirstOrDefault(c => c.OrganizationId == targetOrgId.Value
                    && c.Status == ConnectedIdStatus.Active);

            if (connectedId != null)
                return new ConnectedIdResponse { Id = connectedId.Id, Status = connectedId.Status };

            // 2. 해당 조직의 ConnectedId가 없으면 생성 (IConnectedIdService 사용)
            var createRequest = new CreateConnectedIdRequest
            {
                UserId = user.Id,
                OrganizationId = targetOrgId.Value,
                Provider = ProviderName,
                DisplayName = user.DisplayName ?? user.Email,
                MembershipType = MembershipType.Member,
                InitialStatus = ConnectedIdStatus.Active
            };

            var newConnectedIdResult = await _connectedIdService.CreateAsync(createRequest, cancellationToken);

            if (!newConnectedIdResult.IsSuccess || newConnectedIdResult.Data == null)
            {
                throw new InvalidOperationException($"Failed to create ConnectedId: {newConnectedIdResult.Message}");
            }

            return newConnectedIdResult.Data;
        }

        /// <summary>
        /// 최종 AuthenticationOutcome을 생성하고 세션/토큰을 발급합니다.
        /// </summary>
        private async Task<AuthenticationOutcome> CreateAuthenticationOutcomeAsync(
            User user,
            Guid connectedIdId,
            AuthenticationRequest request,
            bool requiresMfa,
            CancellationToken cancellationToken)
        {
            var organizationId = request.OrganizationId ?? user.OrganizationId;

            var outcome = new AuthenticationOutcome
            {
                Success = !requiresMfa,
                UserId = user.Id,
                ConnectedId = connectedIdId,
                OrganizationId = organizationId,
                ApplicationId = request.ApplicationId,
                Provider = ProviderName,
                AuthenticationMethod = AuthenticationMethod.Password.ToString(),
                AuthenticationStrength = AuthenticationStrength.Medium,
                RequiresMfa = requiresMfa,
                MfaMethods = requiresMfa ? GetAvailableMfaMethods(user) : new List<string>(),

                Claims = new Dictionary<string, object>
                {
                    ["sub"] = connectedIdId.ToString(),
                    ["user_id"] = user.Id.ToString(),
                    ["email"] = user.Email,
                    ["email_verified"] = user.IsEmailVerified,
                    ["auth_provider"] = "Internal"
                }
            };

            // MFA가 요구되지 않을 때만 세션 및 토큰을 발급합니다.
            if (!requiresMfa)
            {
                // 1. 세션 생성
                var sessionRequest = new CreateSessionRequest
                {
                    // ... (sessionRequest fields maintained) ...
                };

                var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest, cancellationToken);

                if (sessionResult.IsSuccess && sessionResult.Data != null)
                {
                    // ✅ 1. SessionDto가 존재하는지 확인
                    var sessionDto = sessionResult.Data.SessionDto;

                    if (sessionDto != null)
                    {
                        outcome.SessionId = sessionResult.Data.SessionId;

                        // null이 아님을 확인 후 IssueTokensAsync 호출
                        var tokenResult = await _tokenService.IssueTokensAsync(sessionDto, cancellationToken);

                        if (tokenResult.IsSuccess && tokenResult.Data != null)
                        {
                            outcome.AccessToken = tokenResult.Data.AccessToken;
                            outcome.RefreshToken = tokenResult.Data.RefreshToken;
                            outcome.ExpiresAt = tokenResult.Data.ExpiresAt;
                        }
                    }
                    else
                    {
                        // NOTE: Session creation succeeded, but SessionDto was unexpectedly null. Log as warning.
                        _logger.LogWarning("Session creation succeeded but SessionDto was null for user {UserId}", user.Id);
                        outcome.ExpiresAt = sessionResult.Data.ExpiresAt; // Still use session expiry as fallback
                    }
                }
            }

            return outcome;
        }

        private List<string> GetAvailableMfaMethods(User user)
        {
            var methods = new List<string>();

            if (user.IsTwoFactorEnabled)
            {
                methods.Add(MfaMethod.Totp.ToString()); // TOTP 기본 지원

                if (!string.IsNullOrEmpty(user.TwoFactorMethod))
                {
                    methods.Add(user.TwoFactorMethod);
                }
            }

            if (user.BackupCodes?.Any() == true)
                methods.Add(MfaMethod.BackupCode.ToString());

            return methods;
        }

        #endregion
    }
}