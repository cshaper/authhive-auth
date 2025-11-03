using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Auth.Data.Context;
using static AuthHive.Core.Enums.Core.UserEnums;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Enums.Core;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Auth;
using UserEntity = AuthHive.Core.Entities.User.User;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

// --- 모든 필수 네임스페이스 ---
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Security;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Events;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using static AuthHive.Core.Constants.Auth.AuthConstants;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// IPasswordService의 구현체.
    /// 패스워드 기반의 사용자 등록, 인증, 재설정, 변경 등 핵심 로직을 담당합니다.
    /// </summary>
    public class PasswordService : IPasswordService
    {
        private readonly AuthDbContext _context;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly IPasswordHashProvider _passwordHashProvider;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ICacheService _cacheService;
        private readonly IConnectedIdService _connectedIdService;
        private readonly ISessionService _sessionService;
        private readonly ITokenService _tokenService;
        private readonly IAccountSecurityService _accountSecurityService;
        private readonly ILogger<PasswordService> _logger;

        public PasswordService(
            AuthDbContext context,
            IUnitOfWork unitOfWork,
            IPrincipalAccessor principalAccessor,
            IPasswordHashProvider passwordHashProvider,
            IAuditService auditService,
            IEventBus eventBus,
            IDateTimeProvider dateTimeProvider,
            ICacheService cacheService,
            IConnectedIdService connectedIdService,
            ISessionService sessionService,
            ITokenService tokenService,
            IAccountSecurityService accountSecurityService,
            ILogger<PasswordService> logger)
        {
            _context = context;
            _unitOfWork = unitOfWork;
            _principalAccessor = principalAccessor;
            _passwordHashProvider = passwordHashProvider;
            _auditService = auditService;
            _eventBus = eventBus;
            _dateTimeProvider = dateTimeProvider;
            _cacheService = cacheService;
            _connectedIdService = connectedIdService;
            _sessionService = sessionService;
            _tokenService = tokenService;
            _accountSecurityService = accountSecurityService;
            _logger = logger;
        }

        #region IService 구현
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // CancellationToken을 DB 연결 확인에 전달합니다.
                return await _context.Database.CanConnectAsync(cancellationToken);
            }
            catch (OperationCanceledException) { return false; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "PasswordService 상태 확인(Health check) 실패");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        #endregion

        #region 핵심 인증 로직
        public async Task<ServiceResult<AuthenticationResult>> RegisterAsync(
            string email,
            string password,
            string displayName,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                if (await _context.Users.AnyAsync(u => u.Email == email, cancellationToken))
                {
                    return ServiceResult<AuthenticationResult>.Failure("이미 존재하는 이메일입니다.");
                }

                var validationResult = await ValidatePasswordAsync(password, organizationId, cancellationToken);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<AuthenticationResult>.Failure(validationResult.ErrorMessage ?? "유효하지 않은 패스워드입니다.");
                }

                var user = new UserEntity
                {
                    Email = email,
                    DisplayName = displayName,
                    PasswordHash = await _passwordHashProvider.HashPasswordAsync(password),
                    Status = UserStatus.Active,
                    EmailVerified = false
                };
                _context.Users.Add(user);

                var targetOrgId = organizationId ?? await GetOrCreatePersonalOrganizationId(user.Id, cancellationToken);

                var connectedIdRequest = new CreateConnectedIdRequest { UserId = user.Id, OrganizationId = targetOrgId, Provider = "local" };
                var connectedIdResult = await _connectedIdService.CreateAsync(connectedIdRequest, cancellationToken);
                if (!connectedIdResult.IsSuccess || connectedIdResult.Data == null)
                {
                    throw new InvalidOperationException("ConnectedId 생성에 실패했습니다.");
                }

                var ipAddress = _principalAccessor.IpAddress ?? CommonDefaults.DefaultLocalIpV4;
                var sessionRequest = new CreateSessionRequest { ConnectedId = connectedIdResult.Data.Id, OrganizationId = targetOrgId, IpAddress = ipAddress, UserAgent = CommonDefaults.RegistrationUserAgent };
                var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest, cancellationToken);
                if (!sessionResult.IsSuccess || sessionResult.Data?.SessionDto == null)
                {
                    throw new InvalidOperationException("세션 생성에 실패했습니다.");
                }

                var sessionDto = sessionResult.Data.SessionDto;
                var tokenResult = await _tokenService.IssueTokensAsync(sessionDto, cancellationToken);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    throw new InvalidOperationException("토큰 발급에 실패했습니다.");
                }

                // 감사 로그 기록
                await _auditService.LogActionAsync(
                    actionType: AuditActionType.UserRegistration,
                    action: "User registered with password",
                    connectedId: connectedIdResult.Data.Id,
                    resourceType: "User",
                    resourceId: user.Id.ToString(),
                    metadata: new Dictionary<string, object> { { "Email", email }, { "OrganizationId", targetOrgId } },
                    cancellationToken: cancellationToken);

                // 이벤트 발행
                await _eventBus.PublishAsync(new UserRegisteredEvent(
                    user.Id,
                    connectedIdResult.Data.Id,
                    targetOrgId,
                    email,
                    displayName), cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                return ServiceResult<AuthenticationResult>.Success(new AuthenticationResult
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedIdResult.Data.Id,
                    SessionId = sessionDto.Id,
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
                _logger.LogError(ex, "사용자({Email}) 등록 실패", email);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult<AuthenticationResult>.Failure($"등록 실패: {ex.Message}");
            }
        }

        public async Task<ServiceResult<AuthenticationResult>> AuthenticateWithPasswordAsync(
            string username,
            string password,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == username, cancellationToken);

                if (user == null || !await _passwordHashProvider.VerifyPasswordAsync(password, user.PasswordHash!))
                {
                    if (user != null)
                    {
                        await _accountSecurityService.IncrementFailedAttemptsAsync(user.Id, cancellationToken);
                    }
                    return ServiceResult<AuthenticationResult>.Failure("잘못된 자격 증명입니다.");
                }

                if (user.Status != UserStatus.Active)
                {
                    return ServiceResult<AuthenticationResult>.Failure($"계정 상태: {user.Status}");
                }

                await _accountSecurityService.ResetFailedAttemptsAsync(user.Id, cancellationToken);

                var targetOrgId = organizationId ?? await GetOrCreatePersonalOrganizationId(user.Id, cancellationToken);
                var connectedIdResult = await _connectedIdService.GetOrCreateAsync(user.Id, targetOrgId, cancellationToken);
                if (!connectedIdResult.IsSuccess || connectedIdResult.Data == null)
                {
                    return ServiceResult<AuthenticationResult>.Failure("ConnectedId를 가져오거나 생성하는 데 실패했습니다.");
                }
                var connectedId = connectedIdResult.Data;

                var ipAddress = _principalAccessor.IpAddress ?? CommonDefaults.DefaultLocalIpV4;
                var sessionRequest = new CreateSessionRequest { ConnectedId = connectedId.Id, OrganizationId = targetOrgId, IpAddress = ipAddress, UserAgent = CommonDefaults.PasswordAuthUserAgent };
                var sessionResult = await _sessionService.CreateSessionAsync(sessionRequest, cancellationToken);
                if (!sessionResult.IsSuccess || sessionResult.Data?.SessionDto == null)
                {
                    return ServiceResult<AuthenticationResult>.Failure("세션 데이터가 불완전합니다.");
                }

                var sessionDto = sessionResult.Data.SessionDto;
                var tokenResult = await _tokenService.IssueTokensAsync(sessionDto, cancellationToken);
                if (!tokenResult.IsSuccess || tokenResult.Data == null)
                {
                    return ServiceResult<AuthenticationResult>.Failure("토큰 발급에 실패했습니다.");
                }

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.Login,
                    action: "User authenticated with password",
                    connectedId: connectedId.Id,
                    resourceType: "User",
                    resourceId: user.Id.ToString(),
                    metadata: new Dictionary<string, object> { { "Method", "Password" }, { "OrganizationId", targetOrgId } },
                    cancellationToken: cancellationToken);

                return ServiceResult<AuthenticationResult>.Success(new AuthenticationResult
                {
                    Success = true,
                    UserId = user.Id,
                    ConnectedId = connectedId.Id,
                    SessionId = sessionDto.Id,
                    AccessToken = tokenResult.Data.AccessToken,
                    RefreshToken = tokenResult.Data.RefreshToken,
                    ExpiresAt = tokenResult.Data.ExpiresAt,
                    OrganizationId = targetOrgId,
                    AuthenticationMethod = "Password"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자({Username}) 인증 실패", username);
                return ServiceResult<AuthenticationResult>.Failure("인증 실패");
            }
        }
        #endregion

        #region 패스워드 관리
        public async Task<ServiceResult> ChangePasswordAsync(string currentPassword, string newPassword, CancellationToken cancellationToken = default)
        {
            var userId = _principalAccessor.UserId;
            if (userId == null)
            {
                return ServiceResult.Failure("사용자가 인증되지 않았습니다.");
            }

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var user = await _context.Users.FindAsync(new object[] { userId.Value }, cancellationToken);
                if (user == null)
                {
                    return ServiceResult.Failure("사용자를 찾을 수 없습니다.");
                }

                if (!await _passwordHashProvider.VerifyPasswordAsync(currentPassword, user.PasswordHash!))
                {
                    return ServiceResult.Failure("현재 패스워드가 올바르지 않습니다.");
                }

                var validationResult = await ValidatePasswordAsync(newPassword, _principalAccessor.OrganizationId, cancellationToken);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult.Failure(validationResult.ErrorMessage ?? "유효하지 않은 패스워드입니다.");
                }

                user.PasswordHash = await _passwordHashProvider.HashPasswordAsync(newPassword);
                user.PasswordChangedAt = _dateTimeProvider.UtcNow;

                await _auditService.LogActionAsync(
                    actionType: AuditActionType.PasswordChanged,
                    action: "User changed their password",
                    connectedId: _principalAccessor.ConnectedId ?? Guid.Empty, // ConnectedId가 없을 수 있음
                    resourceType: "User",
                    resourceId: user.Id.ToString(),
                    cancellationToken: cancellationToken);

                await _eventBus.PublishAsync(new PasswordChangedEvent(userId.Value, _principalAccessor.ConnectedId), cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                return ServiceResult.Success("패스워드가 성공적으로 변경되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "사용자({UserId})의 패스워드 변경 실패", userId);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult.Failure("패스워드 변경 실패");
            }
        }
        #endregion
        
        #region 패스워드 재설정
        public async Task<ServiceResult<PasswordResetToken>> RequestPasswordResetAsync(string email, Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email, cancellationToken);
                if (user == null)
                {
                    // 보안을 위해 사용자가 없더라도 성공처럼 응답합니다.
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult<PasswordResetToken>.Success(new PasswordResetToken { Message = "이메일이 존재한다면, 재설정 링크가 전송되었습니다." });
                }

                var token = GenerateSecureToken();
                user.PasswordResetToken = await _passwordHashProvider.HashPasswordAsync(token);
                user.PasswordResetTokenExpiresAt = _dateTimeProvider.UtcNow.AddHours(1);

                await _eventBus.PublishAsync(new PasswordResetRequestedEvent(user.Id, user.Email, user.DisplayName, token), cancellationToken);

                await _auditService.LogActionAsync(
                     actionType: AuditActionType.PasswordResetRequested,
                     action: "User requested a password reset",
                     connectedId: Guid.Empty, // 이 시점에는 ConnectedId 컨텍스트가 없음
                     resourceType: "User",
                     resourceId: user.Id.ToString(),
                     metadata: new Dictionary<string, object> { { "Email", email } },
                     cancellationToken: cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                return ServiceResult<PasswordResetToken>.Success(new PasswordResetToken { Message = "패스워드 재설정 토큰이 생성되어 전송되었습니다." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "이메일({Email})에 대한 패스워드 재설정 요청 실패", email);
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult<PasswordResetToken>.Failure("요청 처리 실패");
            }
        }

        public async Task<ServiceResult> ResetPasswordAsync(string token, string newPassword, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(token)) return ServiceResult.Failure("토큰은 비어 있을 수 없습니다.");

            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                var allUsersWithTokens = await _context.Users
                    .Where(u => u.PasswordResetToken != null && u.PasswordResetTokenExpiresAt > _dateTimeProvider.UtcNow)
                    .ToListAsync(cancellationToken);

                UserEntity? targetUser = null;
                foreach (var user in allUsersWithTokens)
                {
                    if (await _passwordHashProvider.VerifyPasswordAsync(token, user.PasswordResetToken!))
                    {
                        targetUser = user;
                        break;
                    }
                }

                if (targetUser == null)
                {
                    return ServiceResult.Failure("유효하지 않거나 만료된 패스워드 재설정 토큰입니다.");
                }

                var validationResult = await ValidatePasswordAsync(newPassword, null, cancellationToken);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult.Failure("INVALID_PASSWORD");
                }

                targetUser.PasswordHash = await _passwordHashProvider.HashPasswordAsync(newPassword);
                targetUser.PasswordResetToken = null;
                targetUser.PasswordResetTokenExpiresAt = null;
                targetUser.PasswordChangedAt = _dateTimeProvider.UtcNow;

                await _auditService.LogActionAsync(
                    AuditActionType.PasswordResetCompleted,
                    "User completed password reset",
                    Guid.Empty,
                    resourceType: "User",
                    resourceId: targetUser.Id.ToString(),
                    cancellationToken: cancellationToken);

                await _eventBus.PublishAsync(new PasswordChangedEvent(targetUser.Id, null), cancellationToken);

                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                return ServiceResult.Success("패스워드가 성공적으로 재설정되었습니다.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "패스워드 재설정 실패");
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                return ServiceResult.Failure("패스워드 재설정 중 오류가 발생했습니다.");
            }
        }
        #endregion

        #region 정책 및 유효성 검사
        public async Task<ServiceResult<PasswordValidationResult>> ValidatePasswordAsync(
            string password,
            Guid? organizationId = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var policyResult = await GetPasswordPolicyAsync(organizationId, cancellationToken);
                if (!policyResult.IsSuccess || policyResult.Data == null)
                {
                    _logger.LogWarning("패스워드 정책을 가져오지 못해, 기본(fallback) 검증을 사용합니다.");
                    return await FallbackPasswordValidation(password);
                }

                var policy = policyResult.Data;
                var result = new PasswordValidationResult { IsValid = true, Errors = new List<string>() };

                if (password.Length < policy.MinimumLength) result.Errors.Add($"패스워드는 최소 {policy.MinimumLength}자 이상이어야 합니다.");
                if (password.Length > policy.MaximumLength) result.Errors.Add($"패스워드는 최대 {policy.MaximumLength}자를 초과할 수 없습니다.");
                if (policy.RequireUppercase && !password.Any(char.IsUpper)) result.Errors.Add("패스워드는 최소 하나 이상의 대문자를 포함해야 합니다.");
                if (policy.RequireLowercase && !password.Any(char.IsLower)) result.Errors.Add("패스워드는 최소 하나 이상의 소문자를 포함해야 합니다.");
                if (policy.RequireNumbers && !password.Any(char.IsDigit)) result.Errors.Add("패스워드는 최소 하나 이상의 숫자를 포함해야 합니다.");
                if (policy.RequireSpecialCharacters && !password.Any(c => !char.IsLetterOrDigit(c))) result.Errors.Add("패스워드는 최소 하나 이상의 특수문자를 포함해야 합니다.");
                if (policy.MinimumUniqueCharacters > 0)
                {
                    if (password.Distinct().Count() < policy.MinimumUniqueCharacters) result.Errors.Add($"패스워드는 최소 {policy.MinimumUniqueCharacters}개의 고유한 문자를 포함해야 합니다.");
                }
                if (policy.PreventCommonPasswords && IsCommonPassword(password)) result.Errors.Add("이 패스워드는 너무 흔합니다. 더 안전한 패스워드를 선택하세요.");

                result.IsValid = result.Errors.Count == 0;

                return result.IsValid
                    ? ServiceResult<PasswordValidationResult>.Success(result)
                    : ServiceResult<PasswordValidationResult>.Failure(string.Join(", ", result.Errors));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "패스워드 검증 실패, 기본(fallback) 검증으로 전환합니다.");
                return await FallbackPasswordValidation(password);
            }
        }

        public async Task<ServiceResult<PasswordPolicyResponse>> GetPasswordPolicyAsync(Guid? organizationId = null, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = CacheKeys.PasswordPolicy(organizationId);
                var policy = await _cacheService.GetOrSetAsync(cacheKey, async () =>
                {
                    _logger.LogDebug("조직({OrganizationId})의 패스워드 정책 캐시 미스. 서비스에서 조회합니다.", organizationId);
                    var result = await _accountSecurityService.GetPasswordPolicyAsync(organizationId, cancellationToken);
                    if (!result.IsSuccess || result.Data == null)
                    {
                        _logger.LogWarning("AccountSecurityService에서 패스워드 정책을 가져오지 못했습니다. 기본 정책을 반환합니다.");
                        return new PasswordPolicyResponse();
                    }
                    return result.Data;
                },
                TimeSpan.FromHours(1), cancellationToken);

                if (policy == null)
                {
                    return ServiceResult<PasswordPolicyResponse>.Failure("패스워드 정책을 조회하거나 생성하는 데 실패했습니다.");
                }
                return ServiceResult<PasswordPolicyResponse>.Success(policy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "조직({OrganizationId})의 패스워드 정책 조회 실패", organizationId);
                return ServiceResult<PasswordPolicyResponse>.Failure("패스워드 정책 조회 중 오류가 발생했습니다.");
            }
        }
        #endregion

        #region 비공개 헬퍼 메서드
        private Task<ServiceResult<PasswordValidationResult>> FallbackPasswordValidation(string password)
        {
            var result = new PasswordValidationResult { IsValid = true, Errors = new List<string>() };

            if (password.Length < 8) result.Errors.Add("패스워드는 최소 8자 이상이어야 합니다.");
            if (!password.Any(char.IsUpper)) result.Errors.Add("패스워드는 최소 하나 이상의 대문자를 포함해야 합니다.");
            if (!password.Any(char.IsLower)) result.Errors.Add("패스워드는 최소 하나 이상의 소문자를 포함해야 합니다.");
            if (!password.Any(char.IsDigit)) result.Errors.Add("패스워드는 최소 하나 이상의 숫자를 포함해야 합니다.");

            result.IsValid = result.Errors.Count == 0;

            return Task.FromResult(result.IsValid
                ? ServiceResult<PasswordValidationResult>.Success(result)
                : ServiceResult<PasswordValidationResult>.Failure(string.Join(", ", result.Errors)));
        }

        private bool IsCommonPassword(string password)
        {
            var commonPasswords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "password", "123456", "password123", "admin", "qwerty",
                "letmein", "welcome", "monkey", "dragon", "master"
            };
            return commonPasswords.Contains(password);
        }

        private string GenerateSecureToken(int byteLength = 32)
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(byteLength))
                .Replace("+", "-").Replace("/", "_").Replace("=", "");
        }

        private async Task<Guid> GetOrCreatePersonalOrganizationId(Guid userId, CancellationToken cancellationToken = default)
        {
            var orgKey = $"personal_{userId}";
            var org = await _context.Organizations
                .FirstOrDefaultAsync(o => o.OrganizationKey == orgKey, cancellationToken);

            if (org == null)
            {
                var user = await _context.Users.FindAsync(new object[] { userId }, cancellationToken);
                if (user == null)
                {
                    throw new InvalidOperationException($"ID가 {userId}인 사용자를 찾을 수 없습니다.");
                }

                org = new OrganizationEntity
                {
                    OrganizationKey = orgKey,
                    Name = $"{user.DisplayName ?? user.Email}의 개인 공간",
                    Type = OrganizationType.Personal,
                    Status = OrganizationStatus.Active
                };
                _context.Organizations.Add(org);
            }
            return org.Id;
        }
        #endregion
    }
}

