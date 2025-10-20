using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Business.Platform;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Providers
{
    /// <summary>
    /// 모든 인증 제공자의 기본 로직을 포함하는 추상 클래스입니다. - v16 근본 수정
    /// Provider는 인증 검증(Validation) 및 감사 로깅에만 집중하며, 세션/토큰 관리는 상위 계층에 위임합니다.
    /// </summary>
    public abstract class BaseAuthenticationProvider : IAuthenticationProvider
    {
        // 토큰 서비스, 세션 서비스, ConnectedId 서비스는 BaseProvider의 책임이 아니므로 삭제
        protected readonly ILogger _logger;
        protected readonly ICacheService _cacheService;
        protected readonly IUnitOfWork _unitOfWork; // 최종 DB 저장을 위해 유지
        protected readonly IDateTimeProvider _dateTimeProvider;
        protected readonly IAuditService _auditService;
        protected readonly IUserRepository _userRepository;
        protected readonly IConnectedIdRepository _connectedIdRepository; // ConnectedId 조회를 위해 유지
        protected readonly IAccountSecurityService _accountSecurityService; 
        protected readonly IPlanRestrictionService _planRestrictionService; 

        public abstract string ProviderName { get; }
        public abstract string ProviderType { get; }

        protected BaseAuthenticationProvider(
            ILogger logger,
            ICacheService cacheService,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            IAuditService auditService,
            IUserRepository userRepository,
            IConnectedIdRepository connectedIdRepository,
            IAccountSecurityService accountSecurityService,
            IPlanRestrictionService planRestrictionService)
        {
            _logger = logger;
            _cacheService = cacheService;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
            _auditService = auditService;
            _userRepository = userRepository;
            _connectedIdRepository = connectedIdRepository;
            _accountSecurityService = accountSecurityService;
            _planRestrictionService = planRestrictionService;
        }

        /// <inheritdoc />
        public async Task<ServiceResult<AuthenticationOutcome>> AuthenticateAsync(
            AuthenticationRequest request, CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            ServiceResult<AuthenticationOutcome> authResult;

            try
            {
                // 1. 속도 제한 체크
                if (!await CheckRateLimitAsync(request, cancellationToken))
                {
                    authResult = ServiceResult<AuthenticationOutcome>.Failure("Too many attempts. Please try again later.", "RATE_LIMIT_EXCEEDED");
                    await LogAuthenticationAttemptAsync(request, authResult, AuthenticationResult.TooManyAttempts, cancellationToken);
                    return authResult;
                }

                // 2. 계정 잠금 상태 확인 (IAccountSecurityService 위임)
                var lockStatusResult = await CheckAccountLockAsync(request, cancellationToken);
                if (lockStatusResult.IsLocked)
                {
                    authResult = ServiceResult<AuthenticationOutcome>.Failure($"Account is locked. Reason: {lockStatusResult.LockReason}", "ACCOUNT_LOCKED");
                    await LogAuthenticationAttemptAsync(request, authResult, AuthenticationResult.AccountLocked, cancellationToken);
                    return authResult;
                }
                
                // 3. 하위 클래스에서 실제 인증 수행 (Template Method Pattern)
                // ✅ 이 시점에서 ConnectedId와 UserId만 확보합니다. 토큰/세션 발급은 상위 계층에서 처리.
                authResult = await PerformAuthenticationAsync(request, cancellationToken);

                // 4. 인증 성공/실패 후처리
                if (authResult.IsSuccess && authResult.Data != null)
                {
                    // ✅ 성공 시: 사용자/ConnectedId의 최종 로그인 시간 업데이트 로직만 수행. (토큰 발급 로직 제거)
                    await OnAuthenticationSuccessAsync(authResult.Data, request.IpAddress, cancellationToken);
                }
                else
                {
                    // ✅ 실패 시: 실패 카운트 증가 로직만 수행.
                    await OnAuthenticationFailureAsync(request, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred during authentication for provider {ProviderName}.", ProviderName);
                authResult = ServiceResult<AuthenticationOutcome>.Failure("An internal error occurred during authentication.", "INTERNAL_ERROR");
            }
            finally
            {
                stopwatch.Stop();
            }

            // 5. 최종 감사 로그 기록
            await LogAuthenticationAttemptAsync(
                request, 
                authResult, 
                authResult.IsSuccess ? null : AuthenticationResult.InvalidCredentials, 
                cancellationToken, 
                stopwatch.ElapsedMilliseconds);
            
            return authResult;
        }

        /// <summary>
        /// 하위 클래스에서 실제 인증 로직을 구현해야 하며, 인증 결과(UserId, ConnectedId)를 반환합니다.
        /// </summary>
        protected abstract Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
            AuthenticationRequest request, CancellationToken cancellationToken);

        /// <inheritdoc />
        public abstract Task<ServiceResult<bool>> ValidateAsync(string token, CancellationToken cancellationToken = default);

        /// <inheritdoc />
        public abstract Task<ServiceResult> RevokeAsync(string token, CancellationToken cancellationToken = default);

        /// <inheritdoc />
        public abstract Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// IP 주소 기반으로 간단한 속도 제한을 확인합니다.
        /// </summary>
        protected virtual async Task<bool> CheckRateLimitAsync(AuthenticationRequest request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(request.IpAddress)) return true;

            var key = $"rate_limit:auth:{request.IpAddress}";
            var attemptsString = await _cacheService.GetAsync<string>(key, cancellationToken);
            int attempts = int.TryParse(attemptsString, out int a) ? a : 0;
            
            if (attempts >= 10)
            {
                _logger.LogWarning("Rate limit exceeded for IP address: {IpAddress}", request.IpAddress);
                return false;
            }

            await _cacheService.SetAsync(key, (attempts + 1).ToString(), TimeSpan.FromMinutes(15), cancellationToken);
            return true;
        }

        /// <summary>
        /// IAccountSecurityService를 사용하여 사용자의 계정이 잠겼는지 확인합니다.
        /// </summary>
        protected virtual async Task<AccountLockStatus> CheckAccountLockAsync(AuthenticationRequest request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(request.Username)) 
                return new AccountLockStatus { IsLocked = false };
            
            var user = await FindUserAsync(request.Username, cancellationToken);
            if (user == null)
            {
                return new AccountLockStatus { IsLocked = false };
            }
            
            // NOTE: IAccountSecurityService의 GetAccountLockStatusAsync가 CancellationToken을 받도록 가정합니다.
            var statusResult = await _accountSecurityService.GetAccountLockStatusAsync(user.Id);

            if (!statusResult.IsSuccess || statusResult.Data == null)
            {
                _logger.LogWarning("Failed to retrieve account lock status for user {UserId}. Assuming account is not locked.", user.Id);
                return new AccountLockStatus { IsLocked = false };
            }
            
            return statusResult.Data;
        }

        /// <summary>
        /// 인증 성공 시 후처리 로직을 수행합니다. (최종 로그인 시간 업데이트)
        /// </summary>
        protected virtual async Task OnAuthenticationSuccessAsync(AuthenticationOutcome outcome, string? ipAddress, CancellationToken cancellationToken)
        {
            if (outcome.ConnectedId.HasValue)
            {
                await UpdateConnectedIdLastLoginAsync(outcome.ConnectedId.Value, _dateTimeProvider.UtcNow, cancellationToken);
            }
            
            if (outcome.UserId.HasValue)
            {
                // Last Login 업데이트 (User Repository는 IP 주소를 포함한 업데이트를 지원한다고 가정)
                await _userRepository.UpdateLastLoginAsync(
                    outcome.UserId.Value, 
                    _dateTimeProvider.UtcNow, 
                    ipAddress, 
                    cancellationToken);
                
                // 성공 시, 실패 카운트 초기화 (IAccountSecurityService에 위임)
                // NOTE: IAccountSecurityService의 ResetFailedAttemptsAsync도 CancellationToken을 받도록 가정합니다.
                await _accountSecurityService.ResetFailedAttemptsAsync(outcome.UserId.Value, cancellationToken);
            }

            // DB 변경사항 저장 (UoW 커밋은 상위 Service Layer에서 수행되어야 하지만, Provider에서 직접 DB 쓰기가 발생하므로 여기서는 UoW를 사용합니다.)
            await _unitOfWork.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// 인증 실패 시 후처리 로직을 수행합니다. (실패 카운트 증가)
        /// </summary>
        protected virtual async Task OnAuthenticationFailureAsync(AuthenticationRequest request, CancellationToken cancellationToken)
        {
            var user = await FindUserAsync(request.Username, cancellationToken);
            if (user != null)
            {
                // NOTE: IAccountSecurityService에 실패 카운트를 증가시키는 메서드가 필요합니다.
                // await _accountSecurityService.IncrementFailedAttemptsAsync(user.Id, cancellationToken);
                _logger.LogWarning("Authentication failed for user {UserId}. Failure count should be incremented via AccountSecurityService.", user.Id);
            }
        }

        /// <summary>
        /// IAuditService를 사용하여 인증 시도 로그를 중앙에서 기록합니다.
        /// </summary>
        protected virtual Task LogAuthenticationAttemptAsync(
            AuthenticationRequest request,
            ServiceResult<AuthenticationOutcome> result,
            AuthenticationResult? failureReason,
            CancellationToken cancellationToken,
            long? processingTimeMs = null)
        {
            return _auditService.LogLoginAttemptAsync(
                username: request.Username,
                success: result.IsSuccess && result.Data?.Success == true,
                ipAddress: request.IpAddress,
                userAgent: request.UserAgent,
                errorMessage: result.ErrorMessage,
                connectedId: result.Data?.ConnectedId,
                cancellationToken: cancellationToken);
        }

        /// <summary>
        /// 사용자명 또는 이메일로 User 엔티티를 조회하는 헬퍼 메서드입니다. (Repository 위임)
        /// </summary>
        protected async Task<User?> FindUserAsync(string? usernameOrEmail, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(usernameOrEmail)) return null;

            var user = await _userRepository.GetByUsernameAsync(usernameOrEmail, cancellationToken: cancellationToken);
            if (user == null && usernameOrEmail.Contains('@'))
            {
                user = await _userRepository.GetByEmailAsync(usernameOrEmail, cancellationToken: cancellationToken);
            }
            return user;
        }

        // --- Low-Level Repository Helper (ConnectedId의 Last Login 업데이트) ---
        private async Task UpdateConnectedIdLastLoginAsync(Guid connectedId, DateTime lastLogin, CancellationToken cancellationToken)
        {
            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
            if (connectedIdEntity != null)
            {
                connectedIdEntity.LastActiveAt = lastLogin;
                // NOTE: IConnectedIdRepository가 UpdateAsync 메서드를 지원한다고 가정합니다.
                await _connectedIdRepository.UpdateAsync(connectedIdEntity, cancellationToken); 
            }
        }
    }
}