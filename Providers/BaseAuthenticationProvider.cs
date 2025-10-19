using System;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.Date;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Service; // IAccountSecurityService 사용
using AuthHive.Core.Models.Auth.Authentication.Common; // 상세 AccountLockStatus DTO 사용

namespace AuthHive.Auth.Providers.Authentication
{
    /// <summary>
    /// 모든 인증 제공자의 기본 로직을 포함하는 추상 클래스입니다. - v16 Refactored
    /// 속도 제한, 계정 잠금 확인, 감사 로깅 등 공통 인증 파이프라인을 제공합니다.
    /// v16 원칙에 따라 DbContext 직접 접근을 제거하고 IUnitOfWork 및 Repository 패턴을 사용합니다.
    /// </summary>
    public abstract class BaseAuthenticationProvider : IAuthenticationProvider
    {
        protected readonly ILogger _logger;
        protected readonly ICacheService _cacheService;
        protected readonly IUnitOfWork _unitOfWork;
        protected readonly IDateTimeProvider _dateTimeProvider;
        protected readonly IAuditService _auditService;
        protected readonly IUserRepository _userRepository;
        protected readonly IConnectedIdRepository _connectedIdRepository;
        protected readonly IAccountSecurityService _accountSecurityService; // 수정: 의존성 추가

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
            IAccountSecurityService accountSecurityService) // 수정: 생성자 주입
        {
            _logger = logger;
            _cacheService = cacheService;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
            _auditService = auditService;
            _userRepository = userRepository;
            _connectedIdRepository = connectedIdRepository;
            _accountSecurityService = accountSecurityService; // 수정: 필드 할당
        }

        /// <inheritdoc />
        public async Task<ServiceResult<AuthenticationOutcome>> AuthenticateAsync(
            AuthenticationRequest request, CancellationToken cancellationToken = default)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            ServiceResult<AuthenticationOutcome> authResult;

            try
            {
                // 1. 속도 제한(Rate Limiting) 체크
                if (!await CheckRateLimitAsync(request, cancellationToken))
                {
                    authResult = ServiceResult<AuthenticationOutcome>.Failure("Too many attempts. Please try again later.", "RATE_LIMIT_EXCEEDED");
                    await LogAuthenticationAttemptAsync(request, authResult, AuthenticationResult.TooManyAttempts, cancellationToken);
                    return authResult;
                }

                // 2. 계정 잠금 상태 확인 (수정: IAccountSecurityService에 위임)
                var lockStatusResult = await CheckAccountLockAsync(request, cancellationToken);
                if (lockStatusResult.IsLocked)
                {
                    authResult = ServiceResult<AuthenticationOutcome>.Failure($"Account is locked. Reason: {lockStatusResult.LockReason}", "ACCOUNT_LOCKED");
                    await LogAuthenticationAttemptAsync(request, authResult, AuthenticationResult.AccountLocked, cancellationToken);
                    return authResult;
                }

                // 3. 하위 클래스에서 실제 인증 수행 (Template Method Pattern)
                authResult = await PerformAuthenticationAsync(request, cancellationToken);

                // 4. 인증 성공/실패 후처리
                if (authResult.IsSuccess && authResult.Data != null)
                {
                    await OnAuthenticationSuccessAsync(authResult.Data, cancellationToken);
                }
                else
                {
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

            // 5. 최종 감사 로그 기록 (성공/실패 모두)
            await LogAuthenticationAttemptAsync(request, authResult, authResult.IsSuccess ? null : AuthenticationResult.InvalidCredentials, cancellationToken, stopwatch.ElapsedMilliseconds);
            
            return authResult;
        }

        /// <summary>
        /// 하위 클래스에서 실제 인증 로직을 구현해야 합니다.
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
            var attempts = await _cacheService.GetAsync<int?>(key, cancellationToken) ?? 0;

            if (attempts >= 10) // TODO: 설정 값으로 분리
            {
                _logger.LogWarning("Rate limit exceeded for IP address: {IpAddress}", request.IpAddress);
                return false;
            }

            await _cacheService.SetAsync(key, attempts + 1, TimeSpan.FromMinutes(15), cancellationToken);
            return true;
        }

        /// <summary>
        /// IAccountSecurityService를 사용하여 사용자의 계정이 잠겼는지 확인합니다.
        /// </summary>
        protected virtual async Task<AccountLockStatus> CheckAccountLockAsync(AuthenticationRequest request, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(request.Username))
                return new AccountLockStatus { IsLocked = false };
            
            // 먼저 User 엔티티를 찾아 UserId를 확보
            var user = await FindUserAsync(request.Username, cancellationToken);
            if (user == null)
            {
                // 사용자가 존재하지 않으면 잠긴 상태가 아님
                return new AccountLockStatus { IsLocked = false };
            }
            
            // IAccountSecurityService를 통해 상태 조회
            var statusResult = await _accountSecurityService.GetAccountLockStatusAsync(user.Id);

            if (!statusResult.IsSuccess || statusResult.Data == null)
            {
                _logger.LogWarning("Failed to retrieve account lock status for user {UserId}. Assuming account is not locked.", user.Id);
                // 서비스 조회 실패 시, 로그인은 허용 (Fail-Open)
                return new AccountLockStatus { IsLocked = false };
            }
            
            return statusResult.Data;
        }


        /// <summary>
        /// 인증 성공 시 후처리 로직을 수행합니다.
        /// </summary>
        protected virtual async Task OnAuthenticationSuccessAsync(AuthenticationOutcome outcome, CancellationToken cancellationToken)
        {
            // 마지막 활동 시간 업데이트
            if (outcome.ConnectedId.HasValue)
            {
                await _connectedIdRepository.UpdateLastLoginAsync(outcome.ConnectedId.Value, _dateTimeProvider.UtcNow, cancellationToken);
            }
            if (outcome.UserId.HasValue)
            {
                 await _userRepository.UpdateLastLoginAsync(outcome.UserId.Value, _dateTimeProvider.UtcNow, outcome.IpAddress, cancellationToken);
                 // 성공 시, 실패 카운트 초기화
                 await _accountSecurityService.ResetFailedAttemptsAsync(outcome.UserId.Value);
            }

            // DB 변경사항 저장
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
                // TODO: IAccountSecurityService에 실패 카운트를 증가시키는 메서드(예: IncrementFailedAttemptsAsync)를 추가하고 호출
                _logger.LogWarning("Authentication failed for user {UserId}. Failure count should be incremented.", user.Id);
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
        /// 사용자명 또는 이메일로 User 엔티티를 조회하는 헬퍼 메서드입니다.
        /// </summary>
        protected async Task<User?> FindUserAsync(string usernameOrEmail, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(usernameOrEmail)) return null;

            var user = await _userRepository.GetByUsernameAsync(usernameOrEmail, cancellationToken: cancellationToken);
            if (user == null && usernameOrEmail.Contains('@'))
            {
                user = await _userRepository.GetByEmailAsync(usernameOrEmail, cancellationToken: cancellationToken);
            }
            return user;
        }
    }
}

