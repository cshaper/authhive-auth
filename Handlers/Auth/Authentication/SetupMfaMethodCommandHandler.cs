// [AuthHive.Auth] Handlers/Auth/Authentication/SetupMfaMethodCommandHandler.cs
// v17 CQRS "본보기": 'SetupMfaMethodCommand' (MFA 등록 활성화)를 처리합니다.
// (SOP 2-Write-U)
//
// 1. v17 전문가 위임: ITotpService.ValidateCode를 호출하여 6자리 코드를 검증합니다.
// 2. Entity: User.IsTwoFactorEnabled = true로 상태를 "활성화"합니다.
// 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// 4. Mediator (Publish): 'TwoFactorStatusChangedEvent'를 발행합니다.
// 5. Response: 'MfaMethodSetupResult' DTO로 최종 결과를 반환합니다.

using AuthHive.Core.Interfaces.Security; // ITotpService
using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication.Commands;
using AuthHive.Core.Models.Auth.Authentication.Events; // [v17] TwoFactorStatusChangedEvent
using AuthHive.Core.Models.Auth.Authentication.Common; // [v17] MfaMethodSetupResult
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Auth.Events; // IDateTimeProvider

namespace AuthHive.Auth.Handlers.Auth.Authentication
{
    /// <summary>
    /// [v17] "MFA 등록 활성화" 유스케이스 핸들러 (SOP 2-Write-U)
    /// </summary>
    public class SetupMfaMethodCommandHandler : IRequestHandler<SetupMfaMethodCommand, MfaMethodSetupResult>
    {
        private readonly IUserRepository _userRepository;
        private readonly ITotpService _totpService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<SetupMfaMethodCommandHandler> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        public SetupMfaMethodCommandHandler(
            IUserRepository userRepository,
            ITotpService totpService,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<SetupMfaMethodCommandHandler> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _userRepository = userRepository;
            _totpService = totpService;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        public async Task<MfaMethodSetupResult> Handle(SetupMfaMethodCommand command, CancellationToken cancellationToken)
        {
            // 1. [SOP 2.3.2] 엔티티 조회
            var user = await _userRepository.GetByIdAsync(command.AggregateId, cancellationToken); // AggregateId는 UserId
            if (user == null)
            {
                throw new ValidationException($"User not found: {command.AggregateId}");
            }

            // 2. [SOP 2.3.1] 유효성 검증
            if (string.IsNullOrEmpty(user.TotpSecret))
            {
                _logger.LogWarning("MFA Setup failed: User {UserId} has not enrolled a TOTP secret yet.", user.Id);
                return new MfaMethodSetupResult(false, command.Method, "TOTP method has not been enrolled.", false);
            }
            if (string.IsNullOrEmpty(command.VerificationCode))
            {
                 return new MfaMethodSetupResult(false, command.Method, "Verification code is required.", false);
            }

            // 3. [SOP 2.3.3] 비즈니스 로직 (v17 전문가 위임)
            // ITotpService를 호출하여 코드가 유효한지 검증
            bool isCodeValid = _totpService.ValidateCode(user.TotpSecret, command.VerificationCode);

            if (!isCodeValid)
            {
                _logger.LogWarning("MFA Setup failed: Invalid TOTP code for User {UserId}.", user.Id);
                // TODO: 실패 횟수 증가 로직 (IAccountSecurityService)
                return new MfaMethodSetupResult(false, command.Method, "Invalid verification code.", false);
            }

            // 4. [SOP 2.3.3] 엔티티 상태 변경 (MFA 활성화)
            user.IsTwoFactorEnabled = true; 
            user.TwoFactorEnabledAt = _dateTimeProvider.UtcNow; 
            user.TwoFactorMethod = command.Method;

            // 5. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
            await _userRepository.UpdateAsync(user, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 6. [SOP 2.3.6] 이벤트 발행
            // [v17] TwoFactorStatusChangedEvent 계약서 준수 
            var statusChangedEvent = new TwoFactorStatusChangedEvent(
                userId: user.Id,
                isEnabled: true,
                method: command.Method,
                organizationId: user.OrganizationId,
                triggeredBy: command.TriggeredBy ?? user.Id
            );
            await _mediator.Publish(statusChangedEvent, cancellationToken);

            _logger.LogInformation("MFA Setup successful: TOTP method enabled for User {UserId}.", user.Id);

            // 7. [SOP 2.3.7] 응답 반환
            // MfaMethodSetupResult 계약서 준수 
            return new MfaMethodSetupResult(
                success: true,
                method: command.Method,
                message: "MFA method successfully verified and enabled.",
                requiresVerification: false // 검증이 완료되었음
            );
        }
    }
}