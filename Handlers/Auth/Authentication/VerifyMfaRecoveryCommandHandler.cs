// // [AuthHive.Auth] Handlers/Auth/Authentication/VerifyMfaRecoveryCommandHandler.cs
// // v17 CQRS "본보기": 'VerifyMfaRecoveryCommand' (MFA 복구 완료)를 처리합니다.
// // (SOP 2-Write-U)
// //
// // 1. Logic: 'Email' 복구 시, User.PasswordResetToken(Hash)과 Command.VerificationTokenOrCode(Plaintext)를 비교합니다.
// // 2. v17 전문가 위임: IPasswordHashProvider를 사용하여 코드를 '검증'합니다.
// // 3. Entity: User.IsTwoFactorEnabled = false로 상태를 "비활성화"합니다.
// // 4. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// // 5. Mediator (Publish): 'MfaRecoverySuccessEvent'와 'TwoFactorStatusChangedEvent'를 발행합니다.
// // 6. Response: 'IRequest<Unit>' 계약에 따라 Unit.Value (void)를 반환합니다.

// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repository;
// using AuthHive.Core.Interfaces.Security; // IPasswordHashProvider
// using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
// using AuthHive.Core.Models.Auth.Authentication.Commands;
// using AuthHive.Core.Models.Auth.Authentication.Events; // MfaRecoverySuccessEvent
// using AuthHive.Core.Models.Auth.Events; // TwoFactorStatusChangedEvent
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.ComponentModel.DataAnnotations;
// using System.Threading;
// using System.Threading.Tasks;

// namespace AuthHive.Auth.Handlers.Auth.Authentication
// {
//     /// <summary>
//     /// [v17] "MFA 복구 완료" 유스케이스 핸들러 (SOP 2-Write-U)
//     /// (MFA 비활성화가 주 목적)
//     /// </summary>
//     public class VerifyMfaRecoveryCommandHandler : IRequestHandler<VerifyMfaRecoveryCommand, Unit>
//     {
//         private readonly IUserRepository _userRepository;
//         private readonly IPasswordHashProvider _passwordHashProvider;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IMediator _mediator;
//         private readonly IDateTimeProvider _dateTimeProvider;
//         private readonly ILogger<VerifyMfaRecoveryCommandHandler> _logger;

//         public VerifyMfaRecoveryCommandHandler(
//             IUserRepository userRepository,
//             IPasswordHashProvider passwordHashProvider,
//             IUnitOfWork unitOfWork,
//             IMediator mediator,
//             IDateTimeProvider dateTimeProvider,
//             ILogger<VerifyMfaRecoveryCommandHandler> logger)
//         {
//             _userRepository = userRepository;
//             _passwordHashProvider = passwordHashProvider;
//             _unitOfWork = unitOfWork;
//             _mediator = mediator;
//             _dateTimeProvider = dateTimeProvider;
//             _logger = logger;
//         }

//         public async Task<Unit> Handle(VerifyMfaRecoveryCommand command, CancellationToken cancellationToken)
//         {
//             var utcNow = _dateTimeProvider.UtcNow;
            
//             // 1. [SOP 2.3.2] 엔티티 조회
//             var user = await _userRepository.GetByIdAsync(command.AggregateId, cancellationToken); // AggregateId는 UserId
//             if (user == null || string.IsNullOrEmpty(user.PasswordResetToken) || !user.PasswordResetTokenExpiresAt.HasValue)
//             {
//                 throw new ValidationException("Invalid or expired recovery request.");
//             }

//             // 2. [SOP 2.3.1] 유효성 검증 (토큰 만료)
//             if (user.PasswordResetTokenExpiresAt.Value < utcNow)
//             {
//                 throw new ValidationException("The recovery request has expired.");
//             }

//             // 3. [SOP 2.3.3] 비즈니스 로직 (v17 전문가 위임)
//             // (v16 InitiateMfaRecoveryCommand는 Email 방식만 가정했음)
//             // TODO: command.RecoveryMethod에 따라 BackupCode 검증 로직 분기 필요
            
//             // [v17] IPasswordHashProvider를 사용하여 DB의 해시와 원본 코드 비교
//             var isCodeValid = await _passwordHashProvider.VerifyPasswordAsync(
//                 command.VerificationTokenOrCode, 
//                 user.PasswordResetToken
//             );

//             if (!isCodeValid)
//             {
//                 _logger.LogWarning("MFA Recovery failed: Invalid code for User {UserId}", user.Id);
//                 throw new ValidationException("Invalid verification code.");
//             }

//             // 4. [SOP 2.3.3] 엔티티 상태 변경 (MFA 비활성화)
//             user.IsTwoFactorEnabled = false;
//             user.TwoFactorEnabledAt = null;
//             user.TwoFactorMethod = null;
//             user.TotpSecret = null; // TOTP 비밀 키 삭제
            
//             // 복구 토큰 무효화
//             user.PasswordResetToken = null;
//             user.PasswordResetTokenExpiresAt = null;

//             // 5. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
//             await _userRepository.UpdateAsync(user, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             // 6. [SOP 2.3.6] 이벤트 발행
//             // 6a. 복구 성공 이벤트
//             var recoverySuccessEvent = new MfaRecoverySuccessEvent(
//                 userId: user.Id,
//                 recoverySessionId: command.RecoverySessionId, // [v17] Command DTO가 수정되었으므로 command.AggregateId 사용
//                 recoveryMethod: "Email", // (v16 InitiateMfaRecoveryCommand 기반)
//                 requiresNewMfaSetup: true, // MFA가 비활성화되었으므로 재설정 필요
//                 recoveredByConnectedId: command.TriggeredBy ?? user.Id,
//                 ipAddress: command.IpAddress,
//                 userAgent: command.UserAgent
//             );
//             await _mediator.Publish(recoverySuccessEvent, cancellationToken);

//             // 6b. 2FA 상태 변경 이벤트 (Disabled)
//             var statusChangedEvent = new TwoFactorStatusChangedEvent(
//                 userId: user.Id,
//                 isEnabled: false, // [v17] 비활성화
//                 method: "TOTP", // (비활성화된 방식)
//                 organizationId: user.OrganizationId,
//                 triggeredBy: command.TriggeredBy ?? user.Id
//             );
//             await _mediator.Publish(statusChangedEvent, cancellationToken);

//             _logger.LogInformation("MFA Recovery successful: 2FA disabled for User {UserId}", user.Id);

//             // 7. [SOP 2.3.7] 응답 반환
//             // IRequest<Unit> 계약에 따라 Unit.Value 반환
//             return Unit.Value;
//         }
//     }
// }