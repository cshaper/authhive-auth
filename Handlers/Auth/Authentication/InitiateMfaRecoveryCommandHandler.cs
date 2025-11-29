// // [AuthHive.Auth] Handlers/Auth/Authentication/InitiateMfaRecoveryCommandHandler.cs
// // v17 CQRS "본보기": 'InitiateMfaRecoveryCommand' (MFA 복구 시작)를 처리합니다.
// // (SOP 2-Write-U)
// //
// // 1. Logic: 사용자가 'Email' 복구를 요청했는지 확인합니다.
// // 2. Entity: User 엔티티에 '암호화된 복구 토큰'과 '만료 시간'을 저장합니다.
// // 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// // 4. Mediator (Publish): 'MfaRecoveryInitiatedEvent'를 발행하여 이메일 전송을 위임합니다.
// // 5. Response: 'MfaChallengeResult' DTO로 "이메일을 보냈다"는 챌린지 결과를 반환합니다.

// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repositories;
// using AuthHive.Core.Interfaces.Security; // IPasswordHashProvider
// using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
// using AuthHive.Core.Models.Auth.Authentication.Commands;
// using AuthHive.Core.Models.Auth.Authentication.Common; // MfaChallengeResult
// using AuthHive.Core.Models.Auth.Authentication.Events; // MfaRecoveryInitiatedEvent
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.ComponentModel.DataAnnotations;
// using System.Security.Cryptography; // RandomNumberGenerator
// using System.Text;
// using System.Threading;
// using System.Threading.Tasks;
// using AuthHive.Core.Enums.Auth; // MfaMethod

// using UserEntity = AuthHive.Core.Entities.User.User;


// namespace AuthHive.Auth.Handlers.Auth.Authentication
// {
//     /// <summary>
//     /// [v17] "MFA 복구 시작" 유스케이스 핸들러 (SOP 2-Write-U)
//     /// </summary>
//     public class InitiateMfaRecoveryCommandHandler : IRequestHandler<InitiateMfaRecoveryCommand, MfaChallengeResult>
//     {
//         private readonly IUserRepository _userRepository;
//         private readonly IPasswordHashProvider _passwordHashProvider;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IMediator _mediator;
//         private readonly IDateTimeProvider _dateTimeProvider;
//         private readonly ILogger<InitiateMfaRecoveryCommandHandler> _logger;

//         public InitiateMfaRecoveryCommandHandler(
//             IUserRepository userRepository,
//             IPasswordHashProvider passwordHashProvider,
//             IUnitOfWork unitOfWork,
//             IMediator mediator,
//             IDateTimeProvider dateTimeProvider,
//             ILogger<InitiateMfaRecoveryCommandHandler> logger)
//         {
//             _userRepository = userRepository;
//             _passwordHashProvider = passwordHashProvider;
//             _unitOfWork = unitOfWork;
//             _mediator = mediator;
//             _dateTimeProvider = dateTimeProvider;
//             _logger = logger;
//         }

//         public async Task<MfaChallengeResult> Handle(InitiateMfaRecoveryCommand command, CancellationToken cancellationToken)
//         {
//             var utcNow = _dateTimeProvider.UtcNow;

//             // 1. [SOP 2.3.2] 엔티티 조회
//             var user = await _userRepository.GetByIdAsync(command.AggregateId, cancellationToken); // AggregateId는 UserId
//             if (user == null)
//             {
//                 throw new ValidationException("User not found.");
//             }

//             // 2. [SOP 2.3.1] 유효성 검증
//             if (!user.IsTwoFactorEnabled)
//             {
//                 throw new ValidationException("MFA is not enabled for this user.");
//             }

//             // 3. [SOP 2.3.3] 비즈니스 로직 (RecoveryMethod에 따라 분기)
//             switch (command.RecoveryMethod.ToUpper())
//             {
//                 case "EMAIL":
//                     return await HandleEmailRecovery(command, user, utcNow, cancellationToken);

//                 case "BACKUP_CODE":
//                     // v17 철학: "Initiate" 핸들러는 챌린지를 반환합니다.
//                     // 실제 코드 검증은 'VerifyMfaRecoveryCommand'가 담당합니다.
//                     return new MfaChallengeResult(
//                         challengeId: $"backup_{user.Id}",
//                         method: MfaMethod.BackupCode,
//                         codeSent: false, // 코드를 보내지 않음 (사용자가 입력해야 함)
//                         expiresAt: utcNow.AddMinutes(10),
//                         hint: "Enter one of your saved backup codes."
//                     );

//                 default:
//                     _logger.LogWarning("Unsupported MFA recovery method requested: {Method}", command.RecoveryMethod);
//                     throw new ValidationException($"Recovery method '{command.RecoveryMethod}' is not supported.");
//             }
//         }

//         /// <summary>
//         /// "Email" 복구 방식의 비즈니스 로직을 처리합니다.
//         /// (토큰 생성, DB 저장, 이벤트 발행, 챌린지 반환)
//         /// </summary>
//         private async Task<MfaChallengeResult> HandleEmailRecovery(
//             InitiateMfaRecoveryCommand command, UserEntity user, DateTime utcNow, CancellationToken cancellationToken)
//         {
//             if (string.IsNullOrEmpty(user.Email))
//             {
//                 throw new ValidationException("User does not have a recovery email address configured.");
//             }

//             // [v17] 6자리 숫자 복구 코드 생성 (암호학적으로 안전)
//             string plaintextCode = GenerateNumericCode(6);
//             string hashedCode = await _passwordHashProvider.HashPasswordAsync(plaintextCode);
//             var expiresAt = utcNow.AddMinutes(15);

//             // 4. [SOP 2.3.3] 엔티티 상태 변경
//             // [v17] PasswordResetToken 필드를 MFA 복구 토큰으로 재사용 
//             user.PasswordResetToken = hashedCode;
//             user.PasswordResetTokenExpiresAt = expiresAt;

//             // 5. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
//             await _userRepository.UpdateAsync(user, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             // 6. [SOP 2.3.6] 이벤트 발행 (이메일 전송 위임)
//             // [v17] MfaRecoveryInitiatedEvent 계약서 준수 
//             var recoveryEvent = new MfaRecoveryInitiatedEvent(
//                 userId: user.Id,
//                 recoveryMethod: command.RecoveryMethod,
//                 ipAddress: command.IpAddress,
//                 userAgent: command.UserAgent,
//                 recoveryContact: user.Email, // 실제 이메일 주소
//                 additionalVerification: new Dictionary<string, object> { { "RecoveryCode", plaintextCode } } // [v17] 원본 코드를 이벤트에 담아 전송
//             );
//             await _mediator.Publish(recoveryEvent, cancellationToken);

//             _logger.LogInformation("MFA Recovery initiated via Email for User {UserId}", user.Id);

//             // 7. [SOP 2.3.7] 응답 반환
//             // MfaChallengeResult 계약서 준수 
//             return new MfaChallengeResult(
//                 challengeId: $"mfa_rec_{user.Id}",
//                 method: MfaMethod.Email,
//                 codeSent: true,
//                 expiresAt: expiresAt,
//                 hint: MaskEmail(user.Email), // "t***@g****.com"
//                 message: "A recovery code has been sent to your email address."
//             );
//         }

//         /// <summary>
//         /// 암호학적으로 안전한 6자리 숫자 코드를 생성합니다.
//         /// </summary>
//         private string GenerateNumericCode(int length)
//         {
//             using (var rng = RandomNumberGenerator.Create())
//             {
//                 var bytes = new byte[sizeof(uint)];
//                 var result = new StringBuilder(length);
//                 for (int i = 0; i < length; i++)
//                 {
//                     rng.GetBytes(bytes);
//                     uint num = BitConverter.ToUInt32(bytes, 0);
//                     result.Append(num % 10);
//                 }
//                 return result.ToString();
//             }
//         }

//         /// <summary>
//         /// 이메일 주소를 마스킹합니다. (예: "test@gmail.com" -> "t***@g****.com")
//         /// </summary>
//         private string? MaskEmail(string? email)
//         {
//             if (string.IsNullOrEmpty(email)) return null;
//             var parts = email.Split('@');
//             if (parts.Length != 2) return email;

//             string local = parts[0].Length > 1 ? $"{parts[0][0]}***" : "***";
//             string domain = parts[1].Length > 1 ? $"{parts[1][0]}***.{parts[1].Split('.').LastOrDefault()}" : "***";

//             return $"{local}@{domain}";
//         }
//     }
// }