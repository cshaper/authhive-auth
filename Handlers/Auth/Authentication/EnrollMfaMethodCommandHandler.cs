// // [AuthHive.Auth] Handlers/Auth/Authentication/EnrollMfaMethodCommandHandler.cs
// // v17 CQRS "본보기": 'EnrollMfaMethodCommand' (MFA 등록)를 처리합니다.
// // (SOP 2-Write-U)
// //
// // 1. v17 전문가 위임: Core의 ITotpService를 호출하여 Secret Key와 QR 코드를 생성합니다.
// // 2. Entity: User 엔티티에 'TwoFactorSecret'을 저장합니다.
// // 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// // 4. Mediator (Publish): 'AuthenticationMethodConfiguredEvent'를 발행합니다.
// // 5. Response: 'EnrollMfaMethodResponse' DTO로 Secret/QR 코드를 반환합니다.

// using AuthHive.Core.Interfaces.Security; // 1. ITotpService (from Core)
// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Enums.Auth; // AuthenticationMethod
// using AuthHive.Core.Enums.Business; // ConfigurationActionType
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repository;
// using AuthHive.Core.Models.Auth.Authentication.Commands;
// using AuthHive.Core.Models.Auth.Authentication.Events;
// using AuthHive.Core.Models.Auth.Authentication.Responses;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.ComponentModel.DataAnnotations;
// using System.Threading;
// using System.Threading.Tasks;
// using AuthHive.Core.Models.Auth.Events;
// using AuthHive.Core.Interfaces.Infra.Security;

// namespace AuthHive.Auth.Handlers.Auth.Authentication
// {
//     /// <summary>
//     /// [v17] "MFA 등록" 유스케이스 핸들러 (SOP 2-Write-U)
//     /// </summary>
//     public class EnrollMfaMethodCommandHandler : IRequestHandler<EnrollMfaMethodCommand, EnrollMfaMethodResponse>
//     {
//         private readonly IUserRepository _userRepository;
//         private readonly ITotpService _totpService; // 2. 전문가 서비스 주입
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly IMediator _mediator;
//         private readonly ILogger<EnrollMfaMethodCommandHandler> _logger;

//         public EnrollMfaMethodCommandHandler(
//             IUserRepository userRepository,
//             ITotpService totpService, // 2. 전문가 서비스 주입
//             IUnitOfWork unitOfWork,
//             IMediator mediator,
//             ILogger<EnrollMfaMethodCommandHandler> logger)
//         {
//             _userRepository = userRepository;
//             _totpService = totpService;
//             _unitOfWork = unitOfWork;
//             _mediator = mediator;
//             _logger = logger;
//         }

//         public async Task<EnrollMfaMethodResponse> Handle(EnrollMfaMethodCommand command, CancellationToken cancellationToken)
//         {
//             // 1. [SOP 2.3.1] 유효성 검증
//             if (command.Method.ToUpper() != "TOTP")
//             {
//                 _logger.LogWarning("MFA Enrollment failed: Method {Method} not supported.", command.Method);
//                 return new EnrollMfaMethodResponse(false, command.Method, errorMessage: "Only TOTP method is supported for enrollment.");
//             }

//             // 2. [SOP 2.3.2] 엔티티 조회
//             var user = await _userRepository.GetByIdAsync(command.AggregateId, cancellationToken); // AggregateId는 UserId [cite: 74-78]
//             if (user == null)
//             {
//                 throw new ValidationException($"User not found: {command.AggregateId}");
//             }
//             if (string.IsNullOrEmpty(user.Email))
//             {
//                  throw new ValidationException($"User {user.Id} has no email configured for TOTP setup.");
//             }

//             // 3. [SOP 2.3.3] 비즈니스 로직 (v17 전문가 위임)
//             // ITotpService를 호출하여 TOTP 비밀 키와 QR 코드 생성
//             // (v17 수정) ITotpService는 EnrollMfaMethodResponse를 직접 반환함
//             var setupInfoResponse = _totpService.GenerateTotpSetup("AuthHive", user.Email);
//             if (setupInfoResponse == null || !setupInfoResponse.Success || string.IsNullOrEmpty(setupInfoResponse.SecretKey))
//             {
//                 throw new InvalidOperationException("Failed to generate TOTP setup information.");
//             }

//             // 4. [SOP 2.3.3] 엔티티 상태 변경
//             // [CS1061 해결] 'TwoFactorSecret' -> 'TotpSecret'으로 수정 
//             user.TotpSecret = setupInfoResponse.SecretKey;
            
//             // [v17 중요] 등록(Enroll)은 했지만, 아직 활성화(Verified)되지는 않음.
//             user.IsTwoFactorEnabled = false; 
//             user.TwoFactorMethod = "TOTP"; // [v17] 메서드 이름 저장
//             // 5. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
//             await _userRepository.UpdateAsync(user, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             // 6. [SOP 2.3.6] 이벤트 발행
//             // [v17] AuthenticationMethodConfiguredEvent 계약서 준수 [cite: 94-178]
//             var configuredEvent = AuthenticationMethodConfiguredEvent.Success(
//                 organizationId: user.OrganizationId ?? Guid.Empty, // (User의 기본 OrgId 사용)
//                 method: AuthenticationMethod.Password, // (MFA는 Password의 하위 설정으로 간주)
//                 actionType: ConfigurationActionType.Updated,
//                 configuredBy: command.TriggeredBy ?? user.Id
//             );
//             await _mediator.Publish(configuredEvent, cancellationToken);

//             _logger.LogInformation("TOTP method enrolled for User {UserId}. SecretKey generated.", user.Id);

//             // 7. [SOP 2.3.7] 응답 반환
//             // ITotpService가 반환한 DTO를 그대로 반환
//             return setupInfoResponse;
//         }
//     }
// }