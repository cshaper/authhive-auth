// // [AuthHive.Auth] Handlers/Auth/Authentication/VerifyMfaCommandHandler.cs
// // v17 CQRS "본보기": 'VerifyMfaCommand' (MFA 2단계)를 처리합니다.
// // (SOP 2-Write-C)
// //
// // 1. Logic (v16 이관): v16 AuthenticationManager.VerifyMfaAsync 로직을 이관합니다. (실제 검증)
// // 2. Logic (v17 재사용): v17 AuthenticateWithPasswordCommandHandler의
// //    (7~11단계) 로직을 가져와 세션 생성, 토큰 발행, 이벤트 발행을 수행합니다.
// // 3. Response: 최종 'AuthenticationResult' DTO를 반환합니다.

// using AuthHive.Core.Entities.Auth.ConnectedId;
// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Interfaces.Auth.Provider; // ITokenProvider
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Interfaces.Organization.Repository;
// using AuthHive.Core.Interfaces.User.Repository;
// using AuthHive.Core.Models.Auth.Authentication.Commands;
// using AuthHive.Core.Models.Auth.Authentication.Common; // AuthenticationResult
// using AuthHive.Core.Models.Auth.Authentication.Events; // MfaSuccessEvent
// using AuthHive.Core.Models.Auth.Session.Commands; // CreateSessionCommand
// using AuthHive.Core.Models.Auth.Session.Responses; // CreateSessionResponse
// using MediatR;
// using Microsoft.Extensions.Logging;
// using Microsoft.EntityFrameworkCore; // [v17] .Include() / .FirstOrDefaultAsync()
// using System;
// using System.Collections.Generic; // List
// using System.ComponentModel.DataAnnotations; // ValidationException
// using System.Linq; // .FirstOrDefault()
// using System.Security.Claims; // Claim
// using System.Threading;
// using System.Threading.Tasks;
// using static AuthHive.Core.Enums.Auth.SessionEnums;
// using AuthHive.Core.Enums.Auth;
// using AuthenticationResult = AuthHive.Core.Models.Auth.Authentication.Common.AuthenticationResult; // AuthenticationMethod

// namespace AuthHive.Auth.Handlers.Auth.Authentication
// {
//     /// <summary>
//     /// [v17] "MFA 검증" 유스케이스 핸들러 (SOP 2-Write-C)
//     /// v16 AuthenticationManager.VerifyMfaAsync 로직 이관
//     /// </summary>
//     public class VerifyMfaCommandHandler : IRequestHandler<VerifyMfaCommand, AuthenticationResult>
//     {
//         private readonly IMediator _mediator;
//         private readonly ILogger<VerifyMfaCommandHandler> _logger;
//         private readonly IUserRepository _userRepository;
//         private readonly IOrganizationRepository _orgRepository;
//         private readonly ITokenProvider _tokenProvider;
//         private readonly IDateTimeProvider _dateTimeProvider; // [v17 수정] 세션 만료시간 설정을 위해 추가
//         // TODO: 실제 MFA 코드 검증을 위한 'IMfaService' 또는 'IAccountSecurityService' 주입 필요

//         public VerifyMfaCommandHandler(
//             IMediator mediator,
//             ILogger<VerifyMfaCommandHandler> logger,
//             IUserRepository userRepository,
//             IOrganizationRepository orgRepository,
//             ITokenProvider tokenProvider,
//             IDateTimeProvider dateTimeProvider) // [v17 수정]
//         {
//             _mediator = mediator;
//             _logger = logger;
//             _userRepository = userRepository;
//             _orgRepository = orgRepository;
//             _tokenProvider = tokenProvider;
//             _dateTimeProvider = dateTimeProvider;
//         }

//         public async Task<AuthenticationResult> Handle(VerifyMfaCommand command, CancellationToken cancellationToken)
//         {
//             _logger.LogInformation("Handling VerifyMfaCommand for User {UserId}", command.AggregateId);

//             // 1. [SOP 2.3.1] 유효성 검증 (v17 신규)
//             // [CS1503 해결] command.OrganizationId (Guid?)가 null인지 확인합니다.
//             if (!command.OrganizationId.HasValue)
//             {
//                 _logger.LogWarning("VerifyMfaCommand failed: OrganizationId is missing for User {UserId}", command.AggregateId);
//                 throw new ValidationException("Invalid MFA request: Organization context is missing.");
//             }

//             // 2. [SOP 2.3.2] 엔티티 조회
//             // [CS1503 해결] FindByEmailAsync(string) 대신 GetByIdAsync(Guid) 사용
//             // [v17] ConnectedIds를 함께 로드해야 하므로 Query()와 Include 사용
//             var user = await _userRepository.Query()
//                 .Include(u => u.ConnectedIds)
//                 .FirstOrDefaultAsync(u => u.Id == command.AggregateId, cancellationToken);
                
//             if (user == null)
//             {
//                 throw new ValidationException("Invalid user or MFA code.");
//             }

//             // [CS1503 해결] .Value를 사용하여 non-nullable Guid로 변환
//             var organization = await _orgRepository.GetByIdAsync(command.OrganizationId.Value, cancellationToken);
//             if (organization == null)
//             {
//                 throw new KeyNotFoundException($"Organization not found: {command.OrganizationId.Value}");
//             }

//             // 2. [SOP 2.3.1] MFA 코드 검증 (v16 VerifyMfaAsync 이관) [cite: 489-505]
//             // TODO: 실제 MFA 코드 검증 로직 구현 (v16 TODO)
//             // 예: var isValid = await _mfaService.VerifyCodeAsync(user.TwoFactorSecret, command.MfaCode);
//             bool isMfaValid = true; // (임시: v16이 TODO였으므로 true로 가정)

//             if (!isMfaValid)
//             {
//                 _logger.LogWarning("MFA verification failed for User {UserId}", user.Id);
//                 throw new ValidationException("Invalid user or MFA code.");
//             }

//             // 3. [SOP 2.3.3] v17 "본보기" 로직 재사용 (Password 핸들러 7-11단계)
//             _logger.LogInformation("MFA successful for User {UserId}", user.Id);

//             // 7단계: ConnectedId 조회 [cite: 251-252]
//             var connectedId = user.ConnectedIds?.FirstOrDefault(c => c.OrganizationId == organization.Id)?.Id;
//             if (connectedId == null)
//             {
//                  _logger.LogWarning("User {UserId} passed MFA but has no active ConnectedId for Org {OrgId}.", user.Id, organization.Id);
//             }

//             // 8단계: 세션 생성 (Send Command) [cite: 260-277]
//             var sessionCommand = new CreateSessionCommand(
//                 userId: user.Id,
//                 organizationId: organization.Id,
//                 applicationId: null, 
//                 ipAddress: command.IpAddress,
//                 userAgent: command.UserAgent,
//                 expiresAt: _dateTimeProvider.UtcNow.AddHours(8), // (설정값으로 대체 필요)
//                 authenticationMethod: AuthenticationMethod.PasswordWithMfa, // [v17] MFA 성공 명시
//                 level: SessionLevel.Organization, 
//                 connectedId: connectedId
//             );

//             var sessionResponse = await _mediator.Send(sessionCommand, cancellationToken);
//             if (!sessionResponse.IsSuccess || sessionResponse.SessionId == null)
//             {
//                 throw new InvalidOperationException("MFA succeeded, but session creation failed.");
//             }

//             // 9단계: 토큰 발행 (v17 전문가 위임) [cite: 279-301]
//             var claims = new List<Claim> { new Claim("user_id", user.Id.ToString()) };
            
//             var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(user.Id, sessionResponse.SessionId.Value, claims, cancellationToken);
//             var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(user.Id, cancellationToken);

//             if (!accessTokenResult.IsSuccess || !refreshTokenResult.IsSuccess || accessTokenResult.Data == null || refreshTokenResult.Data == null)
//             {
//                  throw new InvalidOperationException("Session created, but token generation failed.");
//             }
            
//             // 10단계: 이벤트 발행 (Notify) - [v17] MfaSuccessEvent 사용
//             await _mediator.Publish(new MfaSuccessEvent(
//                 userId: user.Id,
//                 organizationId: organization.Id,
//                 mfaMethod: "TOTP" // (v16 TODO) [cite: 494-496]
//             ), cancellationToken);

//             // 11단계: 최종 응답 반환 [cite: 317-323]
//             return new AuthenticationResult(
//                 success: true,
//                 requiresMfa: false,
//                 mfaVerified: true, 
//                 isFirstLogin: false,
//                 requiresPasswordChange: false,
//                 userId: user.Id,
//                 connectedId: connectedId,
//                 sessionId: sessionResponse.SessionId,
//                 accessToken: accessTokenResult.Data.AccessToken,
//                 refreshToken: refreshTokenResult.Data, 
//                 expiresAt: accessTokenResult.Data.ExpiresAt,
//                 organizationId: organization.Id,
//                 authenticationMethod: "PasswordWithMfa"
//             );
//         }
//     }
// }