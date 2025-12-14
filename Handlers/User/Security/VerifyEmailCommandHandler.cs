// using System;
// using System.Linq; // Select 사용
// using System.Threading;
// using System.Threading.Tasks;
// using System.Collections.Generic;
// using MediatR;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Logging;
// using FluentValidation;

// // [Core & Infra]
// using AuthHive.Infra.Persistence.Context; // [변경] AuthDbContext 직접 사용
// using AuthHive.Core.Exceptions;

// // [Models]
// using AuthHive.Core.Models.User.Commands.Security;
// using AuthHive.Core.Models.User.Events.Profile;

// namespace AuthHive.Core.Handlers.User.Security;

// /// <summary>
// /// [Auth] 이메일 인증 확인 핸들러
// /// </summary>
// public class VerifyEmailCommandHandler : IRequestHandler<VerifyEmailCommand, Unit>
// {
//     private readonly AuthDbContext _context; // [변경] Repository 제거 -> DbContext 주입
//     private readonly IValidator<VerifyEmailCommand> _validator;
//     private readonly IPublisher _publisher; // 이벤트 발행용
//     private readonly ILogger<VerifyEmailCommandHandler> _logger;

//     public VerifyEmailCommandHandler(
//         AuthDbContext context,
//         IValidator<VerifyEmailCommand> validator,
//         IPublisher publisher,
//         ILogger<VerifyEmailCommandHandler> logger)
//     {
//         _context = context;
//         _validator = validator;
//         _publisher = publisher;
//         _logger = logger;
//     }

//     public async Task<Unit> Handle(VerifyEmailCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling VerifyEmailCommand for User {UserId}", command.UserId);

//         // 1. 유효성 검사 (FluentValidation)
//         var validationResult = await _validator.ValidateAsync(command, cancellationToken);
//         if (!validationResult.IsValid)
//         {
//             var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
//             throw new DomainValidationException("Email verification validation failed.", errorMessages);
//         }

//         // 2. 사용자 조회 (DbContext 직접 사용)
//         var user = await _context.Users
//             .FirstOrDefaultAsync(u => u.Id == command.UserId, cancellationToken);

//         if (user == null)
//         {
//             throw new KeyNotFoundException($"User not found: {command.UserId}");
//         }

//         // 3. [멱등성] 이미 인증된 사용자인지 먼저 확인
//         // (토큰 검증 로직을 타기 전에 체크하는 것이 효율적입니다)
//         if (user.IsEmailVerified)
//         {
//             _logger.LogInformation("Email is already verified for User {UserId}. Skipping update.", command.UserId);
//             return Unit.Value;
//         }

//         // 4. 토큰 검증 및 상태 변경 (User Entity에게 위임)
//         try
//         {
//             // Entity의 VerifyEmail(string token) 호출
//             // 내부에서 토큰 일치 여부, 만료 시간 확인 후 IsEmailVerified = true로 변경함
//             user.VerifyEmail(command.Token);
//         }
//         catch (InvalidOperationException ex)
//         {
//             // 검증 실패 (토큰 불일치, 만료 등)
//             _logger.LogWarning("Email verification failed for User {UserId}: {Message}", command.UserId, ex.Message);
//             throw new DomainValidationException(ex.Message);
//         }

//         // [삭제됨] user.VerifyEmail(); -> 이 줄이 CS1501 오류의 원인이었으며, 위에서 이미 처리했으므로 삭제함.

//         // 5. 저장 (Change Tracking)
//         await _context.SaveChangesAsync(cancellationToken);

//         // 6. 이벤트 발행
//         var verifiedEvent = new UserAccountVerifiedEvent
//         {
//             // [BaseEvent 필수]
//             AggregateId = user.Id,
//             OccurredOn = DateTime.UtcNow,
            
//             // [Audit info]
//             TriggeredBy = command.TriggeredBy,
//             OrganizationId = command.OrganizationId,
//             CorrelationId = command.CorrelationId?.ToString(),

//             // [Event Props]
//             UserId = user.Id,
//             VerifiedByConnectedId = command.TriggeredBy,
//             VerificationType = "Email",
//             // VerifyEmail() 호출 시점이 인증 시점이므로 현재 시간 사용
//             VerifiedAt = DateTime.UtcNow, 
//             VerificationMethod = "Link",
//             IsManualVerification = false
//         };

//         await _publisher.Publish(verifiedEvent, cancellationToken);

//         _logger.LogInformation("Email verified successfully for User {UserId}", user.Id);

//         return Unit.Value;
//     }
// }