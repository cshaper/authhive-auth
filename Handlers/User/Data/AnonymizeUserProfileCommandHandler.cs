// using System;
// using System.Linq;
// using System.Collections.Generic;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using FluentValidation;

// // [Core Interfaces] 
// // ✅ Infra(DbContext) 제거 -> Repository Interface 추가
// using AuthHive.Core.Interfaces.User.Repositories.Profile; 
// using AuthHive.Core.Exceptions;

// // [Models]
// using AuthHive.Core.Models.User.Commands.Data;
// using AuthHive.Core.Models.User.Events.Profile;

// namespace AuthHive.Core.Handlers.User.Data;

// /// <summary>
// /// [v18] "사용자 프로필 비식별화" 유스케이스 핸들러 (Refactored)
// /// </summary>
// public class AnonymizeUserProfileCommandHandler : IRequestHandler<AnonymizeUserProfileCommand, Unit>
// {
//     // ❌ private readonly AuthDbContext _context;
//     private readonly IUserProfileRepository _repository; // ✅ Repository 사용
//     private readonly IPublisher _publisher;
//     private readonly ILogger<AnonymizeUserProfileCommandHandler> _logger;
//     private readonly IValidator<AnonymizeUserProfileCommand> _validator;

//     public AnonymizeUserProfileCommandHandler(
//         IUserProfileRepository repository, // ✅ 생성자 주입 변경
//         IPublisher publisher,
//         ILogger<AnonymizeUserProfileCommandHandler> logger,
//         IValidator<AnonymizeUserProfileCommand> validator)
//     {
//         _repository = repository;
//         _publisher = publisher;
//         _logger = logger;
//         _validator = validator;
//     }

//     public async Task<Unit> Handle(AnonymizeUserProfileCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Handling AnonymizeUserProfileCommand for User {UserId}", command.UserId);

//         // 0. 유효성 검사
//         var validationResult = await _validator.ValidateAsync(command, cancellationToken);
//         if (!validationResult.IsValid)
//         {
//             var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
//             throw new DomainValidationException("Anonymization command validation failed.", errorMessages);
//         }

//         // 1. 엔티티 조회 (Repository 사용)
//         // ✅ _context.UserProfiles.FirstOrDefaultAsync(...) 대체
//         var profile = await _repository.GetByUserIdAsync(command.UserId, cancellationToken);
            
//         if (profile == null)
//         {
//             _logger.LogWarning("Profile not found for anonymization (UserId: {UserId}). Skipping.", command.UserId);
//             return Unit.Value;
//         }

//         // 2. 엔티티 도메인 메서드 호출 (Anonymize)
//         // (이 부분은 도메인 로직이므로 변경 없음)
//         profile.Anonymize(); 

//         // 2.1. 이벤트에 기록할 비식별화 필드 목록
//         var anonymizedFields = new List<string> 
//         { 
//             nameof(profile.Bio), 
//             nameof(profile.Location), 
//             nameof(profile.ProfileImageUrl),
//             nameof(profile.WebsiteUrl),
//             nameof(profile.ProfileMetadata),
//             nameof(profile.DateOfBirth), 
//             nameof(profile.Gender) 
//         };

//         // 3. 데이터베이스 저장 (Repository 사용)
//         // ✅ _context.SaveChangesAsync(...) 대체
//         await _repository.UpdateAsync(profile, cancellationToken);

//         _logger.LogInformation("Profile anonymized successfully for user {UserId}.", profile.UserId);

//         // 4. 이벤트 발행
//         var now = DateTime.UtcNow;
        
//         var anonymizedEvent = new ProfileDataAnonymizedEvent
//         {
//             // BaseEvent Props
//             AggregateId = profile.UserId,
//             OccurredOn = now,
            
//             // Command/Execution context
//             EventId = Guid.NewGuid(),

//             // Domain Props
//             UserId = profile.UserId,
//             ProfileId = profile.Id,
//             AnonymizedAt = now,
//             AnonymizedFields = anonymizedFields.AsReadOnly(),
//             AnonymizationReason = command.AnonymizationReason,
//             IsSoftDeleted = true 
//         };

//         await _publisher.Publish(anonymizedEvent, cancellationToken);
        
//         return Unit.Value;
//     }
// }