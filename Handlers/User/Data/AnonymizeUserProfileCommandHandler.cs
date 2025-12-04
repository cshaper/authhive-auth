using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using FluentValidation; // v18 표준: Command이므로 필수

// [Core & Infra]
using AuthHive.Infra.Persistence.Context;
using AuthHive.Core.Exceptions;

// [Models]
using AuthHive.Core.Models.User.Commands.Data;
using AuthHive.Core.Models.User.Events.Profile;

namespace AuthHive.Core.Handlers.User.Data;

/// <summary>
/// [v18] "사용자 프로필 비식별화" 유스케이스 핸들러 (최종 수정본)
/// </summary>
public class AnonymizeUserProfileCommandHandler : IRequestHandler<AnonymizeUserProfileCommand, Unit>
{
    private readonly AuthDbContext _context;
    private readonly IPublisher _publisher;
    private readonly ILogger<AnonymizeUserProfileCommandHandler> _logger;
    private readonly IValidator<AnonymizeUserProfileCommand> _validator; // v18 표준: Command Validator

    public AnonymizeUserProfileCommandHandler(
        AuthDbContext context,
        IPublisher publisher,
        ILogger<AnonymizeUserProfileCommandHandler> logger,
        IValidator<AnonymizeUserProfileCommand> validator)
    {
        _context = context;
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<Unit> Handle(AnonymizeUserProfileCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling AnonymizeUserProfileCommand for User {UserId}", command.UserId);

        // 0. 유효성 검사 (v18 표준)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Anonymization command validation failed.", errorMessages);
        }

        // 1. 엔티티 조회
        var profile = await _context.UserProfiles
            .FirstOrDefaultAsync(p => p.UserId == command.UserId, cancellationToken);
            
        if (profile == null)
        {
            _logger.LogWarning("Profile not found for anonymization (UserId: {UserId}). Skipping.", command.UserId);
            return Unit.Value;
        }

        // 2. 엔티티 도메인 메서드 호출 (Anonymize)
        // UserProfile.Anonymize() 메서드는 Bio, Location, DateOfBirth, Gender 등을 null로 만듦
        profile.Anonymize(); 

        // 2.1. [Fix] 이벤트에 기록할 비식별화 필드 목록 (DateOfBirth, Gender 추가)
        var anonymizedFields = new List<string> 
        { 
            nameof(profile.Bio), 
            nameof(profile.Location), 
            nameof(profile.ProfileImageUrl),
            nameof(profile.WebsiteUrl),
            nameof(profile.ProfileMetadata),
            nameof(profile.DateOfBirth), 
            nameof(profile.Gender) 
        };

        // 3. 데이터베이스 저장
        await _context.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Profile anonymized successfully for user {UserId}.", profile.UserId);

        // 4. 이벤트 발행
        var now = DateTime.UtcNow;
        
        var anonymizedEvent = new ProfileDataAnonymizedEvent
        {
            // BaseEvent Props
            AggregateId = profile.UserId,
            OccurredOn = now,
            
            // Command/Execution context (명령어에 따라 값이 달라짐)
            EventId = Guid.NewGuid(),

            // Domain Props
            UserId = profile.UserId,
            ProfileId = profile.Id,
            AnonymizedAt = now,
            AnonymizedFields = anonymizedFields.AsReadOnly(),
            AnonymizationReason = command.AnonymizationReason,
            IsSoftDeleted = true 
        };

        await _publisher.Publish(anonymizedEvent, cancellationToken);
        
        return Unit.Value;
    }
}