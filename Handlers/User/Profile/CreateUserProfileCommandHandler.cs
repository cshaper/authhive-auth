using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Models.User.Commands.Profile;
using AuthHive.Core.Models.User.Events.Profile;
using AuthHive.Core.Models.User.Responses.Profile;
using AuthHive.Core.Interfaces;
using AuthHive.Infra.Persistence.Context;
using FluentValidation;
using AuthHive.Core.Exceptions;

namespace AuthHive.Core.Handlers.User.Profile;

public class CreateUserProfileCommandHandler : IRequestHandler<CreateUserProfileCommand, UserProfileResponse>
{
    private readonly AuthDbContext _context;
    private readonly IPublisher _publisher;
    private readonly ILogger<CreateUserProfileCommandHandler> _logger;
    private readonly IValidator<CreateUserProfileCommand> _validator;
    public CreateUserProfileCommandHandler(
            AuthDbContext context,
            IPublisher publisher,
            ILogger<CreateUserProfileCommandHandler> logger,
            IValidator<CreateUserProfileCommand> validator) // [추가] 생성자 주입
    {
        _context = context;
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<UserProfileResponse> Handle(CreateUserProfileCommand command, CancellationToken cancellationToken)
    {
        // [추가] 0. 유효성 검사 필수!
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Profile creation failed", errorMessages);
        }
        // 2. 중복 체크
        bool exists = await _context.UserProfiles
            .AnyAsync(p => p.UserId == command.UserId, cancellationToken);

        if (exists)
        {
            throw new InvalidOperationException($"UserProfile already exists for UserId: {command.UserId}");
        }

        // 2. 엔티티 생성
        var entity = new UserProfile
        {
            UserId = command.UserId,
            Bio = command.Bio,
            Location = command.Location,

            // [v18 New Fields]
            DateOfBirth = command.DateOfBirth,
            Gender = command.Gender,
            IsPublic = command.IsPublic,

            // 값이 없으면 기본값 사용
            PreferredLanguage = command.PreferredLanguage ?? "en",
            PreferredCurrency = command.PreferredCurrency ?? "USD",
            TimeZone = command.TimeZone ?? "UTC",

            CreatedAt = DateTime.UtcNow,
            LastProfileUpdateAt = DateTime.UtcNow
        };

        _context.UserProfiles.Add(entity);
        await _context.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Created UserProfile for UserId: {UserId}", command.UserId);

        // 3. 이벤트 발행
        await _publisher.Publish(new UserProfileCreatedEvent
        {
            // [Fix] BaseEvent의 필수(required) 속성 초기화
            AggregateId = entity.UserId,      // Aggregate Root ID
            OccurredOn = DateTime.UtcNow,     // 이벤트 발생 시각
            UserId = entity.UserId,
            ProfileId = entity.Id,
            Bio = entity.Bio,
            Location = entity.Location,
            DateOfBirth = entity.DateOfBirth,
            Gender = entity.Gender,
            PreferredCurrency = entity.PreferredCurrency,
            PreferredLanguage = entity.PreferredLanguage,
            TimeZone = entity.TimeZone,
            CreatedAt = entity.CreatedAt
        }, cancellationToken);

        // 4. 응답 반환
        return MapToResponse(entity);
    }

    // 간단한 매핑 헬퍼
    private static UserProfileResponse MapToResponse(UserProfile entity)
    {
        return new UserProfileResponse
        {
            UserId = entity.UserId,
            Bio = entity.Bio,
            Location = entity.Location,
            ProfileImageUrl = entity.ProfileImageUrl,
            WebsiteUrl = entity.WebsiteUrl,
            DateOfBirth = entity.DateOfBirth,
            Gender = entity.Gender,
            PreferredLanguage = entity.PreferredLanguage,
            PreferredCurrency = entity.PreferredCurrency,
            TimeZone = entity.TimeZone,
            IsPublic = entity.IsPublic,
            LastProfileUpdateAt = entity.LastProfileUpdateAt,
            CompletionPercentage = 0 // 계산 로직 필요 시 추가
        };
    }
}