using System;
using System.Linq; 
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation;

// [Core Interfaces]
// ✅ Infra(DbContext) 제거 -> Repository Interface 추가
using AuthHive.Core.Interfaces.User.Repositories.Profile; 
using AuthHive.Core.Exceptions;

// [Models & Entities]
using AuthHive.Core.Entities.User;
using AuthHive.Core.Models.User.Commands.Profile;
using AuthHive.Core.Models.User.Events.Profile;
using AuthHive.Core.Models.User.Responses.Profile;

namespace AuthHive.Core.Handlers.User.Profile;

public class CreateUserProfileCommandHandler : IRequestHandler<CreateUserProfileCommand, UserProfileResponse>
{
    // ❌ private readonly AuthDbContext _context;
    private readonly IUserProfileRepository _repository; // ✅ Repository 사용
    private readonly IPublisher _publisher;
    private readonly ILogger<CreateUserProfileCommandHandler> _logger;
    private readonly IValidator<CreateUserProfileCommand> _validator;

    public CreateUserProfileCommandHandler(
            IUserProfileRepository repository, // ✅ 생성자 주입 변경
            IPublisher publisher,
            ILogger<CreateUserProfileCommandHandler> logger,
            IValidator<CreateUserProfileCommand> validator) 
    {
        _repository = repository;
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<UserProfileResponse> Handle(CreateUserProfileCommand command, CancellationToken cancellationToken)
    {
        // 0. 유효성 검사
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Profile creation failed", errorMessages);
        }

        // 1. 중복 체크 (Repository 메서드 사용)
        // ✅ _context.UserProfiles.AnyAsync(...) 대체
        // (Repository에 ExistsByUserIdAsync 메서드가 필요합니다)
        bool exists = await _repository.ExistsByUserIdAsync(command.UserId, cancellationToken);

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

        // 3. 저장 (Repository Add)
        // ✅ _context.Add + SaveChangesAsync 대체
        await _repository.AddAsync(entity, cancellationToken);

        _logger.LogInformation("Created UserProfile for UserId: {UserId}", command.UserId);

        // 4. 이벤트 발행
        await _publisher.Publish(new UserProfileCreatedEvent
        {
            // [Fix] BaseEvent Required
            AggregateId = entity.UserId,      
            OccurredOn = DateTime.UtcNow,     
            
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

        // 5. 응답 반환
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
            CompletionPercentage = 0 
        };
    }
}