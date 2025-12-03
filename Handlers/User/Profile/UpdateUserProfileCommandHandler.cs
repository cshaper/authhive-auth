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

namespace AuthHive.Core.Handlers.User.Profile;

public class UpdateUserProfileCommandHandler : IRequestHandler<UpdateUserProfileCommand, UserProfileResponse>
{
    private readonly AuthDbContext _context;
    private readonly IPublisher _publisher;
    private readonly ILogger<UpdateUserProfileCommandHandler> _logger;

    public UpdateUserProfileCommandHandler(
        AuthDbContext context, 
        IPublisher publisher, 
        ILogger<UpdateUserProfileCommandHandler> logger)
    {
        _context = context;
        _publisher = publisher;
        _logger = logger;
    }

    public async Task<UserProfileResponse> Handle(UpdateUserProfileCommand command, CancellationToken cancellationToken)
    {
        // 1. 조회
        var entity = await _context.UserProfiles
            .FirstOrDefaultAsync(p => p.UserId == command.UserId, cancellationToken);

        if (entity == null)
        {
            throw new KeyNotFoundException($"UserProfile not found for UserId: {command.UserId}");
        }

        // 2. 수정 (DDD 메서드 활용)
        entity.UpdateDetails(
            bio: command.Bio,
            location: command.Location,
            imageUrl: entity.ProfileImageUrl, // 이미지는 변경 안 함
            language: command.PreferredLanguage,
            timeZone: command.TimeZone,
            websiteUrl: command.WebsiteUrl,
            dateOfBirth: command.DateOfBirth,
            gender: command.Gender
        );

        // [v18] UpdateDetails 메서드에 없는 필드는 수동 처리
        if (command.PreferredCurrency != null) 
            entity.PreferredCurrency = command.PreferredCurrency;
            
        if (command.IsPublic.HasValue) 
            entity.IsPublic = command.IsPublic.Value;

        // 3. 저장
        await _context.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Updated UserProfile for UserId: {UserId}", command.UserId);

        // 4. 이벤트 발행
        await _publisher.Publish(new UserProfileUpdatedEvent
        {
            AggregateId = entity.UserId,      // Aggregate Root ID
            OccurredOn = DateTime.UtcNow,     // 이벤트 발생 시각
            UserId = entity.UserId,
            Bio = entity.Bio,
            Location = entity.Location,
            WebsiteUrl = entity.WebsiteUrl,
            DateOfBirth = entity.DateOfBirth,
            Gender = entity.Gender,
            PreferredCurrency = entity.PreferredCurrency,
            PreferredLanguage = entity.PreferredLanguage,
            TimeZone = entity.TimeZone,
            IsPublic = entity.IsPublic,
            UpdatedAt = entity.LastProfileUpdateAt ?? DateTime.UtcNow
        }, cancellationToken);

        // 5. 응답 반환
        return MapToResponse(entity);
    }

    // 간단한 매핑 헬퍼 (중복이지만 분리된 클래스 원칙을 위해 각각 포함)
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
            CompletionPercentage = 50 // 실제 로직으로 대체
        };
    }
}