using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.User.Repositories.Profile;
using AuthHive.Core.Interfaces.User.Repositories.Security; // [New]
using AuthHive.Core.Models.User.Common;
using AuthHive.Core.Models.User.Queries.Profile;
using AuthHive.Core.Models.User.Responses.Profile;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq; 
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User; // Alias

namespace AuthHive.Auth.Handlers.User.Profile; // Correct Namespace

/// <summary>
/// [v18] "Username으로 사용자 조회" 유스케이스 핸들러 (SOP 1-Read-G)
/// </summary>
public class GetUserByUsernameQueryHandler : IRequestHandler<GetUserByUsernameQuery, UserDetailResponse>
{
    private readonly IUserRepository _userRepository;
    private readonly IUserProfileRepository _profileRepository;
    private readonly IUserSocialAccountRepository _socialRepository; // [New]
    private readonly ILogger<GetUserByUsernameQueryHandler> _logger;

    public GetUserByUsernameQueryHandler(
        IUserRepository userRepository,
        IUserProfileRepository profileRepository,
        IUserSocialAccountRepository socialRepository,
        ILogger<GetUserByUsernameQueryHandler> logger)
    {
        _userRepository = userRepository;
        _profileRepository = profileRepository;
        _socialRepository = socialRepository;
        _logger = logger;
    }

    public async Task<UserDetailResponse> Handle(GetUserByUsernameQuery query, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling GetUserByUsernameQuery for {Username}", query.Username);

        // 1. User Entity Lookup
        // [Fix CS1061] Use GetByUsernameAsync as defined in IUserRepository
        var user = await _userRepository.GetByUsernameAsync(query.Username, cancellationToken);
        
        if (user == null)
        {
            throw new KeyNotFoundException($"User not found with username: {query.Username}");
        }

        // 2. UserProfile Lookup
        var profile = await _profileRepository.GetByIdAsync(user.Id, cancellationToken);

        // 3. Social Account Lookup
        var socialAccounts = await _socialRepository.GetByUserIdAsync(user.Id, cancellationToken);

        // 4. Map to Response DTO
        return MapToDto(profile, user, socialAccounts);
    }

    private UserDetailResponse MapToDto(
        UserProfile? profile, 
        UserEntity user, 
        IEnumerable<UserSocialAccount> socialAccounts)
    {
        var primarySocial = socialAccounts.FirstOrDefault();

        return new UserDetailResponse
        {
            // --- Basic User Info ---
            Id = user.Id,
            Status = user.Status,
            Email = user.Email,
            Username = user.Username,
            // [Fix] DisplayName removed
            IsEmailVerified = user.IsEmailVerified,
            IsTwoFactorEnabled = user.IsTwoFactorEnabled,
            LastLoginAt = user.LastLoginAt,
            CreatedAt = user.CreatedAt,
            PhoneNumber = user.PhoneNumber, // From User Entity

            // --- External Info (from SocialAccount) ---
            ExternalUserId = primarySocial?.ProviderId,
            ExternalSystemType = primarySocial?.Provider.ToString(),
            
            UpdatedAt = user.UpdatedAt,
            // CreatedByConnectedId, UpdatedByConnectedId Removed

            // --- Profile Info ---
            Profile = profile == null ? null : new UserProfileInfo
            {
                 UserId = profile.UserId,
                 // PhoneNumber = profile.PhoneNumber, // Removed (on User)
                 // PhoneVerified = profile.PhoneVerified, // Removed (on User)
                 ProfileImageUrl = profile.ProfileImageUrl,
                 TimeZone = profile.TimeZone,
                 PreferredLanguage = profile.PreferredLanguage,
                 PreferredCurrency = profile.PreferredCurrency,
                 Bio = profile.Bio,
                 WebsiteUrl = profile.WebsiteUrl,
                 Location = profile.Location,
                 DateOfBirth = profile.DateOfBirth,
                 Gender = profile.Gender,
                 IsPublic = profile.IsPublic,
                 LastProfileUpdateAt = profile.LastProfileUpdateAt,
                 
                 CompletionPercentage = CalculateCompletionPercentage(profile)
            },
            
            Organizations = new List<UserOrganizationInfo>(), 
            ActiveSessionCount = 0,
            TotalConnectedIdCount = 0 
        };
    }

    private int CalculateCompletionPercentage(UserProfile profile)
    {
        int score = 0;
        if (!string.IsNullOrEmpty(profile.Bio)) score += 20;
        if (!string.IsNullOrEmpty(profile.Location)) score += 20;
        if (!string.IsNullOrEmpty(profile.ProfileImageUrl)) score += 20;
        return score;
    }
}