using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Core.Interfaces.User.Repositories.Profile;
using AuthHive.Core.Interfaces.User.Repositories.Security;
using AuthHive.Core.Models.User.Common;
using AuthHive.Core.Models.User.Queries.Profile;
using AuthHive.Core.Models.User.Responses.Profile;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq; 
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Handlers.User.Profile;

public class GetIncompleteProfilesQueryHandler : IRequestHandler<GetIncompleteProfilesQuery, IReadOnlyList<UserDetailResponse>>
{
    private readonly IUserProfileRepository _profileRepository;
    private readonly IUserRepository _userRepository;
    private readonly IUserSocialAccountRepository _socialRepository; 
    private readonly ILogger<GetIncompleteProfilesQueryHandler> _logger;

    public GetIncompleteProfilesQueryHandler(
        IUserProfileRepository profileRepository,
        IUserRepository userRepository,
        IUserSocialAccountRepository socialRepository,
        ILogger<GetIncompleteProfilesQueryHandler> logger)
    {
        _profileRepository = profileRepository;
        _userRepository = userRepository;
        _socialRepository = socialRepository;
        _logger = logger;
    }

    public async Task<IReadOnlyList<UserDetailResponse>> Handle(GetIncompleteProfilesQuery query, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling GetIncompleteProfilesQuery...");

        var profiles = await _profileRepository.FindAsync(
            p => true,
            cancellationToken);

        var incompleteProfiles = profiles
            .Where(p => CalculateCompletionPercentage(p) < query.MaxCompletenessThreshold)
            .Take(query.Limit)
            .ToList();

        var result = new List<UserDetailResponse>();

        foreach (var profile in incompleteProfiles)
        {
            var user = await _userRepository.GetByIdAsync(profile.UserId, cancellationToken);
            if (user != null)
            {
                var socialAccounts = await _socialRepository.GetByUserIdAsync(user.Id, cancellationToken);
                result.Add(MapToDto(profile, user, socialAccounts));
            }
        }

        return result;
    }

    private UserDetailResponse MapToDto(
        UserProfile profile, 
        UserEntity user, 
        IEnumerable<UserSocialAccount> socialAccounts)
    {
        var primarySocial = socialAccounts.FirstOrDefault();

        return new UserDetailResponse
        {
            Id = user.Id,
            Status = user.Status,
            Email = user.Email,
            Username = user.Username,
            IsEmailVerified = user.IsEmailVerified,
            PhoneNumber = user.PhoneNumber,
            IsTwoFactorEnabled = user.IsTwoFactorEnabled,
            LastLoginAt = user.LastLoginAt,
            CreatedAt = user.CreatedAt,

            // [Fix CS1061] ProviderUserId -> ProviderId
            ExternalUserId = primarySocial?.ProviderId, 
            ExternalSystemType = primarySocial?.Provider.ToString(),
            
            UpdatedAt = user.UpdatedAt,

            Profile = new UserProfileInfo
            {
                 UserId = profile.UserId,
                 ProfileImageUrl = profile.ProfileImageUrl,
                 TimeZone = profile.TimeZone,
                 PreferredLanguage = profile.PreferredLanguage,
                 PreferredCurrency = profile.PreferredCurrency,
                 Bio = profile.Bio,
                 WebsiteUrl = profile.WebsiteUrl,
                 Location = profile.Location,
                 CompletionPercentage = CalculateCompletionPercentage(profile),
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