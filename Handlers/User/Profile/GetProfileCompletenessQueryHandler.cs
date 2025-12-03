using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories.Profile;
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle; // [New] UserRepo 사용
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.User.Common;
using AuthHive.Core.Models.User.Queries.Profile;
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

// 별칭 사용 (User Entity)
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Handlers.User.Profile;

/// <summary>
/// [v18] "프로필 완성도 조회" 유스케이스 핸들러
/// </summary>
// [Fix CS8631] 인터페이스 정의에 맞춰 반환 타입을 Nullable(?)로 변경
public class GetProfileCompletenessQueryHandler : IRequestHandler<GetProfileCompletenessQuery, ProfileCompletenessInfo?>
{
    private readonly IUserProfileRepository _profileRepository;
    private readonly IUserRepository _userRepository; // User 정보 조회용
    private readonly ICacheService _cacheService;
    private readonly ILogger<GetProfileCompletenessQueryHandler> _logger;
    
    private const string CACHE_KEY_COMPLETENESS_PREFIX = "user:completeness:";
    private const int CACHE_EXPIRATION_MINUTES = 5;

    public GetProfileCompletenessQueryHandler(
        IUserProfileRepository profileRepository,
        IUserRepository userRepository,
        ICacheService cacheService,
        ILogger<GetProfileCompletenessQueryHandler> logger)
    {
        _profileRepository = profileRepository;
        _userRepository = userRepository;
        _cacheService = cacheService;
        _logger = logger;
    }

    // [Fix CS8631] 반환 타입 ? 추가
    public async Task<ProfileCompletenessInfo?> Handle(GetProfileCompletenessQuery query, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling GetProfileCompletenessQuery for User {UserId}", query.UserId);

        var cacheKey = $"{CACHE_KEY_COMPLETENESS_PREFIX}{query.UserId}";

        // 1. 캐시 조회
        var cachedInfo = await _cacheService.GetAsync<ProfileCompletenessInfo>(cacheKey, cancellationToken);
        if (cachedInfo != null) return cachedInfo;

        // 2. DB 조회 (Profile & User)
        var profile = await _profileRepository.GetByIdAsync(query.UserId, cancellationToken);
        var user = await _userRepository.GetByIdAsync(query.UserId, cancellationToken);

        if (profile == null || user == null)
        {
            // User나 Profile이 없으면 null 반환 (Query 정의상 허용됨)
            return null; 
        }

        // 3. 완성도 계산 (User 엔티티 함께 전달)
        var (completedFields, fieldWeights) = CalculateFieldCompletion(profile, user);
        var missingFields = GetMissingFields(completedFields, fieldWeights);
        var nextSteps = GenerateNextSteps(missingFields);
        var (completionPercentage, isComplete) = RecalculateCompleteness(completedFields, fieldWeights);

        // 4. 응답 DTO 생성
        var completenessInfo = new ProfileCompletenessInfo(
            userId: query.UserId,
            completionPercentage: completionPercentage,
            completedFields: completedFields,
            fieldWeights: fieldWeights,
            calculatedAt: DateTime.UtcNow,
            missingFields: missingFields,
            // LastProfileUpdateAt이 없으면 UpdatedAt이나 CreatedAt 사용
            lastUpdated: profile.LastProfileUpdateAt ?? profile.UpdatedAt ?? profile.CreatedAt, 
            isComplete: isComplete,
            nextSteps: nextSteps
        );

        // 5. 캐시 저장
        await _cacheService.SetAsync(cacheKey, completenessInfo, TimeSpan.FromMinutes(CACHE_EXPIRATION_MINUTES), cancellationToken);

        return completenessInfo;
    }

    // [Fix CS1061] User 엔티티를 인자로 받아서 전화번호 정보 확인
    private (Dictionary<string, bool> CompletedFields, Dictionary<string, int> FieldWeights) CalculateFieldCompletion(
        UserProfile profile, 
        UserEntity user)
    {
        var completed = new Dictionary<string, bool>();
        var weights = new Dictionary<string, int>
        {
            { "PhoneNumber", 10 },
            { "ProfileImage", 20 },
            { "Bio", 10 },
            { "Location", 10 },
            { "Website", 10 },
            { "PhoneVerification", 10 },
            { "TimeZone", 5 },
            { "PreferredLanguage", 5 }
            // (엔티티에 추가된 DateOfBirth, Gender가 있다면 가중치 추가 가능)
        };

        // [Fix Logic] User 엔티티의 속성 사용
        completed["PhoneNumber"] = !string.IsNullOrWhiteSpace(user.PhoneNumber);
        completed["PhoneVerification"] = user.IsPhoneNumberConfirmed;

        // Profile 엔티티의 속성 사용
        completed["ProfileImage"] = !string.IsNullOrWhiteSpace(profile.ProfileImageUrl);
        completed["Bio"] = !string.IsNullOrWhiteSpace(profile.Bio);
        completed["Location"] = !string.IsNullOrWhiteSpace(profile.Location);
        completed["Website"] = !string.IsNullOrWhiteSpace(profile.WebsiteUrl);
        completed["TimeZone"] = profile.TimeZone != "UTC";
        completed["PreferredLanguage"] = profile.PreferredLanguage != "en";

        return (completed, weights);
    }

    private List<string> GetMissingFields(Dictionary<string, bool> completedFields, Dictionary<string, int> fieldWeights)
    {
        var missing = new List<string>();
        foreach (var kvp in fieldWeights)
        {
            if (!completedFields.TryGetValue(kvp.Key, out bool isCompleted) || !isCompleted)
            {
                missing.Add(kvp.Key);
            }
        }
        return missing;
    }

    private (int Percentage, bool IsComplete) RecalculateCompleteness(Dictionary<string, bool> completedFields, Dictionary<string, int> fieldWeights)
    {
        int totalWeight = fieldWeights.Values.Sum();
        int completedWeight = 0;
        bool isComplete = true;

        foreach (var kvp in fieldWeights)
        {
            if (completedFields.TryGetValue(kvp.Key, out bool isCompleted) && isCompleted)
            {
                completedWeight += kvp.Value;
            }
            else if (kvp.Value > 0)
            {
                isComplete = false;
            }
        }

        int percentage = (totalWeight > 0) ? (int)Math.Round((double)completedWeight / totalWeight * 100) : 0;
        return (percentage, isComplete);
    }

    private List<string> GenerateNextSteps(List<string> missingFields)
    {
        var nextSteps = new List<string>();
        if (missingFields.Contains("ProfileImage")) nextSteps.Add("Upload a profile photo");
        if (missingFields.Contains("PhoneNumber")) nextSteps.Add("Add your phone number");
        if (missingFields.Contains("PhoneVerification")) nextSteps.Add("Verify your phone number");
        if (missingFields.Contains("Bio")) nextSteps.Add("Write a short bio");
        return nextSteps;
    }
}