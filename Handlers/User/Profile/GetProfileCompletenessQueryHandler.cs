// [AuthHive.Auth] GetProfileCompletenessQueryHandler.cs
// v17 CQRS "본보기": 'GetProfileCompletenessQuery'를 처리하여 사용자의 프로필 완성도를 조회합니다.
// v16 UserProfileService.CalculateCompletenessAsync의 로직과 캐싱(Redis)을 이관합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Interfaces.Infra.Cache; // [v17] Redis 캐시 서비스 주입
using AuthHive.Core.Models.User.Queries;
using AuthHive.Core.Models.User.Common; // ProfileCompletenessInfo
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "프로필 완성도 조회" 유스케이스 핸들러 (SOP 1-Read-J)
    /// v17 철학에 따라 ICacheService(Redis)만 사용합니다.
    /// </summary>
    public class GetProfileCompletenessQueryHandler : IRequestHandler<GetProfileCompletenessQuery, ProfileCompletenessInfo>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly ICacheService _cacheService; // [v17] Redis (L2)만 사용
        private readonly ILogger<GetProfileCompletenessQueryHandler> _logger;
        
        private const string CACHE_KEY_COMPLETENESS_PREFIX = "user:completeness:";
        private const int CACHE_EXPIRATION_MINUTES = 5; // v16 로직 참조

        public GetProfileCompletenessQueryHandler(
            IUserProfileRepository profileRepository,
            ICacheService cacheService,
            ILogger<GetProfileCompletenessQueryHandler> logger)
        {
            _profileRepository = profileRepository;
            _cacheService = cacheService;
            _logger = logger;
        }

        public async Task<ProfileCompletenessInfo> Handle(GetProfileCompletenessQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling GetProfileCompletenessQuery for User {UserId}", query.UserId);

            var cacheKey = $"{CACHE_KEY_COMPLETENESS_PREFIX}{query.UserId}";

            // 1. 분산 캐시(Redis) 조회 (v16 로직 이관)
            var cachedInfo = await _cacheService.GetAsync<ProfileCompletenessInfo>(cacheKey, cancellationToken);
            if (cachedInfo != null)
            {
                _logger.LogDebug("Profile completeness retrieved from cache (Redis) for User {UserId}", query.UserId);
                return cachedInfo;
            }

            // 2. DB 조회 (Cache Miss)
            var profile = await _profileRepository.GetByIdAsync(query.UserId, cancellationToken);
            if (profile == null)
            {
                throw new KeyNotFoundException($"Profile not found for user: {query.UserId}");
            }

            // 3. 완성도 계산 로직 (v16 UserProfile/Service 헬퍼 로직 이관)
            var (completedFields, fieldWeights) = CalculateFieldCompletion(profile);
            var missingFields = GetMissingFields(completedFields, fieldWeights);
            var nextSteps = GenerateNextSteps(missingFields);
            var (completionPercentage, isComplete) = RecalculateCompleteness(completedFields, fieldWeights);

            // 4. 응답 DTO 생성 (v17 Immutable DTO)
            var completenessInfo = new ProfileCompletenessInfo(
                userId: query.UserId,
                completionPercentage: completionPercentage,
                completedFields: completedFields,
                fieldWeights: fieldWeights,
                calculatedAt: DateTime.UtcNow,
                missingFields: missingFields,
                lastUpdated: profile.LastProfileUpdateAt ?? profile.CreatedAt,
                isComplete: isComplete,
                nextSteps: nextSteps
            );

            // 5. 캐시 저장 (Redis에만)
            await _cacheService.SetAsync(cacheKey, completenessInfo, TimeSpan.FromMinutes(CACHE_EXPIRATION_MINUTES), cancellationToken);

            return completenessInfo;
        }

        // --- v16 UserProfile.cs의 CalculateCompletionPercentage 로직 이관 ---
        private (Dictionary<string, bool> CompletedFields, Dictionary<string, int> FieldWeights) CalculateFieldCompletion(UserProfile profile)
        {
            // [v17 로직] v16의 UserProfile.CalculateCompletionPercentage() 로직을 핸들러로 이관
            var completed = new Dictionary<string, bool>();
            var weights = new Dictionary<string, int> // (가중치는 v16 엔티티 기반으로 재구성)
            {
                { "PhoneNumber", 10 },
                { "ProfileImage", 20 },
                { "Bio", 10 },
                { "Location", 10 },
                { "Website", 10 },
                { "DateOfBirth", 10 },
                { "Gender", 10 },
                { "PhoneVerification", 10 },
                { "TimeZone", 5 },
                { "PreferredLanguage", 5 }
            };

            completed["PhoneNumber"] = !string.IsNullOrWhiteSpace(profile.PhoneNumber);
            completed["ProfileImage"] = !string.IsNullOrWhiteSpace(profile.ProfileImageUrl);
            completed["Bio"] = !string.IsNullOrWhiteSpace(profile.Bio);
            completed["Location"] = !string.IsNullOrWhiteSpace(profile.Location);
            completed["Website"] = !string.IsNullOrWhiteSpace(profile.WebsiteUrl);
            completed["DateOfBirth"] = profile.DateOfBirth.HasValue;
            completed["Gender"] = !string.IsNullOrWhiteSpace(profile.Gender);
            completed["PhoneVerification"] = profile.PhoneVerified;
            completed["TimeZone"] = profile.TimeZone != "UTC";
            completed["PreferredLanguage"] = profile.PreferredLanguage != "en";

            return (completed, weights);
        }

        // --- v16 UserProfileService.GetMissingFields 로직 이관 ---
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

        // --- v16 UserProfile.RecalculateCompleteness 로직 이관 ---
        private (int Percentage, bool IsComplete) RecalculateCompleteness(Dictionary<string, bool> completedFields, Dictionary<string, int> fieldWeights)
        {
            int totalWeight = fieldWeights.Values.Sum();
            int completedWeight = 0;
            bool isComplete = true;

            foreach (var kvp in fieldWeights)
            {
                string field = kvp.Key;
                int weight = kvp.Value;

                if (completedFields.TryGetValue(field, out bool isCompleted) && isCompleted)
                {
                    completedWeight += weight;
                }
                else if (weight > 0) // 가중치가 있는 필수 필드
                {
                    isComplete = false;
                }
            }

            int percentage = (totalWeight > 0) ? (int)Math.Round((double)completedWeight / totalWeight * 100) : 0;
            return (percentage, isComplete);
        }

        // --- v16 UserProfileService.GenerateNextSteps 로직 이관 ---
        private List<string> GenerateNextSteps(List<string> missingFields)
        {
            var nextSteps = new List<string>();
            if (missingFields.Contains("ProfileImage")) nextSteps.Add("Upload a profile photo to personalize your account");
            if (missingFields.Contains("PhoneNumber")) nextSteps.Add("Add your phone number for enhanced security");
            if (missingFields.Contains("PhoneVerification")) nextSteps.Add("Verify your phone number");
            if (missingFields.Contains("Bio")) nextSteps.Add("Write a short bio to tell others about yourself");
            if (missingFields.Count > 5) nextSteps.Add($"Complete {missingFields.Count} more fields to reach 100% profile completion");
            return nextSteps;
        }
    }
}