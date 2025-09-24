using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Text.Json;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Handler;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User;
using AuthHive.Core.Models.User.Views;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Models.User.Common;
using AuthHive.Core.Models.User.Events;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Core.AuditActionType;
using static AuthHive.Core.Enums.Core.AuditEventSeverity;
using UserEntity = AuthHive.Core.Entities.User.User;
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Repository;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using static AuthHive.Core.Constants.Event.EventTypeConstants;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Services.User
{
    /// <summary>
    /// 사용자 프로필 서비스 구현 - AuthHive v15 최종판
    /// ConnectedId 기반 작동, SaaS 철학 완벽 구현
    /// 완전한 이벤트 드리븐 아키텍처, 감사 로깅, 캐싱 전략 구현
    /// </summary>
    public class UserProfileService : IUserProfileService
    {
        private readonly IConnectedIdContext _connectedIdContext;
        private readonly IUserProfileRepository _profileRepository;
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ICacheService _cacheService;
        private readonly IMemoryCache _localCache;
        private readonly ILogger<UserProfileService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IAuditService _auditService;
        private readonly IUserEventHandler _eventHandler;
        private readonly IUserValidator _validator;
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IConnectedIdRepository _connectedIdRepository;

        // Cache configuration - 분산 캐시와 로컬 캐시 병행 사용
        private const string CACHE_KEY_PREFIX = "user:profile:";
        private const string CACHE_KEY_CONNECTED_PREFIX = "user:profile:connected:";
        private const string CACHE_KEY_ORGANIZATION_PREFIX = "org:profiles:";
        private const string CACHE_KEY_COMPLETENESS_PREFIX = "user:completeness:";
        private const int CACHE_EXPIRATION_MINUTES = 15;
        private const int CACHE_SLIDING_MINUTES = 5;
        private const int DISTRIBUTED_CACHE_EXPIRATION_MINUTES = 60;

        public UserProfileService(
            IConnectedIdRepository connectedIdRepository,
            IConnectedIdContext connectedIdContext,
            IUserProfileRepository profileRepository,
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ICacheService cacheService,
            IMemoryCache localCache,
            ILogger<UserProfileService> logger,
            IDateTimeProvider dateTimeProvider,
            IAuditService auditService,
            IUserEventHandler eventHandler,
            IUserValidator validator,
            IEmailService emailService,
            ITokenService tokenService,
            IConnectedIdService connectedIdService,
            IHttpContextAccessor httpContextAccessor)
        {
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _connectedIdContext = connectedIdContext ?? throw new ArgumentNullException(nameof(connectedIdContext));
            _profileRepository = profileRepository ?? throw new ArgumentNullException(nameof(profileRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _localCache = localCache ?? throw new ArgumentNullException(nameof(localCache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _eventHandler = eventHandler ?? throw new ArgumentNullException(nameof(eventHandler));
            _validator = validator ?? throw new ArgumentNullException(nameof(validator));
            _emailService = emailService ?? throw new ArgumentNullException(nameof(emailService));
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
            _connectedIdService = connectedIdService ?? throw new ArgumentNullException(nameof(connectedIdService));
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        }

        #region IService Implementation

        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Repository 상태 확인
                await _profileRepository.CountAsync();

                // 캐시 서비스 상태 확인
                await _cacheService.GetAsync<string>("health:check");

                // 이벤트 시스템 상태 확인
                await _eventHandler.CheckHealthAsync();

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UserProfileService health check failed");
                return false;
            }
        }

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public async Task InitializeAsync()
        {
            var initTime = _dateTimeProvider.UtcNow;
            _logger.LogInformation("UserProfileService initializing at {Time}", initTime);

            // 캐시 워밍업 - 자주 사용되는 데이터 미리 로드
            await WarmupCacheAsync();

            // 이벤트 핸들러 초기화
            await _eventHandler.InitializeAsync();

            _logger.LogInformation("UserProfileService initialized successfully at {Time}", initTime);
        }

        #endregion

        #region 프로필 CRUD with Full Features

        /// <summary>
        /// UserId로 프로필 조회 (다층 캐싱 전략)
        /// </summary>
        public async Task<ServiceResult<UserProfileDto>> GetByUserIdAsync(Guid userId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                // 1. 로컬 메모리 캐시 확인 (가장 빠름)
                var localCacheKey = $"{CACHE_KEY_PREFIX}{userId}";
                if (_localCache.TryGetValue<UserProfileDto>(localCacheKey, out var localCachedProfile) && localCachedProfile != null)
                {
                    _logger.LogDebug("Profile retrieved from local cache for user {UserId}", userId);
                    return ServiceResult<UserProfileDto>.Success(localCachedProfile);
                }

                // 2. 분산 캐시 확인 (Redis 등)
                var distributedCachedProfile = await _cacheService.GetAsync<UserProfileDto>(localCacheKey);
                if (distributedCachedProfile != null)
                {
                    // 로컬 캐시에도 저장
                    CacheProfileLocally(localCacheKey, distributedCachedProfile);
                    _logger.LogDebug("Profile retrieved from distributed cache for user {UserId}", userId);
                    return ServiceResult<UserProfileDto>.Success(distributedCachedProfile);
                }

                // 3. Repository에서 조회
                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    _logger.LogWarning("Profile not found for user {UserId}", userId);
                    return ServiceResult<UserProfileDto>.NotFound($"Profile not found for user: {userId}");
                }

                // User 정보도 함께 조회 (Email, Username, DisplayName용)
                var user = await _userRepository.GetByIdAsync(userId);
                var dto = MapToDto(profile, user);

                // 4. 모든 캐시 레벨에 저장
                await CacheProfileAllLevelsAsync(localCacheKey, dto);

                // 5. 조회 이벤트 발생
                await _eventHandler.HandleProfileViewedAsync(new ProfileViewedEvent
                {
                    UserId = userId,
                    ViewedAt = _dateTimeProvider.UtcNow,
                    ViewerConnectedId = await GetCurrentConnectedIdAsync()
                });

                // 6. 감사 로그 (읽기 작업은 Info 레벨)
                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = await GetCurrentConnectedIdAsync(),
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Read,
                    Action = "user_profile.read",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Info
                });

                return ServiceResult<UserProfileDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile for user {UserId}", userId);
                return ServiceResult<UserProfileDto>.Failure($"Failed to retrieve profile: {ex.Message}", "PROFILE_RETRIEVAL_ERROR");
            }
        }

        /// <summary>
        /// ConnectedId로 프로필 조회
        /// </summary>
        public async Task<ServiceResult<UserProfileDto>> GetByConnectedIdAsync(Guid connectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                // ConnectedId 검증
                var connectedIdResult = await _connectedIdService.ValidateConnectedIdAsync(connectedId);
                if (!connectedIdResult.IsSuccess)
                {
                    return ServiceResult<UserProfileDto>.Failure("Invalid ConnectedId", "INVALID_CONNECTED_ID");
                }

                // 다층 캐시 확인
                var cacheKey = $"{CACHE_KEY_CONNECTED_PREFIX}{connectedId}";

                // 1. 로컬 캐시
                if (_localCache.TryGetValue<UserProfileDto>(cacheKey, out var localCachedProfile) && localCachedProfile != null)
                {
                    return ServiceResult<UserProfileDto>.Success(localCachedProfile);
                }

                // 2. 분산 캐시
                var distributedCachedProfile = await _cacheService.GetAsync<UserProfileDto>(cacheKey);
                if (distributedCachedProfile != null)
                {
                    CacheProfileLocally(cacheKey, distributedCachedProfile);
                    return ServiceResult<UserProfileDto>.Success(distributedCachedProfile);
                }

                // 3. Repository 조회
                var profile = await _profileRepository.GetByConnectedIdAsync(connectedId);
                if (profile == null)
                {
                    return ServiceResult<UserProfileDto>.NotFound($"Profile not found for ConnectedId: {connectedId}");
                }

                var user = await _userRepository.GetByIdAsync(profile.UserId);
                var dto = MapToDto(profile, user);
                await CacheProfileAllLevelsAsync(cacheKey, dto);

                return ServiceResult<UserProfileDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<UserProfileDto>.Failure($"Failed to retrieve profile: {ex.Message}", "PROFILE_RETRIEVAL_ERROR");
            }
        }

        /// <summary>
        /// 프로필 생성 (완전한 이벤트 처리 및 감사 로깅)
        /// </summary>
        public async Task<ServiceResult<UserProfileDto>> CreateAsync(
            Guid userId,
            CreateUserProfileRequest request,
            Guid createdByConnectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                // 트랜잭션 시작
                await _unitOfWork.BeginTransactionAsync();

                // 1. 유효성 검사
                var validationResult = await _validator.ValidateProfileCreationAsync(userId, request);
                if (!validationResult.IsSuccess)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<UserProfileDto>.Failure(
                        string.Join(", ", validationResult.ErrorCode),
                        "VALIDATION_ERROR");
                }

                // 2. 사용자 존재 확인
                var userExists = await _userRepository.ExistsAsync(userId);
                if (!userExists)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<UserProfileDto>.NotFound($"User not found: {userId}");
                }

                // 3. 중복 확인
                var existingProfile = await _profileRepository.GetByIdAsync(userId);
                if (existingProfile != null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<UserProfileDto>.Failure(
                        $"Profile already exists for user: {userId}",
                        "PROFILE_ALREADY_EXISTS");
                }

                // 4. 전화번호 중복 확인
                if (!string.IsNullOrWhiteSpace(request.PhoneNumber))
                {
                    var phoneExists = await _profileRepository.GetByPhoneNumberAsync(request.PhoneNumber);
                    if (phoneExists != null)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult<UserProfileDto>.Failure(
                            "Phone number already in use",
                            "PHONE_NUMBER_DUPLICATE");
                    }
                }

                // 5. 엔티티 생성
                var currentTime = _dateTimeProvider.UtcNow;
                var profile = new UserProfile
                {
                    UserId = userId, // PK
                    Id = Guid.NewGuid(), // BaseEntity의 Id
                    PhoneNumber = request.PhoneNumber,
                    TimeZone = request.TimeZone ?? "UTC",
                    // 348번 줄을 다음으로 변경:
                    PreferredLanguage = "en",
                    PreferredCurrency = request.PreferredCurrency ?? "USD",
                    ProfileImageUrl = request.ProfileImageUrl,
                    Bio = request.Bio,
                    WebsiteUrl = request.WebsiteUrl,
                    Location = request.Location,
                    DateOfBirth = request.DateOfBirth,
                    Gender = request.Gender,
                    ProfileMetadata = request.Metadata,
                    IsPublic = request.IsPublic ?? false,
                    EmailNotificationsEnabled = request.EmailNotificationsEnabled ?? true,
                    SmsNotificationsEnabled = request.SmsNotificationsEnabled ?? false,
                    CreatedByConnectedId = createdByConnectedId,
                    CreatedAt = currentTime
                };

                // 완성도 계산
                profile.CompletionPercentage = profile.CalculateCompletionPercentage();
                profile.LastProfileUpdateAt = currentTime;

                // 6. 저장
                await _profileRepository.AddAsync(profile);
                await _unitOfWork.SaveChangesAsync();

                // 7. 이벤트 발생
                await _eventHandler.HandleProfileCreatedAsync(new ProfileCreatedEvent
                {
                    UserId = userId,
                    ProfileId = profile.Id,
                    CreatedByConnectedId = createdByConnectedId,
                    CreatedAt = currentTime,
                    CompletionPercentage = profile.CompletionPercentage
                });

                // 8. 감사 로그
                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = createdByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = currentTime,
                    ActionType = AuditActionType.Create,
                    Action = "user_profile.create",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Success,
                    Metadata = JsonSerializer.Serialize(new
                    {
                        UserId = userId,
                        ProfileCompleteness = profile.CompletionPercentage,
                        HasPhoneNumber = !string.IsNullOrEmpty(profile.PhoneNumber),
                        TimeZone = profile.TimeZone,
                        Language = profile.PreferredLanguage,
                    })
                });

                // 9. 알림 발송 (프로필 생성 환영 이메일)
                if (request.EmailNotificationsEnabled ?? true)
                {
                    await SendWelcomeEmailAsync(userId, profile);
                }

                // 10. 트랜잭션 커밋
                await _unitOfWork.CommitTransactionAsync();

                // 11. 캐시 무효화
                await InvalidateAllRelatedCachesAsync(userId);

                var user = await _userRepository.GetByIdAsync(userId);
                var dto = MapToDto(profile, user);

                _logger.LogInformation(
                    "Profile created for user {UserId} by ConnectedId {CreatedBy}, Completeness: {Completeness}%",
                    userId, createdByConnectedId, profile.CompletionPercentage);

                return ServiceResult<UserProfileDto>.Success(dto, "Profile created successfully");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                // 오류 이벤트 발생
                await _eventHandler.HandleProfileErrorAsync(new ProfileErrorEvent
                {
                    UserId = userId,
                    ErrorType = "CREATE_FAILED",
                    ErrorMessage = ex.Message,
                    OccurredAt = _dateTimeProvider.UtcNow
                });

                // 오류 감사 로그
                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = createdByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Create,
                    Action = "user_profile.create",
                    ResourceType = "UserProfile",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "PROFILE_CREATE_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error creating profile for user {UserId}", userId);
                return ServiceResult<UserProfileDto>.Failure(
                    $"Failed to create profile: {ex.Message}",
                    "PROFILE_CREATE_ERROR");
            }
        }

        /// <summary>
        /// 프로필 업데이트 (변경 추적, 이벤트, 감사 포함)
        /// </summary>
        public async Task<ServiceResult<UserProfileDto>> UpdateAsync(
            Guid userId,
            UpdateUserProfileRequest request,
            Guid updatedByConnectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 1. 프로필 조회
                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<UserProfileDto>.NotFound($"Profile not found for user: {userId}");
                }

                // 2. 유효성 검사
                var validationResult = await _validator.ValidateProfileUpdateAsync(userId, request);
                if (!validationResult.IsSuccess)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<UserProfileDto>.Failure(
                        string.Join(", ", validationResult.ErrorCode),
                        "VALIDATION_ERROR");
                }

                // 3. 변경 이전 상태 저장 (감사용)
                var oldCompletionPercentage = profile.CompletionPercentage;
                var changes = new Dictionary<string, object>();

                // 4. 전화번호 변경시 중복 확인
                if (!string.IsNullOrWhiteSpace(request.PhoneNumber) &&
                    request.PhoneNumber != profile.PhoneNumber)
                {
                    var phoneExists = await _profileRepository.GetByPhoneNumberAsync(request.PhoneNumber);
                    if (phoneExists != null && phoneExists.UserId != userId)
                    {
                        await _unitOfWork.RollbackTransactionAsync();
                        return ServiceResult<UserProfileDto>.Failure(
                            "Phone number already in use",
                            "PHONE_NUMBER_DUPLICATE");
                    }
                }

                // 5. 변경사항 적용 및 추적
                bool hasChanges = false;
                var currentTime = _dateTimeProvider.UtcNow;

                if (!string.IsNullOrWhiteSpace(request.PhoneNumber) && request.PhoneNumber != profile.PhoneNumber)
                {
                    changes["PhoneNumber"] = new { Old = profile.PhoneNumber, New = request.PhoneNumber };
                    profile.PhoneNumber = request.PhoneNumber;
                    profile.PhoneVerified = false;
                    profile.PhoneVerifiedAt = null;
                    hasChanges = true;
                }

                if (!string.IsNullOrWhiteSpace(request.TimeZone) && request.TimeZone != profile.TimeZone)
                {
                    changes["TimeZone"] = new { Old = profile.TimeZone, New = request.TimeZone };
                    profile.TimeZone = request.TimeZone;
                    hasChanges = true;
                }

                if (request.Language.HasValue)
                {
                    var newLang = MapLanguageEnumToString(request.Language.Value);
                    if (newLang != profile.PreferredLanguage)
                    {
                        changes["PreferredLanguage"] = new { Old = profile.PreferredLanguage, New = newLang };
                        profile.PreferredLanguage = newLang;
                        hasChanges = true;
                    }
                }

                if (!string.IsNullOrWhiteSpace(request.PreferredCurrency) && request.PreferredCurrency != profile.PreferredCurrency)
                {
                    changes["PreferredCurrency"] = new { Old = profile.PreferredCurrency, New = request.PreferredCurrency };
                    profile.PreferredCurrency = request.PreferredCurrency;
                    hasChanges = true;
                }

                if (request.ProfileImageUrl != null && request.ProfileImageUrl != profile.ProfileImageUrl)
                {
                    changes["ProfileImageUrl"] = new { Old = profile.ProfileImageUrl, New = request.ProfileImageUrl };
                    profile.ProfileImageUrl = request.ProfileImageUrl;
                    profile.ProfileImageUploadedAt = currentTime;
                    hasChanges = true;
                }

                if (request.Bio != null && request.Bio != profile.Bio)
                {
                    changes["Bio"] = new { Old = profile.Bio, New = request.Bio };
                    profile.Bio = request.Bio;
                    hasChanges = true;
                }

                if (request.Location != null && request.Location != profile.Location)
                {
                    changes["Location"] = new { Old = profile.Location, New = request.Location };
                    profile.Location = request.Location;
                    hasChanges = true;
                }

                if (request.WebsiteUrl != null && request.WebsiteUrl != profile.WebsiteUrl)
                {
                    changes["WebsiteUrl"] = new { Old = profile.WebsiteUrl, New = request.WebsiteUrl };
                    profile.WebsiteUrl = request.WebsiteUrl;
                    hasChanges = true;
                }

                if (request.DateOfBirth.HasValue && request.DateOfBirth != profile.DateOfBirth)
                {
                    changes["DateOfBirth"] = new { Old = profile.DateOfBirth, New = request.DateOfBirth };
                    profile.DateOfBirth = request.DateOfBirth;
                    hasChanges = true;
                }

                if (request.Gender != null && request.Gender != profile.Gender)
                {
                    changes["Gender"] = new { Old = profile.Gender, New = request.Gender };
                    profile.Gender = request.Gender;
                    hasChanges = true;
                }

                if (request.Metadata != null && request.Metadata != profile.ProfileMetadata)
                {
                    changes["ProfileMetadata"] = new { Old = profile.ProfileMetadata, New = request.Metadata };
                    profile.ProfileMetadata = request.Metadata;
                    hasChanges = true;
                }

                if (request.IsPublic.HasValue && request.IsPublic.Value != profile.IsPublic)
                {
                    changes["IsPublic"] = new { Old = profile.IsPublic, New = request.IsPublic.Value };
                    profile.IsPublic = request.IsPublic.Value;
                    hasChanges = true;
                }

                if (request.EmailNotificationsEnabled.HasValue && request.EmailNotificationsEnabled.Value != profile.EmailNotificationsEnabled)
                {
                    changes["EmailNotificationsEnabled"] = new { Old = profile.EmailNotificationsEnabled, New = request.EmailNotificationsEnabled.Value };
                    profile.EmailNotificationsEnabled = request.EmailNotificationsEnabled.Value;
                    hasChanges = true;
                }

                if (request.SmsNotificationsEnabled.HasValue && request.SmsNotificationsEnabled.Value != profile.SmsNotificationsEnabled)
                {
                    changes["SmsNotificationsEnabled"] = new { Old = profile.SmsNotificationsEnabled, New = request.SmsNotificationsEnabled.Value };
                    profile.SmsNotificationsEnabled = request.SmsNotificationsEnabled.Value;
                    hasChanges = true;
                }

                if (!hasChanges)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    var user = await _userRepository.GetByIdAsync(userId);
                    var dto = MapToDto(profile, user);
                    return ServiceResult<UserProfileDto>.Success(dto, "No changes detected");
                }

                // 6. 감사 정보 업데이트
                profile.UpdatedAt = currentTime;
                profile.UpdatedByConnectedId = updatedByConnectedId;
                profile.UpdateProfile(); // 완성도 재계산

                // 7. 저장
                await _profileRepository.UpdateAsync(profile);
                await _unitOfWork.SaveChangesAsync();

                // 8. 변경 이벤트 발생
                await _eventHandler.HandleProfileUpdatedAsync(new ProfileUpdatedEvent
                {
                    UserId = userId,
                    ProfileId = profile.Id,
                    UpdatedByConnectedId = updatedByConnectedId,
                    UpdatedAt = currentTime,
                    Changes = changes,
                    NewCompletionPercentage = profile.CompletionPercentage
                });

                // 9. 감사 로그 (상세 변경 내역 포함)
                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = updatedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = currentTime,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.update",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(new
                    {
                        UserId = userId,
                        Changes = changes,
                        OldCompleteness = oldCompletionPercentage,
                        NewCompleteness = profile.CompletionPercentage,
                        FieldsUpdated = changes.Keys.ToList()
                    })
                });

                // 10. 완성도 변화 알림
                if (profile.CompletionPercentage == 100 && oldCompletionPercentage < 100)
                {
                    await SendProfileCompletionEmailAsync(userId, profile);
                }

                // 11. 트랜잭션 커밋
                await _unitOfWork.CommitTransactionAsync();

                // 12. 캐시 무효화
                await InvalidateAllRelatedCachesAsync(userId);

                var resultUser = await _userRepository.GetByIdAsync(userId);
                var resultDto = MapToDto(profile, resultUser);

                _logger.LogInformation(
                    "Profile updated for user {UserId} by ConnectedId {UpdatedBy}, New Completeness: {Completeness}%, Changes: {Changes}",
                    userId, updatedByConnectedId, profile.CompletionPercentage, JsonSerializer.Serialize(changes));

                return ServiceResult<UserProfileDto>.Success(resultDto, "Profile updated successfully");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                await _eventHandler.HandleProfileErrorAsync(new ProfileErrorEvent
                {
                    UserId = userId,
                    ErrorType = "UPDATE_FAILED",
                    ErrorMessage = ex.Message,
                    OccurredAt = _dateTimeProvider.UtcNow
                });

                // 오류 감사 로그
                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = updatedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.update",
                    ResourceType = "UserProfile",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "PROFILE_UPDATE_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error updating profile for user {UserId}", userId);
                return ServiceResult<UserProfileDto>.Failure(
                    $"Failed to update profile: {ex.Message}",
                    "PROFILE_UPDATE_ERROR");
            }
        }

        /// <summary>
        /// 프로필 삭제 (Soft Delete with GDPR compliance)
        /// </summary>
        public async Task<ServiceResult> DeleteAsync(Guid userId, Guid deletedByConnectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.NotFound($"Profile not found for user: {userId}");
                }

                var currentTime = _dateTimeProvider.UtcNow;

                // Soft Delete 처리
                profile.IsDeleted = true;
                profile.DeletedAt = currentTime;
                profile.DeletedByConnectedId = deletedByConnectedId;

                // GDPR 준수: 개인정보 익명화
                var anonymizedFields = new List<string>();
                if (!string.IsNullOrEmpty(profile.PhoneNumber))
                {
                    profile.PhoneNumber = null;
                    anonymizedFields.Add("PhoneNumber");
                }
                if (!string.IsNullOrEmpty(profile.Bio))
                {
                    profile.Bio = null;
                    anonymizedFields.Add("Bio");
                }
                if (!string.IsNullOrEmpty(profile.Location))
                {
                    profile.Location = null;
                    anonymizedFields.Add("Location");
                }
                if (profile.DateOfBirth.HasValue)
                {
                    profile.DateOfBirth = null;
                    anonymizedFields.Add("DateOfBirth");
                }
                if (!string.IsNullOrEmpty(profile.Gender))
                {
                    profile.Gender = null;
                    anonymizedFields.Add("Gender");
                }
                if (!string.IsNullOrEmpty(profile.ProfileMetadata))
                {
                    profile.ProfileMetadata = null;
                    anonymizedFields.Add("ProfileMetadata");
                }
                if (!string.IsNullOrEmpty(profile.ProfileImageUrl))
                {
                    profile.ProfileImageUrl = null;
                    anonymizedFields.Add("ProfileImageUrl");
                }

                await _profileRepository.UpdateAsync(profile);
                await _unitOfWork.SaveChangesAsync();

                // 삭제 이벤트 발생
                await _eventHandler.HandleProfileDeletedAsync(new ProfileDeletedEvent
                {
                    UserId = userId,
                    ProfileId = profile.Id,
                    DeletedByConnectedId = deletedByConnectedId,
                    DeletedAt = currentTime
                });

                // 감사 로그
                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = deletedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = currentTime,
                    ActionType = AuditActionType.Delete,
                    Action = "user_profile.soft_delete",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Warning,
                    Metadata = JsonSerializer.Serialize(new
                    {
                        UserId = userId,
                        Reason = "GDPR compliance - anonymized",
                        AnonymizedFields = anonymizedFields
                    })
                });

                await _unitOfWork.CommitTransactionAsync();

                // 모든 캐시 무효화
                await InvalidateAllRelatedCachesAsync(userId);

                _logger.LogInformation(
                    "Profile soft-deleted for user {UserId} by ConnectedId {DeletedBy} at {Time}",
                    userId, deletedByConnectedId, currentTime);

                return ServiceResult.Success("Profile deleted successfully");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                // 오류 감사 로그
                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = deletedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Delete,
                    Action = "user_profile.soft_delete",
                    ResourceType = "UserProfile",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "PROFILE_DELETE_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error deleting profile for user {UserId}", userId);
                return ServiceResult.Failure($"Failed to delete profile: {ex.Message}", "PROFILE_DELETE_ERROR");
            }
        }

        #endregion

        #region Helper Methods

        private UserProfileDto MapToDto(UserProfile profile, UserEntity? user = null)
        {
            return new UserProfileDto
            {
                Id = profile.Id,
                UserId = profile.UserId,
                // User 정보 추가 - null 안전 처리
                Email = user?.Email ?? string.Empty,
                Username = user?.Username,
                DisplayName = user?.EffectiveDisplayName ?? user?.DisplayName ?? string.Empty,
                // Profile 정보
                PhoneNumber = profile.PhoneNumber,
                PhoneVerified = profile.PhoneVerified,
                PhoneVerifiedAt = profile.PhoneVerifiedAt,
                ProfileImageUrl = profile.ProfileImageUrl,
                ProfileImageUploadedAt = profile.ProfileImageUploadedAt,
                TimeZone = profile.TimeZone,
                PreferredLanguage = profile.PreferredLanguage,
                PreferredCurrency = profile.PreferredCurrency,
                Bio = profile.Bio,
                WebsiteUrl = profile.WebsiteUrl,
                Location = profile.Location,
                DateOfBirth = profile.DateOfBirth,
                Gender = profile.Gender,
                ProfileMetadata = profile.ProfileMetadata,
                CompletionPercentage = profile.CompletionPercentage,
                IsPublic = profile.IsPublic,
                LastProfileUpdateAt = profile.LastProfileUpdateAt,
                EmailNotificationsEnabled = profile.EmailNotificationsEnabled,
                SmsNotificationsEnabled = profile.SmsNotificationsEnabled,
                CreatedAt = profile.CreatedAt,
                UpdatedAt = profile.UpdatedAt
            };
        }

        private string MapLanguageEnumToString(UserLanguage language) => language switch
        {
            UserLanguage.Korean => "ko",
            UserLanguage.English => "en",
            UserLanguage.Japanese => "ja",
            UserLanguage.ChineseSimplified => "zh-CN",
            UserLanguage.ChineseTraditional => "zh-TW",
            _ => "en"
        };

        private List<string> GetMissingFields(UserProfile profile)
        {
            var missingFields = new List<string>();

            if (string.IsNullOrWhiteSpace(profile.PhoneNumber)) missingFields.Add("PhoneNumber");
            if (!profile.PhoneVerified && !string.IsNullOrWhiteSpace(profile.PhoneNumber)) missingFields.Add("PhoneVerification");
            if (string.IsNullOrWhiteSpace(profile.ProfileImageUrl)) missingFields.Add("ProfileImage");
            if (string.IsNullOrWhiteSpace(profile.Bio)) missingFields.Add("Bio");
            if (string.IsNullOrWhiteSpace(profile.Location)) missingFields.Add("Location");
            if (string.IsNullOrWhiteSpace(profile.WebsiteUrl)) missingFields.Add("Website");
            if (!profile.DateOfBirth.HasValue) missingFields.Add("DateOfBirth");
            if (string.IsNullOrWhiteSpace(profile.Gender)) missingFields.Add("Gender");
            if (profile.TimeZone == "UTC") missingFields.Add("TimeZone");
            if (profile.PreferredLanguage == "en") missingFields.Add("PreferredLanguage");

            return missingFields;
        }

        private List<string> GenerateNextSteps(List<string> missingFields)
        {
            var nextSteps = new List<string>();

            if (missingFields.Contains("ProfileImage"))
                nextSteps.Add("Upload a profile photo to personalize your account");

            if (missingFields.Contains("PhoneNumber"))
                nextSteps.Add("Add your phone number for enhanced security");

            if (missingFields.Contains("PhoneVerification"))
                nextSteps.Add("Verify your phone number");

            if (missingFields.Contains("Bio"))
                nextSteps.Add("Write a short bio to tell others about yourself");

            if (missingFields.Count > 5)
                nextSteps.Add($"Complete {missingFields.Count} more fields to reach 100% profile completion");

            return nextSteps;
        }

        private void CacheProfileLocally(string key, UserProfileDto profile)
        {
            var options = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(CACHE_EXPIRATION_MINUTES),
                SlidingExpiration = TimeSpan.FromMinutes(CACHE_SLIDING_MINUTES)
            };
            _localCache.Set(key, profile, options);
        }

        private async Task CacheProfileAllLevelsAsync(string key, UserProfileDto profile)
        {
            // 로컬 캐시
            CacheProfileLocally(key, profile);

            // 분산 캐시
            await _cacheService.SetAsync(key, profile,
                TimeSpan.FromMinutes(DISTRIBUTED_CACHE_EXPIRATION_MINUTES));
        }

        private async Task InvalidateAllRelatedCachesAsync(Guid userId)
        {
            var tasks = new List<Task>();

            // User 캐시 무효화
            var userCacheKey = $"{CACHE_KEY_PREFIX}{userId}";
            _localCache.Remove(userCacheKey);
            tasks.Add(_cacheService.RemoveAsync(userCacheKey));

            // 완성도 캐시 무효화
            var completenessCacheKey = $"{CACHE_KEY_COMPLETENESS_PREFIX}{userId}";
            _localCache.Remove(completenessCacheKey);
            tasks.Add(_cacheService.RemoveAsync(completenessCacheKey));

            // ConnectedId 캐시 무효화
            try
            {
                var connectedIds = await _userRepository.GetConnectedIdsAsync(userId);
                foreach (var connectedId in connectedIds)
                {
                    var connectedCacheKey = $"{CACHE_KEY_CONNECTED_PREFIX}{connectedId}";
                    _localCache.Remove(connectedCacheKey);
                    tasks.Add(_cacheService.RemoveAsync(connectedCacheKey));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to invalidate ConnectedId caches for user {UserId}", userId);
            }

            await Task.WhenAll(tasks);
        }

        private async Task WarmupCacheAsync()
        {
            try
            {
                // 최근 활동한 사용자들의 프로필을 미리 캐싱
                var recentUsers = await _userRepository.GetRecentUsersAsync(10);
                var tasks = recentUsers.Select(async user =>
                {
                    var profile = await _profileRepository.GetByIdAsync(user.Id);
                    if (profile != null)
                    {
                        var dto = MapToDto(profile, user);
                        var cacheKey = $"{CACHE_KEY_PREFIX}{user.Id}";
                        await CacheProfileAllLevelsAsync(cacheKey, dto);
                    }
                });

                await Task.WhenAll(tasks);

                _logger.LogInformation("Cache warmup completed for {Count} profiles", recentUsers.Count());
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cache warmup failed, continuing without warmup");
            }
        }

        private Task<Guid?> GetCurrentConnectedIdAsync()
        {
            return Task.FromResult(_connectedIdContext.ConnectedId);
        }

        private async Task<Guid?> GetUserOrganizationIdAsync(Guid userId)
        {
            try
            {
                var connectedIds = await _connectedIdRepository.GetByUserIdAsync(userId);
                var activeConnected = connectedIds.FirstOrDefault(c => c.Status == ConnectedIdStatus.Active);
                return activeConnected?.OrganizationId;
            }
            catch
            {
                return null;
            }
        }

        private Guid? GetCurrentApplicationId()
        {
            return _httpContextAccessor?.HttpContext?.Items["ApplicationId"] as Guid?;
        }

        private string GetClientIpAddress()
        {
            var httpContext = _httpContextAccessor?.HttpContext;
            if (httpContext == null) return "127.0.0.1";

            // X-Forwarded-For 헤더 확인 (프록시/로드밸런서 뒤에 있을 때)
            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }

            // X-Real-IP 헤더 확인
            var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp))
            {
                return realIp;
            }

            // RemoteIpAddress 사용
            return httpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        }

        private string GetUserAgent()
        {
            return _httpContextAccessor?.HttpContext?.Request.Headers["User-Agent"].FirstOrDefault()
                ?? "AuthHive/1.0";
        }

        private string GetRequestId()
        {
            return _httpContextAccessor?.HttpContext?.TraceIdentifier ?? Guid.NewGuid().ToString();
        }

        private async Task SendWelcomeEmailAsync(Guid userId, UserProfile profile)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user?.Email != null)
                {
                    // 현재 사용자의 조직 ID 가져오기 (없을 수 있음)
                    var organizationId = await GetCurrentOrganizationIdAsync();

                    if (organizationId.HasValue)
                    {
                        // 조직이 있는 경우 - 조직별 환영 이메일
                        await _emailService.SendWelcomeEmailAsync(
                            user.Email,
                            user.EffectiveDisplayName,
                            organizationId.Value,
                            null);
                    }
                    else
                    {
                        // 조직이 없는 경우 - 시스템 기본 템플릿 사용
                        var variables = new Dictionary<string, object>
                        {
                            { "userName", user.EffectiveDisplayName },
                            { "userEmail", user.Email },
                            { "registeredAt", DateTime.UtcNow.ToString("yyyy-MM-dd") }
                        };

                        await _emailService.SendTemplateEmailAsync(
                            user.Email,
                            "system_welcome",  // 시스템 기본 환영 템플릿
                            variables,
                            null);  // organizationId가 null
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send welcome email for user {UserId}", userId);
                // 이메일 실패해도 계속 진행 (non-critical)
            }
        }

        // GetCurrentOrganizationIdAsync 메서드가 없다면 추가
        private async Task<Guid?> GetCurrentOrganizationIdAsync()
        {
            var connectedId = _connectedIdContext.ConnectedId;
            if (!connectedId.HasValue)
                return null;

            var connected = await _connectedIdRepository.GetByIdAsync(connectedId.Value);
            return connected?.OrganizationId;
        }

        private async Task SendProfileCompletionEmailAsync(Guid userId, UserProfile profile)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user?.Email != null)
                {
                    var variables = new Dictionary<string, object>
                    {
                        { "userName", user.EffectiveDisplayName },
                        { "profileCompletedAt", DateTime.UtcNow }
                    };

                    await _emailService.SendTemplateEmailAsync(
                        user.Email,
                        "profile_completion",  // 템플릿 ID
                        variables,
                        null
                    );
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to send profile completion email for user {UserId}", userId);
            }
        }

        #endregion

        #region 프로필 완성도 관리 with Caching

        /// <summary>
        /// 프로필 완성도 계산 (캐싱 적용)
        /// </summary>
        public async Task<ServiceResult<ProfileCompletenessInfo>> CalculateCompletenessAsync(Guid userId)
        {
            try
            {
                // 캐시에서 먼저 확인
                var cacheKey = $"{CACHE_KEY_COMPLETENESS_PREFIX}{userId}";
                var cachedCompleteness = await _cacheService.GetAsync<ProfileCompletenessInfo>(cacheKey);
                if (cachedCompleteness != null)
                {
                    return ServiceResult<ProfileCompletenessInfo>.Success(cachedCompleteness);
                }

                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    return ServiceResult<ProfileCompletenessInfo>.NotFound($"Profile not found for user: {userId}");
                }

                var missingFields = GetMissingFields(profile);
                var nextSteps = GenerateNextSteps(missingFields);

                var completenessInfo = new ProfileCompletenessInfo
                {
                    UserId = userId,
                    CompletionPercentage = profile.CalculateCompletionPercentage(),
                    MissingFields = missingFields,
                    LastUpdated = profile.LastProfileUpdateAt ?? profile.CreatedAt,
                    IsComplete = profile.IsComplete,
                    NextSteps = nextSteps,
                    CalculatedAt = _dateTimeProvider.UtcNow
                };

                // 캐시에 저장 (짧은 TTL)
                await _cacheService.SetAsync(cacheKey, completenessInfo, TimeSpan.FromMinutes(5));

                return ServiceResult<ProfileCompletenessInfo>.Success(completenessInfo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error calculating completeness for user {UserId}", userId);
                return ServiceResult<ProfileCompletenessInfo>.Failure(
                    $"Failed to calculate completeness: {ex.Message}",
                    "COMPLETENESS_CALC_ERROR");
            }
        }

        /// <summary>
        /// 불완전한 프로필 조회 - 옵셔널 organizationId
        /// </summary>
        public async Task<ServiceResult<IEnumerable<UserProfileDto>>> GetIncompleteProfilesAsync(
            int limit = 100,
            Guid? organizationId = null)
        {
            try
            {
                const int incompletionThreshold = 50;

                IEnumerable<UserProfile> profiles;

                if (organizationId.HasValue)
                {
                    var usersResult = await _userRepository.GetByOrganizationAsync(
                        organizationId.Value,
                        UserStatus.Active);
                    var userIds = usersResult.Items.Select(u => u.Id).ToList();

                    profiles = await _profileRepository
                        .FindAsync(p => userIds.Contains(p.UserId) &&
                                      p.CompletionPercentage < incompletionThreshold);
                }
                else
                {
                    profiles = await _profileRepository
                        .FindAsync(p => p.CompletionPercentage < incompletionThreshold);
                }

                var limitedProfiles = profiles.Take(limit);

                var result = new List<UserProfileDto>();
                foreach (var profile in limitedProfiles)
                {
                    var user = await _userRepository.GetByIdAsync(profile.UserId);
                    if (user == null) continue;

                    var dto = MapToDto(profile, user);
                    result.Add(dto);
                }

                return ServiceResult<IEnumerable<UserProfileDto>>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting incomplete profiles");
                return ServiceResult<IEnumerable<UserProfileDto>>.Failure("Failed to get incomplete profiles");
            }
        }

        /// <summary>
        /// 조직별 불완전한 프로필 조회 - 완성도 기준 지정
        /// </summary>
        public async Task<ServiceResult<IEnumerable<UserProfileDto>>> GetIncompleteProfilesAsync(
            Guid organizationId,
            int maxCompleteness = 50)
        {
            try
            {
                var usersResult = await _userRepository.GetByOrganizationAsync(
                    organizationId,
                    UserStatus.Active);
                var userIds = usersResult.Items.Select(u => u.Id).ToList();

                var profiles = await _profileRepository
                    .FindAsync(p => userIds.Contains(p.UserId) &&
                                  p.CompletionPercentage <= maxCompleteness);

                var result = new List<UserProfileDto>();
                foreach (var profile in profiles)
                {
                    var user = await _userRepository.GetByIdAsync(profile.UserId);
                    if (user == null) continue;

                    var dto = MapToDto(profile, user);
                    result.Add(dto);
                }

                return ServiceResult<IEnumerable<UserProfileDto>>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting incomplete profiles for organization {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<UserProfileDto>>.Failure("Failed to get incomplete profiles");
            }
        }

        #endregion

        #region 메타데이터 모드 관리 with Events and Audit

        /// <summary>
        /// 메타데이터 모드 변경
        /// </summary>
        public async Task<ServiceResult> ChangeMetadataModeAsync(
            Guid userId,
            UserMetadataMode newMode,
            Guid changedByConnectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.NotFound($"User not found: {userId}");
                }

                var currentTime = _dateTimeProvider.UtcNow;
                user.UpdatedAt = currentTime;
                user.UpdatedByConnectedId = changedByConnectedId;

                await _userRepository.UpdateAsync(user);
                await _unitOfWork.SaveChangesAsync();

                await ProcessMetadataModeChange(userId, newMode, newMode, changedByConnectedId);

                await _eventHandler.HandleMetadataModeChangedAsync(new MetadataModeChangedEvent
                {
                    UserId = userId,
                    OldMode = newMode,
                    NewMode = newMode,
                    ChangedByConnectedId = changedByConnectedId,
                    ChangedAt = currentTime
                });

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = changedByConnectedId,
                    TargetOrganizationId = null,
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = currentTime,
                    ActionType = AuditActionType.Update,
                    Action = "user.metadata_mode.change",
                    ResourceType = "User",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(new { NewMode = newMode })
                });

                await _unitOfWork.CommitTransactionAsync();

                await InvalidateAllRelatedCachesAsync(userId);

                _logger.LogInformation(
                    "Metadata mode set to {NewMode} for user {UserId} by {ChangedBy}",
                    newMode, userId, changedByConnectedId);

                return ServiceResult.Success($"Metadata mode set to {newMode}");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = changedByConnectedId,
                    TargetOrganizationId = null,
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Update,
                    Action = "user.metadata_mode.change",
                    ResourceType = "User",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "METADATA_MODE_CHANGE_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error setting metadata mode for user {UserId}", userId);
                return ServiceResult.Failure(
                    $"Failed to set metadata mode: {ex.Message}",
                    "METADATA_MODE_CHANGE_ERROR");
            }
        }

        /// <summary>
        /// 메타데이터 정리 (GDPR 대응)
        /// </summary>
        public async Task<ServiceResult<int>> CleanupMetadataAsync(
            UserMetadataMode mode,
            DateTime? olderThan = null,
            Guid? organizationId = null)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var cutoffDate = olderThan ?? _dateTimeProvider.UtcNow.AddMonths(-6);
                var currentTime = _dateTimeProvider.UtcNow;

                var profiles = await _profileRepository.GetByMetadataModeAsync(mode, organizationId);
                var oldProfiles = profiles.Where(p =>
                    (p.UpdatedAt ?? p.CreatedAt) < cutoffDate).ToList();

                int cleanedCount = 0;
                var cleanedUserIds = new List<Guid>();

                foreach (var profile in oldProfiles)
                {
                    if (mode == UserMetadataMode.Minimal)
                    {
                        profile.PhoneNumber = null;
                        profile.Bio = null;
                        profile.Location = null;
                        profile.DateOfBirth = null;
                        profile.Gender = null;
                        profile.ProfileMetadata = null;
                        profile.WebsiteUrl = null;
                    }
                    else if (mode == UserMetadataMode.Hybrid)
                    {
                        profile.ProfileMetadata = null;
                    }

                    profile.UpdatedAt = currentTime;
                    await _profileRepository.UpdateAsync(profile);
                    cleanedUserIds.Add(profile.UserId);
                    cleanedCount++;
                }

                if (cleanedCount > 0)
                {
                    await _unitOfWork.SaveChangesAsync();

                    await _eventHandler.HandleBulkMetadataCleanedAsync(new BulkMetadataCleanedEvent
                    {
                        Mode = mode,
                        CleanedCount = cleanedCount,
                        CleanedUserIds = cleanedUserIds,
                        CutoffDate = cutoffDate,
                        CleanedAt = currentTime
                    });

                    await _auditService.LogAsync(new AuditLog
                    {
                        PerformedByConnectedId = await GetCurrentConnectedIdAsync(),
                        TargetOrganizationId = organizationId,
                        ApplicationId = GetCurrentApplicationId(),
                        Timestamp = currentTime,
                        ActionType = AuditActionType.System,
                        Action = "metadata.bulk_cleanup",
                        ResourceType = "UserProfile",
                        ResourceId = $"bulk_{cleanedCount}",
                        Success = true,
                        DurationMs = (int)stopwatch.ElapsedMilliseconds,
                        Severity = AuditEventSeverity.Info,
                        Metadata = JsonSerializer.Serialize(new
                        {
                            Mode = mode,
                            CleanedCount = cleanedCount,
                            CutoffDate = cutoffDate,
                            OrganizationId = organizationId
                        })
                    });
                }

                await _unitOfWork.CommitTransactionAsync();

                foreach (var userId in cleanedUserIds)
                {
                    await InvalidateAllRelatedCachesAsync(userId);
                }

                _logger.LogInformation(
                    "Cleaned up {Count} profiles with mode {Mode} older than {CutoffDate}",
                    cleanedCount, mode, cutoffDate);

                return ServiceResult<int>.Success(cleanedCount, $"Cleaned {cleanedCount} profiles");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = await GetCurrentConnectedIdAsync(),
                    TargetOrganizationId = organizationId,
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.System,
                    Action = "metadata.bulk_cleanup",
                    ResourceType = "UserProfile",
                    Success = false,
                    ErrorCode = "METADATA_CLEANUP_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error cleaning up metadata");
                return ServiceResult<int>.Failure(
                    $"Failed to cleanup metadata: {ex.Message}",
                    "METADATA_CLEANUP_ERROR");
            }
        }

        /// <summary>
        /// 메타데이터 내보내기 (데이터 주권)
        /// </summary>
        public async Task<ServiceResult<string>> ExportMetadataAsync(Guid userId, string format = "json")
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                var cacheKey = $"export:{userId}:{format}";
                var cachedExport = await _cacheService.GetAsync<string>(cacheKey);
                if (cachedExport != null)
                {
                    return ServiceResult<string>.Success(cachedExport);
                }

                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    return ServiceResult<string>.NotFound($"Profile not found for user: {userId}");
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<string>.NotFound($"User not found: {userId}");
                }

                string exportedData = format.ToLower() switch
                {
                    "json" => ExportToJson(profile, user),
                    "csv" => ExportToCsv(profile, user),
                    "sql" => ExportToSql(profile, user),
                    _ => throw new ArgumentException($"Unsupported format: {format}")
                };

                await _cacheService.SetAsync(cacheKey, exportedData, TimeSpan.FromMinutes(5));

                await _eventHandler.HandleDataExportedAsync(new DataExportedEvent
                {
                    UserId = userId,
                    Format = format,
                    ExportedAt = _dateTimeProvider.UtcNow,
                    DataSize = System.Text.Encoding.UTF8.GetByteCount(exportedData)
                });

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = await GetCurrentConnectedIdAsync(),
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Read,
                    Action = "user_profile.export",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(new { Format = format, DataSize = exportedData.Length })
                });

                _logger.LogInformation(
                    "Metadata exported for user {UserId} in {Format} format",
                    userId, format);

                return ServiceResult<string>.Success(exportedData);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = await GetCurrentConnectedIdAsync(),
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Read,
                    Action = "user_profile.export",
                    ResourceType = "UserProfile",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "METADATA_EXPORT_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error exporting metadata for user {UserId}", userId);
                return ServiceResult<string>.Failure(
                    $"Failed to export metadata: {ex.Message}",
                    "METADATA_EXPORT_ERROR");
            }
        }

        #endregion

        #region 글로벌 설정 with Events and Caching

        /// <summary>
        /// 시간대 변경
        /// </summary>
        public async Task<ServiceResult> ChangeTimeZoneAsync(
            Guid userId,
            string timeZone,
            Guid changedByConnectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                if (!IsValidTimeZone(timeZone))
                {
                    return ServiceResult.Failure($"Invalid timezone: {timeZone}", "INVALID_TIMEZONE");
                }

                await _unitOfWork.BeginTransactionAsync();

                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    var createRequest = new CreateUserProfileRequest
                    {
                        TimeZone = timeZone
                    };
                    var createResult = await CreateAsync(userId, createRequest, changedByConnectedId);
                    if (createResult.IsSuccess)
                    {
                        return ServiceResult.Success($"Profile created with timezone {timeZone}");
                    }
                    return ServiceResult.Failure(createResult.ErrorMessage ?? "Failed to create profile", createResult.ErrorCode ?? "");
                }

                var oldTimeZone = profile.TimeZone;
                if (profile.TimeZone == timeZone)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.Success($"Timezone is already {timeZone}");
                }

                var currentTime = _dateTimeProvider.UtcNow;
                profile.TimeZone = timeZone;
                profile.UpdatedAt = currentTime;
                profile.UpdatedByConnectedId = changedByConnectedId;
                profile.UpdateProfile();

                await _profileRepository.UpdateAsync(profile);
                await _unitOfWork.SaveChangesAsync();

                await _eventHandler.HandleTimeZoneChangedAsync(new TimeZoneChangedEvent
                {
                    UserId = userId,
                    OldTimeZone = oldTimeZone,
                    NewTimeZone = timeZone,
                    ChangedByConnectedId = changedByConnectedId,
                    ChangedAt = currentTime
                });

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = changedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = currentTime,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.timezone.change",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(new { OldTimeZone = oldTimeZone, NewTimeZone = timeZone })
                });

                await _unitOfWork.CommitTransactionAsync();

                await InvalidateAllRelatedCachesAsync(userId);

                _logger.LogInformation(
                    "TimeZone changed for user {UserId} to {TimeZone}",
                    userId, timeZone);

                return ServiceResult.Success($"TimeZone changed to {timeZone}");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = changedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.timezone.change",
                    ResourceType = "UserProfile",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "TIMEZONE_CHANGE_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error changing timezone for user {UserId}", userId);
                return ServiceResult.Failure(
                    $"Failed to change timezone: {ex.Message}",
                    "TIMEZONE_CHANGE_ERROR");
            }
        }

        /// <summary>
        /// 언어별 사용자 분포 조회 (조직별) - 캐싱 적용
        /// </summary>
        public async Task<ServiceResult<Dictionary<UserLanguage, int>>> GetLanguageDistributionAsync(Guid? organizationId = null)
        {
            try
            {
                var cacheKey = $"language:distribution:{organizationId ?? Guid.Empty}";
                var cachedDistribution = await _cacheService.GetAsync<Dictionary<UserLanguage, int>>(cacheKey);
                if (cachedDistribution != null)
                {
                    return ServiceResult<Dictionary<UserLanguage, int>>.Success(cachedDistribution);
                }

                var distribution = new Dictionary<UserLanguage, int>();

                foreach (UserLanguage lang in Enum.GetValues<UserLanguage>())
                {
                    var result = await _profileRepository.GetByLanguageAsync(lang, organizationId, pageSize: 1);
                    distribution[lang] = result.TotalCount;
                }

                await _cacheService.SetAsync(cacheKey, distribution, TimeSpan.FromHours(1));

                return ServiceResult<Dictionary<UserLanguage, int>>.Success(distribution);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting language distribution");
                return ServiceResult<Dictionary<UserLanguage, int>>.Failure(
                    $"Failed to get language distribution: {ex.Message}",
                    "LANGUAGE_DISTRIBUTION_ERROR");
            }
        }

        #endregion

        #region 프로필 이미지 관리 with Events and Audit

        /// <summary>
        /// 프로필 이미지 업로드
        /// </summary>
        public async Task<ServiceResult<string>> UploadProfileImageAsync(
            Guid userId,
            byte[] imageData,
            string contentType,
            Guid uploadedByConnectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                if (!IsValidImage(imageData, contentType))
                {
                    return ServiceResult<string>.Failure("Invalid image format or size", "INVALID_IMAGE");
                }

                await _unitOfWork.BeginTransactionAsync();

                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult<string>.NotFound($"Profile not found for user: {userId}");
                }

                var oldImageUrl = profile.ProfileImageUrl;
                var currentTime = _dateTimeProvider.UtcNow;

                var imageUrl = await UploadToCloudStorage(userId, imageData, contentType);

                profile.UpdateProfileImage(imageUrl);
                profile.UpdatedByConnectedId = uploadedByConnectedId;
                profile.UpdatedAt = currentTime;

                await _profileRepository.UpdateAsync(profile);
                await _unitOfWork.SaveChangesAsync();

                await _eventHandler.HandleProfileImageUploadedAsync(new ProfileImageUploadedEvent
                {
                    UserId = userId,
                    OldImageUrl = oldImageUrl,
                    NewImageUrl = imageUrl,
                    ImageSize = imageData.Length,
                    ContentType = contentType,
                    UploadedByConnectedId = uploadedByConnectedId,
                    UploadedAt = currentTime
                });

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = uploadedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = currentTime,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.image.upload",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(new
                    {
                        OldImageUrl = oldImageUrl,
                        NewImageUrl = imageUrl,
                        ImageSize = imageData.Length,
                        ContentType = contentType
                    })
                });

                if (!string.IsNullOrWhiteSpace(oldImageUrl))
                {
                    await DeleteFromCloudStorage(oldImageUrl);
                }

                await _unitOfWork.CommitTransactionAsync();

                await InvalidateAllRelatedCachesAsync(userId);

                _logger.LogInformation(
                    "Profile image uploaded for user {UserId}, URL: {ImageUrl}",
                    userId, imageUrl);

                return ServiceResult<string>.Success(imageUrl, "Profile image uploaded successfully");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = uploadedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.image.upload",
                    ResourceType = "UserProfile",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "IMAGE_UPLOAD_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error uploading profile image for user {UserId}", userId);
                return ServiceResult<string>.Failure(
                    $"Failed to upload profile image: {ex.Message}",
                    "IMAGE_UPLOAD_ERROR");
            }
        }

        /// <summary>
        /// 프로필 이미지 삭제
        /// </summary>
        public async Task<ServiceResult> DeleteProfileImageAsync(Guid userId, Guid deletedByConnectedId)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    await _unitOfWork.RollbackTransactionAsync();
                    return ServiceResult.NotFound($"Profile not found for user: {userId}");
                }

                var currentTime = _dateTimeProvider.UtcNow;
                var oldImageUrl = profile.ProfileImageUrl;

                if (!string.IsNullOrWhiteSpace(oldImageUrl))
                {
                    await DeleteFromCloudStorage(oldImageUrl);
                }

                profile.ProfileImageUrl = null;
                profile.ProfileImageUploadedAt = null;
                profile.UpdatedByConnectedId = deletedByConnectedId;
                profile.UpdatedAt = currentTime;
                profile.UpdateProfile();

                await _profileRepository.UpdateAsync(profile);
                await _unitOfWork.SaveChangesAsync();

                await _eventHandler.HandleProfileImageDeletedAsync(new ProfileImageDeletedEvent
                {
                    UserId = userId,
                    DeletedImageUrl = oldImageUrl,
                    DeletedByConnectedId = deletedByConnectedId,
                    DeletedAt = currentTime
                });

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = deletedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = currentTime,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.image.delete",
                    ResourceType = "UserProfile",
                    ResourceId = profile.Id.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = true,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Info,
                    Metadata = JsonSerializer.Serialize(new { DeletedImageUrl = oldImageUrl })
                });

                await _unitOfWork.CommitTransactionAsync();

                await InvalidateAllRelatedCachesAsync(userId);

                _logger.LogInformation(
                    "Profile image deleted for user {UserId}",
                    userId);

                return ServiceResult.Success("Profile image deleted successfully");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                stopwatch.Stop();

                await _auditService.LogAsync(new AuditLog
                {
                    PerformedByConnectedId = deletedByConnectedId,
                    TargetOrganizationId = await GetUserOrganizationIdAsync(userId),
                    ApplicationId = GetCurrentApplicationId(),
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = AuditActionType.Update,
                    Action = "user_profile.image.delete",
                    ResourceType = "UserProfile",
                    ResourceId = userId.ToString(),
                    IPAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent(),
                    RequestId = GetRequestId(),
                    Success = false,
                    ErrorCode = "IMAGE_DELETE_ERROR",
                    ErrorMessage = ex.Message,
                    DurationMs = (int)stopwatch.ElapsedMilliseconds,
                    Severity = AuditEventSeverity.Error
                });

                _logger.LogError(ex, "Error deleting profile image for user {UserId}", userId);
                return ServiceResult.Failure(
                    $"Failed to delete profile image: {ex.Message}",
                    "IMAGE_DELETE_ERROR");
            }
        }

        /// <summary>
        /// 기본 아바타 생성
        /// </summary>
        public async Task<ServiceResult<string>> GenerateDefaultAvatarAsync(Guid userId)
        {
            try
            {
                var cacheKey = $"avatar:default:{userId}";
                var cachedAvatar = await _cacheService.GetAsync<string>(cacheKey);
                if (cachedAvatar != null)
                {
                    return ServiceResult<string>.Success(cachedAvatar);
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<string>.NotFound($"User not found: {userId}");
                }

                var identifier = user.Email ?? user.Username ?? userId.ToString();
                var avatarUrl = GenerateAvatarUrl(identifier);

                await _cacheService.SetAsync(cacheKey, avatarUrl, TimeSpan.FromDays(7));

                return ServiceResult<string>.Success(avatarUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating default avatar for user {UserId}", userId);
                return ServiceResult<string>.Failure(
                    $"Failed to generate default avatar: {ex.Message}",
                    "AVATAR_GENERATION_ERROR");
            }
        }

        #endregion

        #region 프로필 뷰 및 통계

        /// <summary>
        /// 프로필 뷰 조회
        /// </summary>
        public async Task<ServiceResult<UserProfileView>> GetProfileViewAsync(Guid userId)
        {
            try
            {
                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile == null)
                {
                    return ServiceResult<UserProfileView>.NotFound($"Profile not found for user: {userId}");
                }

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    return ServiceResult<UserProfileView>.NotFound($"User not found: {userId}");
                }

                var connectedIds = await _connectedIdRepository.GetByUserIdAsync(userId);
                var organizations = new List<OrganizationMembership>();

                // ConnectedId의 첫 번째를 기본으로 설정
                bool isFirst = true;
                foreach (var connectedId in connectedIds.Where(c => c.Status == ConnectedIdStatus.Active))
                {
                    organizations.Add(new OrganizationMembership
                    {
                        OrganizationId = connectedId.OrganizationId,
                        OrganizationName = $"Org-{connectedId.OrganizationId.ToString().Substring(0, 8)}", // 임시
                        Role = connectedId.MembershipType.ToString(),
                        JoinedAt = connectedId.JoinedAt,
                        IsDefault = isFirst
                    });
                    isFirst = false;
                }

                var view = new UserProfileView
                {
                    Id = userId,
                    Basic = new BasicInfo
                    {
                        Email = user.Email,
                        Username = user.Username,
                        DisplayName = user.DisplayName,
                        Status = user.Status,
                        EmailVerified = user.IsEmailVerified,
                        CreatedAt = user.CreatedAt
                    },
                    Organizations = organizations,
                    Activity = new ActivitySummary
                    {
                        LastLoginAt = user.LastLoginAt,
                        TotalLogins = 0,  // 추후 구현
                        RecentActivities = 0,  // 추후 구현
                        PreferredDevice = "Web"  // 추후 구현
                    },
                    Security = new SecurityInfo
                    {
                        IsTwoFactorEnabled = user.IsTwoFactorEnabled,
                        PasswordChangedAt = user.PasswordChangedAt,
                        ActiveSessions = new List<string>(),  // 추후 구현
                        SecurityLevel = user.IsTwoFactorEnabled ? "Enhanced" : "Standard"
                    },
                    Subscription = new SubscriptionInfo
                    {
                        PlanName = "Basic",  // 추후 구현
                        ExpiresAt = null,
                        ActiveAddons = new List<string>(),
                        UsagePercentage = 0
                    }
                };

                return ServiceResult<UserProfileView>.Success(view);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting profile view for user {UserId}", userId);
                return ServiceResult<UserProfileView>.Failure($"Failed to get profile view: {ex.Message}");
            }
        }
        #endregion

        #region Additional Helper Methods

        private bool IsValidTimeZone(string timeZone)
        {
            try
            {
                TimeZoneInfo.FindSystemTimeZoneById(timeZone);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool IsValidImage(byte[] imageData, string contentType)
        {
            if (imageData.Length > 5 * 1024 * 1024) return false;

            var validTypes = new[] { "image/jpeg", "image/png", "image/gif", "image/webp" };
            return validTypes.Contains(contentType.ToLower());
        }

        private string GenerateAvatarUrl(string identifier)
        {
            var encodedIdentifier = Uri.EscapeDataString(identifier);
            return $"https://ui-avatars.com/api/?name={encodedIdentifier}&background=random&size=200";
        }

        private async Task ProcessMetadataModeChange(Guid userId, UserMetadataMode oldMode, UserMetadataMode newMode, Guid changedBy)
        {
            if (newMode == UserMetadataMode.Minimal && oldMode != UserMetadataMode.Minimal)
            {
                var profile = await _profileRepository.GetByIdAsync(userId);
                if (profile != null)
                {
                    profile.Bio = null;
                    profile.Location = null;
                    profile.DateOfBirth = null;
                    profile.Gender = null;
                    profile.ProfileMetadata = null;
                    profile.WebsiteUrl = null;
                    profile.UpdatedByConnectedId = changedBy;
                    profile.UpdatedAt = _dateTimeProvider.UtcNow;

                    await _profileRepository.UpdateAsync(profile);
                    await _unitOfWork.SaveChangesAsync();

                    _logger.LogInformation(
                        "User {UserId} profile cleaned for Minimal metadata mode",
                        userId);
                }
            }
        }

        private async Task<string> UploadToCloudStorage(Guid userId, byte[] imageData, string contentType)
        {
            var fileName = $"{userId}/{Guid.NewGuid()}.jpg";
            var baseUrl = "https://storage.authhive.com/profiles/";

            await Task.Delay(100); // 시뮬레이션

            return $"{baseUrl}{fileName}";
        }

        private async Task DeleteFromCloudStorage(string imageUrl)
        {
            await Task.Delay(100); // 시뮬레이션
        }

        private string ExportToJson(UserProfile profile, UserEntity user)
        {
            var data = new
            {
                User = new
                {
                    user.Id,
                    user.Email,
                    user.Username,
                    user.DisplayName,
                    user.Status,
                    user.IsEmailVerified,
                    user.IsTwoFactorEnabled,
                    user.CreatedAt,
                    user.LastLoginAt
                },
                Profile = new
                {
                    profile.UserId,
                    profile.PhoneNumber,
                    profile.PhoneVerified,
                    profile.ProfileImageUrl,
                    profile.TimeZone,
                    profile.PreferredLanguage,
                    profile.PreferredCurrency,
                    profile.Bio,
                    profile.WebsiteUrl,
                    profile.Location,
                    profile.DateOfBirth,
                    profile.Gender,
                    profile.ProfileMetadata,
                    profile.CompletionPercentage,
                    profile.IsPublic,
                    profile.EmailNotificationsEnabled,
                    profile.SmsNotificationsEnabled
                },
                Metadata = new
                {
                    profile.CreatedAt,
                    profile.UpdatedAt,
                    profile.LastProfileUpdateAt,
                    ExportedAt = _dateTimeProvider.UtcNow
                }
            };

            return JsonSerializer.Serialize(data, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
        }

        private string ExportToCsv(UserProfile profile, UserEntity user)
        {
            var csv = "Field,Value\n";
            csv += $"UserId,{user.Id}\n";
            csv += $"Email,{user.Email}\n";
            csv += $"Username,{user.Username}\n";
            csv += $"DisplayName,{user.DisplayName}\n";
            csv += $"PhoneNumber,{profile.PhoneNumber}\n";
            csv += $"PhoneVerified,{profile.PhoneVerified}\n";
            csv += $"TimeZone,{profile.TimeZone}\n";
            csv += $"PreferredLanguage,{profile.PreferredLanguage}\n";
            csv += $"PreferredCurrency,{profile.PreferredCurrency}\n";
            csv += $"Bio,\"{profile.Bio?.Replace("\"", "\"\"")}\"\n";
            csv += $"Location,{profile.Location}\n";
            csv += $"CompletionPercentage,{profile.CompletionPercentage}\n";
            csv += $"CreatedAt,{profile.CreatedAt:yyyy-MM-dd HH:mm:ss}\n";
            csv += $"ExportedAt,{_dateTimeProvider.UtcNow:yyyy-MM-dd HH:mm:ss}\n";
            return csv;
        }

        private string ExportToSql(UserProfile profile, UserEntity user)
        {
            return $@"
-- User Profile Export for UserId: {user.Id}
-- Generated at: {_dateTimeProvider.UtcNow:yyyy-MM-dd HH:mm:ss} UTC

INSERT INTO users (
    id, email, username, display_name, status, 
    is_email_verified, is_two_factor_enabled,
    created_at, last_login_at
) VALUES (
    '{user.Id}',
    '{user.Email?.Replace("'", "''")}',
    {(user.Username != null ? $"'{user.Username.Replace("'", "''")}'" : "NULL")},
    {(user.DisplayName != null ? $"'{user.DisplayName.Replace("'", "''")}'" : "NULL")},
    {(int)user.Status},
    {user.IsEmailVerified.ToString().ToLower()},
    {user.IsTwoFactorEnabled.ToString().ToLower()},
    '{user.CreatedAt:yyyy-MM-dd HH:mm:ss}',
    {(user.LastLoginAt.HasValue ? $"'{user.LastLoginAt.Value:yyyy-MM-dd HH:mm:ss}'" : "NULL")}
);

INSERT INTO user_profiles (
    user_id, phone_number, phone_verified, phone_verified_at,
    profile_image_url, profile_image_uploaded_at,
    time_zone, preferred_language, preferred_currency,
    bio, website_url, location, date_of_birth, gender,
    profile_metadata, completion_percentage, is_public,
    last_profile_update_at, email_notifications_enabled,
    sms_notifications_enabled, created_at, updated_at
) VALUES (
    '{profile.UserId}',
    {(profile.PhoneNumber != null ? $"'{profile.PhoneNumber}'" : "NULL")},
    {profile.PhoneVerified.ToString().ToLower()},
    {(profile.PhoneVerifiedAt.HasValue ? $"'{profile.PhoneVerifiedAt.Value:yyyy-MM-dd HH:mm:ss}'" : "NULL")},
    {(profile.ProfileImageUrl != null ? $"'{profile.ProfileImageUrl}'" : "NULL")},
    {(profile.ProfileImageUploadedAt.HasValue ? $"'{profile.ProfileImageUploadedAt.Value:yyyy-MM-dd HH:mm:ss}'" : "NULL")},
    '{profile.TimeZone}',
    '{profile.PreferredLanguage}',
    '{profile.PreferredCurrency}',
    {(profile.Bio != null ? $"'{profile.Bio.Replace("'", "''")}'" : "NULL")},
    {(profile.WebsiteUrl != null ? $"'{profile.WebsiteUrl}'" : "NULL")},
    {(profile.Location != null ? $"'{profile.Location.Replace("'", "''")}'" : "NULL")},
    {(profile.DateOfBirth.HasValue ? $"'{profile.DateOfBirth.Value:yyyy-MM-dd}'" : "NULL")},
    {(profile.Gender != null ? $"'{profile.Gender}'" : "NULL")},
    {(profile.ProfileMetadata != null ? $"'{profile.ProfileMetadata.Replace("'", "''")}'" : "NULL")},
    {profile.CompletionPercentage},
    {profile.IsPublic.ToString().ToLower()},
    {(profile.LastProfileUpdateAt.HasValue ? $"'{profile.LastProfileUpdateAt.Value:yyyy-MM-dd HH:mm:ss}'" : "NULL")},
    {profile.EmailNotificationsEnabled.ToString().ToLower()},
    {profile.SmsNotificationsEnabled.ToString().ToLower()},
    '{profile.CreatedAt:yyyy-MM-dd HH:mm:ss}',
    {(profile.UpdatedAt.HasValue ? $"'{profile.UpdatedAt.Value:yyyy-MM-dd HH:mm:ss}'" : "NULL")}
);";
        }

        #endregion
    }
}