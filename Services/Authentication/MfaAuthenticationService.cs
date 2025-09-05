using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Infra.Communication;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Common;
using Google.Authenticator;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using UserEntity = AuthHive.Core.Entities.User.User;
using UserProfileEntity = AuthHive.Core.Entities.User.UserProfile;
using MfaBypassTokenEntity = AuthHive.Core.Entities.Auth.MfaBypassToken;
using MfaBypassTokenDto = AuthHive.Core.Models.Auth.Authentication.Common.MfaBypassToken;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Enums.Auth;

namespace AuthHive.Auth.Services.Authentication
{
    public class MfaAuthenticationService : IMfaAuthenticationService
    {
        private readonly IUserRepository _userRepository;
        private readonly IMemoryCache _cache;
        private readonly ILogger<MfaAuthenticationService> _logger;
        private readonly TwoFactorAuthenticator _twoFactorAuthenticator;
        private readonly IAuthenticationAttemptLogRepository _logRepository;
        private readonly IMfaBypassTokenRepository _tokenRepository;
        private readonly IAccountRecoveryRepository _accountRecoveryRepository;
        private readonly IEmailService _emailService;
        private readonly IAccountSecurityService _accountSecurityService;
        private const int MFA_CODE_VALIDITY_MINUTES = 5;
        private const string ISSUER = "AuthHive";

        public MfaAuthenticationService(
            IUserRepository userRepository,
            IMemoryCache cache,
            ILogger<MfaAuthenticationService> logger,
            IAuthenticationAttemptLogRepository logRepository,
            IMfaBypassTokenRepository tokenRepository,
            IAccountRecoveryRepository accountRecoveryRepository,
            IEmailService emailService,
            IAccountSecurityService accountSecurityService)
        {
            _userRepository = userRepository;
            _cache = cache;
            _logger = logger;
            _twoFactorAuthenticator = new TwoFactorAuthenticator();
            _logRepository = logRepository;
            _tokenRepository = tokenRepository;
            _accountRecoveryRepository = accountRecoveryRepository;
            _emailService = emailService;
            _accountSecurityService = accountSecurityService;
        }

        #region MFA 인증 플로우

        public async Task<ServiceResult<MfaChallengeResponse>> InitiateMfaAsync(
            Guid userId,
            string method,
            Guid? sessionId = null)
        {
            try
            {
                var user = await _userRepository.GetByIdWithProfileAsync(userId);
                if (user == null)
                    return ServiceResult<MfaChallengeResponse>.Failure("User not found");

                // Parse method string to enum
                if (!Enum.TryParse<MfaMethod>(method, true, out var mfaMethod))
                    return ServiceResult<MfaChallengeResponse>.Failure($"Invalid MFA method: {method}");

                var challengeId = Guid.NewGuid().ToString();
                var challenge = new MfaChallengeResponse
                {
                    ChallengeId = challengeId,
                    Method = mfaMethod,
                    CodeSent = false,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(MFA_CODE_VALIDITY_MINUTES),
                    AttemptsAllowed = 5,
                    AlternativeMethods = GetAlternativeMethods(user, mfaMethod)
                };

                var cacheKey = $"mfa_challenge_{userId}_{challengeId}";
                _cache.Set(cacheKey, challenge, TimeSpan.FromMinutes(MFA_CODE_VALIDITY_MINUTES));

                switch (mfaMethod)
                {
                    case MfaMethod.Sms:
                        if (string.IsNullOrEmpty(user.UserProfile?.PhoneNumber))
                            return ServiceResult<MfaChallengeResponse>.Failure("Phone number not configured");

                        var smsCode = GenerateCode();
                        await SendSmsCode(user.UserProfile.PhoneNumber, smsCode);
                        CacheCode(userId, Guid.Parse(challengeId), smsCode);
                        challenge.CodeSent = true;
                        challenge.Hint = $"SMS sent to {MaskPhoneNumber(user.UserProfile.PhoneNumber)}";
                        break;

                    case MfaMethod.Email:
                        var emailCode = GenerateCode();
                        await SendEmailCode(user.Email, emailCode);
                        CacheCode(userId, Guid.Parse(challengeId), emailCode);
                        challenge.CodeSent = true;
                        challenge.Hint = $"Email sent to {MaskEmail(user.Email)}";
                        break;

                    case MfaMethod.Totp:
                        challenge.Message = "Enter code from your authenticator app";
                        break;
                }

                return ServiceResult<MfaChallengeResponse>.Success(challenge);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initiate MFA for user {UserId}", userId);
                return ServiceResult<MfaChallengeResponse>.Failure("Failed to initiate MFA");
            }
        }

        public async Task<ServiceResult<AuthenticationResponse>> CompleteMfaAuthenticationAsync(
            Guid userId,
            string code,
            string method,
            Guid? sessionId = null)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                    return ServiceResult<AuthenticationResponse>.Failure("User not found");

                bool isValid = await VerifyMfaCode(userId, code, method);

                if (!isValid)
                {
                    await RecordFailedAttempt(userId, method, "Invalid code");
                    return ServiceResult<AuthenticationResponse>.Failure("Invalid MFA code");
                }

                // Update last used time for the method
                UpdateMethodLastUsedTime(userId, method);

                ClearUserCodes(userId);

                var response = new AuthenticationResponse
                {
                    Success = true,
                    MfaVerified = true,
                    Message = "MFA verification successful"
                };

                return ServiceResult<AuthenticationResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MFA completion failed for user {UserId}", userId);
                return ServiceResult<AuthenticationResponse>.Failure("MFA verification failed");
            }
        }

        public async Task<ServiceResult<MfaChallengeResponse>> ResendMfaChallengeAsync(
            Guid userId,
            string challengeId)
        {
            var cacheKey = $"mfa_challenge_{userId}_{challengeId}";
            if (!_cache.TryGetValue(cacheKey, out MfaChallengeResponse? challenge))
            {
                return ServiceResult<MfaChallengeResponse>.Failure("Challenge not found or expired");
            }
            
            // Use the MfaMethod enum directly
            return await InitiateMfaAsync(userId, challenge!.Method.ToString());
        }

        public Task<ServiceResult> CancelMfaChallengeAsync(
            Guid userId,
            string challengeId)
        {
            var cacheKey = $"mfa_challenge_{userId}_{challengeId}";
            _cache.Remove(cacheKey);
            return Task.FromResult(ServiceResult.Success("Challenge cancelled"));
        }

        #endregion

        #region MFA 정책

        public Task<ServiceResult<MfaPolicyDto>> GetMfaPolicyAsync(Guid organizationId)
        {
            // TODO: DB에서 organizationId에 해당하는 MFA 정책을 조회하는 로직 구현 필요.
            var policy = new MfaPolicyDto
            {
                OrganizationId = organizationId,
                IsRequired = false,
                AllowedMethods = new List<string> { "totp", "sms", "email" },
                GracePeriodDays = 7,
                EnforceForAdmins = true,
                ExemptRoles = new List<string>()
            };

            return Task.FromResult(ServiceResult<MfaPolicyDto>.Success(policy));
        }

        public Task<ServiceResult> SetMfaPolicyAsync(Guid organizationId, MfaPolicyRequest request)
        {
            // TODO: DB에서 organizationId에 해당하는 MFA 정책을 찾아 업데이트하는 로직 구현 필요.
            _logger.LogInformation("MFA policy for organization {OrganizationId} would be updated.", organizationId);
            return Task.FromResult(ServiceResult.Success("Policy updated"));
        }

        public Task<ServiceResult<MfaRequirement>> CheckMfaRequirementAsync(Guid userId, Guid? organizationId = null, string? resource = null)
        {
            // TODO: 조직의 정책과 사용자의 MFA 상태를 교차 확인하는 복잡한 로직 구현 필요.
            var requirement = new MfaRequirement
            {
                IsRequired = false,
                Reason = "MFA is optional by default."
            };
            return Task.FromResult(ServiceResult<MfaRequirement>.Success(requirement));
        }

        #endregion

        #region 신뢰할 수 있는 장치
        public async Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetTrustedDevicesAsync(Guid userId)
        {
            try
            {
                var securityResult = await _accountSecurityService.GetTrustedDevicesAsync(userId);

                if (!securityResult.IsSuccess || securityResult.Data == null)
                {
                    return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure(
                        securityResult.ErrorMessage ?? "Failed to get trusted devices from security service.");
                }

                var dtos = securityResult.Data.Select(sourceDto => new TrustedDeviceDto
                {
                    DeviceId = sourceDto.DeviceId,
                    DeviceName = sourceDto.DeviceName,
                    DeviceType = sourceDto.DeviceType,
                    TrustedAt = sourceDto.TrustedAt,
                    LastUsedAt = sourceDto.LastUsedAt ?? default,
                    Browser = sourceDto.Browser,
                    OperatingSystem = sourceDto.OperatingSystem,
                    IpAddress = sourceDto.IpAddress
                }).ToList();

                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get trusted devices for user {UserId}", userId);
                return ServiceResult<IEnumerable<TrustedDeviceDto>>.Failure("Failed to get trusted devices.");
            }
        }
        
        public Task<ServiceResult> TrustCurrentDeviceAsync(Guid userId, TrustedDeviceRequest request)
        {
            return _accountSecurityService.RegisterTrustedDeviceAsync(userId, request);
        }

        public Task<ServiceResult> RemoveTrustedDeviceAsync(Guid userId, string deviceId)
        {
            return _accountSecurityService.RemoveTrustedDeviceAsync(userId, deviceId);
        }

        public Task<ServiceResult<int>> RemoveAllTrustedDevicesAsync(Guid userId)
        {
            return _accountSecurityService.RemoveAllTrustedDevicesAsync(userId);
        }

        #endregion

        #region MFA 설정 관리

        public async Task<ServiceResult<MfaSettingsResponse>> GetMfaSettingsAsync(Guid userId)
        {
            try
            {
                var user = await _userRepository.GetByIdWithProfileAsync(userId);
                if (user == null)
                    return ServiceResult<MfaSettingsResponse>.Failure("User not found");

                var settings = new MfaSettingsResponse
                {
                    IsEnabled = user.IsTwoFactorEnabled,
                    PreferredMethod = user.TwoFactorMethod ?? string.Empty,
                    EnabledMethods = GetEnabledMethods(user),
                    IsRequired = false,
                    MethodSettings = GetMethodSettings(user)
                };
                return ServiceResult<MfaSettingsResponse>.Success(settings);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get MFA settings for user {UserId}", userId);
                return ServiceResult<MfaSettingsResponse>.Failure("Failed to get MFA settings");
            }
        }

        public async Task<ServiceResult> UpdateMfaSettingsAsync(
            Guid userId,
            MfaSettingsRequest request)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                    return ServiceResult.Failure("User not found");

                user.IsTwoFactorEnabled = request.Enable;
                user.TwoFactorMethod = request.PreferredMethod;

                await _userRepository.UpdateAsync(user);
                return ServiceResult.Success("MFA settings updated");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update MFA settings");
                return ServiceResult.Failure("Failed to update MFA settings");
            }
        }

        public async Task<ServiceResult<MfaSetupResponse>> EnableMfaAsync(
             Guid userId,
             string method,
             MfaSetupRequest request)
        {
            try
            {
                var user = await _userRepository.GetByIdWithProfileAsync(userId);
                if (user == null)
                    return ServiceResult<MfaSetupResponse>.Failure("User not found");

                if (user.UserProfile == null)
                {
                    user.UserProfile = new UserProfileEntity();
                }

                // Parse method string to enum
                if (!Enum.TryParse<MfaMethod>(method, true, out var mfaMethod))
                    return ServiceResult<MfaSetupResponse>.Failure($"Invalid MFA method: {method}");

                var response = new MfaSetupResponse
                {
                    Success = true,
                    Method = mfaMethod,
                    SetupToken = GenerateSetupToken(),
                    ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                    Metadata = new Dictionary<string, object>()
                };

                switch (mfaMethod)
                {
                    case MfaMethod.Totp:
                        var totpResponse = await GenerateTotpSecretAsync(userId);
                        if (totpResponse.IsSuccess && totpResponse.Data != null)
                        {
                            response.Secret = totpResponse.Data.ManualEntryKey;
                            response.QrCodeUrl = totpResponse.Data.QrCodeUrl;
                            response.Issuer = totpResponse.Data.Issuer;
                            response.AccountName = totpResponse.Data.AccountName;
                            response.Metadata["algorithm"] = "SHA1";
                            response.Metadata["digits"] = 6;
                            response.Metadata["period"] = 30;
                        }
                        else
                        {
                            return ServiceResult<MfaSetupResponse>.Failure(totpResponse.ErrorMessage ?? "Failed to generate TOTP secret");
                        }
                        break;

                    case MfaMethod.Sms:
                        if (string.IsNullOrEmpty(request.PhoneNumber))
                            return ServiceResult<MfaSetupResponse>.Failure("Phone number required");

                        user.UserProfile.PhoneNumber = request.PhoneNumber;
                        await _userRepository.UpdateAsync(user);

                        var verificationCode = GenerateCode();
                        await SendSmsCode(request.PhoneNumber, verificationCode);
                        CacheCode(userId, Guid.Parse(response.SetupToken), verificationCode);
                        response.PhoneNumber = MaskPhoneNumber(request.PhoneNumber);
                        response.VerificationCodeSent = true;
                        response.Message = "Verification code sent to phone";
                        break;

                    case MfaMethod.Email:
                        var emailCode = GenerateCode();
                        await SendEmailCode(user.Email, emailCode);
                        CacheCode(userId, Guid.Parse(response.SetupToken), emailCode);
                        response.Email = MaskEmail(user.Email);
                        response.VerificationCodeSent = true;
                        response.Message = "Verification code sent to email";
                        break;

                    case MfaMethod.BackupCode:
                        // Generate backup codes
                        var backupCodes = new List<string>();
                        for (int i = 0; i < 10; i++)
                        {
                            backupCodes.Add(GenerateBackupCode());
                        }
                        response.BackupCodes = backupCodes;
                        
                        // Store hashed backup codes
                        user.BackupCodes = backupCodes.Select(HashCode).ToList();
                        await _userRepository.UpdateAsync(user);
                        response.Message = "Backup codes generated. Store them safely.";
                        break;
                }
                
                return ServiceResult<MfaSetupResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enable MFA");
                return ServiceResult<MfaSetupResponse>.Failure("Failed to enable MFA");
            }
        }

        public async Task<ServiceResult> DisableMfaAsync(
            Guid userId,
            string method,
            string verificationCode)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                    return ServiceResult.Failure("User not found");

                if (!await VerifyMfaCode(userId, verificationCode, method))
                    return ServiceResult.Failure("Invalid verification code");

                user.IsTwoFactorEnabled = false;
                user.TwoFactorMethod = null;
                user.TotpSecret = null;
                await _userRepository.UpdateAsync(user);

                return ServiceResult.Success("MFA disabled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to disable MFA");
                return ServiceResult.Failure("Failed to disable MFA");
            }
        }

        #endregion

        #region MFA 방식 관리

        public Task<ServiceResult<IEnumerable<MfaMethodDto>>> GetAvailableMfaMethodsAsync(
            Guid? organizationId = null)
        {
            // organizationId를 사용하여 사용자의 MFA 메서드 정보를 가져올 수 있도록 개선
            // 현재는 기본 메서드만 반환
            var methods = new List<MfaMethodDto>
            {
                new MfaMethodDto 
                { 
                    Method = MfaMethod.Totp,
                    IsConfigured = false,
                    IsVerified = false,
                    IsPreferred = false,
                    DisplayInfo = "Authenticator App",
                    Metadata = new Dictionary<string, object>
                    {
                        ["description"] = "Use an authenticator app like Google Authenticator",
                        ["priority"] = 1
                    }
                },
                new MfaMethodDto 
                { 
                    Method = MfaMethod.Sms,
                    IsConfigured = false,
                    IsVerified = false,
                    IsPreferred = false,
                    DisplayInfo = "SMS",
                    Metadata = new Dictionary<string, object>
                    {
                        ["description"] = "Receive codes via SMS",
                        ["priority"] = 2
                    }
                },
                new MfaMethodDto 
                { 
                    Method = MfaMethod.Email,
                    IsConfigured = false,
                    IsVerified = false,
                    IsPreferred = false,
                    DisplayInfo = "Email",
                    Metadata = new Dictionary<string, object>
                    {
                        ["description"] = "Receive codes via email",
                        ["priority"] = 3
                    }
                }
            };
            
            return Task.FromResult(ServiceResult<IEnumerable<MfaMethodDto>>.Success(methods));
        }

        // 사용자별 MFA 메서드 상태를 가져오는 새로운 메서드
        public async Task<ServiceResult<IEnumerable<MfaMethodDto>>> GetUserMfaMethodsAsync(Guid userId)
        {
            try
            {
                var user = await _userRepository.GetByIdWithProfileAsync(userId);
                if (user == null)
                    return ServiceResult<IEnumerable<MfaMethodDto>>.Failure("User not found");

                var methods = new List<MfaMethodDto>();
                
                // TOTP 메서드
                var totpMethod = new MfaMethodDto
                {
                    Method = MfaMethod.Totp,
                    IsConfigured = !string.IsNullOrEmpty(user.TotpSecret),
                    IsVerified = !string.IsNullOrEmpty(user.TotpSecret),
                    IsPreferred = user.TwoFactorMethod?.ToLower() == "totp",
                    DisplayInfo = "Authenticator App",
                    ConfiguredAt = GetMethodConfiguredAt(user, "totp"),
                    LastUsedAt = await GetMethodLastUsedAt(userId, "totp"),
                    DeviceName = GetTotpDeviceName(user),
                    Metadata = new Dictionary<string, object>
                    {
                        ["appName"] = ISSUER
                    }
                };
                methods.Add(totpMethod);
                
                // SMS 메서드
                if (user.UserProfile != null)
                {
                    var smsMethod = new MfaMethodDto
                    {
                        Method = MfaMethod.Sms,
                        IsConfigured = !string.IsNullOrEmpty(user.UserProfile.PhoneNumber),
                        IsVerified = user.UserProfile.PhoneVerified,
                        IsPreferred = user.TwoFactorMethod?.ToLower() == "sms",
                        DisplayInfo = !string.IsNullOrEmpty(user.UserProfile.PhoneNumber) 
                            ? MaskPhoneNumber(user.UserProfile.PhoneNumber) 
                            : null,
                        ConfiguredAt = GetMethodConfiguredAt(user, "sms"),
                        LastUsedAt = await GetMethodLastUsedAt(userId, "sms"),
                        Metadata = new Dictionary<string, object>()
                    };
                    methods.Add(smsMethod);
                }
                
                // Email 메서드
                var emailMethod = new MfaMethodDto
                {
                    Method = MfaMethod.Email,
                    IsConfigured = true, // Email은 항상 설정됨
                    IsVerified = user.IsEmailVerified,
                    IsPreferred = user.TwoFactorMethod?.ToLower() == "email",
                    DisplayInfo = MaskEmail(user.Email),
                    ConfiguredAt = user.CreatedAt, // 계정 생성 시점
                    LastUsedAt = await GetMethodLastUsedAt(userId, "email"),
                    Metadata = new Dictionary<string, object>()
                };
                methods.Add(emailMethod);

                return ServiceResult<IEnumerable<MfaMethodDto>>.Success(methods);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user MFA methods for user {UserId}", userId);
                return ServiceResult<IEnumerable<MfaMethodDto>>.Failure("Failed to get MFA methods");
            }
        }

        public async Task<ServiceResult> SetPreferredMfaMethodAsync(
            Guid userId,
            string method)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                    return ServiceResult.Failure("User not found");

                user.TwoFactorMethod = method;
                await _userRepository.UpdateAsync(user);

                return ServiceResult.Success("Preferred method updated");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set preferred MFA method");
                return ServiceResult.Failure("Failed to set preferred method");
            }
        }

        public Task<ServiceResult<MfaMethodSetupResponse>> AddMfaMethodAsync(
            Guid userId,
            string method,
            MfaMethodSetupRequest request)
        {
            var response = new MfaMethodSetupResponse
            {
                Success = true,
                Method = method,
                RequiresVerification = true,
                VerificationToken = GenerateSetupToken(),
                VerificationExpiresAt = DateTime.UtcNow.AddMinutes(10)
            };
            return Task.FromResult(ServiceResult<MfaMethodSetupResponse>.Success(response));
        }

        public async Task<ServiceResult> RemoveMfaMethodAsync(
            Guid userId,
            string method,
            string verificationCode)
        {
            if (!await VerifyMfaCode(userId, verificationCode, method))
                return ServiceResult.Failure("Invalid verification code");

            // TODO: Implement actual logic to remove the method configuration from the user
            return ServiceResult.Success("Method removed");
        }

        #endregion

        #region TOTP/OTP 관리

        public async Task<ServiceResult<TotpSecretResponse>> GenerateTotpSecretAsync(Guid userId)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                    return ServiceResult<TotpSecretResponse>.Failure("User not found");

                var secretKey = GenerateSecureToken();
                var setupInfo = _twoFactorAuthenticator.GenerateSetupCode(ISSUER, user.Email, secretKey, false, 3);

                var response = new TotpSecretResponse
                {
                    Secret = secretKey,
                    QrCodeUrl = setupInfo.QrCodeSetupImageUrl,
                    ManualEntryKey = setupInfo.ManualEntryKey,
                    Issuer = ISSUER,
                    AccountName = user.Email
                };

                _cache.Set($"totp_setup_{userId}", secretKey, TimeSpan.FromMinutes(10));
                return ServiceResult<TotpSecretResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate TOTP secret");
                return ServiceResult<TotpSecretResponse>.Failure("Failed to generate TOTP secret");
            }
        }

        public async Task<ServiceResult> VerifyTotpSetupAsync(Guid userId, string code)
        {
            try
            {
                if (!_cache.TryGetValue($"totp_setup_{userId}", out string? secret) || secret is null)
                    return ServiceResult.Failure("Setup expired or invalid secret.");

                if (!_twoFactorAuthenticator.ValidateTwoFactorPIN(secret, code, TimeSpan.FromSeconds(60)))
                    return ServiceResult.Failure("Invalid code");

                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                {
                    _cache.Remove($"totp_setup_{userId}");
                    return ServiceResult.Failure("User not found during verification.");
                }

                user.TotpSecret = EncryptSecret(secret);
                user.IsTwoFactorEnabled = true;
                user.TwoFactorMethod = "totp";
                await _userRepository.UpdateAsync(user);

                _cache.Remove($"totp_setup_{userId}");
                return ServiceResult.Success("TOTP setup completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify TOTP setup for user {UserId}", userId);
                return ServiceResult.Failure("Failed to verify TOTP setup");
            }
        }

        public async Task<ServiceResult<BackupCodesResponse>> GenerateBackupCodesAsync(
            Guid userId,
            int count = 10)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                    return ServiceResult<BackupCodesResponse>.Failure("User not found");

                var codes = new List<string>();
                for (int i = 0; i < count; i++)
                {
                    codes.Add(GenerateBackupCode());
                }

                user.BackupCodes = codes.Select(HashCode).ToList();
                await _userRepository.UpdateAsync(user);

                var response = new BackupCodesResponse
                {
                    Codes = codes,
                    GeneratedAt = DateTime.UtcNow,
                    RemainingCount = count
                };
                return ServiceResult<BackupCodesResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate backup codes");
                return ServiceResult<BackupCodesResponse>.Failure("Failed to generate backup codes");
            }
        }

        public async Task<ServiceResult<AuthenticationResponse>> UseBackupCodeAsync(
            Guid userId,
            string code,
            Guid? sessionId = null)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user?.BackupCodes == null || !user.BackupCodes.Any())
                return ServiceResult<AuthenticationResponse>.Failure("No backup codes available");

            var hashedCode = HashCode(code);
            if (!user.BackupCodes.Contains(hashedCode))
                return ServiceResult<AuthenticationResponse>.Failure("Invalid backup code");

            user.BackupCodes.Remove(hashedCode);
            await _userRepository.UpdateAsync(user);

            return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
            {
                Success = true,
                MfaVerified = true,
                Message = "Backup code used successfully"
            });
        }

        #endregion

        #region 응급 접근

        public async Task<ServiceResult<MfaBypassTokenDto>> GenerateMfaBypassTokenAsync(
           Guid userId,
           string reason,
           TimeSpan? validity = null)
        {
            try
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user == null)
                    return ServiceResult<MfaBypassTokenDto>.Failure("User not found.");

                var validityDuration = validity ?? TimeSpan.FromHours(1);
                var tokenValue = GenerateSecureToken();

                var tokenEntity = new MfaBypassTokenEntity
                {
                    TokenHash = HashCode(tokenValue),
                    UserId = userId,
                    User = user,
                    Reason = reason,
                    ExpiresAt = DateTime.UtcNow.Add(validityDuration)
                };
                var savedEntity = await _tokenRepository.AddAsync(tokenEntity);

                var tokenDto = new MfaBypassTokenDto
                {
                    Token = tokenValue,
                    UserId = savedEntity.UserId,
                    Reason = savedEntity.Reason,
                    IssuedAt = savedEntity.CreatedAt,
                    ExpiresAt = savedEntity.ExpiresAt,
                    IsUsed = savedEntity.IsUsed
                };

                return ServiceResult<MfaBypassTokenDto>.Success(tokenDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate MFA bypass token for user {UserId}", userId);
                return ServiceResult<MfaBypassTokenDto>.Failure("Failed to generate bypass token");
            }
        }

        public async Task<ServiceResult<AuthenticationResponse>> UseMfaBypassTokenAsync(string bypassToken)
        {
            try
            {
                var hashedToken = HashCode(bypassToken);
                var tokenEntity = await _tokenRepository.FindByTokenValueAsync(hashedToken);

                if (tokenEntity == null || tokenEntity.IsUsed || tokenEntity.ExpiresAt < DateTime.UtcNow)
                {
                    return ServiceResult<AuthenticationResponse>.Failure("Invalid, used, or expired bypass token");
                }

                tokenEntity.IsUsed = true;
                tokenEntity.UsedAt = DateTime.UtcNow;
                await _tokenRepository.UpdateAsync(tokenEntity);

                _cache.Remove($"mfa_bypass_{bypassToken}");

                return ServiceResult<AuthenticationResponse>.Success(new AuthenticationResponse
                {
                    Success = true,
                    MfaVerified = true,
                    Message = "MFA bypassed with emergency token"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to use MFA bypass token");
                return ServiceResult<AuthenticationResponse>.Failure("An error occurred while using the bypass token");
            }
        }

        public async Task<ServiceResult> RequestMfaRecoveryAsync(
            string email,
            MfaRecoveryRequest request,
            string ipAddress)
        {
            try
            {
                var user = await _userRepository.GetByEmailAsync(email);
                if (user == null)
                {
                    _logger.LogWarning("MFA recovery requested for non-existent user: {Email}", email);
                    return ServiceResult.Success("If your account exists, a recovery email has been sent.");
                }

                var recoveryToken = GenerateSecureToken();
                var recoveryRequest = new AccountRecoveryRequest
                {
                    UserId = user.Id,
                    User = user,
                    TokenHash = HashCode(recoveryToken),
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    RequestIpAddress = ipAddress
                };
                await _accountRecoveryRepository.AddAsync(recoveryRequest);

                var recoveryLink = $"https://authhive.com/recover-mfa?token={recoveryToken}";
                await _emailService.SendMfaRecoveryEmailAsync(user.Email, user.Username, recoveryLink);

                return ServiceResult.Success("If your account exists, a recovery email has been sent.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to request MFA recovery for email {Email}", email);
                return ServiceResult.Success("If your account exists, a recovery email has been sent.");
            }
        }

        #endregion

        #region MFA 이력 및 감사

        public async Task<ServiceResult<IEnumerable<MfaAuthenticationHistory>>> GetMfaHistoryAsync(
            Guid userId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                var historyLogs = await _logRepository.GetHistoryForUserAsync(userId, startDate, endDate);

                var historyDtos = historyLogs.Select(log => new MfaAuthenticationHistory
                {
                    Id = log.Id,
                    AttemptedAt = log.AttemptedAt,
                    Method = log.Method.ToString(),
                    Success = log.IsSuccess,
                    FailureReason = log.FailureReason.ToString(),
                    IpAddress = log.IpAddress
                }).ToList();

                return ServiceResult<IEnumerable<MfaAuthenticationHistory>>.Success(historyDtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get MFA history for user {UserId}", userId);
                return ServiceResult<IEnumerable<MfaAuthenticationHistory>>.Failure("Failed to get MFA history");
            }
        }

        public Task<ServiceResult<IEnumerable<MfaFailureAttempt>>> GetMfaFailuresAsync(
            Guid userId,
            DateTime? since = null)
        {
            var cacheKey = $"mfa_failures_{userId}";
            if (_cache.TryGetValue(cacheKey, out List<MfaFailureAttempt>? failures) && failures is not null)
            {
                var result = since.HasValue
                    ? failures.Where(f => f.AttemptedAt >= since.Value).ToList()
                    : failures;
                return Task.FromResult(ServiceResult<IEnumerable<MfaFailureAttempt>>.Success(result));
            }
            return Task.FromResult(ServiceResult<IEnumerable<MfaFailureAttempt>>.Success(new List<MfaFailureAttempt>()));
        }

        public Task<ServiceResult<MfaStatistics>> GetMfaStatisticsAsync(
            Guid? organizationId = null,
            DateTime? from = null,
            DateTime? to = null)
        {
            var stats = new MfaStatistics();
            return Task.FromResult(ServiceResult<MfaStatistics>.Success(stats));
        }

        #endregion

        #region Private Helper Methods

        private string GenerateCode()
        {
            return RandomNumberGenerator.GetInt32(100000, 999999).ToString("D6");
        }

        private string GenerateBackupCode()
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            return new string(Enumerable.Repeat(chars, 8)
                .Select(s => s[RandomNumberGenerator.GetInt32(s.Length)]).ToArray());
        }

        private string GenerateSecureToken()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private string GenerateSetupToken() => Guid.NewGuid().ToString("N");

        private string HashCode(string code)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(code));
            return Convert.ToBase64String(bytes);
        }

        private string EncryptSecret(string secret) => Convert.ToBase64String(Encoding.UTF8.GetBytes(secret));
        private string DecryptSecret(string encrypted) => Encoding.UTF8.GetString(Convert.FromBase64String(encrypted));

        private void CacheCode(Guid userId, Guid challengeId, string code)
        {
            var key = $"mfa_code_{userId}_{challengeId}";
            _cache.Set(key, code, TimeSpan.FromMinutes(MFA_CODE_VALIDITY_MINUTES));
        }

        private void ClearUserCodes(Guid userId)
        {
            // TODO: Implement cache key iteration and removal if necessary
        }

        private async Task<bool> VerifyMfaCode(Guid userId, string code, string method)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null) return false;

            // Parse method string to enum
            if (!Enum.TryParse<MfaMethod>(method, true, out var mfaMethod))
                return false;

            switch (mfaMethod)
            {
                case MfaMethod.Totp:
                    if (string.IsNullOrEmpty(user.TotpSecret)) return false;
                    var secret = DecryptSecret(user.TotpSecret);
                    return _twoFactorAuthenticator.ValidateTwoFactorPIN(secret, code);

                case MfaMethod.BackupCode:
                    if (user.BackupCodes == null || !user.BackupCodes.Any()) return false;
                    var hashedCode = HashCode(code);
                    return user.BackupCodes.Contains(hashedCode);

                default:
                    return false; // SMS/Email requires challengeId which is not present here
            }
        }

        private string GetChallengeType(MfaMethod method) => method switch
        {
            MfaMethod.Sms => "SMS_CODE",
            MfaMethod.Email => "EMAIL_CODE",
            MfaMethod.Totp => "TOTP_CODE",
            MfaMethod.BackupCode => "BACKUP_CODE",
            _ => "UNKNOWN"
        };

        private string MaskEmail(string? email)
        {
            if (string.IsNullOrEmpty(email)) return string.Empty;
            var parts = email.Split('@');
            if (parts.Length != 2) return "***@***";
            var name = parts[0];
            var masked = name.Length > 2
                ? name[0] + new string('*', Math.Min(name.Length - 2, 4)) + name[^1]
                : new string('*', name.Length);
            return $"{masked}@{parts[1]}";
        }

        private string MaskPhoneNumber(string? phone)
        {
            if (string.IsNullOrEmpty(phone) || phone.Length < 4) return "****";
            return new string('*', phone.Length - 4) + phone.Substring(phone.Length - 4);
        }

        private List<string> GetEnabledMethods(UserEntity user)
        {
            var methods = new List<string>();
            if (!string.IsNullOrEmpty(user.TotpSecret)) methods.Add("totp");
            if (!string.IsNullOrEmpty(user.UserProfile?.PhoneNumber)) methods.Add("sms");
            methods.Add("email");
            return methods;
        }

        private Dictionary<string, MfaMethodSettings> GetMethodSettings(UserEntity user) =>
            new()
            {
                ["totp"] = new MfaMethodSettings
                {
                    IsConfigured = !string.IsNullOrEmpty(user.TotpSecret),
                    IsVerified = !string.IsNullOrEmpty(user.TotpSecret)
                },
                ["sms"] = new MfaMethodSettings
                {
                    IsConfigured = !string.IsNullOrEmpty(user.UserProfile?.PhoneNumber),
                    IsVerified = user.UserProfile?.PhoneVerified ?? false
                },
                ["email"] = new MfaMethodSettings
                {
                    IsConfigured = true,
                    IsVerified = user.IsEmailVerified
                }
            };

        private async Task RecordFailedAttempt(Guid userId, string method, string reason)
        {
            var log = new AuthenticationAttemptLog
            {
                UserId = userId,
                Method = Enum.Parse<AuthenticationMethod>(method, true),
                IsSuccess = false,
                FailureReason = Enum.Parse<AuthenticationResult>(reason, true),
                AttemptedAt = DateTime.UtcNow,
                IpAddress = CommonDefaults.DefaultLocalIpV6
            };
            await _logRepository.AddAsync(log);
        }

        private async Task SendSmsCode(string phoneNumber, string code)
        {
            _logger.LogInformation("SMS code {Code} would be sent to {Phone}", code, phoneNumber);
            await _emailService.SendSmsAsync(phoneNumber, $"Your verification code is: {code}");
        }

        private async Task SendEmailCode(string email, string code)
        {
            _logger.LogInformation("Email code {Code} would be sent to {Email}", code, email);
            await _emailService.SendEmailAsync(email, "Your Verification Code", $"Your verification code is: {code}");
        }

        // Helper methods
        private List<MfaMethod> GetAlternativeMethods(UserEntity user, MfaMethod currentMethod)
        {
            var alternatives = new List<MfaMethod>();
            
            // Add available methods except the current one
            if (currentMethod != MfaMethod.Totp && !string.IsNullOrEmpty(user.TotpSecret))
                alternatives.Add(MfaMethod.Totp);
                
            if (currentMethod != MfaMethod.Sms && !string.IsNullOrEmpty(user.UserProfile?.PhoneNumber))
                alternatives.Add(MfaMethod.Sms);
                
            if (currentMethod != MfaMethod.Email)
                alternatives.Add(MfaMethod.Email);
                
            if (currentMethod != MfaMethod.BackupCode && user.BackupCodes?.Any() == true)
                alternatives.Add(MfaMethod.BackupCode);
                
            return alternatives;
        }

        private DateTime? GetMethodConfiguredAt(UserEntity user, string method)
        {
            // This would ideally come from a separate MFA configuration table
            // For now, return user creation date as a placeholder
            return user.CreatedAt;
        }

        private async Task<DateTime?> GetMethodLastUsedAt(Guid userId, string method)
        {
            // Query the authentication logs for the last successful use of this method
            var logs = await _logRepository.GetHistoryForUserAsync(userId, DateTime.UtcNow.AddYears(-1), DateTime.UtcNow);
            var lastLog = logs
                .Where(l => l.IsSuccess && l.Method.ToString().Equals(method, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(l => l.AttemptedAt)
                .FirstOrDefault();
                
            return lastLog?.AttemptedAt;
        }

        private void UpdateMethodLastUsedTime(Guid userId, string method)
        {
            // This would update the last used time in the MFA configuration table
            // For now, we'll just log it
            _logger.LogInformation("MFA method {Method} used by user {UserId} at {Time}", 
                method, userId, DateTime.UtcNow);
        }

        private string? GetTotpDeviceName(UserEntity user)
        {
            // This could be stored when the TOTP was initially configured
            // For now, return a default value
            return !string.IsNullOrEmpty(user.TotpSecret) ? "Authenticator App" : null;
        }

        #endregion

        #region IService Implementation

        /// <summary>
        /// 서비스의 상태를 확인하는 헬스 체크 메서드입니다.
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                await _userRepository.CountAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "MfaAuthenticationService health check failed");
                return false;
            }
        }

        /// <summary>
        /// 서비스 시작 시 필요한 초기화 작업을 수행합니다.
        /// </summary>
        public Task InitializeAsync()
        {
            // 이 서비스에서는 별도의 초기화 작업이 필요 없으므로 완료된 Task를 반환합니다.
            return Task.CompletedTask;
        }

        #endregion
    }
}