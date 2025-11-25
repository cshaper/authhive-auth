// // Providers/Authentication/MagicLinkAuthenticationProvider.cs
// using System;
// using System.Collections.Generic;
// using System.Linq;
// using System.Security.Claims;
// using System.Security.Cryptography;
// using System.Threading.Tasks;
// using AuthHive.Auth.Data.Context;
// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Enums.Auth;
// using AuthHive.Core.Enums.Infra.UserExperience;
// using AuthHive.Core.Interfaces.Auth.Provider;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Auth.Service;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra.Cache;
// using AuthHive.Core.Interfaces.Infra.UserExperience;
// using AuthHive.Core.Models.Auth.Authentication;
// using AuthHive.Core.Models.Auth.Authentication.Requests;
// using AuthHive.Core.Models.Auth.ConnectedId.Requests;
// using AuthHive.Core.Models.Common;
// using AuthHive.Core.Models.External;
// using Microsoft.EntityFrameworkCore;
// using Microsoft.Extensions.Caching.Distributed;
// using Microsoft.Extensions.Configuration;
// using Microsoft.Extensions.Logging;
// using static AuthHive.Core.Enums.Auth.SessionEnums;

// namespace AuthHive.Auth.Providers.Authentication
// {
//     /// <summary>
//     /// Magic Link 인증 제공자 - AuthHive v15
//     /// 이메일로 전송된 일회용 링크를 통한 비밀번호 없는 인증
//     /// </summary>
//     public class MagicLinkAuthenticationProvider : BaseAuthenticationProvider
//     {
//         private readonly ITokenProvider _tokenProvider;
//         private readonly ICacheService _cacheService;
//         private readonly IConfiguration _configuration;
//         private readonly IEmailService _emailService;
        
//         // Magic Link 설정
//         private const string MAGIC_LINK_PREFIX = "magic:";
//         private const int MAGIC_LINK_LENGTH = 32;
//         private readonly TimeSpan MAGIC_LINK_EXPIRY = TimeSpan.FromMinutes(15);
        
//         public override string ProviderName => "MagicLink";
//         public override string ProviderType => "Internal";

//         public MagicLinkAuthenticationProvider(
//             ILogger<MagicLinkAuthenticationProvider> logger,
//             IDistributedCache cache,
//             IAuthenticationAttemptLogRepository attemptLogRepository,
//             ISessionService sessionService,
//             IConnectedIdService connectedIdService,
//             AuthDbContext context,
//             ITokenProvider tokenProvider,
//             ICacheService cacheService,
//             IConfiguration configuration,
//             IEmailService emailService)
//             : base(logger, cache, attemptLogRepository, sessionService, connectedIdService, context)
//         {
//             _tokenProvider = tokenProvider;
//             _cacheService = cacheService;
//             _configuration = configuration;
//             _emailService = emailService;
//         }

//         protected override async Task<ServiceResult<AuthenticationOutcome>> PerformAuthenticationAsync(
//             AuthenticationRequest request)
//         {
//             try
//             {
//                 // MagicLink 요청 처리 - Email 필드 사용
//                 if (!string.IsNullOrEmpty(request.Email) && string.IsNullOrEmpty(request.MagicLinkToken))
//                 {
//                     return await SendMagicLinkAsync(request);
//                 }

//                 // MagicLink 검증 처리
//                 if (!string.IsNullOrEmpty(request.MagicLinkToken))
//                 {
//                     return await VerifyMagicLinkAsync(request);
//                 }

//                 return ServiceResult<AuthenticationOutcome>.Failure("Email or magic link token is required");
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Magic link authentication failed");
//                 return ServiceResult<AuthenticationOutcome>.Failure("Authentication failed");
//             }
//         }

//         private async Task<ServiceResult<AuthenticationOutcome>> SendMagicLinkAsync(
//             AuthenticationRequest request)
//         {
//             // 이메일 검증
//             if (string.IsNullOrEmpty(request.Email) || !IsValidEmail(request.Email))
//             {
//                 return ServiceResult<AuthenticationOutcome>.Failure("Valid email address is required");
//             }
            
//             // 이메일로 사용자 찾기
//             var userProfile = await _context.UserProfiles
//                 .Include(up => up.User)
//                 .FirstOrDefaultAsync(up => up.User.Email == request.Email);

//             if (userProfile == null)
//             {
//                 // 보안상 사용자 존재 여부를 노출하지 않음
//                 _logger.LogWarning("Magic link requested for non-existent email: {Email}", request.Email);
                
//                 // 가짜 성공 응답 (이메일 열거 공격 방지)
//                 return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
//                 {
//                     Success = false,
//                     RequiresMfa = false,
//                     Message = "If the email exists, a magic link has been sent"
//                 });
//             }

//             // Magic Link 토큰 생성
//             var magicToken = GenerateSecureToken();
//             var cacheKey = $"{MAGIC_LINK_PREFIX}{magicToken}";
            
//             // 토큰 정보를 캐시에 저장
//             var tokenData = new MagicLinkData
//             {
//                 UserId = userProfile.User.Id,
//                 Email = request.Email,
//                 OrganizationId = request.OrganizationId,
//                 ApplicationId = request.ApplicationId,
//                 IpAddress = request.IpAddress,
//                 UserAgent = request.UserAgent,
//                 CreatedAt = DateTime.UtcNow,
//                 ExpiresAt = DateTime.UtcNow.Add(MAGIC_LINK_EXPIRY)
//             };

//             await _cacheService.SetAsync(cacheKey, tokenData, MAGIC_LINK_EXPIRY);

//             // Magic Link URL 생성
//             var baseUrl = _configuration["Application:BaseUrl"] ?? "https://app.authhive.com";
//             var magicLinkUrl = $"{baseUrl}/auth/magic-link/verify?token={magicToken}";
            
//             if (request.OrganizationId.HasValue)
//             {
//                 magicLinkUrl += $"&org={request.OrganizationId.Value}";
//             }

//             // 이메일 전송 - 템플릿 기반 또는 일반 이메일 사용
//             var emailVariables = new Dictionary<string, object>
//             {
//                 { "userName", userProfile.User.Username ?? "User" },
//                 { "magicLink", magicLinkUrl },
//                 { "expiryMinutes", MAGIC_LINK_EXPIRY.TotalMinutes },
//                 { "organizationName", "AuthHive" }
//             };

//             ServiceResult<string> emailResult;
            
//             // 템플릿 기반 이메일 시도
//             var magicLinkTemplateId = _configuration["MagicLink:EmailTemplateId"];
//             if (!string.IsNullOrEmpty(magicLinkTemplateId))
//             {
//                 emailResult = await _emailService.SendTemplateEmailAsync(
//                     request.Email,
//                     magicLinkTemplateId,
//                     emailVariables,
//                     request.OrganizationId);
//             }
//             else
//             {
//                 // 일반 이메일로 발송
//                 var emailMessage = new EmailMessageDto
//                 {
//                     To = request.Email,
//                     Subject = "Your Magic Link - AuthHive",
//                     Body = $@"
//                         <h2>Hello {userProfile.User.Username ?? "User"},</h2>
//                         <p>Click the link below to sign in to your account:</p>
//                         <p><a href='{magicLinkUrl}' style='padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; display: inline-block;'>Sign In</a></p>
//                         <p>This link will expire in {MAGIC_LINK_EXPIRY.TotalMinutes} minutes.</p>
//                         <p>If you didn't request this, please ignore this email.</p>
//                         <hr>
//                         <p><small>AuthHive - Secure Authentication Platform</small></p>
//                     ",
//                     IsHtml = true,
//                     Priority = EmailPriority.High
//                 };
                
//                 if (request.OrganizationId.HasValue)
//                 {
//                     emailResult = await _emailService.SendOrganizationEmailAsync(
//                         request.OrganizationId.Value,
//                         emailMessage);
//                 }
//                 else
//                 {
//                     emailResult = await _emailService.SendEmailAsync(emailMessage);
//                 }
//             }

//             if (!emailResult.IsSuccess)
//             {
//                 _logger.LogError("Failed to send magic link email to {Email}", request.Email);
//                 return ServiceResult<AuthenticationOutcome>.Failure("Failed to send magic link email");
//             }

//             // 부분 성공 응답 (이메일 전송됨, 검증 대기)
//             return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
//             {
//                 Success = false,
//                 RequiresMfa = false,
//                 Message = "Magic link has been sent to your email"
//             });
//         }
        
//         private bool IsValidEmail(string email)
//         {
//             try
//             {
//                 var addr = new System.Net.Mail.MailAddress(email);
//                 return addr.Address == email;
//             }
//             catch
//             {
//                 return false;
//             }
//         }

//         private async Task<ServiceResult<AuthenticationOutcome>> VerifyMagicLinkAsync(
//             AuthenticationRequest request, CancellationToken cancellationToken = default)
//         {
//             if (string.IsNullOrEmpty(request.MagicLinkToken))
//             {
//                 return ServiceResult<AuthenticationOutcome>.Failure("Magic link token is required");
//             }

//             var cacheKey = $"{MAGIC_LINK_PREFIX}{request.MagicLinkToken}";
            
//             // 캐시에서 토큰 데이터 조회
//             var tokenData = await _cacheService.GetAsync<MagicLinkData>(cacheKey);
            
//             if (tokenData == null)
//             {
//                 _logger.LogWarning("Invalid or expired magic link token: {Token}", request.MagicLinkToken);
//                 return ServiceResult<AuthenticationOutcome>.Failure("Invalid or expired magic link");
//             }

//             // IP 주소 검증 (선택적 - 보안 강화)
//             if (_configuration.GetValue<bool>("MagicLink:ValidateIpAddress") && 
//                 !string.IsNullOrEmpty(tokenData.IpAddress) && 
//                 tokenData.IpAddress != request.IpAddress)
//             {
//                 _logger.LogWarning("IP address mismatch for magic link token. Expected: {Expected}, Actual: {Actual}",
//                     tokenData.IpAddress, request.IpAddress);
                
//                 // 의심스러운 활동으로 기록
//                 await LogSuspiciousActivity(tokenData.UserId, "IP address mismatch during magic link verification");
//             }

//             // 토큰 만료 확인
//             if (DateTime.UtcNow > tokenData.ExpiresAt)
//             {
//                 await _cacheService.RemoveAsync(cacheKey);
//                 return ServiceResult<AuthenticationOutcome>.Failure("Magic link has expired");
//             }

//             // 사용한 토큰 즉시 삭제 (일회용)
//             await _cacheService.RemoveAsync(cacheKey);

//             // 사용자 조회
//             var user = await _context.Users.FindAsync(tokenData.UserId);
//             if (user == null)
//             {
//                 return ServiceResult<AuthenticationOutcome>.Failure("User not found");
//             }

//             // 이메일 인증 처리
//             if (!user.EmailVerified)
//             {
//                 user.EmailVerified = true;
//                 user.EmailVerifiedAt = DateTime.UtcNow;
//                 await _context.SaveChangesAsync();
//             }

//             // ConnectedId 처리
//             Guid connectedIdValue;
//             Guid organizationId;
            
//             if (tokenData.OrganizationId.HasValue)
//             {
//                 organizationId = tokenData.OrganizationId.Value;
                
//                 // 먼저 기존 ConnectedId 조회
//                 var existingConnectedIds = await _connectedIdService.GetByUserAsync(user.Id, cancellationToken);
//                 if (existingConnectedIds.IsSuccess && existingConnectedIds.Data != null)
//                 {
//                     var existingConnectedId = existingConnectedIds.Data
//                         .FirstOrDefault(c => c.OrganizationId == organizationId);
                    
//                     if (existingConnectedId != null)
//                     {
//                         connectedIdValue = existingConnectedId.Id;
//                     }
//                     else
//                     {
//                         // ConnectedId가 없으면 새로 생성
//                         var createRequest = new CreateConnectedIdRequest
//                         {
//                             UserId = user.Id,
//                             OrganizationId = organizationId,
//                             ApplicationId = tokenData.ApplicationId
//                         };
                        
//                         var connectedIdResult = await _connectedIdService.CreateAsync(createRequest, cancellationToken);
//                         if (connectedIdResult.IsSuccess && connectedIdResult.Data != null)
//                         {
//                             connectedIdValue = connectedIdResult.Data.Id;
//                         }
//                         else
//                         {
//                             return ServiceResult<AuthenticationOutcome>.Failure("Failed to create ConnectedId");
//                         }
//                     }
//                 }
//                 else
//                 {
//                     // ConnectedId 조회 실패 시 새로 생성
//                     var createRequest = new CreateConnectedIdRequest
//                     {
//                         UserId = user.Id,
//                         OrganizationId = organizationId,
//                         ApplicationId = tokenData.ApplicationId
//                     };
                    
//                     var connectedIdResult = await _connectedIdService.CreateAsync(createRequest, cancellationToken);
//                     if (connectedIdResult.IsSuccess && connectedIdResult.Data != null)
//                     {
//                         connectedIdValue = connectedIdResult.Data.Id;
//                     }
//                     else
//                     {
//                         return ServiceResult<AuthenticationOutcome>.Failure("Failed to create ConnectedId");
//                     }
//                 }
//             }
//             else
//             {
//                 // 조직이 없는 경우 글로벌/기본 조직 사용
//                 organizationId = _configuration.GetValue<Guid>("Auth:GlobalOrganizationId", 
//                     Guid.Parse("00000000-0000-0000-0000-000000000001"));
                
//                 // 글로벌 조직용 ConnectedId 생성 또는 조회
//                 var existingConnectedIds = await _connectedIdService.GetByUserAsync(user.Id, cancellationToken);
//                 if (existingConnectedIds.IsSuccess && existingConnectedIds.Data != null)
//                 {
//                     var existingConnectedId = existingConnectedIds.Data
//                         .FirstOrDefault(c => c.OrganizationId == organizationId);
                    
//                     if (existingConnectedId != null)
//                     {
//                         connectedIdValue = existingConnectedId.Id;
//                     }
//                     else
//                     {
//                         var createRequest = new CreateConnectedIdRequest
//                         {
//                             UserId = user.Id,
//                             OrganizationId = organizationId
//                         };
                        
//                         var connectedIdResult = await _connectedIdService.CreateAsync(createRequest, cancellationToken);
//                         if (connectedIdResult.IsSuccess && connectedIdResult.Data != null)
//                         {
//                             connectedIdValue = connectedIdResult.Data.Id;
//                         }
//                         else
//                         {
//                             return ServiceResult<AuthenticationOutcome>.Failure("Failed to create global ConnectedId");
//                         }
//                     }
//                 }
//                 else
//                 {
//                     var createRequest = new CreateConnectedIdRequest
//                     {
//                         UserId = user.Id,
//                         OrganizationId = organizationId
//                     };
                    
//                     var connectedIdResult = await _connectedIdService.CreateAsync(createRequest, cancellationToken);
//                     if (connectedIdResult.IsSuccess && connectedIdResult.Data != null)
//                     {
//                         connectedIdValue = connectedIdResult.Data.Id;
//                     }
//                     else
//                     {
//                         return ServiceResult<AuthenticationOutcome>.Failure("Failed to create global ConnectedId");
//                     }
//                 }
//             }

//             // 세션 생성
//             var sessionResult = await _sessionService.CreateSessionAsync(
//                 new Core.Models.Auth.Session.Requests.CreateSessionRequest
//                 {
//                     ConnectedId = connectedIdValue,
//                     OrganizationId = organizationId,
//                     SessionType = SessionType.Web,
//                     IpAddress = request.IpAddress,
//                     UserAgent = request.UserAgent,
//                     DeviceInfo = request.DeviceInfo?.DeviceId,
//                     OperatingSystem = request.DeviceInfo?.OperatingSystem,
//                     Browser = request.DeviceInfo?.Browser,
//                     Location = request.DeviceInfo?.Location,
//                     ExpiresAt = DateTime.UtcNow.AddHours(24),
//                     InitialStatus = SessionStatus.Active,
//                     Metadata = System.Text.Json.JsonSerializer.Serialize(new
//                     {
//                         AuthenticationMethod = AuthenticationMethod.MagicLink.ToString(),
//                         Provider = "MagicLink",
//                         ApplicationId = tokenData.ApplicationId
//                     })
//                 });

//             if (!sessionResult.IsSuccess || sessionResult.Data == null)
//             {
//                 return ServiceResult<AuthenticationOutcome>.Failure("Session creation failed");
//             }

//             // 토큰 생성
//             var claims = new List<Claim>
//             {
//                 new Claim("user_id", user.Id.ToString()),
//                 new Claim("email", user.Email ?? ""),
//                 new Claim("auth_method", "magic_link"),
//                 new Claim("session_id", sessionResult.Data?.SessionId.ToString() ?? "")
//             };

//             claims.Add(new Claim("connected_id", connectedIdValue.ToString()));
//             claims.Add(new Claim("org_id", organizationId.ToString()));

//             var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(
//                 user.Id,
//                 connectedIdValue,
//                 claims);

//             if (!accessTokenResult.IsSuccess || accessTokenResult.Data == null)
//             {
//                 return ServiceResult<AuthenticationOutcome>.Failure("Token generation failed");
//             }

//             var refreshToken = await _tokenProvider.GenerateRefreshTokenAsync(user.Id);

//             // 마지막 로그인 시간 업데이트
//             user.LastLoginAt = DateTime.UtcNow;
//             await _context.SaveChangesAsync();

//             return ServiceResult<AuthenticationOutcome>.Success(new AuthenticationOutcome
//             {
//                 Success = true,
//                 UserId = user.Id,
//                 ConnectedId = connectedIdValue,
//                 SessionId = sessionResult.Data?.SessionId ?? Guid.Empty,
//                 AccessToken = accessTokenResult.Data.AccessToken,
//                 RefreshToken = refreshToken.Data,
//                 ExpiresAt = accessTokenResult.Data.ExpiresAt,
//                 OrganizationId = organizationId,
//                 ApplicationId = tokenData.ApplicationId,
//                 AuthenticationMethod = AuthenticationMethod.MagicLink.ToString()
//             });
//         }

//         private string GenerateSecureToken()
//         {
//             var randomBytes = new byte[MAGIC_LINK_LENGTH];
//             using (var rng = RandomNumberGenerator.Create())
//             {
//                 rng.GetBytes(randomBytes);
//             }
            
//             // URL-safe base64 인코딩
//             return Convert.ToBase64String(randomBytes)
//                 .Replace("+", "-")
//                 .Replace("/", "_")
//                 .Replace("=", "");
//         }

//         private async Task LogSuspiciousActivity(Guid userId, string reason)
//         {
//             // TODO: 의심스러운 활동 로깅
//             await Task.CompletedTask;
//             _logger.LogWarning("Suspicious activity for user {UserId}: {Reason}", userId, reason);
//         }

//         protected override Task<UserProfile?> FindUserProfileAsync(AuthenticationRequest request)
//         {
//             // MagicLink는 이메일 기반이므로 이 메서드는 사용하지 않음
//             return Task.FromResult<UserProfile?>(null);
//         }

//         public override async Task<ServiceResult<bool>> ValidateAsync(string token)
//         {
//             return await _tokenProvider.ValidateAccessTokenAsync(token)
//                 .ContinueWith(t => ServiceResult<bool>.Success(t.Result.IsSuccess));
//         }

//         public override async Task<ServiceResult> RevokeAsync(string token)
//         {
//             var session = await _context.Sessions
//                 .FirstOrDefaultAsync(s => s.TokenId == token && s.Status == SessionStatus.Active);

//             if (session != null)
//             {
//                 session.Status = SessionStatus.LoggedOut;
//                 session.EndedAt = DateTime.UtcNow;
//                 session.EndReason = SessionEndReason.UserLogout;
//                 await _context.SaveChangesAsync();

//                 await _cache.RemoveAsync($"session:{session.Id}");
//             }

//             return ServiceResult.Success();
//         }

//         public override async Task<bool> IsEnabledAsync()
//         {
//             var isEnabled = _configuration.GetValue<bool>("MagicLink:Enabled");
//             var hasEmailService = _emailService != null;
            
//             return await Task.FromResult(isEnabled && hasEmailService);
//         }
//     }

//     // Magic Link 데이터 모델
//     internal class MagicLinkData
//     {
//         public Guid UserId { get; set; }
//         public string Email { get; set; } = string.Empty;
//         public Guid? OrganizationId { get; set; }
//         public Guid? ApplicationId { get; set; }
//         public string? IpAddress { get; set; }
//         public string? UserAgent { get; set; }
//         public DateTime CreatedAt { get; set; }
//         public DateTime ExpiresAt { get; set; }
//     }
// }