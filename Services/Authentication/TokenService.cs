using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Session;
using System.Security.Cryptography;
using System.Text;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Enums.Auth;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Auth;


namespace AuthHive.Auth.Services.Authentication
{
    public class TokenService : ITokenService
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IOAuthTokenRepository _tokenRepository;
        private readonly IOAuthClientRepository _clientRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly ILogger<TokenService> _logger;

        public TokenService(
            ITokenProvider tokenProvider,
            IOAuthTokenRepository tokenRepository,
            IOAuthClientRepository clientRepository,
            ISessionRepository sessionRepository,
            ILogger<TokenService> logger)
        {
            _tokenProvider = tokenProvider;
            _tokenRepository = tokenRepository;
            _clientRepository = clientRepository;
            _sessionRepository = sessionRepository;
            _logger = logger;
        }

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                await _tokenRepository.CountAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TokenService health check failed");
                return false;
            }
        }
        public Task InitializeAsync() => Task.CompletedTask;

        // Session 엔티티를 받는 버전 (기존 호환성)
        public async Task<string> GenerateTokenAsync(AuthHive.Core.Entities.Auth.ConnectedId connectedId, SessionEntity session)
        {
            var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                session.UserId,
                session.ConnectedId ?? Guid.Empty,
                new Dictionary<string, object>
                {
                    ["session_id"] = session.Id.ToString(),
                    ["org_id"] = (session.OrganizationId ?? Guid.Empty).ToString()
                });

            if (!tokenResult.IsSuccess || tokenResult.Data == null)
                throw new InvalidOperationException("Failed to generate token");

            return tokenResult.Data.AccessToken;
        }

        // SessionDto를 받는 버전
        public async Task<ServiceResult<TokenIssueResponse>> IssueTokensAsync(SessionDto sessionDto)
        {
            try
            {
                var client = await _clientRepository.GetByClientIdAsync(CommonDefaults.DefaultClientId);
                if (client == null)
                {
                    return ServiceResult<TokenIssueResponse>.Failure("Default OAuth client not found");
                }

                var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                    sessionDto.UserId,
                    sessionDto.ConnectedId ?? Guid.Empty,
                    new Dictionary<string, object>
                    {
                        ["session_id"] = sessionDto.Id.ToString(),
                        ["org_id"] = (sessionDto.OrganizationId ?? Guid.Empty).ToString()
                    });

                if (!accessTokenResult.IsSuccess || accessTokenResult.Data == null)
                {
                    return ServiceResult<TokenIssueResponse>.Failure("Failed to generate access token");
                }

                var accessTokenValue = accessTokenResult.Data.AccessToken;

                var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(sessionDto.UserId);
                if (!refreshTokenResult.IsSuccess || refreshTokenResult.Data == null)
                {
                    return ServiceResult<TokenIssueResponse>.Failure("Failed to generate refresh token");
                }

                // AccessToken 엔티티 생성
                var accessTokenEntity = new OAuthAccessToken
                {
                    ClientId = client.Id,
                    ConnectedId = sessionDto.ConnectedId ?? Guid.Empty,
                    OrganizationId = sessionDto.OrganizationId ?? Guid.Empty,
                    SessionId = sessionDto.Id,
                    TokenValue = accessTokenValue,
                    TokenHash = HashToken(accessTokenValue),
                    TokenType = OAuthTokenType.Bearer,
                    Scopes = "[\"read\",\"write\"]",
                    IssuedAt = DateTime.UtcNow,
                    ExpiresAt = accessTokenResult.Data.ExpiresAt,
                    IsActive = true,
                    GrantType = OAuthGrantType.ResourceOwnerPassword,
                    IPAddress = sessionDto.IPAddress ?? string.Empty,
                    UserAgent = sessionDto.UserAgent ?? string.Empty
                };

                await _tokenRepository.AddAsync(accessTokenEntity);

                // RefreshToken 엔티티 생성
                var refreshToken = new RefreshToken
                {
                    AccessTokenId = accessTokenEntity.Id,
                    ClientId = client.Id,
                    ConnectedId = sessionDto.ConnectedId ?? Guid.Empty,
                    OrganizationId = sessionDto.OrganizationId ?? Guid.Empty,
                    TokenValue = refreshTokenResult.Data,
                    TokenHash = HashToken(refreshTokenResult.Data),
                    IssuedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    IsActive = true,
                    Scopes = "[\"read\",\"write\"]",
                    SessionId = sessionDto.Id,
                    IPAddress = sessionDto.IPAddress ?? string.Empty,
                    UserAgent = sessionDto.UserAgent ?? string.Empty
                };

                _logger.LogWarning("RefreshToken save needs separate repository method");

                return ServiceResult<TokenIssueResponse>.Success(new TokenIssueResponse
                {
                    AccessToken = accessTokenValue,
                    RefreshToken = refreshTokenResult.Data,
                    ExpiresAt = accessTokenResult.Data.ExpiresAt
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to issue tokens");
                return ServiceResult<TokenIssueResponse>.Failure($"Failed to issue tokens: {ex.Message}");
            }
        }

        public async Task<ServiceResult<TokenRefreshResponse>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashToken(refreshToken);
                var storedToken = await _tokenRepository.GetRefreshTokenByHashAsync(tokenHash);

                if (storedToken == null)
                    return ServiceResult<TokenRefreshResponse>.Failure("Invalid refresh token");

                if (storedToken.IsRevoked)
                    return ServiceResult<TokenRefreshResponse>.Failure("Token has been revoked");

                if (storedToken.ExpiresAt < DateTime.UtcNow)
                    return ServiceResult<TokenRefreshResponse>.Failure("Token has expired");

                var sessionId = storedToken.SessionId ?? Guid.Empty;
                var session = await _sessionRepository.GetByIdAsync(sessionId);

                if (session == null || session.Status != SessionStatus.Active)
                    return ServiceResult<TokenRefreshResponse>.Failure("Session is invalid");

                // Session 엔티티를 SessionDto로 변환
                var sessionDto = new SessionDto
                {
                    Id = session.Id,
                    UserId = session.UserId,
                    ConnectedId = session.ConnectedId,
                    OrganizationId = session.OrganizationId,
                    IPAddress = session.IPAddress,
                    UserAgent = session.UserAgent,
                    ExpiresAt = session.ExpiresAt,
                    Status = session.Status,
                    SessionType = session.SessionType,
                    Level = session.Level
                };

                await _tokenRepository.RevokeRefreshTokenAsync(
                    storedToken.Id,
                    "Token rotation",
                    DateTime.UtcNow);

                var newTokens = await IssueTokensAsync(sessionDto);

                if (!newTokens.IsSuccess || newTokens.Data == null)
                    return ServiceResult<TokenRefreshResponse>.Failure("Failed to issue new tokens");

                return ServiceResult<TokenRefreshResponse>.Success(new TokenRefreshResponse
                {
                    AccessToken = newTokens.Data.AccessToken,
                    RefreshToken = newTokens.Data.RefreshToken,
                    ExpiresAt = newTokens.Data.ExpiresAt,
                    TokenType = "Bearer"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to refresh token");
                return ServiceResult<TokenRefreshResponse>.Failure($"Failed to refresh token: {ex.Message}");
            }
        }

        public async Task<ServiceResult<TokenValidationResponse>> ValidateTokenAsync(string token)
        {
            try
            {
                var validationResult = await _tokenProvider.ValidateTokenAsync(token);

                if (!validationResult.IsSuccess || validationResult.Data == null)
                {
                    return ServiceResult<TokenValidationResponse>.Failure(
                        validationResult.Message ?? "Token validation failed");
                }

                var principal = validationResult.Data;
                var userIdClaim = principal.FindFirst("user_id")?.Value;
                var connectedIdClaim = principal.FindFirst("connected_id")?.Value;
                var orgIdClaim = principal.FindFirst("org_id")?.Value;

                return ServiceResult<TokenValidationResponse>.Success(new TokenValidationResponse
                {
                    IsValid = true,
                    UserId = Guid.TryParse(userIdClaim, out var uid) ? uid : null,
                    ConnectedId = Guid.TryParse(connectedIdClaim, out var cid) ? cid : null,
                    OrganizationId = Guid.TryParse(orgIdClaim, out var oid) ? oid : null
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate token");
                return ServiceResult<TokenValidationResponse>.Failure($"Token validation failed: {ex.Message}");
            }
        }

        public async Task<ServiceResult> RevokeTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashToken(refreshToken);
                var storedToken = await _tokenRepository.GetRefreshTokenByHashAsync(tokenHash);

                if (storedToken != null)
                {
                    await _tokenRepository.RevokeRefreshTokenAsync(
                        storedToken.Id,
                        "User requested revocation",
                        DateTime.UtcNow);
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke token");
                return ServiceResult.Failure($"Failed to revoke token: {ex.Message}");
            }
        }

        public async Task<ServiceResult<int>> RevokeAllTokensForUserAsync(Guid userId)
        {
            try
            {
                var count = await _tokenRepository.RevokeAllTokensForConnectedIdAsync(
                    userId,
                    "User requested logout from all devices");

                _logger.LogInformation("Revoked {Count} tokens for user {UserId}", count, userId);
                return ServiceResult<int>.Success(count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke all tokens");
                return ServiceResult<int>.Failure($"Failed to revoke tokens: {ex.Message}");
            }
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}