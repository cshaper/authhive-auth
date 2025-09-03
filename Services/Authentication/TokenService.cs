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
using System.Collections.Generic;
using System.Security.Claims;
using System;
using System.Threading.Tasks;
using System.Linq;
using ConnectedIdEntity = AuthHive.Core.Entities.Auth.ConnectedId;

namespace AuthHive.Auth.Services.Authentication
{
    /// <summary>
    /// 토큰 관련 비즈니스 로직을 총괄하는 서비스입니다. (ITokenService 구현체)
    /// ITokenProvider가 생성한 토큰 문자열을 받아 데이터베이스에 저장하고,
    /// 토큰 갱신(Refresh), 폐기(Revoke) 등 상태와 생명주기를 관리하는 역할을 담당합니다.
    /// </summary>
    public class TokenService : ITokenService
    {
        // 의존성 주입(Dependency Injection)을 통해 필요한 서비스와 리포지토리를 가져옵니다.
        private readonly ITokenProvider _tokenProvider;
        private readonly IAccessTokenRepository _accessTokenRepository;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IOAuthClientRepository _clientRepository;
        private readonly ISessionRepository _sessionRepository;
        private readonly ILogger<TokenService> _logger;

        public TokenService(
            ITokenProvider tokenProvider,
            IAccessTokenRepository accessTokenRepository,
            IRefreshTokenRepository refreshTokenRepository,
            IConnectedIdRepository connectedIdRepository,
            IOAuthClientRepository clientRepository,
            ISessionRepository sessionRepository,
            ILogger<TokenService> logger)
        {
            _tokenProvider = tokenProvider;
            _accessTokenRepository = accessTokenRepository;
            _refreshTokenRepository = refreshTokenRepository;
            _connectedIdRepository = connectedIdRepository;
            _clientRepository = clientRepository;
            _sessionRepository = sessionRepository;
            _logger = logger;
        }

        /// <summary>
        /// 서비스의 상태를 확인합니다. (Health Check)
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // DB에 정상적으로 접근 가능한지 확인
                await _accessTokenRepository.CountAsync();
                await _refreshTokenRepository.CountAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TokenService health check failed");
                return false;
            }
        }

        /// <summary>
        /// 서비스 초기화 로직 (현재는 특별한 작업 없음)
        /// </summary>
        public Task InitializeAsync() => Task.CompletedTask;

        /// <summary>
        /// 세션 엔티티를 기반으로 액세스 토큰을 생성합니다. (내부 시스템용)
        /// </summary>
        public async Task<string> GenerateTokenAsync(ConnectedIdEntity connectedId, SessionEntity session)
        {
            var additionalClaims = new List<Claim>
            {
                new Claim("session_id", session.Id.ToString()),
                new Claim("org_id", (session.OrganizationId ?? Guid.Empty).ToString())
            };

            var tokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                session.UserId,
                session.ConnectedId ?? Guid.Empty,
                additionalClaims);

            if (!tokenResult.IsSuccess || tokenResult.Data == null)
                throw new InvalidOperationException("Failed to generate token");

            return tokenResult.Data.AccessToken;
        }

        /// <summary>
        /// 새로운 세션에 대해 액세스 토큰과 리프레시 토큰을 모두 발급합니다.
        /// 로그인 성공 시 최종적으로 호출되는 메서드입니다.
        /// </summary>
        public async Task<ServiceResult<TokenIssueResponse>> IssueTokensAsync(SessionDto sessionDto)
        {
            try
            {
                var client = await _clientRepository.GetByClientIdAsync(CommonDefaults.DefaultClientId);
                if (client == null)
                {
                    return ServiceResult<TokenIssueResponse>.Failure("Default OAuth client not found");
                }

                var additionalClaims = new List<Claim>
                {
                    new Claim("session_id", sessionDto.Id.ToString()),
                    new Claim("org_id", (sessionDto.OrganizationId ?? Guid.Empty).ToString())
                };

                var accessTokenResult = await _tokenProvider.GenerateAccessTokenAsync(
                    sessionDto.UserId,
                    sessionDto.ConnectedId ?? Guid.Empty,
                    additionalClaims);

                if (!accessTokenResult.IsSuccess || accessTokenResult.Data == null)
                {
                    return ServiceResult<TokenIssueResponse>.Failure("Failed to generate access token");
                }

                var accessTokenValue = accessTokenResult.Data.AccessToken;

                var refreshTokenResult = await _tokenProvider.GenerateRefreshTokenAsync(sessionDto.UserId);
                if (!refreshTokenResult.IsSuccess || string.IsNullOrEmpty(refreshTokenResult.Data))
                {
                    return ServiceResult<TokenIssueResponse>.Failure("Failed to generate refresh token");
                }

                var accessTokenEntity = new AccessToken
                {
                    ClientId = client.Id,
                    ConnectedId = sessionDto.ConnectedId ?? Guid.Empty,
                    OrganizationId = sessionDto.OrganizationId ?? Guid.Empty,
                    SessionId = sessionDto.Id,
                    TokenValue = accessTokenValue,
                    TokenHash = HashToken(accessTokenValue),
                    TokenType = OAuthTokenType.Bearer,
                    Scopes = "[\"read\",\"write\"]",
                    IssuedAt = accessTokenResult.Data.IssuedAt,
                    ExpiresAt = accessTokenResult.Data.ExpiresAt,
                    IsActive = true,
                    GrantType = OAuthGrantType.ResourceOwnerPassword,
                    IPAddress = sessionDto.IPAddress ?? string.Empty,
                    UserAgent = sessionDto.UserAgent ?? string.Empty
                };

                var savedAccessToken = await _accessTokenRepository.AddAsync(accessTokenEntity);

                var refreshTokenEntity = new RefreshToken
                {
                    AccessTokenId = savedAccessToken.Id,
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

                await _refreshTokenRepository.AddAsync(refreshTokenEntity);

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

        /// <summary>
        /// 리프레시 토큰을 사용하여 만료된 액세스 토큰을 새로 발급받습니다.
        /// </summary>
        public async Task<ServiceResult<TokenRefreshResponse>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashToken(refreshToken);
                var storedToken = await _refreshTokenRepository.GetByTokenHashAsync(tokenHash);

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

                await RevokeRefreshTokenInternalAsync(storedToken.Id, "Token rotation");

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

        /// <summary>
        /// 액세스 토큰이 유효한지 검증하고, 토큰에 담긴 주요 정보를 반환합니다.
        /// </summary>
        public async Task<ServiceResult<TokenValidationResponse>> ValidateTokenAsync(string token)
        {
            try
            {
                var validationResult = await _tokenProvider.ValidateAccessTokenAsync(token);

                if (!validationResult.IsSuccess || validationResult.Data == null)
                {
                    return ServiceResult<TokenValidationResponse>.Failure(
                        validationResult.Message ?? "Token validation failed");
                }

                var principal = validationResult.Data;
                var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
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

        /// <summary>
        /// 리프레시 토큰을 폐기합니다. (로그아웃 시 사용)
        /// </summary>
        public async Task<ServiceResult> RevokeTokenAsync(string refreshToken)
        {
            try
            {
                var tokenHash = HashToken(refreshToken);
                var storedToken = await _refreshTokenRepository.GetByTokenHashAsync(tokenHash);

                if (storedToken != null)
                {
                    await RevokeRefreshTokenInternalAsync(storedToken.Id, "User requested revocation");
                }

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke token");
                return ServiceResult.Failure($"Failed to revoke token: {ex.Message}");
            }
        }

        /// <summary>
        /// 특정 사용자의 모든 토큰을 폐기합니다. (AuthHive 철학에 맞게 수정됨)
        /// 1. User ID로 모든 ConnectedId를 조회합니다.
        /// 2. 각 ConnectedId에 대해 모든 AccessToken을 폐기합니다.
        /// 3. User ID로 모든 RefreshToken을 폐기합니다.
        /// </summary>
        public async Task<ServiceResult<int>> RevokeAllTokensForUserAsync(Guid userId)
        {
            try
            {
                // BaseRepository의 FindAsync 메서드 활용
                var connectedIds = await _connectedIdRepository.FindAsync(c => c.UserId == userId);

                if (connectedIds == null || !connectedIds.Any())
                {
                    _logger.LogInformation("No ConnectedIds found for user {UserId}, proceeding to revoke refresh tokens only.", userId);
                }

                var totalAccessTokenCount = 0;
                if (connectedIds != null)
                {
                    foreach (var connectedId in connectedIds)
                    {
                        totalAccessTokenCount += await _accessTokenRepository.RevokeAllAccessTokensForConnectedIdAsync(
                            connectedId.Id, "User requested logout from all devices");
                    }
                }

                var refreshTokenCount = await _refreshTokenRepository.RevokeAllForUserAsync(userId);
                var totalCount = totalAccessTokenCount + refreshTokenCount;

                _logger.LogInformation("Revoked {AccessTokenCount} access tokens and {RefreshTokenCount} refresh tokens for user {UserId}",
                    totalAccessTokenCount, refreshTokenCount, userId);

                return ServiceResult<int>.Success(totalCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke all tokens for user {UserId}", userId);
                return ServiceResult<int>.Failure($"Failed to revoke tokens: {ex.Message}");
            }
        }
        #region Private Helper Methods

        /// <summary>
        /// DB에 저장된 리프레시 토큰을 폐기 상태로 업데이트하는 내부 메서드
        /// </summary>
        private async Task RevokeRefreshTokenInternalAsync(Guid tokenId, string reason)
        {
            var token = await _refreshTokenRepository.GetByIdAsync(tokenId);
            if (token != null)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedReason = reason;
                await _refreshTokenRepository.UpdateAsync(token);
            }
        }

        /// <summary>
        /// 보안을 위해 토큰을 SHA256으로 해싱하는 헬퍼 메서드
        /// </summary>
        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        #endregion
    }
}
