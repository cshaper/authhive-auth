// Path: AuthHive.Auth/Repositories/OAuthProviderRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Auth.Authentication;
using AuthHive.Core.Models.Auth.Authentication.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OAuth Provider 설정 관리 리포지토리 구현
    /// 외부 OAuth Provider (Google, GitHub 등) 연동 설정 관리
    /// OAuthClient 엔티티를 활용하되, 특별한 prefix로 구분
    /// </summary>
    public class OAuthProviderRepository : BaseRepository<OAuthClient>, IOAuthProviderRepository
    {
        private readonly ILogger<OAuthProviderRepository> _logger;
        private const string PROVIDER_PREFIX = "PROVIDER_"; // 외부 Provider 구분용 prefix
        
        // JSON 직렬화 옵션
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false
        };

        public OAuthProviderRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache,
            ILogger<OAuthProviderRepository> logger) 
            : base(context, organizationContext, cache)
        {
            _logger = logger;
        }

        /// <summary>
        /// OAuth Provider 설정 저장 (신규 또는 업데이트)
        /// </summary>
        public async Task<OAuthProviderConfiguration> SaveConfigurationAsync(
            Guid organizationId,
            SSOProvider provider,
            OAuthProviderConfiguration configuration,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Provider별 고유 ClientId 생성 (내부 관리용)
                var internalClientId = $"{PROVIDER_PREFIX}{organizationId}_{provider}";
                
                // 기존 설정 확인
                var existingEntity = await Query()
                    .FirstOrDefaultAsync(o => 
                        o.OrganizationId == organizationId && 
                        o.ClientId == internalClientId &&
                        !o.IsDeleted, 
                        cancellationToken);

                if (existingEntity != null)
                {
                    // 업데이트
                    MapToEntity(configuration, existingEntity, provider);
                    existingEntity.UpdatedAt = DateTime.UtcNow;
                    await UpdateAsync(existingEntity);
                }
                else
                {
                    // 신규 생성
                    existingEntity = new OAuthClient
                    {
                        Id = Guid.NewGuid(),
                        OrganizationId = organizationId,
                        ApplicationId = Guid.Empty, // Provider 설정은 특정 App과 무관
                        ClientId = internalClientId,
                        ClientName = $"{provider} OAuth Provider",
                        Description = $"External OAuth Provider Configuration for {provider}",
                        ClientType = OAuthClientType.Public, // 외부 Provider는 Public으로 표시
                        CreatedAt = DateTime.UtcNow,
                        IsActive = configuration.IsEnabled,
                        RequireClientSecret = !string.IsNullOrEmpty(configuration.ClientSecret)
                    };
                    
                    MapToEntity(configuration, existingEntity, provider);
                    await AddAsync(existingEntity);
                }

                await _context.SaveChangesAsync(cancellationToken);
                
                // 캐시 무효화
                InvalidateCache(organizationId, provider);
                
                _logger.LogInformation(
                    "OAuth provider {Provider} configuration saved for organization {OrganizationId}", 
                    provider, organizationId);
                
                return configuration;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to save OAuth provider {Provider} configuration for organization {OrganizationId}", 
                    provider, organizationId);
                throw;
            }
        }

        /// <summary>
        /// OAuth Provider 설정 조회
        /// </summary>
        public async Task<OAuthProviderConfiguration?> GetConfigurationAsync(
            Guid organizationId,
            SSOProvider provider,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 캐시 확인
                var cacheKey = GetCacheKey(organizationId, provider);
                if (_cache != null && _cache.TryGetValue(cacheKey, out OAuthProviderConfiguration? cached))
                {
                    return cached;
                }

                var internalClientId = $"{PROVIDER_PREFIX}{organizationId}_{provider}";
                
                var entity = await Query()
                    .AsNoTracking()
                    .FirstOrDefaultAsync(o => 
                        o.OrganizationId == organizationId && 
                        o.ClientId == internalClientId &&
                        !o.IsDeleted, 
                        cancellationToken);

                if (entity == null)
                    return null;

                var configuration = MapToConfiguration(entity, provider);
                
                // 캐시 저장
                if (_cache != null && configuration != null)
                {
                    _cache.Set(cacheKey, configuration, TimeSpan.FromMinutes(15));
                }

                return configuration;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to get OAuth provider {Provider} configuration for organization {OrganizationId}", 
                    provider, organizationId);
                throw;
            }
        }

        /// <summary>
        /// 조직의 모든 OAuth Provider 설정 조회
        /// </summary>
        public async Task<IEnumerable<OAuthProviderConfiguration>> GetAllConfigurationsAsync(
            Guid organizationId,
            bool includeDisabled = false,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var query = Query()
                    .AsNoTracking()
                    .Where(o => 
                        o.OrganizationId == organizationId && 
                        o.ClientId.StartsWith(PROVIDER_PREFIX) &&
                        !o.IsDeleted);

                if (!includeDisabled)
                {
                    query = query.Where(o => o.IsActive);
                }

                var entities = await query.ToListAsync(cancellationToken);
                
                var configurations = new List<OAuthProviderConfiguration>();
                foreach (var entity in entities)
                {
                    // ClientId에서 Provider 추출
                    var provider = ExtractProviderFromClientId(entity.ClientId);
                    if (provider.HasValue)
                    {
                        var config = MapToConfiguration(entity, provider.Value);
                        if (config != null)
                        {
                            configurations.Add(config);
                        }
                    }
                }

                return configurations;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to get all OAuth configurations for organization {OrganizationId}", 
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// OAuth Provider 설정 제거
        /// </summary>
        public async Task<bool> RemoveConfigurationAsync(
            Guid organizationId,
            SSOProvider provider,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var internalClientId = $"{PROVIDER_PREFIX}{organizationId}_{provider}";
                
                var entity = await Query()
                    .FirstOrDefaultAsync(o => 
                        o.OrganizationId == organizationId && 
                        o.ClientId == internalClientId &&
                        !o.IsDeleted, 
                        cancellationToken);

                if (entity == null)
                {
                    return false;
                }

                // Soft delete
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;
                entity.IsActive = false;
                
                await UpdateAsync(entity);
                await _context.SaveChangesAsync(cancellationToken);

                // 캐시 무효화
                InvalidateCache(organizationId, provider);

                _logger.LogInformation(
                    "OAuth provider {Provider} configuration removed for organization {OrganizationId}", 
                    provider, organizationId);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to remove OAuth provider {Provider} configuration for organization {OrganizationId}", 
                    provider, organizationId);
                throw;
            }
        }

        /// <summary>
        /// OAuth Provider 활성화/비활성화
        /// </summary>
        public async Task<bool> SetEnabledAsync(
            Guid organizationId,
            SSOProvider provider,
            bool isEnabled,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var internalClientId = $"{PROVIDER_PREFIX}{organizationId}_{provider}";
                
                var entity = await Query()
                    .FirstOrDefaultAsync(o => 
                        o.OrganizationId == organizationId && 
                        o.ClientId == internalClientId &&
                        !o.IsDeleted, 
                        cancellationToken);

                if (entity == null)
                {
                    return false;
                }

                entity.IsActive = isEnabled;
                entity.UpdatedAt = DateTime.UtcNow;
                
                await UpdateAsync(entity);
                await _context.SaveChangesAsync(cancellationToken);

                // 캐시 무효화
                InvalidateCache(organizationId, provider);

                _logger.LogInformation(
                    "OAuth provider {Provider} {Status} for organization {OrganizationId}", 
                    provider, isEnabled ? "enabled" : "disabled", organizationId);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to set OAuth provider {Provider} enabled status for organization {OrganizationId}", 
                    provider, organizationId);
                throw;
            }
        }

        /// <summary>
        /// 조직의 활성화된 Provider 개수 조회
        /// </summary>
        public async Task<int> GetEnabledProviderCountAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                return await Query()
                    .CountAsync(o => 
                        o.OrganizationId == organizationId && 
                        o.ClientId.StartsWith(PROVIDER_PREFIX) &&
                        o.IsActive && 
                        !o.IsDeleted, 
                        cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to get enabled provider count for organization {OrganizationId}", 
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// Client ID로 설정 조회 (OAuth 콜백 처리용)
        /// 실제 외부 Provider의 Client ID로 조회
        /// </summary>
        public async Task<OAuthProviderConfiguration?> GetByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 실제 Client ID가 저장된 Description 필드에서 검색
                var entity = await Query()
                    .AsNoTracking()
                    .FirstOrDefaultAsync(o => 
                        o.ClientId.StartsWith(PROVIDER_PREFIX) &&
                        o.Description != null && 
                        o.Description.Contains(clientId) &&
                        !o.IsDeleted, 
                        cancellationToken);

                if (entity == null)
                    return null;

                var provider = ExtractProviderFromClientId(entity.ClientId);
                return provider.HasValue ? MapToConfiguration(entity, provider.Value) : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to get OAuth configuration for client ID {ClientId}", 
                    clientId);
                throw;
            }
        }

        /// <summary>
        /// Provider별 설정 개수 조회
        /// </summary>
        public async Task<Dictionary<SSOProvider, int>> GetProviderCountsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entities = await Query()
                    .Where(o => 
                        o.OrganizationId == organizationId && 
                        o.ClientId.StartsWith(PROVIDER_PREFIX) &&
                        o.IsActive && 
                        !o.IsDeleted)
                    .Select(o => o.ClientId)
                    .ToListAsync(cancellationToken);

                var result = new Dictionary<SSOProvider, int>();
                
                foreach (var clientId in entities)
                {
                    var provider = ExtractProviderFromClientId(clientId);
                    if (provider.HasValue)
                    {
                        result[provider.Value] = result.GetValueOrDefault(provider.Value) + 1;
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, 
                    "Failed to get provider counts for organization {OrganizationId}", 
                    organizationId);
                throw;
            }
        }

        #region Private Helper Methods

        /// <summary>
        /// Configuration을 Entity로 매핑
        /// </summary>
        private void MapToEntity(OAuthProviderConfiguration config, OAuthClient entity, SSOProvider provider)
        {
            // 실제 Client ID와 Secret은 특별한 방식으로 저장
            var configData = new Dictionary<string, object>
            {
                ["provider"] = provider.ToString(),
                ["clientId"] = config.ClientId,
                ["redirectUri"] = config.RedirectUri ?? string.Empty
            };

            // ClientSecretHash에 실제 Client Secret 저장 (암호화 필요)
            entity.ClientSecretHash = config.ClientSecret; // TODO: 실제로는 암호화 필요
            
            // Scopes를 AllowedScopes에 저장
            entity.AllowedScopes = JsonSerializer.Serialize(config.Scopes, _jsonOptions);
            
            // AdditionalSettings를 AllowedGrantTypes에 저장 (필드 재활용)
            entity.AllowedGrantTypes = JsonSerializer.Serialize(config.AdditionalSettings, _jsonOptions);
            
            // RedirectUri 저장
            if (!string.IsNullOrEmpty(config.RedirectUri))
            {
                entity.RedirectUris = JsonSerializer.Serialize(new[] { config.RedirectUri }, _jsonOptions);
            }
            
            // 실제 Client ID를 Description에 저장 (검색용)
            entity.Description = $"ClientId:{config.ClientId}|Provider:{provider}";
            
            entity.IsActive = config.IsEnabled;
        }

        /// <summary>
        /// Entity를 Configuration으로 매핑
        /// </summary>
        private OAuthProviderConfiguration? MapToConfiguration(OAuthClient entity, SSOProvider provider)
        {
            try
            {
                var config = new OAuthProviderConfiguration
                {
                    Provider = provider,
                    IsEnabled = entity.IsActive
                };

                // ClientSecretHash에서 Client Secret 복원 (복호화 필요)
                config.ClientSecret = entity.ClientSecretHash; // TODO: 실제로는 복호화 필요
                
                // Description에서 실제 Client ID 추출
                if (!string.IsNullOrEmpty(entity.Description))
                {
                    var parts = entity.Description.Split('|');
                    foreach (var part in parts)
                    {
                        if (part.StartsWith("ClientId:"))
                        {
                            config.ClientId = part.Substring("ClientId:".Length);
                            break;
                        }
                    }
                }

                // Scopes 복원
                if (!string.IsNullOrEmpty(entity.AllowedScopes))
                {
                    config.Scopes = JsonSerializer.Deserialize<List<string>>(entity.AllowedScopes, _jsonOptions) 
                        ?? new List<string>();
                }

                // RedirectUri 복원
                if (!string.IsNullOrEmpty(entity.RedirectUris))
                {
                    var uris = JsonSerializer.Deserialize<List<string>>(entity.RedirectUris, _jsonOptions);
                    config.RedirectUri = uris?.FirstOrDefault();
                }

                // AdditionalSettings 복원
                if (!string.IsNullOrEmpty(entity.AllowedGrantTypes))
                {
                    config.AdditionalSettings = JsonSerializer.Deserialize<Dictionary<string, string>>(
                        entity.AllowedGrantTypes, _jsonOptions) 
                        ?? new Dictionary<string, string>();
                }

                return config;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to map entity to configuration for provider {Provider}", provider);
                return null;
            }
        }

        /// <summary>
        /// ClientId에서 Provider 추출
        /// </summary>
        private SSOProvider? ExtractProviderFromClientId(string clientId)
        {
            if (!clientId.StartsWith(PROVIDER_PREFIX))
                return null;

            var parts = clientId.Substring(PROVIDER_PREFIX.Length).Split('_');
            if (parts.Length >= 2)
            {
                if (Enum.TryParse<SSOProvider>(parts[1], out var provider))
                {
                    return provider;
                }
            }

            return null;
        }

        /// <summary>
        /// 캐시 키 생성
        /// </summary>
        private string GetCacheKey(Guid organizationId, SSOProvider provider)
        {
            return $"OAuthProvider:{organizationId}:{provider}";
        }

        /// <summary>
        /// 캐시 무효화
        /// </summary>
        private void InvalidateCache(Guid organizationId, SSOProvider provider)
        {
            if (_cache != null)
            {
                var cacheKey = GetCacheKey(organizationId, provider);
                _cache.Remove(cacheKey);
            }
        }

        #endregion
    }
}