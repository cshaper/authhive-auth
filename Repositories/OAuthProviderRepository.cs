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
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Models.Auth.Authentication.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// OAuth Provider 설정 관리 리포지토리 구현 (v17 - 리팩토링)
    /// 외부 OAuth Provider (Google, GitHub 등) 연동 설정 관리
    /// </summary>
    public class OAuthProviderRepository : BaseRepository<OAuthProvider>, IOAuthProviderRepository
    {
        private readonly ILogger<OAuthProviderRepository> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;
        
        // JSON 직렬화 옵션
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = false
        };

        public OAuthProviderRepository(
            AuthDbContext context,
            ICacheService cacheService,
            IDateTimeProvider dateTimeProvider,
            ILogger<OAuthProviderRepository> logger) 
            : base(context, cacheService)
        {
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        protected override bool IsOrganizationScopedEntity() => true;

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
                var providerName = provider.ToString();
                var existingEntity = await QueryForOrganization(organizationId)
                    .FirstOrDefaultAsync(o => o.Provider == providerName, cancellationToken);

                if (existingEntity != null)
                {
                    // 업데이트
                    MapToEntity(configuration, existingEntity);
                    existingEntity.UpdatedAt = _dateTimeProvider.UtcNow;
                    await UpdateAsync(existingEntity, cancellationToken);
                }
                else
                {
                    // 신규 생성
                    existingEntity = new OAuthProvider
                    {
                        Id = Guid.NewGuid(),
                        OrganizationId = organizationId,
                        Provider = providerName,
                        CreatedAt = _dateTimeProvider.UtcNow,
                        CreatedBy = Guid.Empty // TODO: 현재 요청을 수행하는 사용자 ID를 주입받아 설정해야 합니다.
                    };
                    
                    MapToEntity(configuration, existingEntity);
                    await AddAsync(existingEntity, cancellationToken);
                }

                await _context.SaveChangesAsync(cancellationToken);
                
                await InvalidateCacheAsync(organizationId, provider, cancellationToken);
                
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
                var cacheKey = GetCacheKey(organizationId, provider);
                if (_cacheService != null)
                {
                    var cached = await _cacheService.GetAsync<OAuthProviderConfiguration>(cacheKey, cancellationToken);
                    if (cached != null) return cached;
                }

                var providerName = provider.ToString();
                var entity = await QueryForOrganization(organizationId)
                    .AsNoTracking()
                    .FirstOrDefaultAsync(o => o.Provider == providerName, cancellationToken);

                if (entity == null) return null;

                var configuration = MapToConfiguration(entity);
                
                if (_cacheService != null && configuration != null)
                {
                    await _cacheService.SetAsync(cacheKey, configuration, TimeSpan.FromMinutes(15), cancellationToken);
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
                var query = QueryForOrganization(organizationId).AsNoTracking();

                if (!includeDisabled)
                {
                    query = query.Where(o => o.IsEnabled);
                }

                var entities = await query.ToListAsync(cancellationToken);
                
                return entities.Select(MapToConfiguration)
                               .Where(config => config != null)
                               .ToList()!;
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
                var providerName = provider.ToString();
                var entity = await QueryForOrganization(organizationId)
                    .FirstOrDefaultAsync(o => o.Provider == providerName, cancellationToken);

                if (entity == null) return false;

                await DeleteAsync(entity, cancellationToken);
                await _context.SaveChangesAsync(cancellationToken);

                await InvalidateCacheAsync(organizationId, provider, cancellationToken);

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

        public async Task<bool> SetEnabledAsync(Guid organizationId, SSOProvider provider, bool isEnabled, CancellationToken cancellationToken = default)
        {
            var providerName = provider.ToString();
            var entity = await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(o => o.Provider == providerName, cancellationToken);

            if (entity == null) return false;

            entity.IsEnabled = isEnabled;
            entity.UpdatedAt = _dateTimeProvider.UtcNow;
            
            await UpdateAsync(entity, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
            
            await InvalidateCacheAsync(organizationId, provider, cancellationToken);
            
            return true;
        }

        public async Task<int> GetEnabledProviderCountAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .CountAsync(o => o.IsEnabled, cancellationToken);
        }
        
        public async Task<OAuthProviderConfiguration?> GetByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
        {
             var entity = await Query()
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.ClientId == clientId && p.IsEnabled, cancellationToken);

             return entity != null ? MapToConfiguration(entity) : null;
        }

        public async Task<Dictionary<SSOProvider, int>> GetProviderCountsAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            var counts = await QueryForOrganization(organizationId)
                .GroupBy(p => p.Provider)
                .Select(g => new { ProviderName = g.Key, Count = g.Count() })
                .ToListAsync(cancellationToken);
            
            var result = new Dictionary<SSOProvider, int>();
            foreach(var item in counts)
            {
                if(Enum.TryParse<SSOProvider>(item.ProviderName, true, out var providerEnum))
                {
                    result[providerEnum] = item.Count;
                }
            }
            return result;
        }

        public async Task<OAuthProvider?> GetByProviderNameAsync(Guid organizationId, string providerName, CancellationToken cancellationToken = default)
        {
            return await QueryForOrganization(organizationId)
                .FirstOrDefaultAsync(o => o.Provider.Equals(providerName, StringComparison.OrdinalIgnoreCase), cancellationToken);
        }

        #region Private Helper Methods

        private void MapToEntity(OAuthProviderConfiguration config, OAuthProvider entity)
        {
            entity.ClientId = config.ClientId;
            entity.ClientSecretEncrypted = config.ClientSecret ?? string.Empty; // TODO: Encrypt the secret before saving
            entity.IsEnabled = config.IsEnabled;
            entity.Scopes = string.Join(" ", config.Scopes);

            // AdditionalSettings에서 Endpoint 정보 추출
            config.AdditionalSettings.TryGetValue("AuthorizationEndpoint", out var authEndpoint);
            config.AdditionalSettings.TryGetValue("TokenEndpoint", out var tokenEndpoint);
            config.AdditionalSettings.TryGetValue("UserInfoEndpoint", out var userInfoEndpoint);

            entity.AuthorizationEndpoint = authEndpoint ?? string.Empty;
            entity.TokenEndpoint = tokenEndpoint ?? string.Empty;
            entity.UserInfoEndpoint = userInfoEndpoint ?? string.Empty;
        }

        private OAuthProviderConfiguration? MapToConfiguration(OAuthProvider entity)
        {
            if (!Enum.TryParse<SSOProvider>(entity.Provider, true, out var providerEnum))
            {
                _logger.LogWarning("Could not parse SSOProvider from string: {Provider}", entity.Provider);
                return null;
            }

            return new OAuthProviderConfiguration
            {
                Provider = providerEnum,
                IsEnabled = entity.IsEnabled,
                ClientId = entity.ClientId,
                ClientSecret = entity.ClientSecretEncrypted, // TODO: Decrypt the secret before returning
                Scopes = entity.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList(),
                AdditionalSettings = new Dictionary<string, string>
                {
                    { "AuthorizationEndpoint", entity.AuthorizationEndpoint },
                    { "TokenEndpoint", entity.TokenEndpoint },
                    { "UserInfoEndpoint", entity.UserInfoEndpoint }
                }
            };
        }

        private async Task InvalidateCacheAsync(Guid organizationId, SSOProvider provider, CancellationToken cancellationToken = default)
        {
            if (_cacheService != null)
            {
                var cacheKey = GetCacheKey(organizationId, provider);
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
            }
        }

        private string GetCacheKey(Guid organizationId, SSOProvider provider)
        {
            return $"OAuthProvider:{organizationId}:{provider}";
        }

        #endregion
    }
}

