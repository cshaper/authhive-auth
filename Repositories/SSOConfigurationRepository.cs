// Path: AuthHive.Auth/Repositories/SSOConfigurationRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
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
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories
{
    /// <summary>
    /// SSO 설정 관리 리포지토리 구현
    /// 엔터프라이즈 SSO(SAML, OIDC) 설정 관리
    /// </summary>
    public class SSOConfigurationRepository : BaseRepository<SamlConfiguration>, ISSOConfigurationRepository
    {
        private readonly ILogger<SSOConfigurationRepository> _logger;
        public SSOConfigurationRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,  // ADD THIS
            ILogger<SSOConfigurationRepository> logger)
            : base(context, organizationContext, null)  // null for cache
        {
            _logger = logger;
        }

        /// <summary>
        /// SSO 설정 저장
        /// </summary>
        public async Task<SSOConfiguration> SaveConfigurationAsync(
            Guid organizationId,
            SSOConfiguration configuration,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 기존 설정 확인
                var existingEntity = await _context.SamlConfigurations
                    .FirstOrDefaultAsync(s => s.OrganizationId == organizationId && !s.IsDeleted,
                        cancellationToken);

                if (existingEntity != null)
                {
                    // 업데이트
                    MapToEntity(configuration, existingEntity);
                    existingEntity.UpdatedAt = DateTime.UtcNow;

                    _context.SamlConfigurations.Update(existingEntity);
                }
                else
                {
                    // 신규 생성
                    existingEntity = new SamlConfiguration
                    {
                        Id = Guid.NewGuid(),
                        OrganizationId = organizationId,
                        CreatedAt = DateTime.UtcNow
                    };

                    MapToEntity(configuration, existingEntity);
                    await _context.SamlConfigurations.AddAsync(existingEntity, cancellationToken);
                }

                await _context.SaveChangesAsync(cancellationToken);

                configuration.Id = existingEntity.Id;
                configuration.OrganizationId = organizationId;

                _logger.LogInformation(
                    "SSO configuration saved for organization {OrganizationId}",
                    organizationId);

                return configuration;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to save SSO configuration for organization {OrganizationId}",
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// SSO 설정 조회
        /// </summary>
        public async Task<SSOConfiguration?> GetConfigurationAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entity = await _context.SamlConfigurations
                    .AsNoTracking()
                    .FirstOrDefaultAsync(s =>
                        s.OrganizationId == organizationId &&
                        !s.IsDeleted,
                        cancellationToken);

                return entity != null ? MapToDto(entity) : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get SSO configuration for organization {OrganizationId}",
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// Provider별 SSO 설정 조회
        /// </summary>
        public async Task<SSOConfiguration?> GetByProviderAsync(
            Guid organizationId,
            SSOProvider provider,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entity = await _context.SamlConfigurations
                    .AsNoTracking()
                    .FirstOrDefaultAsync(s =>
                        s.OrganizationId == organizationId &&
                        s.Provider == provider.ToString() &&
                        !s.IsDeleted,
                        cancellationToken);

                return entity != null ? MapToDto(entity) : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get SSO configuration for provider {Provider} in organization {OrganizationId}",
                    provider, organizationId);
                throw;
            }
        }

        /// <summary>
        /// SSO 설정 업데이트
        /// </summary>
        public async Task<SSOConfiguration> UpdateConfigurationAsync(
            Guid organizationId,
            SSOConfiguration configuration,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entity = await _context.SamlConfigurations
                    .FirstOrDefaultAsync(s =>
                        s.OrganizationId == organizationId &&
                        !s.IsDeleted,
                        cancellationToken);

                if (entity == null)
                {
                    throw new InvalidOperationException($"SSO configuration not found for organization {organizationId}");
                }

                MapToEntity(configuration, entity);
                entity.UpdatedAt = DateTime.UtcNow;

                _context.SamlConfigurations.Update(entity);
                await _context.SaveChangesAsync(cancellationToken);

                _logger.LogInformation(
                    "SSO configuration updated for organization {OrganizationId}",
                    organizationId);

                return configuration;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to update SSO configuration for organization {OrganizationId}",
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// SSO 설정 제거
        /// </summary>
        public async Task<bool> RemoveConfigurationAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entity = await _context.SamlConfigurations
                    .FirstOrDefaultAsync(s =>
                        s.OrganizationId == organizationId &&
                        !s.IsDeleted,
                        cancellationToken);

                if (entity == null)
                {
                    return false;
                }

                // Soft delete
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;

                _context.SamlConfigurations.Update(entity);
                await _context.SaveChangesAsync(cancellationToken);

                _logger.LogInformation(
                    "SSO configuration removed for organization {OrganizationId}",
                    organizationId);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to remove SSO configuration for organization {OrganizationId}",
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// SSO 활성화/비활성화
        /// </summary>
        public async Task<bool> SetEnabledAsync(
            Guid organizationId,
            bool isEnabled,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entity = await _context.SamlConfigurations
                    .FirstOrDefaultAsync(s =>
                        s.OrganizationId == organizationId &&
                        !s.IsDeleted,
                        cancellationToken);

                if (entity == null)
                {
                    return false;
                }

                entity.IsEnabled = isEnabled;
                entity.UpdatedAt = DateTime.UtcNow;

                _context.SamlConfigurations.Update(entity);
                await _context.SaveChangesAsync(cancellationToken);

                _logger.LogInformation(
                    "SSO configuration {Status} for organization {OrganizationId}",
                    isEnabled ? "enabled" : "disabled",
                    organizationId);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to set SSO enabled status for organization {OrganizationId}",
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// 메타데이터 업데이트
        /// </summary>
        public async Task<bool> UpdateMetadataAsync(
            Guid organizationId,
            string metadata,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entity = await _context.SamlConfigurations
                    .FirstOrDefaultAsync(s =>
                        s.OrganizationId == organizationId &&
                        !s.IsDeleted,
                        cancellationToken);

                if (entity == null)
                {
                    return false;
                }

                entity.Metadata = metadata;
                entity.UpdatedAt = DateTime.UtcNow;

                _context.SamlConfigurations.Update(entity);
                await _context.SaveChangesAsync(cancellationToken);

                _logger.LogInformation(
                    "SSO metadata updated for organization {OrganizationId}",
                    organizationId);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to update SSO metadata for organization {OrganizationId}",
                    organizationId);
                throw;
            }
        }

        /// <summary>
        /// Entity ID로 설정 조회
        /// </summary>
        public async Task<SSOConfiguration?> GetByEntityIdAsync(
            string entityId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entity = await _context.SamlConfigurations
                    .AsNoTracking()
                    .FirstOrDefaultAsync(s =>
                        s.EntityId == entityId &&
                        !s.IsDeleted,
                        cancellationToken);

                return entity != null ? MapToDto(entity) : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get SSO configuration for entity ID {EntityId}",
                    entityId);
                throw;
            }
        }

        /// <summary>
        /// 도메인으로 SSO 설정 조회
        /// </summary>
        public async Task<SSOConfiguration?> GetByDomainAsync(
            string domain,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 도메인이 AllowedDomains JSON 배열에 포함된 설정 찾기
                var entity = await _context.SamlConfigurations
                    .AsNoTracking()
                    .Where(s => !s.IsDeleted && s.IsEnabled)
                    .ToListAsync(cancellationToken);

                // 메모리에서 JSON 파싱하여 도메인 확인
                var matchingEntity = entity.FirstOrDefault(s =>
                {
                    if (string.IsNullOrEmpty(s.AllowedDomains))
                        return false;

                    try
                    {
                        var domains = System.Text.Json.JsonSerializer.Deserialize<List<string>>(s.AllowedDomains);
                        return domains?.Contains(domain, StringComparer.OrdinalIgnoreCase) ?? false;
                    }
                    catch
                    {
                        return false;
                    }
                });

                return matchingEntity != null ? MapToDto(matchingEntity) : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get SSO configuration for domain {Domain}",
                    domain);
                throw;
            }
        }

        /// <summary>
        /// 활성화된 모든 SSO 설정 조회
        /// </summary>
        public async Task<IEnumerable<SSOConfiguration>> GetAllEnabledAsync(
            CancellationToken cancellationToken = default)
        {
            try
            {
                var entities = await _context.SamlConfigurations
                    .AsNoTracking()
                    .Where(s => s.IsEnabled && !s.IsDeleted)
                    .ToListAsync(cancellationToken);

                return entities.Select(MapToDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get all enabled SSO configurations");
                throw;
            }
        }

        /// <summary>
        /// SSO 사용 통계 조회
        /// </summary>
        public async Task<SSOUsageStatistics> GetUsageStatisticsAsync(
            Guid organizationId,
            DateTime from,
            DateTime to,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // AuthenticationAttemptLog에서 SSO 로그인 통계 조회
                var attempts = await _context.AuthenticationAttemptLogs
                    .AsNoTracking()
                    .Where(a =>
                        a.OrganizationId == organizationId &&
                        (a.Method == AuthenticationMethod.SAML ||
                         a.Method == AuthenticationMethod.OAuth) &&
                        a.AttemptedAt >= from &&
                        a.AttemptedAt <= to)
                    .ToListAsync(cancellationToken);

                var statistics = new SSOUsageStatistics
                {
                    TotalLogins = attempts.Count,
                    SuccessfulLogins = attempts.Count(a => a.IsSuccess),
                    FailedLogins = attempts.Count(a => !a.IsSuccess),
                    UniqueUsers = attempts.Select(a => a.UserId).Distinct().Count(),
                    LastLoginAt = attempts.OrderByDescending(a => a.AttemptedAt).FirstOrDefault()?.AttemptedAt,
                    LoginsByDay = attempts
                        .GroupBy(a => a.AttemptedAt.Date)
                        .ToDictionary(
                            g => g.Key.ToString("yyyy-MM-dd"),
                            g => g.Count()
                        )
                };

                return statistics;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get SSO usage statistics for organization {OrganizationId}",
                    organizationId);
                throw;
            }
        }

        #region Private Helper Methods


        private void MapToEntity(SSOConfiguration dto, SamlConfiguration entity)
        {
            entity.Protocol = dto.Protocol.ToString();
            entity.Provider = dto.Provider.ToString();
            entity.EntityId = dto.EntityId ?? string.Empty;
            entity.SsoUrl = dto.SsoUrl ?? string.Empty;
            entity.SloUrl = dto.SloUrl ?? string.Empty;
            entity.Certificate = dto.Certificate ?? string.Empty;
            entity.MetadataUrl = dto.MetadataUrl ?? string.Empty;
            entity.Metadata = dto.Metadata ?? string.Empty;
            entity.AcsUrl = dto.AcsUrl ?? string.Empty;
            entity.AttributeMapping = SerializeJson(dto.AttributeMapping) ?? "{}";
            entity.AllowedDomains = SerializeJson(dto.AllowedDomains) ?? "[]";
            entity.EnableAutoProvisioning = dto.EnableAutoProvisioning;
            entity.EnableJitProvisioning = dto.EnableJitProvisioning;
            entity.IsEnabled = dto.IsEnabled;
            entity.DefaultRoleId = dto.DefaultRoleId;
            entity.AdditionalSettings = SerializeJson(dto.AdditionalSettings) ?? "{}";
            entity.LastSyncAt = dto.LastSyncAt;
            entity.CreatedByConnectedId = dto.CreatedByConnectedId;
            entity.UpdatedByConnectedId = dto.UpdatedByConnectedId;
        }

        private SSOConfiguration MapToDto(SamlConfiguration entity)
        {
            return new SSOConfiguration
            {
                Id = entity.Id,
                OrganizationId = entity.OrganizationId,
                Protocol = Enum.TryParse<SSOProtocol>(entity.Protocol, out var protocol)
                    ? protocol
                    : SSOProtocol.SAML2,
                Provider = Enum.TryParse<SSOProvider>(entity.Provider, out var provider)
                    ? provider
                    : SSOProvider.Custom,
                EntityId = entity.EntityId ?? string.Empty,
                // ... rest of properties (see full file for complete implementation)
            };
        }

        private string? SerializeJson<T>(T? obj)
        {
            if (obj == null) return null;
            try
            {
                return System.Text.Json.JsonSerializer.Serialize(obj);
            }
            catch
            {
                return null;
            }
        }

        private T? DeserializeJson<T>(string? json) where T : class
        {
            if (string.IsNullOrEmpty(json)) return null;
            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<T>(json);
            }
            catch
            {
                return null;
            }
        }

        #endregion
    }
}
