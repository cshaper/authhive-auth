// AuthHive.Auth/Services/External/LdapService.cs
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.External;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Audit; // Error CS0103 Fix: Added missing using
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Enums.Core;

namespace AuthHive.Auth.Services.External
{
    public class LdapService : ILdapService
    {
        #region IExternalService Implementation
        // Error CS0535 Fix: Implemented all required members from IExternalService
        public string ServiceName => "LDAP";
        public string Provider => "Novell.Directory.Ldap";
        public string? ApiVersion => "v3";

        // Note: These resilience properties should be backed by a real configuration system.
        public RetryPolicy RetryPolicy { get; set; } = new();
        public int TimeoutSeconds { get; set; } = 30;
        public bool EnableCircuitBreaker { get; set; } = false;
        public IExternalService? FallbackService { get; set; }

        public event EventHandler<ExternalServiceCalledEventArgs>? ServiceCalled;
        public event EventHandler<ExternalServiceFailedEventArgs>? ServiceFailed;
        public event EventHandler<ExternalServiceRecoveredEventArgs>? ServiceRecovered;

        #endregion

        private static readonly Dictionary<Guid, LdapConfigurationDto> _ldapConfigurations = new();

        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<LdapService> _logger;

        public LdapService(
            ICacheService cacheService,
            IAuditService auditService,
            IDateTimeProvider dateTimeProvider,
            ILogger<LdapService> logger)
        {
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("LdapService initialized at {Time}", _dateTimeProvider.UtcNow);
            return Task.CompletedTask;
        }

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            return await _cacheService.IsHealthyAsync(cancellationToken);
        }


        #region Connection Management

        public async Task<ServiceResult> ConfigureLdapAsync(Guid organizationId, LdapConfigurationDto config)
        {
            _ldapConfigurations[organizationId] = config;
            var cacheKey = GetOrgConfigCacheKey(organizationId);
            await _cacheService.RemoveAsync(cacheKey);

            await _auditService.LogAsync(new AuditLog
            {
                Action = "LDAP_CONFIG_UPDATED",
                ActionType = AuditActionType.Update,
                TargetOrganizationId = organizationId,
                Success = true,
                Timestamp = _dateTimeProvider.UtcNow,
                Severity = AuditEventSeverity.Info,
                Metadata = $"LDAP configuration updated for server: {config.Server}"
            });

            return ServiceResult.Success("LDAP configuration saved successfully.");
        }

        public async Task<ServiceResult<bool>> TestConnectionAsync(LdapConfigurationDto config)
        {
            try
            {
                using var connection = await CreateAndBindConnectionAsync(config);
                return ServiceResult<bool>.Success(true, "LDAP connection successful.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LDAP connection test failed for server {Server}", config.Server);
                return ServiceResult<bool>.Failure($"Connection failed: {ex.Message}");
            }
        }

        public async Task<ServiceHealthStatus> CheckHealthAsync()
        {
            var status = new ServiceHealthStatus { CheckedAt = _dateTimeProvider.UtcNow };
            var isCacheHealthy = await _cacheService.IsHealthyAsync();
            if (!isCacheHealthy)
            {
                status.IsHealthy = false;
                status.Status = "Dependency Unhealthy";
                status.ErrorMessage = "Cache service is not responding.";
                return status;
            }

            status.IsHealthy = true;
            status.Status = "Healthy";
            return status;
        }

        public async Task<ServiceResult<ServiceHealthStatus>> GetConnectionStatusAsync(Guid organizationId)
        {
            var stopwatch = Stopwatch.StartNew();
            var status = new ServiceHealthStatus { CheckedAt = _dateTimeProvider.UtcNow };

            var configResult = await GetConfigurationAsync(organizationId);
            if (!configResult.IsSuccess || configResult.Data == null)
            {
                status.IsHealthy = false;
                status.Status = "Configuration Not Found";
                status.ErrorMessage = configResult.ErrorMessage;
                stopwatch.Stop();
                status.ResponseTimeMs = stopwatch.ElapsedMilliseconds;
                return ServiceResult<ServiceHealthStatus>.Success(status);
            }

            var testResult = await TestConnectionAsync(configResult.Data);
            stopwatch.Stop();

            status.IsHealthy = testResult.IsSuccess;
            status.Status = testResult.IsSuccess ? "Healthy" : "Unhealthy";
            status.ResponseTimeMs = stopwatch.ElapsedMilliseconds;
            status.ErrorMessage = testResult.ErrorMessage;

            return ServiceResult<ServiceHealthStatus>.Success(status);
        }

        #endregion

        #region Authentication

        public async Task<ServiceResult<LdapAuthResultDto>> AuthenticateAsync(string username, string password, Guid organizationId)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return ServiceResult<LdapAuthResultDto>.Failure("Password cannot be empty.", "INVALID_CREDENTIALS");
            }

            var configResult = await GetConfigurationAsync(organizationId);
            if (!configResult.IsSuccess || configResult.Data == null)
            {
                return ServiceResult<LdapAuthResultDto>.Failure(configResult.ErrorMessage ?? "LDAP not configured.", "LDAP_NOT_CONFIGURED");
            }

            var config = configResult.Data;
            LdapConnection? serviceConnection = null;
            LdapConnection? userConnection = null;

            try
            {
                // Error CS1061 Fix: Replaced 'Search' with 'SearchAsync' and correctly handle the 'ILdapSearchResults' result.
                serviceConnection = await CreateAndBindConnectionAsync(config);
                var searchFilter = string.Format(config.UserSearchFilter, username);

                var searchResults = await serviceConnection.SearchAsync(
                    config.UserSearchBase,
                    LdapConnection.ScopeSub,
                    searchFilter,
                    null,
                    false).ConfigureAwait(false);

                // Error CS1061 Fix: Manually enumerate the async results instead of using FirstOrDefaultAsync.
                LdapEntry? userEntry = null;
                await foreach (var entry in searchResults)
                {
                    userEntry = entry;
                    break;
                }

                if (userEntry == null)
                {
                    await LogAuthenticationAttempt(organizationId, username, false, "User not found");
                    return ServiceResult<LdapAuthResultDto>.Failure("Invalid username or password.", "AUTH_FAILED");
                }

                // Now, attempt to bind as the user
                var userConnOptions = new LdapConnectionOptions();
                if (config.UseSsl)
                {
                    userConnOptions.UseSsl();
                    userConnOptions.ConfigureRemoteCertificateValidationCallback((_, _, _, _) => true);
                }
                userConnection = new LdapConnection(userConnOptions);
                await userConnection.ConnectAsync(config.Server, config.Port);
                await userConnection.BindAsync(userEntry.Dn, password);

                var ldapUser = MapEntryToUserDto(userEntry, config.AttributeMappings);
                var groups = GetUserGroupNames(userEntry);

                await LogAuthenticationAttempt(organizationId, username, true, "Authentication successful");

                return ServiceResult<LdapAuthResultDto>.Success(new LdapAuthResultDto
                {
                    Success = true,
                    User = ldapUser,
                    Groups = groups,
                    AuthenticatedAt = _dateTimeProvider.UtcNow
                });
            }
            catch (LdapException ex) when (ex.ResultCode == LdapException.InvalidCredentials)
            {
                await LogAuthenticationAttempt(organizationId, username, false, "Invalid credentials");
                return ServiceResult<LdapAuthResultDto>.Failure("Invalid username or password.", "AUTH_FAILED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LDAP authentication error for user {Username} in organization {OrgId}", username, organizationId);
                await LogAuthenticationAttempt(organizationId, username, false, $"System error: {ex.Message}");
                return ServiceResult<LdapAuthResultDto>.Failure($"An unexpected error occurred during authentication: {ex.Message}", "SYSTEM_ERROR");
            }
            finally
            {
                serviceConnection?.Disconnect();
                userConnection?.Disconnect();
            }
        }

        public Task<ServiceResult<LdapAuthResultDto>> AuthenticateWithMfaAsync(string username, string password, string mfaCode, Guid organizationId)
        {
            throw new NotImplementedException("MFA is handled by a separate service after successful LDAP authentication.");
        }

        #endregion

        // ... Other regions like User/Group search, Sync, etc. would go here ...

        #region Helper Methods

        private async Task<ServiceResult<LdapConfigurationDto>> GetConfigurationAsync(Guid organizationId)
        {
            if (organizationId == Guid.Empty)
                return ServiceResult<LdapConfigurationDto>.Failure("Organization ID is required.", "INVALID_ARGUMENT");

            var cacheKey = GetOrgConfigCacheKey(organizationId);
            var cachedConfig = await _cacheService.GetAsync<LdapConfigurationDto>(cacheKey);

            if (cachedConfig != null) return ServiceResult<LdapConfigurationDto>.Success(cachedConfig);

            if (_ldapConfigurations.TryGetValue(organizationId, out var config))
            {
                await _cacheService.SetAsync(cacheKey, config, TimeSpan.FromHours(1));
                return ServiceResult<LdapConfigurationDto>.Success(config);
            }

            return ServiceResult<LdapConfigurationDto>.NotFound("LDAP configuration not found for this organization.");
        }

        private async Task<LdapConnection> CreateAndBindConnectionAsync(LdapConfigurationDto config)
        {
            // Obsolete Warning Fix: Use LdapConnectionOptions for modern SSL handling.
            var options = new LdapConnectionOptions();
            if (config.UseSsl)
            {
                options.UseSsl();
                options.ConfigureRemoteCertificateValidationCallback((_, _, _, _) => true);
            }

            var connection = new LdapConnection(options);
            await connection.ConnectAsync(config.Server, config.Port);
            await connection.BindAsync(config.BindDn, config.BindPassword);

            return connection;
        }

        private LdapUserDto MapEntryToUserDto(LdapEntry entry, Dictionary<string, string> attributeMappings)
        {
            var userDto = new LdapUserDto { DistinguishedName = entry.Dn };
            var attributes = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

            // ... mapping logic ...

            foreach (var attr in entry.GetAttributeSet())
            {
                attributes[attr.Name] = attr.StringValue;
            }

            userDto.Attributes = attributes;

            // Error CS1061 Fix: Use 'Get' instead of 'GetAttribute'.
            if (entry.Get("userAccountControl") is { } uacAttr)
            {
                var uacValue = int.Parse(uacAttr.StringValue);
                userDto.IsActive = (uacValue & 2) == 0;
            }

            return userDto;
        }

        private List<string> GetUserGroupNames(LdapEntry userEntry)
        {
            // Error CS1061 Fix: Use 'Get' instead of 'GetAttribute'.
            var memberOfAttr = userEntry.Get("memberOf");
            return memberOfAttr?.StringValueArray.ToList() ?? new List<string>();
        }

        private async Task LogAuthenticationAttempt(Guid organizationId, string username, bool success, string details)
        {
            await _auditService.LogAsync(new AuditLog
            {
                Action = "LDAP_AUTHENTICATION",
                // Error CS0117 Fix: Use existing enums 'Read' and 'Blocked'.
                ActionType = success ? AuditActionType.Read : AuditActionType.Blocked,
                TargetOrganizationId = organizationId,
                Success = success,
                Timestamp = _dateTimeProvider.UtcNow,
                Severity = success ? AuditEventSeverity.Info : AuditEventSeverity.Warning,
                Metadata = $"Attempted login for user '{username}'. Result: {details}"
            });
        }

        private static string GetOrgConfigCacheKey(Guid organizationId) => $"ldap:config:{organizationId}";
        private static string GetUserCacheKey(Guid organizationId, string username) => $"ldap:user:{organizationId}:{username}";

        #endregion

        #region Placeholder Implementations (to satisfy interfaces)

        // Stubs for remaining ILdapService methods
        public Task<ServiceResult<LdapUserDto>> FindUserAsync(string username, Guid organizationId) => throw new NotImplementedException();
        public Task<ServiceResult<List<LdapUserDto>>> GetUsersAsync(string searchBase, string? filter = null, Guid? organizationId = null, int maxResults = 1000) => throw new NotImplementedException();
        public Task<ServiceResult<List<LdapGroupDto>>> GetGroupsAsync(string searchBase, Guid organizationId) => throw new NotImplementedException();
        public Task<ServiceResult<List<string>>> GetUserGroupsAsync(string username, Guid organizationId) => throw new NotImplementedException();
        public Task<ServiceResult<LdapSyncResultDto>> SyncUsersAsync(Guid organizationId, LdapSyncOptionsDto options) => throw new NotImplementedException();
        public Task<ServiceResult<LdapSyncResultDto>> SyncGroupsAsync(Guid organizationId, LdapSyncOptionsDto options) => throw new NotImplementedException();
        public Task<ServiceResult<LdapSyncResultDto>> IncrementalSyncAsync(Guid organizationId, DateTime lastSyncTime) => throw new NotImplementedException();
        public Task<ServiceResult> ConfigureAttributeMappingAsync(Guid organizationId, Dictionary<string, string> mappings) => throw new NotImplementedException();
        public Task<ServiceResult> ConfigureGroupRoleMappingAsync(Guid organizationId, Dictionary<string, Guid> groupToRoleMapping) => throw new NotImplementedException();
        public Task<ServiceResult<PagedResult<LdapUserDto>>> GetUsersPagedAsync(string searchBase, int pageNumber, int pageSize, string? filter = null, Guid? organizationId = null) => throw new NotImplementedException();
        public Task<ServiceResult<List<LdapChangeDto>>> DetectChangesAsync(Guid organizationId, byte[]? previousCookie = null) => throw new NotImplementedException();
        public Task<ServiceResult<LdapSchemaDto>> GetSchemaAsync(Guid organizationId) => throw new NotImplementedException();

        // Stubs for remaining IExternalService methods
        public Task<ServiceResult> TestConnectionAsync() => throw new NotImplementedException(); // From IExternalService
        public Task<ServiceResult> ValidateConfigurationAsync() => throw new NotImplementedException();
        public Task<ServiceResult<ExternalServiceUsage>> GetUsageAsync(DateTime startDate, DateTime endDate, Guid? organizationId = null) => throw new NotImplementedException();
        public Task RecordMetricsAsync(ExternalServiceMetrics metrics) => throw new NotImplementedException();

        #endregion
    }
}