using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Service;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Common;
using Newtonsoft.Json;

namespace AuthHive.Auth.Services.PlatformApplication
{
    /// <summary>
    /// PlatformApplication 관리 서비스
    /// Application 자체의 CRUD 및 비즈니스 로직 처리
    /// </summary>
    public class ApplicationService : IApplicationService
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<ApplicationService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        public ApplicationService(
            AuthDbContext context,
            ILogger<ApplicationService> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _context = context;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        #region Application CRUD

        public async Task<ServiceResult<Core.Entities.PlatformApplications.PlatformApplication>> CreateApplicationAsync(
            CreateApplicationRequest request,
            Guid createdByConnectedId)
        {
            try
            {
                var application = new Core.Entities.PlatformApplications.PlatformApplication
                {
                    OrganizationId = request.OrganizationId,
                    Name = request.Name,
                    Description = request.Description,
                    ApplicationKey = GenerateApplicationKey(request.OrganizationId, request.Name),
                    ApplicationType = request.ApplicationType,
                    Status = ApplicationStatus.Active,
                    Environment = request.Environment,
                    IsPublic = request.IsPublic,
                    
                    // OAuth 설정
                    CallbackUrls = JsonConvert.SerializeObject(request.CallbackUrls ?? new List<string>()),
                    AllowedOrigins = JsonConvert.SerializeObject(request.AllowedOrigins ?? new List<string>()),
                    AllowedScopes = JsonConvert.SerializeObject(request.AllowedScopes ?? new List<string>()),
                    
                    // Rate Limits
                    ApiRateLimitPerMinute = request.ApiRateLimitPerMinute ?? 60,
                    DailyApiQuota = request.DailyApiQuota ?? 10000,
                    MonthlyApiQuota = request.MonthlyApiQuota ?? 300000,
                    
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = createdByConnectedId
                };

                _context.PlatformApplications.Add(application);
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    "Application created: {ApplicationId} by {CreatedBy}",
                    application.Id, createdByConnectedId);

                return ServiceResult<Core.Entities.PlatformApplications.PlatformApplication>.Success(application);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create application");
                return ServiceResult<Core.Entities.PlatformApplications.PlatformApplication>.Failure(
                    "Failed to create application");
            }
        }

        public async Task<Core.Entities.PlatformApplications.PlatformApplication?> GetApplicationAsync(Guid applicationId)
        {
            return await _context.PlatformApplications
                .Include(a => a.Organization)
                .Include(a => a.ApiKeys)
                .Include(a => a.UserAccesses)
                .FirstOrDefaultAsync(a => a.Id == applicationId && !a.IsDeleted);
        }

        public async Task<ServiceResult> UpdateApplicationAsync(
            Guid applicationId,
            UpdateApplicationRequest request,
            Guid updatedByConnectedId)
        {
            try
            {
                var application = await GetApplicationAsync(applicationId);
                if (application == null)
                {
                    return ServiceResult.Failure("Application not found");
                }

                // Update fields
                if (!string.IsNullOrEmpty(request.Name))
                    application.Name = request.Name;
                
                if (!string.IsNullOrEmpty(request.Description))
                    application.Description = request.Description;
                
                if (request.Status.HasValue)
                    application.Status = request.Status.Value;
                
                if (request.ApiRateLimitPerMinute.HasValue)
                    application.ApiRateLimitPerMinute = request.ApiRateLimitPerMinute.Value;

                application.UpdatedAt = _dateTimeProvider.UtcNow;
                application.UpdatedByConnectedId = updatedByConnectedId;

                _context.PlatformApplications.Update(application);
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    "Application updated: {ApplicationId} by {UpdatedBy}",
                    applicationId, updatedByConnectedId);

                return ServiceResult.Success("Application updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update application");
                return ServiceResult.Failure("Failed to update application");
            }
        }

        #endregion

        #region Business Logic

        public int GetActiveApiKeyCount(Core.Entities.PlatformApplications.PlatformApplication application)
        {
            return application.ApiKeys?.Count(k => k.IsActive && !k.RevokedAt.HasValue) ?? 0;
        }

        public bool CanCreateApiKey(Core.Entities.PlatformApplications.PlatformApplication application)
        {
            const int MAX_KEYS_PER_APPLICATION = 10;
            return application.Status == ApplicationStatus.Active &&
                   GetActiveApiKeyCount(application) < MAX_KEYS_PER_APPLICATION;
        }

        public ApiKeyAccessControl? GetDefaultApiKeyAccessControl(Core.Entities.PlatformApplications.PlatformApplication application)
        {
            if (string.IsNullOrEmpty(application.AdditionalSettings))
                return null;

            try
            {
                var settings = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                    application.AdditionalSettings);
                    
                if (settings != null && settings.ContainsKey("DefaultApiKeyAccessControl"))
                {
                    var json = JsonConvert.SerializeObject(settings["DefaultApiKeyAccessControl"]);
                    return JsonConvert.DeserializeObject<ApiKeyAccessControl>(json);
                }
            }
            catch
            {
                return null;
            }

            return null;
        }

        public bool HasSufficientQuota(Core.Entities.PlatformApplications.PlatformApplication application)
        {
            return application.CurrentDailyApiUsage < application.DailyApiQuota &&
                   application.CurrentMonthlyApiUsage < application.MonthlyApiQuota;
        }

        public bool NeedsDailyReset(Core.Entities.PlatformApplications.PlatformApplication application)
        {
            if (!application.LastDailyResetAt.HasValue)
                return true;

            return (_dateTimeProvider.UtcNow - application.LastDailyResetAt.Value).TotalDays >= 1;
        }

        public bool NeedsMonthlyReset(Core.Entities.PlatformApplications.PlatformApplication application)
        {
            if (!application.LastMonthlyResetAt.HasValue)
                return true;

            var lastReset = application.LastMonthlyResetAt.Value;
            var now = _dateTimeProvider.UtcNow;

            return lastReset.Year != now.Year || lastReset.Month != now.Month;
        }

        public async Task<ServiceResult> ResetDailyUsageAsync(Guid applicationId)
        {
            try
            {
                var application = await GetApplicationAsync(applicationId);
                if (application == null)
                {
                    return ServiceResult.Failure("Application not found");
                }

                application.CurrentDailyApiUsage = 0;
                application.LastDailyResetAt = _dateTimeProvider.UtcNow;

                _context.PlatformApplications.Update(application);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Daily usage reset for application {ApplicationId}", applicationId);

                return ServiceResult.Success("Daily usage reset successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reset daily usage");
                return ServiceResult.Failure("Failed to reset daily usage");
            }
        }

        public async Task<ServiceResult> ResetMonthlyUsageAsync(Guid applicationId)
        {
            try
            {
                var application = await GetApplicationAsync(applicationId);
                if (application == null)
                {
                    return ServiceResult.Failure("Application not found");
                }

                application.CurrentMonthlyApiUsage = 0;
                application.LastMonthlyResetAt = _dateTimeProvider.UtcNow;

                _context.PlatformApplications.Update(application);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Monthly usage reset for application {ApplicationId}", applicationId);

                return ServiceResult.Success("Monthly usage reset successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reset monthly usage");
                return ServiceResult.Failure("Failed to reset monthly usage");
            }
        }

        #endregion

        #region Helper Methods

        private string GenerateApplicationKey(Guid organizationId, string name)
        {
            // 조직 키 조회 (실제 구현 필요)
            var orgKey = "org";
            
            // 이름 정규화
            var normalizedName = name.ToLower()
                .Replace(" ", "-")
                .Replace("_", "-");
            
            return $"app-{orgKey}-{normalizedName}";
        }

        #endregion
    }

    #region Interfaces and DTOs

    public interface IApplicationService
    {
        Task<ServiceResult<Core.Entities.PlatformApplications.PlatformApplication>> CreateApplicationAsync(
            CreateApplicationRequest request, Guid createdByConnectedId);
        Task<Core.Entities.PlatformApplications.PlatformApplication?> GetApplicationAsync(Guid applicationId);
        Task<ServiceResult> UpdateApplicationAsync(Guid applicationId, UpdateApplicationRequest request, Guid updatedByConnectedId);
        
        // Business Logic
        int GetActiveApiKeyCount(Core.Entities.PlatformApplications.PlatformApplication application);
        bool CanCreateApiKey(Core.Entities.PlatformApplications.PlatformApplication application);
        ApiKeyAccessControl? GetDefaultApiKeyAccessControl(Core.Entities.PlatformApplications.PlatformApplication application);
        bool HasSufficientQuota(Core.Entities.PlatformApplications.PlatformApplication application);
        bool NeedsDailyReset(Core.Entities.PlatformApplications.PlatformApplication application);
        bool NeedsMonthlyReset(Core.Entities.PlatformApplications.PlatformApplication application);
        Task<ServiceResult> ResetDailyUsageAsync(Guid applicationId);
        Task<ServiceResult> ResetMonthlyUsageAsync(Guid applicationId);
    }

    public class CreateApplicationRequest
    {
        public Guid OrganizationId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public ApplicationType ApplicationType { get; set; } = ApplicationType.Web;
        public ApplicationEnvironment Environment { get; set; } = ApplicationEnvironment.Production;
        public bool IsPublic { get; set; } = false;
        public List<string>? CallbackUrls { get; set; }
        public List<string>? AllowedOrigins { get; set; }
        public List<string>? AllowedScopes { get; set; }
        public int? ApiRateLimitPerMinute { get; set; }
        public long? DailyApiQuota { get; set; }
        public long? MonthlyApiQuota { get; set; }
    }

    public class UpdateApplicationRequest
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public ApplicationStatus? Status { get; set; }
        public int? ApiRateLimitPerMinute { get; set; }
        public long? DailyApiQuota { get; set; }
        public long? MonthlyApiQuota { get; set; }
    }

    #endregion
}