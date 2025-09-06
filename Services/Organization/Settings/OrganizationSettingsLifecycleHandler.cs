using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Core.Interfaces.Organization.Service.Settings;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Core.Enums.Core;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Models.Organization.Common;

namespace AuthHive.Auth.Services.Organization.Settings;

public class OrganizationSettingsLifecycleHandler : IOrganizationSettingsLifecycleHandler
{
    private readonly IOrganizationSettingsCommandRepository _commandRepository;
    private readonly IMapper _mapper;
    private readonly ILogger<OrganizationSettingsLifecycleHandler> _logger;

    public OrganizationSettingsLifecycleHandler(
        IOrganizationSettingsCommandRepository commandRepository,
        IMapper mapper,
        ILogger<OrganizationSettingsLifecycleHandler> logger)
    {
        _commandRepository = commandRepository;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<ServiceResult<ResetOrganizationSettingsResponse>> ResetToDefaultsAsync(
        Guid organizationId, 
        OrganizationSettingCategory? category, 
        Guid connectedId)
    {
        var entities = await _commandRepository.ResetToDefaultsAsync(
            organizationId, 
            category?.ToString(), 
            connectedId);

        var response = new ResetOrganizationSettingsResponse
        {
            SettingsReset = entities.Count(),
            ResetSettingKeys = entities.Select(e => e.SettingKey).ToList(),
            Category = category,
            ResetAt = DateTime.UtcNow,
            ResetByConnectedId = connectedId
        };
        
        return ServiceResult<ResetOrganizationSettingsResponse>.Success(response);
    }

    public async Task<ServiceResult<OrganizationSettingsBackupResponse>> BackupSettingsAsync(
        Guid organizationId, 
        Guid connectedId, 
        bool includeEncrypted = false)
    {
        var backupJson = await _commandRepository.BackupSettingsAsync(organizationId);
        
        var response = new OrganizationSettingsBackupResponse
        {
            OrganizationId = organizationId,
            BackupData = backupJson,
            BackupDate = DateTime.UtcNow,
            IncludesEncrypted = includeEncrypted
        };
        
        return ServiceResult<OrganizationSettingsBackupResponse>.Success(response);
    }

    public async Task<ServiceResult<RestoreOrganizationSettingsResponse>> RestoreSettingsAsync(
        RestoreOrganizationSettingsRequest request, 
        Guid connectedId)
    {
        var restoredEntities = await _commandRepository.RestoreSettingsAsync(
            request.OrganizationId, 
            request.BackupData, 
            connectedId);

        var response = new RestoreOrganizationSettingsResponse
        {
            BackupId = request.BackupId,
            SettingsRestored = restoredEntities.Count(),
            RestoredKeys = restoredEntities.Select(e => e.SettingKey).ToList(),
            RestoredAt = DateTime.UtcNow
        };
        
        return ServiceResult<RestoreOrganizationSettingsResponse>.Success(response);
    }

    public async Task<ServiceResult<ApplyOrganizationSettingsTemplateResponse>> ApplyTemplateAsync(
        ApplyOrganizationSettingsTemplateRequest request, 
        Guid connectedId)
    {
        var appliedEntities = await _commandRepository.ApplySettingsTemplateAsync(
            request.OrganizationId, 
            request.TemplateName, 
            connectedId);
            
        var response = new ApplyOrganizationSettingsTemplateResponse
        {
            TemplateName = request.TemplateName,
            SettingsApplied = appliedEntities.Count(),
            AppliedAt = DateTime.UtcNow
        };
        
        return ServiceResult<ApplyOrganizationSettingsTemplateResponse>.Success(response);
    }

    public Task<ServiceResult<IEnumerable<OrganizationSettingsDto>>> InitializeDefaultSettingsAsync(
        Guid organizationId, 
        string planType, 
        Guid createdByConnectedId)
    {
        // TODO: 구현
        return Task.FromResult(ServiceResult<IEnumerable<OrganizationSettingsDto>>.Success(
            Enumerable.Empty<OrganizationSettingsDto>()));
    }
}