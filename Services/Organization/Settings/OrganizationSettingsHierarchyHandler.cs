using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Core.Interfaces.Organization.Service.Settings;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Organization.Settings;

public class OrganizationSettingsHierarchyHandler : IOrganizationSettingsHierarchyHandler
{
    private readonly IOrganizationRepository _organizationRepository;
    private readonly IOrganizationSettingsRepository _settingsRepository;
    private readonly IOrganizationSettingsCommandRepository _commandRepository;
    private readonly IMapper _mapper;
    private readonly ILogger<OrganizationSettingsHierarchyHandler> _logger;

    public OrganizationSettingsHierarchyHandler(
        IOrganizationRepository organizationRepository,
        IOrganizationSettingsRepository settingsRepository,
        IOrganizationSettingsCommandRepository commandRepository,
        IMapper mapper,
        ILogger<OrganizationSettingsHierarchyHandler> logger)
    {
        _organizationRepository = organizationRepository;
        _settingsRepository = settingsRepository;
        _commandRepository = commandRepository;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<ServiceResult<InheritOrganizationSettingsResponse>> InheritFromParentAsync(
        Guid organizationId,
        Guid connectedId,
        IEnumerable<OrganizationSettingCategory>? categories = null)
    {
        var organization = await _organizationRepository.GetByIdAsync(organizationId);
        if (organization?.ParentId == null)
        {
            _logger.LogWarning("Organization {OrgId} has no parent to inherit from.", organizationId);
            return ServiceResult<InheritOrganizationSettingsResponse>.Failure("Organization does not have a parent.");
        }

        var parentId = organization.ParentId.Value;
        _logger.LogInformation("Inheriting settings from parent {ParentId} to child {ChildId}", parentId, organizationId);

        var inheritedEntities = await _settingsRepository.InheritSettingsFromParentAsync(
            organizationId,
            parentId,
            categories?.Select(c => c.ToString()));

        var response = new InheritOrganizationSettingsResponse
        {
            ParentOrganizationId = parentId,
            SettingsInherited = inheritedEntities.Count(),
            InheritedSettingKeys = inheritedEntities.Select(s => s.SettingKey).ToList(),
            Message = $"{inheritedEntities.Count()} settings were successfully inherited."
        };

        return ServiceResult<InheritOrganizationSettingsResponse>.Success(response);
    }

    public async Task<ServiceResult<PropagateOrganizationSettingsResponse>> PropagateToChildrenAsync(
        PropagateOrganizationSettingsRequest request,
        Guid connectedId)
    {
        _logger.LogInformation("Propagating settings from parent {ParentId} by user {ConnectedId}",
            request.ParentOrganizationId, connectedId);

        var affectedCount = await _commandRepository.PropagateSettingsToChildrenAsync(
            request.ParentOrganizationId,
            request.SettingKeys,
            request.ForceOverride);

        var response = new PropagateOrganizationSettingsResponse
        {
            IsSuccess = affectedCount > 0,
            PropagatedSettingsCount = affectedCount,  // 올바른 속성명
            AffectedOrganizationsCount = 0,  // 실제 영향받은 조직 수를 계산해야 함
            Message = $"{affectedCount}개의 설정이 하위 조직에 전파되었습니다."
        };

        return ServiceResult<PropagateOrganizationSettingsResponse>.Success(response);
    }

    public async Task<ServiceResult<OrganizationSettingsDto>> OverrideInheritedSettingAsync(
        OverrideInheritedSettingRequest request,
        Guid connectedId)
    {
        _logger.LogInformation("User {ConnectedId} is overriding setting '{SettingKey}' for organization {OrgId}",
            connectedId, request.SettingKey, request.OrganizationId);

        var settingToUpsert = new Core.Entities.Organization.OrganizationSettings
        {
            OrganizationId = request.OrganizationId,
            Category = request.Category.ToString(),
            SettingKey = request.SettingKey,
            SettingValue = request.NewValue,
            IsInherited = false
        };

        var upsertedEntity = await _settingsRepository.UpsertSettingAsync(settingToUpsert, connectedId);
        var dto = _mapper.Map<OrganizationSettingsDto>(upsertedEntity);

        return ServiceResult<OrganizationSettingsDto>.Success(dto);
    }
}