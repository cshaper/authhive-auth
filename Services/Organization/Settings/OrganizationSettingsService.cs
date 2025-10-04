using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Core.Interfaces.Organization.Service.Settings;

namespace AuthHive.Auth.Services.Organization.Settings;

public class OrganizationSettingsService : IOrganizationSettingsService
{
    private readonly IOrganizationSettingsRepository _repository;
    private readonly IOrganizationSettingsQueryRepository _queryRepository;
    private readonly IOrganizationSettingsCommandRepository _commandRepository;
    private readonly IOrganizationSettingsLifecycleHandler _lifecycleHandler;
    private readonly IMapper _mapper;
    private readonly ILogger<OrganizationSettingsService> _logger;
    private readonly IMemoryCache _cache;

    public OrganizationSettingsService(
        IOrganizationSettingsRepository repository,
        IOrganizationSettingsQueryRepository queryRepository,
        IOrganizationSettingsCommandRepository commandRepository,
        IOrganizationSettingsLifecycleHandler lifecycleHandler,
        IMapper mapper,
        ILogger<OrganizationSettingsService> logger,
        IMemoryCache cache)
    {
        _repository = repository;
        _queryRepository = queryRepository;
        _commandRepository = commandRepository;
        _lifecycleHandler = lifecycleHandler;
        _mapper = mapper;
        _logger = logger;
        _cache = cache;
    }

    #region 기본 CRUD 작업

    public async Task<OrganizationSettingsDto?> GetSettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, Guid connectedId)
    {
        var entity = await _queryRepository.GetSettingAsync(organizationId, category.ToString(), settingKey);
        return _mapper.Map<OrganizationSettingsDto?>(entity);
    }

    public async Task<T?> GetSettingValueAsync<T>(Guid organizationId, OrganizationSettingCategory category, string settingKey, Guid connectedId) where T : class
    {
        var setting = await GetSettingAsync(organizationId, category, settingKey, connectedId);
        if (setting?.SettingValue == null) return null;

        try
        {
            if (setting.SettingValue is T value) return value;
            return (T)Convert.ChangeType(setting.SettingValue, typeof(T));
        }
        catch
        {
            return null;
        }
    }

    public async Task<OrganizationSettingsDto> UpsertSettingAsync(CreateOrUpdateOrganizationSettingRequest request, Guid connectedId)
    {
        var entity = _mapper.Map<Core.Entities.Organization.OrganizationSettings>(request);
        var resultEntity = await _repository.UpsertSettingAsync(entity, connectedId);
        return _mapper.Map<OrganizationSettingsDto>(resultEntity);
    }

    public async Task<bool> DeleteSettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, Guid connectedId)
    {
        return await _repository.DeleteSettingAsync(organizationId, category.ToString(), settingKey, connectedId);
    }

    #endregion

    #region 조회 작업

    public async Task<IEnumerable<OrganizationSettingsDto>> GetSettingsByCategoryAsync(Guid organizationId, OrganizationSettingCategory category, Guid connectedId)
    {
        var entities = await _queryRepository.GetSettingsByCategoryAsync(organizationId, category);
        return _mapper.Map<IEnumerable<OrganizationSettingsDto>>(entities);
    }

    public async Task<OrganizationSettingsListResponse> GetAllSettingsAsync(Guid organizationId, Guid connectedId, bool groupByCategory = true)
    {
        var entities = await _queryRepository.GetAllSettingsAsync(organizationId);
        var dtos = _mapper.Map<List<OrganizationSettingsDto>>(entities);

        var response = new OrganizationSettingsListResponse
        {
            OrganizationId = organizationId,
            TotalSettings = dtos.Count,
            ActiveSettings = dtos.Count(s => s.IsActive),
            InheritedSettings = dtos.Count(s => s.IsInherited),
            CustomSettings = dtos.Count(s => !s.IsInherited),
            LastModified = dtos.Max(s => s.UpdatedAt ?? s.CreatedAt)
        };

        if (groupByCategory)
        {
            response.SettingsByCategory = dtos
                .GroupBy(s => s.Category)
                .ToDictionary(g => g.Key, g => g.ToList());
        }

        return response;
    }

    public async Task<IEnumerable<OrganizationSettingsDto>> GetActiveSettingsAsync(Guid organizationId, Guid connectedId)
    {
        var entities = await _queryRepository.GetActiveSettingsAsync(organizationId);
        return _mapper.Map<IEnumerable<OrganizationSettingsDto>>(entities);
    }

    public async Task<IEnumerable<OrganizationSettingsDto>> GetUserConfigurableSettingsAsync(Guid organizationId, Guid connectedId)
    {
        var entities = await _queryRepository.GetUserConfigurableSettingsAsync(organizationId);
        return _mapper.Map<IEnumerable<OrganizationSettingsDto>>(entities);
    }

    public async Task<IEnumerable<OrganizationSettingsDto>> GetRecentlyModifiedSettingsAsync(Guid organizationId, int days, Guid connectedId)
    {
        var entities = await _queryRepository.GetRecentlyModifiedSettingsAsync(organizationId, days);
        return _mapper.Map<IEnumerable<OrganizationSettingsDto>>(entities);
    }

    #endregion

    #region 일괄 작업

    public async Task<BulkUpdateOrganizationSettingsResponse> BulkUpdateSettingsAsync(BulkUpdateOrganizationSettingsRequest request, Guid connectedId)
    {
        var entities = _mapper.Map<IEnumerable<Core.Entities.Organization.OrganizationSettings>>(request.Settings);
        var resultEntities = await _repository.BulkUpsertAsync(entities, connectedId);
        var dtos = _mapper.Map<List<OrganizationSettingsDto>>(resultEntities);

        return new BulkUpdateOrganizationSettingsResponse
        {
            UpdatedSettings = dtos,
            SuccessfullyUpdated = dtos.Count,
            TotalRequested = request.Settings.Count(),
            Failed = 0
        };
    }

    public async Task<ResetOrganizationSettingsResponse> ResetToDefaultsAsync(Guid organizationId, OrganizationSettingCategory? category, Guid connectedId)
    {
        var result = await _lifecycleHandler.ResetToDefaultsAsync(organizationId, category, connectedId);
        return result.Data!;
    }

    #endregion

    #region 상속 및 전파 (간단 구현)

    public Task<InheritOrganizationSettingsResponse> InheritFromParentAsync(Guid organizationId, Guid connectedId, IEnumerable<OrganizationSettingCategory>? categories = null)
    {
        // TODO: 부모 조직 ID 조회 로직 추가 필요
        _logger.LogWarning("InheritFromParentAsync not fully implemented");
        return Task.FromResult(new InheritOrganizationSettingsResponse());
    }

    public async Task<PropagateOrganizationSettingsResponse> PropagateToChildrenAsync(
        PropagateOrganizationSettingsRequest request,
        Guid connectedId)
    {
        var affectedCount = await _commandRepository.PropagateSettingsToChildrenAsync(
            request.ParentOrganizationId,
            request.SettingKeys,
            request.ForceOverride);

        return new PropagateOrganizationSettingsResponse
        {
            IsSuccess = affectedCount > 0,
            PropagatedSettingsCount = affectedCount,
            AffectedOrganizationsCount = affectedCount > 0 ? 1 : 0, // 또는 실제 영향받은 조직 수
            Message = $"{affectedCount}개의 설정이 하위 조직에 전파되었습니다."
        };
    }

    public async Task<OrganizationSettingsDto> OverrideInheritedSettingAsync(OverrideInheritedSettingRequest request, Guid connectedId)
    {
        var entity = new Core.Entities.Organization.OrganizationSettings
        {
            OrganizationId = request.OrganizationId,
            Category = request.Category.ToString(),
            SettingKey = request.SettingKey,
            SettingValue = request.NewValue,
            IsInherited = false
        };

        var result = await _repository.UpsertSettingAsync(entity, connectedId);
        return _mapper.Map<OrganizationSettingsDto>(result);
    }

    #endregion

    #region 검증 및 권한

    public async Task<ValidationResult> ValidateSettingValueAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, string value)
    {
        var isValid = await _queryRepository.ValidateSettingValueAsync(organizationId, category.ToString(), settingKey, value);
        return new ValidationResult { IsValid = isValid };
    }

    public Task<bool> CanModifySettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, Guid connectedId)
    {
        // TODO: 권한 검증 로직 구현
        return Task.FromResult(true);
    }

    public Task<bool> IsSettingAvailableForPlanAsync(Guid organizationId, string settingKey)
    {
        // TODO: 플랜 검증 로직 구현
        return Task.FromResult(true);
    }

    #endregion

    #region 템플릿 관리

    public async Task<ApplyOrganizationSettingsTemplateResponse> ApplyTemplateAsync(ApplyOrganizationSettingsTemplateRequest request, Guid connectedId)
    {
        var result = await _lifecycleHandler.ApplyTemplateAsync(request, connectedId);
        return result.Data!;
    }

    public async Task<IEnumerable<OrganizationSettingsDto>> InitializeDefaultSettingsAsync(Guid organizationId, string planType, Guid createdByConnectedId)
    {
        var result = await _lifecycleHandler.InitializeDefaultSettingsAsync(organizationId, planType, createdByConnectedId);
        return result.Data!;
    }

    #endregion

    #region 암호화 및 보안

    public Task<OrganizationSettingsDto> EncryptSensitiveSettingAsync(EncryptSensitiveSettingRequest request, Guid connectedId)
    {
        // TODO: 암호화 로직 구현
        _logger.LogWarning("EncryptSensitiveSettingAsync not implemented");
        return Task.FromResult(new OrganizationSettingsDto());
    }

    public Task<string> DecryptSensitiveSettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, Guid connectedId)
    {
        // TODO: 복호화 로직 구현
        _logger.LogWarning("DecryptSensitiveSettingAsync not implemented");
        return Task.FromResult(string.Empty);
    }

    #endregion

    #region 내보내기 및 백업

    public async Task<OrganizationSettingsBackupResponse> BackupSettingsAsync(Guid organizationId, Guid connectedId, bool includeEncrypted = false)
    {
        var result = await _lifecycleHandler.BackupSettingsAsync(organizationId, connectedId, includeEncrypted);
        return result.Data!;
    }

    public async Task<RestoreOrganizationSettingsResponse> RestoreSettingsAsync(RestoreOrganizationSettingsRequest request, Guid connectedId)
    {
        var result = await _lifecycleHandler.RestoreSettingsAsync(request, connectedId);
        return result.Data!;
    }

    public Task<ExportOrganizationSettingsResponse> ExportSettingsAsync(Guid organizationId, OrganizationSettingsExportFormat format, Guid connectedId)
    {
        // TODO: Export 로직 구현
        _logger.LogWarning("ExportSettingsAsync not implemented");
        return Task.FromResult(new ExportOrganizationSettingsResponse());
    }

    #endregion

    #region 변경 이력

    public Task<OrganizationSettingsHistoryResponse> GetSettingHistoryAsync(GetOrganizationSettingsHistoryRequest request, Guid connectedId)
    {
        // TODO: 이력 조회 로직 구현
        _logger.LogWarning("GetSettingHistoryAsync not implemented");
        return Task.FromResult(new OrganizationSettingsHistoryResponse());
    }

    #endregion

    #region 캐싱 관리

    public async Task RefreshSettingsCacheAsync(Guid organizationId)
    {
        var cacheKey = $"org-settings:{organizationId}";
        _cache.Remove(cacheKey);
        await Task.CompletedTask;
    }

    public async Task InvalidateSettingCacheAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey)
    {
        var cacheKey = $"org-settings:{organizationId}:{category}:{settingKey}";
        _cache.Remove(cacheKey);
        await Task.CompletedTask;
    }

    #endregion
}