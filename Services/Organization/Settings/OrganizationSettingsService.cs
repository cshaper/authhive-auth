using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Services.Organization.Settings
{
    /// <summary>
    /// 조직 설정 서비스 구현체 - v16 Refactored
    /// v16 원칙에 따라 IPrincipalAccessor, ICacheService, IAuditService, IEventBus, IPlanRestrictionService를 사용하여
    /// 안전하고 확장 가능하며 추적 가능한 비즈니스 로직을 제공합니다.
    /// </summary>
    public class OrganizationSettingsService : IOrganizationSettingsService
    {
        private readonly IOrganizationSettingsRepository _repository;
        private readonly IOrganizationSettingsQueryRepository _queryRepository;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly ICacheService _cacheService;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPlanRestrictionService _planRestrictionService;
        private readonly IMapper _mapper;
        private readonly ILogger<OrganizationSettingsService> _logger;

        public OrganizationSettingsService(
            IOrganizationSettingsRepository repository,
            IOrganizationSettingsQueryRepository queryRepository,
            IPrincipalAccessor principalAccessor,
            ICacheService cacheService,
            IAuditService auditService,
            IEventBus eventBus,
            IDateTimeProvider dateTimeProvider,
            IUnitOfWork unitOfWork,
            IPlanRestrictionService planRestrictionService,
            IMapper mapper,
            ILogger<OrganizationSettingsService> logger)
        {
            _repository = repository;
            _queryRepository = queryRepository;
            _principalAccessor = principalAccessor;
            _cacheService = cacheService;
            _auditService = auditService;
            _eventBus = eventBus;
            _dateTimeProvider = dateTimeProvider;
            _unitOfWork = unitOfWork;
            _planRestrictionService = planRestrictionService;
            _mapper = mapper;
            _logger = logger;
        }

        #region 기본 CRUD 작업

        /// <summary>
        /// 특정 조직의 개별 설정 하나를 조회합니다.
        /// 이 메서드는 캐시를 우선적으로 확인하고, 캐시에 없는 경우 리포지토리를 통해 데이터를 조회한 후 결과를 캐시에 저장합니다.
        /// 상속 규칙이 적용된 최종 설정 값을 DTO 형태로 반환합니다.
        /// </summary>
        public async Task<ServiceResult<OrganizationSettingsDto>> GetSettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, bool includeInherited = true, CancellationToken cancellationToken = default)
        {
            var connectedId = _principalAccessor.ConnectedId;
            if (!connectedId.HasValue) return ServiceResult<OrganizationSettingsDto>.Unauthorized();

            try
            {
                // TODO: Add permission check if user can read settings for this organization

                var cacheKey = $"org-setting:{organizationId}:{category}:{settingKey}:{includeInherited}";
                var cachedDto = await _cacheService.GetAsync<OrganizationSettingsDto>(cacheKey, cancellationToken);
                if (cachedDto != null)
                {
                    return ServiceResult<OrganizationSettingsDto>.Success(cachedDto);
                }

                var entity = await _queryRepository.GetSettingAsync(organizationId, category, settingKey, includeInherited, cancellationToken);
                if (entity == null)
                {
                    // TODO: Load default setting value
                    return ServiceResult<OrganizationSettingsDto>.NotFound("Setting not found.");
                }

                var dto = _mapper.Map<OrganizationSettingsDto>(entity);
                await _cacheService.SetAsync(cacheKey, dto, TimeSpan.FromMinutes(30), cancellationToken); // Cache for 30 minutes

                return ServiceResult<OrganizationSettingsDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting setting '{SettingKey}' for organization {OrganizationId}", settingKey, organizationId);
                return ServiceResult<OrganizationSettingsDto>.Failure("An error occurred while retrieving the setting.");
            }
        }

        public async Task<ServiceResult<T?>> GetSettingValueAsync<T>(Guid organizationId, OrganizationSettingCategory category, string settingKey, CancellationToken cancellationToken = default) where T : class
        {
            var settingResult = await GetSettingAsync(organizationId, category, settingKey, true, cancellationToken); // Always include inherited for value resolution
            if (!settingResult.IsSuccess || settingResult.Data?.SettingValue == null)
            {
                return ServiceResult<T?>.Failure(settingResult.ErrorMessage ?? "Setting value not found.", settingResult.ErrorCode);
            }

            try
            {
                // Assuming SettingValue is stored as JSON string for complex types
                var value = System.Text.Json.JsonSerializer.Deserialize<T>(settingResult.Data.SettingValue.ToString() ?? string.Empty);
                return ServiceResult<T?>.Success(value);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to convert setting value for '{SettingKey}' to type {TypeName}", settingKey, typeof(T).Name);
                return ServiceResult<T?>.Failure($"Could not convert setting value to the requested type '{typeof(T).Name}'.");
            }
        }

        public async Task<ServiceResult<OrganizationSettingsDto>> UpsertSettingAsync(CreateOrUpdateOrganizationSettingRequest request, CancellationToken cancellationToken = default)
        {
            var connectedId = _principalAccessor.ConnectedId;
            if (!connectedId.HasValue) return ServiceResult<OrganizationSettingsDto>.Unauthorized();

            try
            {
                // if (request.Category == OrganizationSettingCategory.Security)
                // {
                //     await _planRestrictionService.EnforceFeatureEnabledAsync(
                //         request.OrganizationId,
                //         PricingConstants.FeatureKeys.AdvancedSecuritySettings,
                //         cancellationToken);
                // }

                var canModifyResult = await CanModifySettingAsync(request.OrganizationId, request.Category, request.SettingKey, cancellationToken);
                if (!canModifyResult.IsSuccess || !canModifyResult.Data)
                {
                    return ServiceResult<OrganizationSettingsDto>.Forbidden(canModifyResult.ErrorMessage ?? "You do not have permission to modify this setting.");
                }

                var entity = _mapper.Map<Core.Entities.Organization.OrganizationSettings>(request);
                var resultEntity = await _repository.UpsertSettingAsync(entity, connectedId.Value, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                
                await InvalidateSettingCacheAsync(request.OrganizationId, request.Category, request.SettingKey, cancellationToken);

                await _auditService.LogSettingChangeAsync(
                    request.SettingKey,
                    null,
                    request.SettingValue?.ToString(),
                    connectedId.Value,
                    request.OrganizationId,
                    cancellationToken: cancellationToken);

                var dto = _mapper.Map<OrganizationSettingsDto>(resultEntity);
                return ServiceResult<OrganizationSettingsDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error upserting setting '{SettingKey}' for organization {OrganizationId}", request.SettingKey, request.OrganizationId);
                return ServiceResult<OrganizationSettingsDto>.Failure(ex.Message, "UPSERT_SETTING_FAILED");
            }
        }
        
        public async Task<ServiceResult> DeleteSettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, CancellationToken cancellationToken = default)
        {
            var connectedId = _principalAccessor.ConnectedId;
            if (!connectedId.HasValue) return ServiceResult.Unauthorized();
            
            try
            {
                var success = await _repository.DeleteSettingAsync(organizationId, category.ToString(), settingKey, connectedId.Value, cancellationToken);
                if (!success)
                {
                    return ServiceResult.NotFound("Setting not found or could not be deleted.");
                }
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                await InvalidateSettingCacheAsync(organizationId, category, settingKey, cancellationToken);
                
                await _auditService.LogSettingChangeAsync(
                   settingKey,
                   "[DELETED]",
                   "[DEFAULT]",
                   connectedId.Value,
                   organizationId,
                   cancellationToken: cancellationToken);

                return ServiceResult.Success();
            }
            catch(Exception ex)
            {
                 _logger.LogError(ex, "Error deleting setting '{SettingKey}' for organization {OrganizationId}", settingKey, organizationId);
                return ServiceResult.Failure("An error occurred while deleting the setting.");
            }
        }

        #endregion

        #region 조회 작업

        public async Task<ServiceResult<IEnumerable<OrganizationSettingsDto>>> GetSettingsByCategoryAsync(Guid organizationId, OrganizationSettingCategory category, CancellationToken cancellationToken = default)
        {
            try
            {
                var entities = await _queryRepository.GetSettingsByCategoryAsync(organizationId, category, true, cancellationToken);
                var dtos = _mapper.Map<IEnumerable<OrganizationSettingsDto>>(entities);
                return ServiceResult<IEnumerable<OrganizationSettingsDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting settings for category {Category} in organization {OrganizationId}", category, organizationId);
                return ServiceResult<IEnumerable<OrganizationSettingsDto>>.Failure("An error occurred while retrieving settings.");
            }
        }

        public async Task<ServiceResult<OrganizationSettingsListResponse>> GetAllSettingsAsync(Guid organizationId, bool groupByCategory = true, CancellationToken cancellationToken = default)
        {
            try
            {
                var entities = await _queryRepository.GetAllSettingsAsync(organizationId, true, true, cancellationToken);
                var dtos = _mapper.Map<List<OrganizationSettingsDto>>(entities);
                
                var response = new OrganizationSettingsListResponse
                {
                    OrganizationId = organizationId,
                    TotalSettings = dtos.Count,
                    ActiveSettings = dtos.Count(s => s.IsActive),
                    InheritedSettings = dtos.Count(s => s.IsInherited),
                    CustomSettings = dtos.Count(s => !s.IsInherited),
                    LastModified = dtos.Any() ? dtos.Max(s => s.UpdatedAt ?? s.CreatedAt) : _dateTimeProvider.UtcNow
                };

                if (groupByCategory)
                {
                    response.SettingsByCategory = dtos.GroupBy(s => s.Category).ToDictionary(g => g.Key, g => g.ToList());
                }

                return ServiceResult<OrganizationSettingsListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all settings for organization {OrganizationId}", organizationId);
                return ServiceResult<OrganizationSettingsListResponse>.Failure("An error occurred while retrieving all settings.");
            }
        }
        
        #endregion

        #region 검증 및 권한

        public async Task<ServiceResult<bool>> CanModifySettingAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, CancellationToken cancellationToken = default)
        {
            var connectedId = _principalAccessor.ConnectedId;
            if (!connectedId.HasValue)
            {
                return ServiceResult<bool>.Unauthorized("Authentication required.");
            }

            // TODO: IAuthorizationService를 주입받아 실제 권한 검증 로직 구현
            // 예: 사용자가 'Admin' 역할을 가졌는지 또는 'settings:manage' 권한이 있는지 확인
            // var hasPermission = await _authorizationService.HasPermissionAsync(connectedId.Value, "settings:manage");
            // return ServiceResult<bool>.Success(hasPermission);

            // 임시 구현
            await Task.CompletedTask;
            return ServiceResult<bool>.Success(true);
        }

        #endregion
        
        #region IService Implementation

        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // Can connect to the database via repository?
            // All dependencies are resolved?
            return Task.FromResult(_repository != null && _queryRepository != null && _principalAccessor != null);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("OrganizationSettingsService (v16) Initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region Dummy Implementations (TODO: Implement fully)

        public Task<ServiceResult<BulkUpdateOrganizationSettingsResponse>> BulkUpdateSettingsAsync(BulkUpdateOrganizationSettingsRequest request, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<ResetOrganizationSettingsResponse>> ResetToDefaultsAsync(Guid organizationId, OrganizationSettingCategory? category, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<InheritOrganizationSettingsResponse>> InheritFromParentAsync(Guid organizationId, IEnumerable<OrganizationSettingCategory>? categories = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<PropagateOrganizationSettingsResponse>> PropagateToChildrenAsync(PropagateOrganizationSettingsRequest request, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<ValidationResult>> ValidateSettingValueAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, string value, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<ApplyOrganizationSettingsTemplateResponse>> ApplyTemplateAsync(ApplyOrganizationSettingsTemplateRequest request, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<IEnumerable<OrganizationSettingsDto>>> InitializeDefaultSettingsAsync(Guid organizationId, string planType, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> RefreshSettingsCacheAsync(Guid organizationId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public async Task<ServiceResult> InvalidateSettingCacheAsync(Guid organizationId, OrganizationSettingCategory category, string settingKey, CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"org-setting:{organizationId}:{category}:{settingKey}";
                await _cacheService.RemoveAsync(cacheKey, cancellationToken);
                _logger.LogInformation("Cache invalidated for setting {SettingKey} in organization {OrganizationId}", settingKey, organizationId);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate cache for setting {SettingKey}", settingKey);
                return ServiceResult.Failure("Failed to invalidate cache.");
            }
        }
        #endregion
    }
}

