using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Organization.Handler;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Auth.Data.Context;
using AutoMapper;
using System.ComponentModel.DataAnnotations;

// 엔티티에 별칭 사용
using OrganizationCapabilityEntity = AuthHive.Core.Entities.Organization.OrganizationCapability;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Models.Organization.Events;

namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 역할(Capability) 관리 서비스 구현체 - AuthHive v15
    /// </summary>
    public class OrganizationCapabilityService : IOrganizationCapabilityService
    {
        private readonly AuthDbContext _context;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationCapabilityRepository _capabilityRepository;
        private readonly IOrganizationCapabilityEventHandler? _eventHandler;
        private readonly IMapper _mapper;
        private readonly ILogger<OrganizationCapabilityService> _logger;

        // 플랜별 최대 Capability 수
        private readonly Dictionary<string, int> _planCapabilityLimits = new()
        {
            { "Basic", 1 },
            { "Pro", 3 },
            { "Business", 5 },
            { "Enterprise", -1 } // 무제한
        };

        public OrganizationCapabilityService(
            AuthDbContext context,
            IOrganizationRepository organizationRepository,
            IOrganizationCapabilityRepository capabilityRepository,
            IMapper mapper,
            ILogger<OrganizationCapabilityService> logger,
            IOrganizationCapabilityEventHandler? eventHandler = null)
        {
            _context = context;
            _organizationRepository = organizationRepository;
            _capabilityRepository = capabilityRepository;
            _mapper = mapper;
            _logger = logger;
            _eventHandler = eventHandler;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                return await _context.Database.CanConnectAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationCapabilityService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("OrganizationCapabilityService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region Capability 조회

        public async Task<ServiceResult<OrganizationCapabilityAssignmentDetailResponse>> GetAllCapabilitiesAsync(
            Guid organizationId)
        {
            try
            {
                var organization = await _context.Organizations
                    .Include(o => o.Capabilities)
                    .ThenInclude(c => c.Capability)
                    .FirstOrDefaultAsync(o => o.Id == organizationId && !o.IsDeleted);

                if (organization == null)
                {
                    return ServiceResult<OrganizationCapabilityAssignmentDetailResponse>.Failure(
                        "Organization not found");
                }

                var response = new OrganizationCapabilityAssignmentDetailResponse
                {
                    Id = Guid.NewGuid(),
                    OrganizationId = organizationId,
                    CreatedAt = DateTime.UtcNow
                };

                // Primary Capability
                var primaryAssignment = organization.Capabilities?.FirstOrDefault(c => c.IsPrimary);
                if (primaryAssignment?.Capability != null)
                {
                    response.CapabilityType = MapCodeToEnum(primaryAssignment.Capability.Code);
                    response.IsActive = primaryAssignment.IsActive;
                    response.AssignedAt = primaryAssignment.AssignedAt ?? DateTime.UtcNow;
                    response.Configuration = primaryAssignment.Settings;

                    // 상세 정보 설정
                    response.CapabilityDetail = new CapabilityDetail
                    {
                        Name = primaryAssignment.Capability.Name,
                        Description = primaryAssignment.Capability.Description ?? "",
                        RequiredPlan = primaryAssignment.Capability.RequiredPlan ?? "Basic",
                        MonthlyCost = primaryAssignment.Capability.MonthlyCost,
                        CommissionRate = primaryAssignment.Capability.DefaultCommissionRate,
                        IconUrl = primaryAssignment.Capability.IconUrl
                    };
                }

                // Response 모델의 Statistics 사용
                response.Statistics = new CapabilityUsageSummary
                {
                    TotalUsageCount = 0,
                    TodayUsageCount = 0,
                    MonthlyUsageCount = 0,
                    LastUsedAt = null,
                    ActiveUsers = 0
                };

                return ServiceResult<OrganizationCapabilityAssignmentDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get all capabilities for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<OrganizationCapabilityAssignmentDetailResponse>.Failure(
                    "Failed to retrieve capabilities");
            }
        }

        public async Task<ServiceResult<OrganizationCapabilityAssignmentDto>> GetByIdAsync(
            Guid capabilityAssignmentId)
        {
            try
            {
                var assignment = await _context.OrganizationCapabilityAssignments
                    .Include(a => a.Capability)
                    .FirstOrDefaultAsync(a => a.Id == capabilityAssignmentId && !a.IsDeleted);

                if (assignment == null)
                {
                    return ServiceResult<OrganizationCapabilityAssignmentDto>.Failure(
                        "Capability assignment not found");
                }

                var dto = _mapper.Map<OrganizationCapabilityAssignmentDto>(assignment);
                return ServiceResult<OrganizationCapabilityAssignmentDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get capability assignment {Id}", capabilityAssignmentId);
                return ServiceResult<OrganizationCapabilityAssignmentDto>.Failure(
                    "Failed to retrieve capability assignment");
            }
        }

        public async Task<ServiceResult<bool>> HasCapabilityAsync(
            Guid organizationId,
            OrganizationCapabilityEntity capability)
        {
            try
            {
                var hasCapability = await _context.OrganizationCapabilityAssignments
                    .Include(a => a.Capability)
                    .AnyAsync(a => a.OrganizationId == organizationId &&
                                  a.Capability!.Code == capability.Code &&
                                  a.IsActive &&
                                  !a.IsDeleted);

                return ServiceResult<bool>.Success(hasCapability);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check capability for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<bool>.Failure("Failed to check capability");
            }
        }

        public async Task<ServiceResult<OrganizationCapabilityEntity>> GetPrimaryCapabilityAsync(
            Guid organizationId)
        {
            try
            {
                var primaryAssignment = await _context.OrganizationCapabilityAssignments
                    .Include(a => a.Capability)
                    .FirstOrDefaultAsync(a => a.OrganizationId == organizationId &&
                                             a.IsPrimary &&
                                             !a.IsDeleted);

                if (primaryAssignment?.Capability == null)
                {
                    return ServiceResult<OrganizationCapabilityEntity>.Failure(
                        "Primary capability not found");
                }

                return ServiceResult<OrganizationCapabilityEntity>.Success(primaryAssignment.Capability);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get primary capability for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<OrganizationCapabilityEntity>.Failure(
                    "Failed to retrieve primary capability");
            }
        }

        #endregion

        #region Capability 할당/제거

        public async Task<ServiceResult<OrganizationCapabilityAssignmentResponse>> AssignAsync(
            Guid organizationId,
            AssignOrganizationCapabilityRequest request,
            Guid assignedByConnectedId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationCapabilityAssignmentResponse>.Failure(
                        "Organization not found");
                }

                var capabilityCode = request.CapabilityType?.Code ?? "CUSTOMER";
                var capability = await _capabilityRepository.GetByCodeAsync(capabilityCode);
                if (capability == null)
                {
                    return ServiceResult<OrganizationCapabilityAssignmentResponse>.Failure(
                        $"Capability {capabilityCode} not found in master data");
                }

                var validationResult = await ValidateCapabilityAsync(organizationId, capability);
                if (!validationResult.Data?.IsValid == true)
                {
                    return ServiceResult<OrganizationCapabilityAssignmentResponse>.Failure(
                        string.Join(", ", validationResult.Data?.ValidationErrors ?? new List<string>()));
                }

                var existingAssignment = await _context.OrganizationCapabilityAssignments
                    .FirstOrDefaultAsync(a => a.OrganizationId == organizationId &&
                                             a.CapabilityId == capability.Id &&
                                             !a.IsDeleted);

                if (existingAssignment != null)
                {
                    return ServiceResult<OrganizationCapabilityAssignmentResponse>.Failure(
                        "Capability already assigned to organization");
                }

                var assignment = new OrganizationCapabilityAssignment
                {
                    OrganizationId = organizationId,
                    CapabilityId = capability.Id,
                    IsPrimary = false,
                    IsActive = request.ActivateImmediately,
                    Settings = request.Configuration,
                    AssignedAt = DateTime.UtcNow,
                    AssignedByConnectedId = assignedByConnectedId,
                    EnabledAt = request.ActivateImmediately ? DateTime.UtcNow : null,
                    ExpiresAt = request.ExpiresAt,
                    CreatedByConnectedId = assignedByConnectedId
                };

                await _context.OrganizationCapabilityAssignments.AddAsync(assignment);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                if (_eventHandler != null)
                {
                    await _eventHandler.HandleCapabilityAssignedAsync(new CapabilityAssignedEvent
                    {
                        OrganizationId = organizationId,
                        CapabilityAssignmentId = assignment.Id,
                        Capability = MapCodeToEnum(capability.Code),
                        Settings = request.Configuration,
                        IsActive = assignment.IsActive,
                        AssignedByConnectedId = assignedByConnectedId
                    });
                }

                var response = new OrganizationCapabilityAssignmentResponse
                {
                    Id = assignment.Id,
                    OrganizationId = organizationId,
                    CapabilityType = MapCodeToEnum(capability.Code),
                    IsActive = assignment.IsActive,
                    AssignedAt = assignment.AssignedAt ?? DateTime.UtcNow,
                    ExpiresAt = assignment.ExpiresAt,
                    AssignmentReason = request.AssignmentReason,
                    Configuration = assignment.Settings,
                    ApprovalStatus = capability.RequiresApproval ?
                        ApprovalStatus.Pending : ApprovalStatus.Approved,
                    CreatedAt = assignment.CreatedAt
                };

                return ServiceResult<OrganizationCapabilityAssignmentResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to assign capability to organization {OrganizationId}",
                    organizationId);
                return ServiceResult<OrganizationCapabilityAssignmentResponse>.Failure(
                    "Failed to assign capability");
            }
        }

        public async Task<ServiceResult> RemoveAsync(
            Guid organizationId,
            RemoveOrganizationCapabilityRequest request,
            Guid removedByConnectedId)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var assignment = await _context.OrganizationCapabilityAssignments
                    .Include(a => a.Capability)
                    .FirstOrDefaultAsync(a => a.Id == request.CapabilityAssignmentId &&
                                             a.OrganizationId == organizationId &&
                                             !a.IsDeleted);

                if (assignment == null)
                {
                    return ServiceResult.Failure("Capability assignment not found");
                }

                if (assignment.IsPrimary)
                {
                    return ServiceResult.Failure("Cannot remove primary capability");
                }

                assignment.IsDeleted = true;
                assignment.DeletedAt = DateTime.UtcNow;
                assignment.DeletedByConnectedId = removedByConnectedId;

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                if (_eventHandler != null)
                {
                    await _eventHandler.HandleCapabilityRemovedAsync(new CapabilityRemovedEvent
                    {
                        OrganizationId = organizationId,
                        CapabilityAssignmentId = assignment.Id,
                        Capability = assignment.Capability != null
            ? MapCodeToEnum(assignment.Capability.Code)
            : (OrganizationCapabilityEnum?)null,
                        Reason = request.RemovalReason,
                        RemovedByConnectedId = removedByConnectedId
                    });
                }

                return ServiceResult.Success("Capability removed successfully");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to remove capability from organization {OrganizationId}",
                    organizationId);
                return ServiceResult.Failure("Failed to remove capability");
            }
        }

        public async Task<ServiceResult<BulkOperationResult>> BulkAssignAsync(
            Guid organizationId,
            BulkAssignCapabilityRequest request,
            Guid assignedByConnectedId)
        {
            var result = new BulkOperationResult();
            var capabilityEntities = new List<OrganizationCapabilityEntity>();

            foreach (var capabilityEnum in request.Capabilities)
            {
                var capability = await _capabilityRepository.GetByCodeAsync(capabilityEnum.Code);
                if (capability != null)
                {
                    capabilityEntities.Add(capability);
                }
            }

            foreach (var capability in capabilityEntities)
            {
                var assignRequest = new AssignOrganizationCapabilityRequest
                {
                    CapabilityType = capability,
                    AssignmentReason = request.Reason ?? "Bulk assignment",
                    ActivateImmediately = request.ActivateImmediately,
                    Configuration = request.CapabilitySettings?.GetValueOrDefault(
                        new OrganizationCapabilityEntity { Code = capability.Code })
                };

                var assignResult = await AssignAsync(organizationId, assignRequest, assignedByConnectedId);

                if (assignResult.IsSuccess)
                {
                    result.SuccessCount++;
                }
                else
                {
                    result.FailureCount++;
                    result.Errors.Add(new BulkOperationError
                    {
                        EntityKey = capability.Code,
                        Reason = assignResult.ErrorMessage ?? "Unknown error"
                    });
                }
            }

            if (_eventHandler != null)
            {
                await _eventHandler.HandleBulkCapabilitiesAssignedAsync(new BulkCapabilitiesAssignedEvent
                {
                    OrganizationId = organizationId,
                    Capabilities = capabilityEntities.Select(c => MapCodeToEnum(c.Code)).ToList(),
                    SuccessCount = result.SuccessCount,
                    FailureCount = result.FailureCount,
                    FailureReasons = result.Errors.Select(e => e.Reason).ToList(),
                    AssignedByConnectedId = assignedByConnectedId
                });
            }

            return ServiceResult<BulkOperationResult>.Success(result);
        }

        #endregion

        #region Capability 설정 관리

        public async Task<ServiceResult<OrganizationCapabilityAssignmentResponse>> UpdateSettingsAsync(
            Guid capabilityAssignmentId,
            UpdateCapabilitySettingsRequest request,
            Guid updatedByConnectedId)
        {
            try
            {
                var assignment = await _context.OrganizationCapabilityAssignments
                    .Include(a => a.Capability)
                    .FirstOrDefaultAsync(a => a.Id == capabilityAssignmentId && !a.IsDeleted);

                if (assignment == null)
                {
                    return ServiceResult<OrganizationCapabilityAssignmentResponse>.Failure(
                        "Capability assignment not found");
                }

                var oldSettings = assignment.Settings;
                assignment.Settings = request.Settings;
                assignment.UpdatedAt = DateTime.UtcNow;
                assignment.UpdatedByConnectedId = updatedByConnectedId;

                await _context.SaveChangesAsync();

                if (_eventHandler != null)
                {
                    await _eventHandler.HandleCapabilitySettingsUpdatedAsync(new CapabilitySettingsUpdatedEvent
                    {
                        OrganizationId = assignment.OrganizationId,
                        CapabilityAssignmentId = assignment.Id,
                        Capability = assignment.Capability != null
            ? MapCodeToEnum(assignment.Capability.Code)
            : (OrganizationCapabilityEnum?)null,
                        OldSettings = oldSettings,
                        NewSettings = request.Settings,
                        EffectiveFrom = request.EffectiveFrom,
                        UpdatedByConnectedId = updatedByConnectedId
                    });
                }

                var response = _mapper.Map<OrganizationCapabilityAssignmentResponse>(assignment);
                return ServiceResult<OrganizationCapabilityAssignmentResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update capability settings {Id}", capabilityAssignmentId);
                return ServiceResult<OrganizationCapabilityAssignmentResponse>.Failure(
                    "Failed to update capability settings");
            }
        }

        public async Task<ServiceResult> SetActiveStatusAsync(
            Guid capabilityAssignmentId,
            bool isActive,
            Guid changedByConnectedId)
        {
            try
            {
                var assignment = await _context.OrganizationCapabilityAssignments
                    .Include(a => a.Capability)
                    .FirstOrDefaultAsync(a => a.Id == capabilityAssignmentId && !a.IsDeleted);

                if (assignment == null)
                {
                    return ServiceResult.Failure("Capability assignment not found");
                }

                var oldStatus = assignment.IsActive;
                assignment.IsActive = isActive;
                assignment.UpdatedAt = DateTime.UtcNow;
                assignment.UpdatedByConnectedId = changedByConnectedId;

                if (isActive && !oldStatus)
                {
                    assignment.EnabledAt = DateTime.UtcNow;
                }
                else if (!isActive && oldStatus)
                {
                    assignment.DisabledAt = DateTime.UtcNow;
                }

                await _context.SaveChangesAsync();

                if (_eventHandler != null)
                {
                    await _eventHandler.HandleCapabilityStatusChangedAsync(new CapabilityStatusChangedEvent
                    {
                        OrganizationId = assignment.OrganizationId,
                        CapabilityAssignmentId = assignment.Id,
                        Capability = assignment.Capability != null
            ? MapCodeToEnum(assignment.Capability.Code)
            : (OrganizationCapabilityEnum?)null,
                        OldIsActive = oldStatus,
                        NewIsActive = isActive,
                        ChangedByConnectedId = changedByConnectedId
                    });
                }

                return ServiceResult.Success($"Capability {(isActive ? "activated" : "deactivated")} successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set active status for capability {Id}", capabilityAssignmentId);
                return ServiceResult.Failure("Failed to update capability status");
            }
        }

        #endregion

        #region 사용 분석

        // IOrganizationCapabilityService에서 정의된 타입 사용
        public Task<ServiceResult<CapabilityUsageStatistics>> GetUsageStatisticsAsync(
            Guid organizationId,
            Guid? capabilityAssignmentId = null,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                var stats = new CapabilityUsageStatistics
                {
                    OrganizationId = organizationId,
                    PeriodStart = startDate ?? DateTime.UtcNow.AddMonths(-1),
                    PeriodEnd = endDate ?? DateTime.UtcNow,
                    Statistics = new Dictionary<string, decimal>()
                };

                stats.TotalTransactions = 0;
                stats.TotalRevenue = 0;
                stats.ActiveDays = 0;

                return Task.FromResult(ServiceResult<CapabilityUsageStatistics>.Success(stats));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get usage statistics for organization {OrganizationId}",
                    organizationId);
                return Task.FromResult(ServiceResult<CapabilityUsageStatistics>.Failure(
                    "Failed to retrieve usage statistics"));
            }
        }

        public Task<ServiceResult<IEnumerable<CapabilityChangeHistory>>> GetChangeHistoryAsync(
            Guid organizationId,
            DateTime? startDate = null,
            DateTime? endDate = null)
        {
            try
            {
                var history = new List<CapabilityChangeHistory>();
                return Task.FromResult(ServiceResult<IEnumerable<CapabilityChangeHistory>>.Success(history));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get change history for organization {OrganizationId}",
                    organizationId);
                return Task.FromResult(ServiceResult<IEnumerable<CapabilityChangeHistory>>.Failure(
                    "Failed to retrieve change history"));
            }
        }

        #endregion

        #region 검증 및 기타 메서드

        public async Task<ServiceResult<CapabilityValidationResult>> ValidateCapabilityAsync(
            Guid organizationId,
            OrganizationCapabilityEntity capability)
        {
            var result = new CapabilityValidationResult
            {
                IsValid = true,
                ValidationErrors = new List<string>()
            };

            try
            {
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    result.IsValid = false;
                    result.ValidationErrors.Add("Organization not found");
                    return ServiceResult<CapabilityValidationResult>.Success(result);
                }

                if (capability.RequiredPlan != null)
                {
                    result.MeetsPlanRequirements = true;
                }

                var currentCount = await _context.OrganizationCapabilityAssignments
                    .CountAsync(a => a.OrganizationId == organizationId && !a.IsDeleted);

                var planLimit = _planCapabilityLimits.GetValueOrDefault(organization.Type.ToString(), 1);
                if (planLimit != -1 && currentCount >= planLimit)
                {
                    result.IsValid = false;
                    result.ValidationErrors.Add($"Maximum capability limit ({planLimit}) reached for plan");
                }

                return ServiceResult<CapabilityValidationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate capability for organization {OrganizationId}",
                    organizationId);
                result.IsValid = false;
                result.ValidationErrors.Add("Validation failed");
                return ServiceResult<CapabilityValidationResult>.Success(result);
            }
        }

        public async Task<ServiceResult<CapabilityLimitsDto>> GetCapabilityLimitsAsync(
            Guid organizationId)
        {
            try
            {
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<CapabilityLimitsDto>.Failure("Organization not found");
                }

                var currentCount = await _context.OrganizationCapabilityAssignments
                    .CountAsync(a => a.OrganizationId == organizationId && !a.IsDeleted);

                var planLimit = _planCapabilityLimits.GetValueOrDefault(organization.Type.ToString(), 1);

                var limits = new CapabilityLimitsDto
                {
                    MaxCapabilities = planLimit == -1 ? int.MaxValue : planLimit,
                    CurrentCapabilityCount = currentCount,
                    RemainingCapabilities = planLimit == -1 ? int.MaxValue : Math.Max(0, planLimit - currentCount),
                    CurrentPlan = organization.Type.ToString(),
                    AllowedCapabilities = new List<OrganizationCapabilityEntity>
                    {
                        new() { Code = "CUSTOMER", Name = "Customer", Description = "Basic customer role" },
                        new() { Code = "RESELLER", Name = "Reseller", Description = "Can sell products" },
                        new() { Code = "PROVIDER", Name = "Provider", Description = "Can provide APIs/services" }
                    }
                };

                return ServiceResult<CapabilityLimitsDto>.Success(limits);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get capability limits for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<CapabilityLimitsDto>.Failure("Failed to retrieve capability limits");
            }
        }

        public async Task<ServiceResult<IEnumerable<InheritableCapabilityDto>>> GetInheritableCapabilitiesAsync(
            Guid organizationId)
        {
            try
            {
                var organization = await _context.Organizations
                    .Include(o => o.ParentOrganization)
                    .ThenInclude(p => p!.Capabilities)
                    .ThenInclude(c => c.Capability)
                    .FirstOrDefaultAsync(o => o.Id == organizationId && !o.IsDeleted);

                if (organization?.ParentOrganization == null)
                {
                    return ServiceResult<IEnumerable<InheritableCapabilityDto>>.Success(
                        new List<InheritableCapabilityDto>());
                }

                var inheritableCapabilities = organization.ParentOrganization.Capabilities?
                    .Where(c => c.IsActive && !c.IsDeleted && c.Capability != null)
                    .Select(c => new InheritableCapabilityDto
                    {
                        ParentOrganizationId = organization.ParentId ?? Guid.Empty,
                        ParentOrganizationName = organization.ParentOrganization.Name,
                        Capability = c.Capability,
                        IsCurrentlyInherited = false,
                        InheritanceSettings = c.Settings
                    })
                    .ToList() ?? new List<InheritableCapabilityDto>();

                return ServiceResult<IEnumerable<InheritableCapabilityDto>>.Success(inheritableCapabilities);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get inheritable capabilities for organization {OrganizationId}",
                    organizationId);
                return ServiceResult<IEnumerable<InheritableCapabilityDto>>.Failure(
                    "Failed to retrieve inheritable capabilities");
            }
        }

        public async Task<ServiceResult> SetInheritanceAsync(
            Guid parentOrganizationId,
            Guid childOrganizationId,
            SetCapabilityInheritanceRequest request,
            Guid setByConnectedId)
        {
            try
            {
                if (_eventHandler != null)
                {
                    await _eventHandler.HandleCapabilityInheritanceSetAsync(new CapabilityInheritanceSetEvent
                    {
                        ParentOrganizationId = parentOrganizationId,
                        ChildOrganizationId = childOrganizationId,
                        Capability = request.Capability != null
            ? MapCodeToEnum(request.Capability.Code)
            : (OrganizationCapabilityEnum?)null,
                        EnableInheritance = request.EnableInheritance,
                        AllowOverride = request.AllowOverride,
                        Reason = request.Reason,
                        SetByConnectedId = setByConnectedId
                    });
                }

                return ServiceResult.Success("Inheritance settings updated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to set inheritance for organizations {Parent} -> {Child}",
                    parentOrganizationId, childOrganizationId);
                return ServiceResult.Failure("Failed to set inheritance");
            }
        }

        private OrganizationCapabilityEnum MapCodeToEnum(string code)
        {
            return code?.ToUpper() switch
            {
                "CUSTOMER" => OrganizationCapabilityEnum.Customer,
                "RESELLER" => OrganizationCapabilityEnum.Reseller,
                "PROVIDER" => OrganizationCapabilityEnum.Provider,
                "PLATFORM" => OrganizationCapabilityEnum.Platform,
                "PARTNER" => OrganizationCapabilityEnum.Partner,
                _ => OrganizationCapabilityEnum.Customer
            };
        }

        #endregion
    }
}