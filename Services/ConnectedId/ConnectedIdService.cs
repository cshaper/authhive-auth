using AuthHive.Auth.Data.Context;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Business;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Repositories.Business.Platform; // CORRECT NAMESPACE
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using AuthHive.Core.Models.Auth.Events;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.Common;
using AutoMapper;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Services
{
    public class ConnectedIdService : IConnectedIdService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IOrganizationPlanRepository _organizationPlanRepository;
        private readonly ILogger<ConnectedIdService> _logger;
        private readonly IMapper _mapper;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEventBus _eventBus;
        private readonly IAuditService _auditService;
        private readonly ICacheService _cacheService;
        private readonly AuthDbContext _context;

        public ConnectedIdService(
            IUnitOfWork unitOfWork,
            IConnectedIdRepository connectedIdRepository,
            IOrganizationRepository organizationRepository,
            IOrganizationPlanRepository organizationPlanRepository,
            ILogger<ConnectedIdService> logger,
            IMapper mapper,
            IDateTimeProvider dateTimeProvider,
            IEventBus eventBus,
            IAuditService auditService,
            ICacheService cacheService,
            AuthDbContext context)
        {
            _unitOfWork = unitOfWork;
            _connectedIdRepository = connectedIdRepository;
            _organizationRepository = organizationRepository;
            _organizationPlanRepository = organizationPlanRepository;
            _logger = logger;
            _mapper = mapper;
            _dateTimeProvider = dateTimeProvider;
            _eventBus = eventBus;
            _auditService = auditService;
            _cacheService = cacheService;
            _context = context;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try { return await _context.Database.CanConnectAsync(); }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConnectedIdService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region CRUD Operations

        public async Task<ServiceResult<ConnectedIdResponse>> CreateAsync(CreateConnectedIdRequest request)
        {
            var createdByConnectedId = Guid.NewGuid();

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var validationResult = await ValidateMemberLimitAsync(request.OrganizationId, createdByConnectedId);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure(validationResult.ErrorMessage ?? "Validation failed with an unknown error.", validationResult.ErrorCode);
                }

                var existing = await _connectedIdRepository.GetByUserAndOrganizationAsync(request.UserId, request.OrganizationId);
                if (existing != null && !existing.IsDeleted)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure("User is already an active member of this organization.", "ALREADY_MEMBER");
                }

                var newEntity = _mapper.Map<ConnectedId>(request);
                newEntity.Status = ConnectedIdStatus.Active;
                newEntity.JoinedAt = _dateTimeProvider.UtcNow;

                await _connectedIdRepository.AddAsync(newEntity);
                await _eventBus.PublishAsync(new MemberAddedToOrganizationEvent(newEntity.Id, newEntity.UserId, newEntity.OrganizationId, createdByConnectedId));
                await _auditService.LogActionAsync(
                    performedByConnectedId: createdByConnectedId,
                    action: "Create ConnectedId",
                    actionType: AuditActionType.Create,
                    resourceType: nameof(ConnectedId),
                    resourceId: newEntity.Id.ToString()
                );
                await InvalidateOrganizationCache(request.OrganizationId);
                await _unitOfWork.CommitTransactionAsync();

                var response = _mapper.Map<ConnectedIdResponse>(newEntity);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error creating ConnectedId for User {UserId} in Organization {OrganizationId}", request.UserId, request.OrganizationId);
                return ServiceResult<ConnectedIdResponse>.Failure($"Failed to create ConnectedId: {ex.Message}", "CREATE_ERROR");
            }
        }

        public async Task<ServiceResult<ConnectedIdResponse>> UpdateAsync(Guid id, UpdateConnectedIdRequest request)
        {
            var updatedByConnectedId = Guid.NewGuid();

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null)
                {
                    return ServiceResult<ConnectedIdResponse>.NotFound("ConnectedId not found.");
                }

                var originalStatus = entity.Status;
                _mapper.Map(request, entity);
                entity.UpdatedAt = _dateTimeProvider.UtcNow;

                await _connectedIdRepository.UpdateAsync(entity);

                if (originalStatus != entity.Status)
                {
                    await _eventBus.PublishAsync(new MemberStatusChangedEvent(id, entity.UserId, entity.OrganizationId, entity.Status, updatedByConnectedId));
                }
                await _auditService.LogActionAsync(
                    performedByConnectedId: updatedByConnectedId,
                    action: "Update ConnectedId",
                    actionType: AuditActionType.Update,
                    resourceType: nameof(ConnectedId),
                    resourceId: entity.Id.ToString()
                );

                await InvalidateSingleConnectedIdCache(id, entity.OrganizationId, entity.UserId);
                await _unitOfWork.CommitTransactionAsync();

                var response = _mapper.Map<ConnectedIdResponse>(entity);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error updating ConnectedId: {Id}", id);
                return ServiceResult<ConnectedIdResponse>.Failure($"Failed to update ConnectedId: {ex.Message}", "UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid id)
        {
            var deletedByConnectedId = Guid.NewGuid();

            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null || entity.IsDeleted)
                {
                    return ServiceResult.NotFound("ConnectedId not found.");
                }

                entity.IsDeleted = true;
                entity.DeletedAt = _dateTimeProvider.UtcNow;
                entity.Status = ConnectedIdStatus.Inactive;

                await _connectedIdRepository.UpdateAsync(entity);
                await _eventBus.PublishAsync(new MemberRemovedFromOrganizationEvent(entity.Id, entity.UserId, entity.OrganizationId, deletedByConnectedId));
                await _auditService.LogActionAsync(
               performedByConnectedId: deletedByConnectedId,
               action: "Delete ConnectedId (Soft)",
               actionType: AuditActionType.Delete,
               resourceType: nameof(ConnectedId),
               resourceId: entity.Id.ToString()
           );
                await InvalidateSingleConnectedIdCache(id, entity.OrganizationId, entity.UserId);
                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult.Success("ConnectedId deleted successfully.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error deleting ConnectedId: {Id}", id);
                return ServiceResult.Failure($"Failed to delete ConnectedId: {ex.Message}", "DELETE_ERROR");
            }
        }

        public async Task<ServiceResult<ConnectedId>> GetOrCreateAsync(Guid userId, Guid organizationId)
        {
            var existingEntity = await _connectedIdRepository.GetByUserAndOrganizationAsync(userId, organizationId);
            if (existingEntity != null)
            {
                return ServiceResult<ConnectedId>.Success(existingEntity);
            }

            var createRequest = new CreateConnectedIdRequest { UserId = userId, OrganizationId = organizationId };
            var creationResult = await CreateAsync(createRequest);

            if (!creationResult.IsSuccess)
            {
                return ServiceResult<ConnectedId>.Failure(creationResult.ErrorMessage ?? "Failed to create ConnectedId for an unknown reason.", creationResult.ErrorCode);
            }
            if (creationResult.Data == null)
            {
                return ServiceResult<ConnectedId>.Failure("Creation succeeded but returned no data.", "DATA_INCONSISTENCY");
            }
            var newEntity = await _connectedIdRepository.GetByIdAsync(creationResult.Data.Id);
            if (newEntity == null)
            {
                return ServiceResult<ConnectedId>.Failure("Failed to retrieve the newly created ConnectedId.", "RETRIEVAL_ERROR");
            }
            return ServiceResult<ConnectedId>.Success(newEntity);
        }

        #endregion

        #region Query Operations

        public async Task<ServiceResult<ConnectedIdDetailResponse>> GetByIdAsync(Guid id)
        {
            var cacheKey = $"cache:connectedid:{id}";
            var cachedResponse = await _cacheService.GetAsync<ConnectedIdDetailResponse>(cacheKey);
            if (cachedResponse != null) return ServiceResult<ConnectedIdDetailResponse>.Success(cachedResponse);

            try
            {
                var entity = await _connectedIdRepository.GetWithRelatedDataAsync(id, includeUser: true, includeOrganization: true);
                if (entity == null) return ServiceResult<ConnectedIdDetailResponse>.NotFound("ConnectedId not found.");

                var response = _mapper.Map<ConnectedIdDetailResponse>(entity);
                await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromHours(1));
                return ServiceResult<ConnectedIdDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedId by ID: {Id}", id);
                return ServiceResult<ConnectedIdDetailResponse>.Failure($"Failed to get ConnectedId: {ex.Message}", "GET_ERROR");
            }
        }

        public async Task<ServiceResult<ConnectedIdListResponse>> GetByOrganizationAsync(Guid organizationId, SearchConnectedIdsRequest request)
        {
            try
            {
                var (pagedEntities, totalCount) = await _connectedIdRepository.GetPagedAsync(
                    request.PageNumber, request.PageSize,
                    predicate: c => c.OrganizationId == organizationId && !c.IsDeleted,
                    orderBy: c => c.CreatedAt, isDescending: true
                );

                var response = new ConnectedIdListResponse
                {
                    Items = _mapper.Map<List<ConnectedIdResponse>>(pagedEntities),
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };
                return ServiceResult<ConnectedIdListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedIds by organization: {OrgId}", organizationId);
                return ServiceResult<ConnectedIdListResponse>.Failure($"Failed to get organization members: {ex.Message}", "QUERY_ERROR");
            }
        }

        public async Task<ServiceResult<IEnumerable<ConnectedIdResponse>>> GetByUserAsync(Guid userId)
        {
            var cacheKey = $"cache:user:{userId}:connections";
            var cachedConnections = await _cacheService.GetAsync<IEnumerable<ConnectedIdResponse>>(cacheKey);
            if (cachedConnections != null) return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(cachedConnections);

            try
            {
                var entities = await _connectedIdRepository.GetByUserIdAsync(userId);
                var response = _mapper.Map<IEnumerable<ConnectedIdResponse>>(entities);
                await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(10));
                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedIds by user: {UserId}", userId);
                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Failure($"Failed to get user connections: {ex.Message}", "QUERY_ERROR");
            }
        }

        public async Task<ServiceResult<Guid>> GetActiveConnectedIdByUserIdAsync(Guid userId)
        {
            try
            {
                var allConnections = await _connectedIdRepository.GetByUserIdAsync(userId);
                var activeConnection = allConnections
                    .Where(c => c.Status == ConnectedIdStatus.Active && !c.IsDeleted)
                    .OrderByDescending(c => c.LastActiveAt)
                    .FirstOrDefault();

                if (activeConnection == null)
                {
                    return ServiceResult<Guid>.NotFound("No active ConnectedId found for the user.");
                }
                return ServiceResult<Guid>.Success(activeConnection.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active ConnectedId for User: {UserId}", userId);
                return ServiceResult<Guid>.Failure($"Failed to get active connection: {ex.Message}", "QUERY_ERROR");
            }
        }

        #endregion

        #region Activity & Validation

        public async Task<ServiceResult> UpdateLastActivityAsync(Guid id)
        {
            await _unitOfWork.BeginTransactionAsync();
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null || entity.IsDeleted)
                {
                    return ServiceResult.NotFound("ConnectedId not found to update activity.");
                }

                entity.LastActiveAt = _dateTimeProvider.UtcNow;
                await _connectedIdRepository.UpdateAsync(entity);
                await InvalidateSingleConnectedIdCache(id, entity.OrganizationId, entity.UserId);
                await _unitOfWork.CommitTransactionAsync();

                return ServiceResult.Success("Last activity updated.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error updating last activity: {Id}", id);
                return ServiceResult.Failure($"Failed to update last activity: {ex.Message}", "UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult> ValidateConnectedIdAsync(Guid connectedId)
        {
            var validationResult = await ValidateAsync(connectedId);
            if (!validationResult.IsSuccess) return ServiceResult.Failure(validationResult.ErrorMessage ?? "Validation check failed unexpectedly.", validationResult.ErrorCode);
            if (!validationResult.Data) return ServiceResult.Failure("ConnectedId is not valid (inactive or deleted).", "VALIDATION_FAILED");
            return ServiceResult.Success("ConnectedId is valid.");
        }

        public async Task<ServiceResult<bool>> ValidateAsync(Guid id)
        {
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                var isValid = entity != null && entity.Status == ConnectedIdStatus.Active && !entity.IsDeleted;
                return ServiceResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating ConnectedId: {Id}", id);
                return ServiceResult<bool>.Failure($"Failed to validate: {ex.Message}", "VALIDATION_ERROR");
            }
        }

        public async Task<ServiceResult<bool>> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId)
        {
            try
            {
                var isMember = await _connectedIdRepository.IsMemberOfOrganizationAsync(userId, organizationId);
                return ServiceResult<bool>.Success(isMember);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking membership for User {UserId} in Org {OrgId}", userId, organizationId);
                return ServiceResult<bool>.Failure($"Failed to check membership: {ex.Message}", "QUERY_ERROR");
            }
        }

        #endregion

        #region Private Helpers

        private async Task<ServiceResult> ValidateMemberLimitAsync(Guid organizationId, Guid? triggeredBy)
        {
            var plan = await _organizationPlanRepository.GetActivePlanByOrganizationIdAsync(organizationId);
            var planKey = plan?.PlanKey ?? PricingConstants.DefaultPlanKey;

            if (!PricingConstants.SubscriptionPlans.MemberLimits.TryGetValue(planKey, out var memberLimit))
            {
                _logger.LogWarning("Member limit for plan key '{PlanKey}' not found. Falling back to default.", planKey);
                memberLimit = PricingConstants.SubscriptionPlans.MemberLimits[PricingConstants.DefaultPlanKey];
            }

            if (memberLimit == -1) return ServiceResult.Success();

            var activeMembers = await _connectedIdRepository.GetByOrganizationAndStatusAsync(organizationId, ConnectedIdStatus.Active);
            var currentMemberCount = activeMembers.Count();

            if (currentMemberCount >= memberLimit)
            {
                var errorMessage = $"Organization member limit of {memberLimit} for the '{planKey}' plan has been exceeded.";
                var limitEvent = new PlanLimitReachedEvent(organizationId, planKey, PlanLimitType.OrganizationMemberCount, currentMemberCount, memberLimit, triggeredBy);
                await _eventBus.PublishAsync(limitEvent);
                return ServiceResult.Failure(errorMessage, "PLAN_LIMIT_EXCEEDED");
            }

            return ServiceResult.Success();
        }

        private async Task InvalidateOrganizationCache(Guid organizationId)
        {
            await _cacheService.RemoveAsync($"cache:org:{organizationId}:members:page:1:size:10");
        }

        private async Task InvalidateSingleConnectedIdCache(Guid id, Guid organizationId, Guid userId)
        {
            await _cacheService.RemoveAsync($"cache:connectedid:{id}");
            await _cacheService.RemoveAsync($"cache:user:{userId}:connections");
            await _cacheService.RemoveAsync($"cache:user:{userId}:active-connectedid");
            await _cacheService.RemoveAsync($"cache:org:{organizationId}:ismember:{userId}");
            await InvalidateOrganizationCache(organizationId);
        }

        #endregion
    }
}