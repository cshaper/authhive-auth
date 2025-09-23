using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
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
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly ILogger<ConnectedIdService> _logger;
        private readonly IMapper _mapper;
        private readonly AuthDbContext _context;
        private readonly IDateTimeProvider _dateTimeProvider;

        public ConnectedIdService(
            IConnectedIdRepository connectedIdRepository,
            ILogger<ConnectedIdService> logger,
            IMapper mapper,
            AuthDbContext context,
            IDateTimeProvider dateTimeProvider)
        {
            _connectedIdRepository = connectedIdRepository;
            _logger = logger;
            _mapper = mapper;
            _context = context;
            _dateTimeProvider = dateTimeProvider;
        }

        #region IService Implementation
        public async Task<ServiceResult<Core.Entities.Auth.ConnectedId>> GetOrCreateAsync(Guid userId, Guid organizationId)
        {
            try
            {
                // 1. 먼저 기존 ConnectedId가 있는지 찾아봅니다.
                var existingEntity = await _connectedIdRepository.GetByUserAndOrganizationAsync(userId, organizationId);
                if (existingEntity != null)
                {
                    // 이미 존재하면 찾은 엔티티를 반환합니다.
                    return ServiceResult<Core.Entities.Auth.ConnectedId>.Success(existingEntity);
                }

                // 2. 존재하지 않으면 새로 생성합니다.
                var newEntity = new Core.Entities.Auth.ConnectedId
                {
                    UserId = userId,
                    OrganizationId = organizationId,
                    Status = ConnectedIdStatus.Active,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    JoinedAt = _dateTimeProvider.UtcNow
                };

                await _connectedIdRepository.AddAsync(newEntity);

                _logger.LogInformation("Created new ConnectedId for User {UserId} in Organization {OrganizationId}", userId, organizationId);

                // 새로 생성한 엔티티를 반환합니다.
                return ServiceResult<Core.Entities.Auth.ConnectedId>.Success(newEntity);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GetOrCreateAsync for User {UserId}, Organization {OrganizationId}", userId, organizationId);
                return ServiceResult<Core.Entities.Auth.ConnectedId>.Failure(
                    $"Failed to get or create ConnectedId: {ex.Message}",
                    "GET_OR_CREATE_ERROR");
            }
        }
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // DB 연결 가능 여부와 Repository 기본 동작 여부 확인
                return await _context.Database.CanConnectAsync();
            }
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
            try
            {
                // 중복 확인
                var existing = await _connectedIdRepository.GetByUserAndOrganizationAsync(
                    request.UserId,
                    request.OrganizationId);

                if (existing != null)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure(
                        "User is already a member of this organization.",
                        "ALREADY_MEMBER");
                }

                var newEntity = _mapper.Map<AuthHive.Core.Entities.Auth.ConnectedId>(request);

                // 기본값 설정
                newEntity.Status = ConnectedIdStatus.Active;
                newEntity.CreatedAt = _dateTimeProvider.UtcNow;
                newEntity.JoinedAt = _dateTimeProvider.UtcNow;
                // IsDefault 속성 제거 (엔티티에 없음)

                await _connectedIdRepository.AddAsync(newEntity);

                var response = _mapper.Map<ConnectedIdResponse>(newEntity);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating ConnectedId");
                return ServiceResult<ConnectedIdResponse>.Failure(
                    $"Failed to create ConnectedId: {ex.Message}",
                    "CREATE_ERROR");
            }
        }

        public async Task<ServiceResult<ConnectedIdDetailResponse>> GetByIdAsync(Guid id)
        {
            try
            {
                var entity = await _connectedIdRepository.GetWithRelatedDataAsync(
                    id,
                    includeUser: true,
                    includeOrganization: true);

                if (entity == null)
                {
                    return ServiceResult<ConnectedIdDetailResponse>.NotFound(
                        "ConnectedId not found.");
                }

                var response = _mapper.Map<ConnectedIdDetailResponse>(entity);
                return ServiceResult<ConnectedIdDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedId by ID: {Id}", id);
                return ServiceResult<ConnectedIdDetailResponse>.Failure(
                    $"Failed to get ConnectedId: {ex.Message}",
                    "GET_ERROR");
            }
        }

        public async Task<ServiceResult<ConnectedIdResponse>> UpdateAsync(Guid id, UpdateConnectedIdRequest request)
        {
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null)
                {
                    return ServiceResult<ConnectedIdResponse>.NotFound(
                        "ConnectedId not found.");
                }

                _mapper.Map(request, entity);
                entity.UpdatedAt = _dateTimeProvider.UtcNow;

                await _connectedIdRepository.UpdateAsync(entity);

                var response = _mapper.Map<ConnectedIdResponse>(entity);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating ConnectedId: {Id}", id);
                return ServiceResult<ConnectedIdResponse>.Failure(
                    $"Failed to update ConnectedId: {ex.Message}",
                    "UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid id)
        {
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null)
                {
                    return ServiceResult.NotFound("ConnectedId not found.");
                }

                // Soft delete
                entity.IsDeleted = true;
                entity.DeletedAt = _dateTimeProvider.UtcNow;
                entity.Status = ConnectedIdStatus.Inactive;

                await _connectedIdRepository.UpdateAsync(entity);

                return ServiceResult.Success("ConnectedId deleted successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting ConnectedId: {Id}", id);
                return ServiceResult.Failure(
                    $"Failed to delete ConnectedId: {ex.Message}",
                    "DELETE_ERROR");
            }
        }

        #endregion

        #region Query Operations

        public async Task<ServiceResult<ConnectedIdListResponse>> GetByOrganizationAsync(
            Guid organizationId,
            SearchConnectedIdsRequest request)
        {
            try
            {
                // 조직 내 ConnectedId 조회 - Status로 필터링
                var entities = await _connectedIdRepository.GetByOrganizationAndStatusAsync(
                    organizationId,
                    ConnectedIdStatus.Active);

                // 페이징 처리
                var pageNumber = request?.PageNumber ?? 1;
                var pageSize = request?.PageSize ?? 10;

                var paged = entities
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .ToList();

                var response = new ConnectedIdListResponse
                {
                    Items = _mapper.Map<List<ConnectedIdResponse>>(paged),
                    TotalCount = entities.Count(),
                    PageNumber = pageNumber,
                    PageSize = pageSize
                };

                return ServiceResult<ConnectedIdListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedIds by organization: {OrgId}", organizationId);
                return ServiceResult<ConnectedIdListResponse>.Failure(
                    $"Failed to get organization members: {ex.Message}",
                    "QUERY_ERROR");
            }
        }

        public async Task<ServiceResult<IEnumerable<ConnectedIdResponse>>> GetByUserAsync(Guid userId)
        {
            try
            {
                var entities = await _connectedIdRepository.GetByUserIdAsync(userId);
                var response = _mapper.Map<IEnumerable<ConnectedIdResponse>>(entities);
                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting ConnectedIds by user: {UserId}", userId);
                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Failure(
                    $"Failed to get user connections: {ex.Message}",
                    "QUERY_ERROR");
            }
        }

        #endregion

        #region Activity & Validation

        public async Task<ServiceResult> UpdateLastActivityAsync(Guid id)
        {
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                if (entity == null)
                {
                    return ServiceResult.NotFound("ConnectedId not found.");
                }

                // LastActiveAt 속성 사용 (LastActivityAt 대신)
                entity.LastActiveAt = _dateTimeProvider.UtcNow;
                await _connectedIdRepository.UpdateAsync(entity);

                return ServiceResult.Success("Last activity updated.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating last activity: {Id}", id);
                return ServiceResult.Failure(
                    $"Failed to update last activity: {ex.Message}",
                    "UPDATE_ERROR");
            }
        }

        public async Task<ServiceResult<bool>> ValidateAsync(Guid id)
        {
            try
            {
                var entity = await _connectedIdRepository.GetByIdAsync(id);
                var isValid = entity != null
                    && !entity.IsDeleted
                    && entity.Status == ConnectedIdStatus.Active;

                return ServiceResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating ConnectedId: {Id}", id);
                return ServiceResult<bool>.Failure(
                    $"Failed to validate: {ex.Message}",
                    "VALIDATION_ERROR");
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
                _logger.LogError(ex, "Error checking membership: User {UserId}, Org {OrgId}",
                    userId, organizationId);
                return ServiceResult<bool>.Failure(
                    $"Failed to check membership: {ex.Message}",
                    "QUERY_ERROR");
            }
        }

        /// <summary>
        /// ConnectedId 유효성 검증
        /// </summary>
        public async Task<ServiceResult> ValidateConnectedIdAsync(Guid connectedId)
        {
            try
            {
                // ConnectedId 존재 확인
                var connected = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connected == null)
                {
                    return ServiceResult.NotFound("ConnectedId not found");
                }

                // 상태 확인
                if (connected.Status != ConnectedIdStatus.Active)
                {
                    return ServiceResult.Failure(
                        $"ConnectedId is not active: {connected.Status}",
                        "CONNECTED_ID_INACTIVE");
                }

                // 삭제 여부 확인
                if (connected.IsDeleted)
                {
                    return ServiceResult.Failure(
                        "ConnectedId has been deleted",
                        "CONNECTED_ID_DELETED");
                }

                return ServiceResult.Success("ConnectedId is valid");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult.Failure(
                    $"Failed to validate ConnectedId: {ex.Message}",
                    "VALIDATION_ERROR");
            }
        }

        #endregion
    }
}