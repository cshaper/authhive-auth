using AutoMapper;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Models.Auth.Permissions.Requests;
using AuthHive.Core.Models.Auth.Permissions.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PermissionEntity = AuthHive.Core.Entities.Auth.Permission;
using static AuthHive.Core.Enums.Auth.PermissionEnums;

namespace AuthHive.Auth.Services.Authentication
{
    public class PermissionService : IPermissionService
    {
        private readonly IPermissionRepository _permissionRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ILogger<PermissionService> _logger;

        public PermissionService(
            IPermissionRepository permissionRepository,
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ILogger<PermissionService> logger)
        {
            _permissionRepository = permissionRepository;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                await _permissionRepository.AnyAsync(p => true);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Permission service health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("PermissionService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region Standard CRUD (from IService<T>)

        public async Task<ServiceResult<PermissionDto>> CreateAsync(CreatePermissionRequest request)
        {
            try
            {
                var existing = await _permissionRepository.FirstOrDefaultAsync(p => p.Scope == request.Scope);
                if (existing != null)
                {
                    return ServiceResult<PermissionDto>.Failure($"Permission with scope '{request.Scope}' already exists.", PermissionConstants.ErrorCodes.DuplicateScope);
                }

                var permission = _mapper.Map<PermissionEntity>(request);
                var createdPermission = await _permissionRepository.AddAsync(permission);
                await _unitOfWork.SaveChangesAsync();

                var permissionDto = _mapper.Map<PermissionDto>(createdPermission);
                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating permission: {Scope}", request.Scope);
                return ServiceResult<PermissionDto>.Failure("An error occurred while creating permission.", PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<PermissionDto>> GetByIdAsync(Guid id)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.Failure("Permission not found", PermissionConstants.ErrorCodes.PermissionNotFound);
                }
                var permissionDto = _mapper.Map<PermissionDto>(permission);
                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission by ID: {Id}", id);
                return ServiceResult<PermissionDto>.Failure("An error occurred while retrieving permission.", PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        
        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetAllAsync()
        {
            try
            {
                var permissions = await _permissionRepository.GetAllAsync();
                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);
                return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving all permissions.");
                return ServiceResult<IEnumerable<PermissionDto>>.Failure("An error occurred while retrieving permissions.", PermissionConstants.ErrorCodes.DatabaseError);
            }
        }
        
        public async Task<ServiceResult<PermissionDto>> UpdateAsync(Guid id, UpdatePermissionRequest request)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.Failure("Permission not found", PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                _mapper.Map(request, permission);
                await _permissionRepository.UpdateAsync(permission);
                await _unitOfWork.SaveChangesAsync();

                var permissionDto = _mapper.Map<PermissionDto>(permission);
                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating permission: {Id}", id);
                return ServiceResult<PermissionDto>.Failure("An error occurred while updating permission.", PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult> DeleteAsync(Guid id)
        {
            try
            {
                var permission = await _permissionRepository.GetByIdAsync(id);
                if (permission == null)
                {
                    return ServiceResult.Failure("Permission not found", PermissionConstants.ErrorCodes.PermissionNotFound);
                }

                await _permissionRepository.DeleteAsync(permission);
                await _unitOfWork.SaveChangesAsync();
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting permission: {Id}", id);
                return ServiceResult.Failure("An error occurred while deleting permission.", PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<PagedResult<PermissionDto>>> GetPagedAsync(PaginationRequest request)
        {
            try
            {
                var (items, totalCount) = await _permissionRepository.GetPagedAsync(
                    request.PageNumber,
                    request.PageSize,
                    null,
                    p => p.Scope
                );

                var dtos = _mapper.Map<IEnumerable<PermissionDto>>(items);
                var pagedResult = new PagedResult<PermissionDto>(dtos, totalCount, request.PageNumber, request.PageSize);
                return ServiceResult<PagedResult<PermissionDto>>.Success(pagedResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving paged permissions.");
                return ServiceResult<PagedResult<PermissionDto>>.Failure("An error occurred while retrieving paged permissions.", PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        // [오류 수정] IService<T>에 정의된 나머지 메서드들 구현
        public Task<ServiceResult<bool>> ExistsAsync(Guid id) => throw new NotImplementedException();
        public Task<ServiceResult<int>> CountAsync() => throw new NotImplementedException();
        public Task<ServiceResult<IEnumerable<PermissionDto>>> CreateBulkAsync(IEnumerable<CreatePermissionRequest> requests) => throw new NotImplementedException();
        public Task<ServiceResult<IEnumerable<PermissionDto>>> UpdateBulkAsync(IEnumerable<(Guid Id, UpdatePermissionRequest Request)> updates) => throw new NotImplementedException();
        public Task<ServiceResult> DeleteBulkAsync(IEnumerable<Guid> ids) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> ValidateCreateAsync(CreatePermissionRequest request) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> ValidateUpdateAsync(Guid id, UpdatePermissionRequest request) => throw new NotImplementedException();
        
        #endregion

        #region Domain-Specific Queries (from IPermissionService)

        public async Task<ServiceResult<PermissionDto>> GetByScopeAsync(string scope)
        {
             try
            {
                var permission = await _permissionRepository.FirstOrDefaultAsync(p => p.Scope == scope);
                if (permission == null)
                {
                    return ServiceResult<PermissionDto>.Failure($"Permission with scope '{scope}' not found", PermissionConstants.ErrorCodes.PermissionNotFound);
                }
                var permissionDto = _mapper.Map<PermissionDto>(permission);
                return ServiceResult<PermissionDto>.Success(permissionDto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving permission by scope: {Scope}", scope);
                return ServiceResult<PermissionDto>.Failure("An error occurred while retrieving permission.", PermissionConstants.ErrorCodes.DatabaseError);
            }
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetByCategoryAsync(string category, bool includeInactive = false)
        {
            if (!Enum.TryParse<PermissionCategory>(category, true, out var categoryEnum))
            {
                return ServiceResult<IEnumerable<PermissionDto>>.Failure($"Invalid category: {category}", "INVALID_PARAMETER");
            }

            var query = _permissionRepository.Query().Where(p => p.Category == categoryEnum);
            if (!includeInactive)
            {
                query = query.Where(p => p.IsActive);
            }
            
            var permissions = await query.ToListAsync();
            var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);
            return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetByResourceTypeAsync(string resourceType)
        {
            var permissions = await _permissionRepository.FindAsync(p => p.ResourceType == resourceType);
            var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);
            return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
        }

        public async Task<ServiceResult<bool>> ExistsByScopeAsync(string scope)
        {
            var exists = await _permissionRepository.AnyAsync(p => p.Scope == scope);
            return ServiceResult<bool>.Success(exists);
        }

        #endregion

        #region Hierarchy Queries (from IPermissionService)

        public async Task<ServiceResult<PermissionTreeResponse>> GetTreeAsync(Guid? rootPermissionId = null, int? maxDepth = null)
        {
            // This requires a more complex recursive implementation. Placeholder for now.
            var permissions = await _permissionRepository.GetAllAsync();
            var nodes = _mapper.Map<List<PermissionNode>>(permissions);
            return ServiceResult<PermissionTreeResponse>.Success(new PermissionTreeResponse { Nodes = nodes });
        }

        public async Task<ServiceResult<IEnumerable<PermissionDto>>> GetChildrenAsync(Guid parentPermissionId, bool includeInactive = false)
        {
            var query = _permissionRepository.Query().Where(p => p.ParentPermissionId == parentPermissionId);
            if (!includeInactive)
            {
                query = query.Where(p => p.IsActive);
            }
            var permissions = await query.ToListAsync();
            var dtos = _mapper.Map<IEnumerable<PermissionDto>>(permissions);
            return ServiceResult<IEnumerable<PermissionDto>>.Success(dtos);
        }

        #endregion
    }
}