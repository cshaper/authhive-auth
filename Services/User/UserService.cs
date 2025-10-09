using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Requests;
using AuthHive.Core.Models.User;
using AuthHive.Core.Models.User.Requests;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Core.UserEnums;
// User 엔티티를 별칭으로 정의
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UserService> _logger;

        public UserService(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ILogger<UserService> logger)
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        #region IService (Non-Generic) Implementation
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) 
        {
            // The implementation remains efficient by returning a completed task with the result.
            return Task.FromResult(true);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) 
        {
            _logger.LogInformation("UserService initialized.");
            // The implementation remains optimized by returning Task.CompletedTask directly.
            return Task.CompletedTask;
        }
        #endregion

        #region IService<T> Generic Implementation
        public async Task<ServiceResult<UserDto>> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var user = await _userRepository.GetByIdAsync(id);
            if (user == null) return ServiceResult<UserDto>.Failure("User not found.");
            return ServiceResult<UserDto>.Success(MapToDto(user)!);
        }

        public async Task<ServiceResult<IEnumerable<UserDto>>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var users = await _userRepository.GetAllAsync();
            var dtos = users.Select(MapToDto).Where(dto => dto is not null).Cast<UserDto>().ToList();
            return ServiceResult<IEnumerable<UserDto>>.Success(dtos);
        }

        public async Task<ServiceResult<PagedResult<UserDto>>> GetPagedAsync(PaginationRequest request, CancellationToken cancellationToken = default)
        {
            var (items, totalCount) = await _userRepository.GetPagedAsync(request.PageNumber, request.PageSize);
            var dtoList = items.Select(MapToDto).Where(dto => dto is not null).Cast<UserDto>().ToList();
            var result = new PagedResult<UserDto>
            {
                Items = dtoList,
                TotalCount = totalCount,
                PageNumber = request.PageNumber,
                PageSize = request.PageSize
            };
            return ServiceResult<PagedResult<UserDto>>.Success(result);
        }

        public async Task<ServiceResult<UserDto>> CreateAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
        {
            var validation = await ValidateCreateAsync(request);
            if (!validation.IsSuccess || !validation.Data)
                return ServiceResult<UserDto>.Failure(validation.ErrorMessage ?? "Validation failed.");

            var newUser = new UserEntity
            {
                Id = Guid.NewGuid(),
                Email = request.Email ?? string.Empty,
                Username = request.Username,
                DisplayName = request.DisplayName,
                Status = UserStatus.Active,
                ExternalSystemType = request.ExternalSystemType,
                ExternalUserId = request.ExternalUserId,
                CreatedAt = DateTime.UtcNow,
                IsEmailVerified = false,
                IsTwoFactorEnabled = false
            };

            var createdUser = await _userRepository.AddAsync(newUser);
            var dto = MapToDto(createdUser);
            return dto != null
                ? ServiceResult<UserDto>.Success(dto)
                : ServiceResult<UserDto>.Failure("Failed to map created user");
        }

        public async Task<ServiceResult<UserDto>> UpdateAsync(Guid id, UpdateUserRequest request, CancellationToken cancellationToken = default)
        {
            var validation = await ValidateUpdateAsync(id, request);
            if (!validation.IsSuccess || !validation.Data)
                return ServiceResult<UserDto>.Failure(validation.ErrorMessage ?? "Validation failed.");

            var userToUpdate = await _userRepository.GetByIdAsync(id);
            if (userToUpdate == null)
                return ServiceResult<UserDto>.Failure("User not found.");

            if (!string.IsNullOrEmpty(request.DisplayName))
                userToUpdate.DisplayName = request.DisplayName;

            if (request.Status.HasValue)
                userToUpdate.Status = request.Status.Value;

            if (request.IsTwoFactorEnabled.HasValue)
                userToUpdate.IsTwoFactorEnabled = request.IsTwoFactorEnabled.Value;

            userToUpdate.UpdatedAt = DateTime.UtcNow;

            await _userRepository.UpdateAsync(userToUpdate);
            var dto = MapToDto(userToUpdate);
            return dto != null
                ? ServiceResult<UserDto>.Success(dto)
                : ServiceResult<UserDto>.Failure("Failed to map updated user");
        }

        public async Task<ServiceResult> DeleteAsync(Guid id)
        {
            await _userRepository.SoftDeleteAsync(id);
            return ServiceResult.Success();
        }

        public async Task<ServiceResult<bool>> ExistsAsync(Guid id)
        {
            var exists = await _userRepository.ExistsAsync(id);
            return ServiceResult<bool>.Success(exists);
        }

        public async Task<ServiceResult<int>> CountAsync()
        {
            var count = await _userRepository.CountAsync();
            return ServiceResult<int>.Success(count);
        }

        public async Task<ServiceResult<IEnumerable<UserDto>>> CreateBulkAsync(IEnumerable<CreateUserRequest> requests)
        {
            var newUsers = new List<UserEntity>();
            foreach (var request in requests)
            {
                newUsers.Add(new UserEntity
                {
                    Id = Guid.NewGuid(),
                    Email = request.Email ?? string.Empty,
                    Username = request.Username,
                    DisplayName = request.DisplayName,
                    Status = UserStatus.Active,
                    ExternalSystemType = request.ExternalSystemType,
                    ExternalUserId = request.ExternalUserId,
                    CreatedAt = DateTime.UtcNow,
                    IsEmailVerified = false,
                    IsTwoFactorEnabled = false
                });
            }
            await _userRepository.AddRangeAsync(newUsers);
            var dtos = newUsers.Select(MapToDto).Where(dto => dto is not null).Cast<UserDto>();
            return ServiceResult<IEnumerable<UserDto>>.Success(dtos);
        }

        public async Task<ServiceResult<IEnumerable<UserDto>>> UpdateBulkAsync(IEnumerable<(Guid Id, UpdateUserRequest Request)> updates)
        {
            var updatedUsers = new List<UserEntity>();
            foreach (var (id, request) in updates)
            {
                var user = await _userRepository.GetByIdAsync(id);
                if (user != null)
                {
                    if (!string.IsNullOrEmpty(request.DisplayName))
                        user.DisplayName = request.DisplayName;

                    if (request.Status.HasValue)
                        user.Status = request.Status.Value;

                    if (request.IsTwoFactorEnabled.HasValue)
                        user.IsTwoFactorEnabled = request.IsTwoFactorEnabled.Value;

                    user.UpdatedAt = DateTime.UtcNow;
                    updatedUsers.Add(user);
                }
            }
            await _userRepository.UpdateRangeAsync(updatedUsers);
            var dtos = updatedUsers.Select(MapToDto).Where(dto => dto is not null).Cast<UserDto>();
            return ServiceResult<IEnumerable<UserDto>>.Success(dtos);
        }

        public async Task<ServiceResult> DeleteBulkAsync(IEnumerable<Guid> ids)
        {
            foreach (var id in ids)
            {
                await _userRepository.SoftDeleteAsync(id);
            }
            return ServiceResult.Success();
        }

        public async Task<ServiceResult<bool>> ValidateCreateAsync(CreateUserRequest request)
        {
            if (string.IsNullOrEmpty(request.Email))
                return ServiceResult<bool>.Failure("Email is required.");

            var emailAvailable = await IsEmailAvailableAsync(request.Email);
            if (!emailAvailable.IsSuccess || !emailAvailable.Data)
                return ServiceResult<bool>.Failure(emailAvailable.ErrorMessage ?? "Email is already in use.");

            if (!string.IsNullOrEmpty(request.Username))
            {
                var usernameAvailable = await IsUsernameAvailableAsync(request.Username);
                if (!usernameAvailable.IsSuccess || !usernameAvailable.Data)
                    return ServiceResult<bool>.Failure(usernameAvailable.ErrorMessage ?? "Username is already in use.");
            }
            return ServiceResult<bool>.Success(true);
        }

        public async Task<ServiceResult<bool>> ValidateUpdateAsync(Guid id, UpdateUserRequest request)
        {
            var userExists = await _userRepository.ExistsAsync(id);
            if (!userExists)
                return ServiceResult<bool>.Failure("User does not exist.");
            return ServiceResult<bool>.Success(true);
        }

        #endregion

        #region IUserService Specific Implementations

        public async Task<ServiceResult<UserDto>> GetByEmailAsync(string email)
        {
            var user = await _userRepository.GetByEmailAsync(email);
            if (user == null)
                return ServiceResult<UserDto>.Failure("User not found.");
            var dto = MapToDto(user);
            return dto != null
                ? ServiceResult<UserDto>.Success(dto)
                : ServiceResult<UserDto>.Failure("Failed to map user");
        }

        public async Task<ServiceResult<UserDto>> GetByUsernameAsync(string username)
        {
            var user = await _userRepository.GetByUsernameAsync(username);
            if (user == null)
                return ServiceResult<UserDto>.Failure("User not found.");
            var dto = MapToDto(user);
            return dto != null
                ? ServiceResult<UserDto>.Success(dto)
                : ServiceResult<UserDto>.Failure("Failed to map user");
        }

        public async Task<ServiceResult<UserDto>> GetByExternalIdAsync(string externalSystemType, string externalUserId)
        {
            var user = await _userRepository.GetByExternalIdAsync(externalSystemType, externalUserId);
            if (user == null)
                return ServiceResult<UserDto>.Failure("External user not found.");
            var dto = MapToDto(user);
            return dto != null
                ? ServiceResult<UserDto>.Success(dto)
                : ServiceResult<UserDto>.Failure("Failed to map user");
        }

        public async Task<ServiceResult<PagedResult<UserDto>>> SearchUsersAsync(SearchUserRequest request)
        {
            var pagedResult = await _userRepository.SearchAsync(request);
            var dtoList = pagedResult.Items.Select(MapToDto).Where(dto => dto is not null).Cast<UserDto>().ToList();
            var pagedDtoResult = new PagedResult<UserDto>
            {
                Items = dtoList,
                PageNumber = pagedResult.PageNumber,
                PageSize = pagedResult.PageSize,
                TotalCount = pagedResult.TotalCount
            };
            return ServiceResult<PagedResult<UserDto>>.Success(pagedDtoResult);
        }

        public async Task<ServiceResult<UserDto>> CreateOrGetByExternalAsync(ExternalUserRequest request)
        {
            var user = await _userRepository.GetByExternalIdAsync(request.ExternalSystemType, request.ExternalUserId);
            if (user != null)
            {
                var existingDto = MapToDto(user);
                return existingDto != null
                    ? ServiceResult<UserDto>.Success(existingDto)
                    : ServiceResult<UserDto>.Failure("Failed to map existing user");
            }

            if (string.IsNullOrEmpty(request.Email))
                return ServiceResult<UserDto>.Failure("Email is required for external user creation.");

            var createUserRequest = new CreateUserRequest
            {
                Email = request.Email,
                DisplayName = request.DisplayName,
                ExternalSystemType = request.ExternalSystemType,
                ExternalUserId = request.ExternalUserId,
                Username = request.Email
            };
            return await CreateAsync(createUserRequest);
        }

        public async Task<ServiceResult<bool>> IsEmailAvailableAsync(string email, Guid? excludeUserId = null)
        {
            var isTaken = await _userRepository.IsEmailExistsAsync(email, excludeUserId);
            return ServiceResult<bool>.Success(!isTaken);
        }

        public async Task<ServiceResult<bool>> IsUsernameAvailableAsync(string username, Guid? excludeUserId = null)
        {
            if (string.IsNullOrEmpty(username))
                return ServiceResult<bool>.Success(true);
            var isTaken = await _userRepository.IsUsernameExistsAsync(username, excludeUserId);
            return ServiceResult<bool>.Success(!isTaken);
        }

        #endregion

        private UserDto? MapToDto(UserEntity? user)
        {
            if (user == null) return null;

            return new UserDto
            {
                Id = user.Id,
                Email = user.Email,
                Username = user.Username,
                DisplayName = user.DisplayName,
                Status = user.Status,
                EmailVerified = user.IsEmailVerified,
                IsTwoFactorEnabled = user.IsTwoFactorEnabled,
                LastLoginAt = user.LastLoginAt,
                LastLoginIp = user.LastLoginIp,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt ?? user.CreatedAt,
                ExternalSystemType = user.ExternalSystemType,
                ExternalUserId = user.ExternalUserId
            };
        }
    }
}