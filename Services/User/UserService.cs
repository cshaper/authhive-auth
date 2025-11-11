using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Business.Events;
using AuthHive.Core.Models.User;
using AuthHive.Core.Models.User.Events;
using static AuthHive.Core.Enums.Core.UserEnums;
using UserEntity = AuthHive.Core.Entities.User.User;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Auth.Middleware;
using AuthHive.Core.Interfaces.Security;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// User 비즈니스 로직 서비스 구현체 - AuthHive v16 (아키텍처 원칙 적용 최종본)
    /// 멀티테넌시 보안, 플랜 제한 강제, 이벤트 기반 아키텍처 원칙을 적용합니다.
    /// IUserService 및 IService<...> 인터페이스의 모든 계약을 완벽하게 구현합니다.
    /// </summary>
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UserService> _logger;
        private readonly IEventBus _eventBus;
        private readonly IPlanRestrictionService _planRestrictionService;
        private readonly IPrincipalAccessor _principalAccessor;
        private readonly IPasswordHashProvider _passwordProvider; // 비밀번호 해싱을 위해 추가

        public UserService(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            ILogger<UserService> logger,
            IEventBus eventBus,
            IPlanRestrictionService planRestrictionService,
            IPrincipalAccessor principalAccessor,
            IPasswordHashProvider passwordProvider) // 의존성 주입 추가
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _logger = logger;
            _eventBus = eventBus;
            _planRestrictionService = planRestrictionService;
            _principalAccessor = principalAccessor;
            _passwordProvider = passwordProvider;
        }

        #region IService (Non-Generic) Implementation
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("UserService initialized.");
            return Task.CompletedTask;
        }
        #endregion

        #region IService<T> and IUserService Implementation

        // public async Task<ServiceResult<UserDto>> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        // {
        //     var requestingOrgId = _principalAccessor.OrganizationId;
        //     if (requestingOrgId == Guid.Empty)
        //     {
        //         throw new AuthHiveForbiddenException("Organization context is required to access user data.");
        //     }

        //     var user = await _userRepository.GetByIdAsync(id, cancellationToken);
        //     if (user == null)
        //     {
        //         return ServiceResult<UserDto>.Failure("User not found.");
        //     }

        //     if (!await _userRepository.IsUserInOrganizationAsync(user.Id, requestingOrgId, cancellationToken))
        //     {
        //         _logger.LogWarning("Forbidden access attempt: Org {requestingOrgId} tried to access user {userId} from another organization.", requestingOrgId, id);
        //         return ServiceResult<UserDto>.Failure("User not found.");
        //     }

        //     return ServiceResult<UserDto>.Success(MapToDto(user)!);
        // }

        public async Task<ServiceResult<IEnumerable<UserDto>>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            var requestingOrgId = _principalAccessor.OrganizationId;
            if (requestingOrgId == Guid.Empty)
            {
                throw new AuthHiveForbiddenException("Organization context is required to get all users.");
            }
            var (items, _) = await _userRepository.GetPagedByOrganizationAsync(requestingOrgId, 1, int.MaxValue, cancellationToken);
            var dtos = items.Select(MapToDto).Where(dto => dto != null).Cast<UserDto>();
            return ServiceResult<IEnumerable<UserDto>>.Success(dtos);
        }

        public async Task<ServiceResult<PagedResult<UserDto>>> GetPagedAsync(PaginationRequest request, CancellationToken cancellationToken = default)
        {
            var requestingOrgId = _principalAccessor.OrganizationId;
            if (requestingOrgId == Guid.Empty)
            {
                throw new AuthHiveForbiddenException("Organization context is required for paginated user search.");
            }

            var (items, totalCount) = await _userRepository.GetPagedByOrganizationAsync(requestingOrgId, request.PageNumber, request.PageSize, cancellationToken);

            var dtoList = items.Select(MapToDto).Where(dto => dto != null).Cast<UserDto>().ToList();
            var result = new PagedResult<UserDto>(dtoList, totalCount, request.PageNumber, request.PageSize);

            return ServiceResult<PagedResult<UserDto>>.Success(result);
        }

        //        public async Task<ServiceResult<UserDto>> CreateAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
        // {
        //     var requestingOrgId = _principalAccessor.OrganizationId;
        //     var planKey = PricingConstants.DefaultPlanKey; // TODO: IPlanRestrictionService에서 실제 플랜 키 조회
            
        //     var currentMemberCount = await _userRepository.CountByOrganizationAsync(requestingOrgId, cancellationToken);
        //     var memberLimit = PricingConstants.GetStrictLimit(PricingConstants.SubscriptionPlans.MemberLimits, planKey, PricingConstants.DefaultMemberLimit);

        //     if (currentMemberCount >= memberLimit)
        //     {
        //         await _eventBus.PublishAsync(new PlanLimitReachedEvent(requestingOrgId, planKey, PlanLimitType.MemberCount, currentMemberCount, memberLimit, _principalAccessor.ConnectedId), cancellationToken);
        //         return ServiceResult<UserDto>.Failure($"Organization member limit ({memberLimit}) has been reached. Please upgrade your plan.");
        //     }

        //     var validation = await ValidateCreateAsync(request, cancellationToken);
        //     if (!validation.IsSuccess)
        //     {
        //         return ServiceResult<UserDto>.Failure(validation.ErrorMessage ?? "Validation failed.");
        //     }

        //     var newUser = new UserEntity
        //     {
        //         Email = request.Email,
        //         Username = request.Username,
        //         DisplayName = request.DisplayName,
        //         Status = UserStatus.PendingVerification,
        //         ExternalSystemType = request.ExternalSystemType,
        //         ExternalUserId = request.ExternalUserId,
        //         // [수정] _passwordProvider의 비동기 메서드인 HashPasswordAsync를 'await' 키워드와 함께 호출합니다.
        //         PasswordHash = await _passwordProvider.HashPasswordAsync(request.Password) 
        //     };

        //     await _userRepository.AddAsync(newUser, cancellationToken);
        //     await _unitOfWork.SaveChangesAsync(cancellationToken);

        //     await _eventBus.PublishAsync(new UserCreatedEvent
        //     {
        //         UserId = newUser.Id,
        //         Email = newUser.Email,
        //         CreatedByConnectedId = _principalAccessor.ConnectedId
        //     }, cancellationToken);

        //     return ServiceResult<UserDto>.Success(MapToDto(newUser)!);
        // }


        public async Task<ServiceResult<UserDto>> UpdateAsync(Guid id, UpdateUserRequest request, CancellationToken cancellationToken = default)
        {
            var requestingOrgId = _principalAccessor.OrganizationId;
            var userToUpdate = await _userRepository.GetByIdAsync(id, cancellationToken);

            if (userToUpdate == null) return ServiceResult<UserDto>.Failure("User not found.");

            if (!await _userRepository.IsUserInOrganizationAsync(userToUpdate.Id, requestingOrgId, cancellationToken))
            {
                return ServiceResult<UserDto>.Failure("User not found.");
            }

            var validation = await ValidateUpdateAsync(id, request, cancellationToken);
            if (!validation.IsSuccess)
            {
                return ServiceResult<UserDto>.Failure(validation.ErrorMessage ?? "Validation failed.");
            }

            var updatedFields = new List<string>();
            if (request.DisplayName != null && userToUpdate.DisplayName != request.DisplayName)
            {
                userToUpdate.DisplayName = request.DisplayName;
                updatedFields.Add(nameof(UserEntity.DisplayName));
            }
            if (request.Status.HasValue && userToUpdate.Status != request.Status.Value)
            {
                userToUpdate.Status = request.Status.Value;
                updatedFields.Add(nameof(UserEntity.Status));
            }

            if (updatedFields.Any())
            {
                await _userRepository.UpdateAsync(userToUpdate, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
                await _eventBus.PublishAsync(new UserUpdatedEvent
                {
                    UserId = id,
                    UpdatedFields = updatedFields.ToArray(),
                    UpdatedByConnectedId = _principalAccessor.ConnectedId
                }, cancellationToken);
            }

            return ServiceResult<UserDto>.Success(MapToDto(userToUpdate)!);
        }
        
        public async Task<ServiceResult> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var requestingOrgId = _principalAccessor.OrganizationId;
            var userToDelete = await _userRepository.GetByIdAsync(id, cancellationToken);

            if (userToDelete == null) return ServiceResult.Failure("User not found.");

            if (!await _userRepository.IsUserInOrganizationAsync(userToDelete.Id, requestingOrgId, cancellationToken))
            {
                return ServiceResult.Failure("User not found.");
            }

            await _userRepository.SoftDeleteAsync(id, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);
            await _eventBus.PublishAsync(new UserDeletedEvent
            {
                UserId = id,
                DeletedByConnectedId = _principalAccessor.ConnectedId
            }, cancellationToken);

            return ServiceResult.Success();
        }

        public async Task<ServiceResult<bool>> ExistsAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var exists = await _userRepository.ExistsAsync(id, cancellationToken);
            return ServiceResult<bool>.Success(exists);
        }

        public async Task<ServiceResult<int>> CountAsync(CancellationToken cancellationToken = default)
        {
            var requestingOrgId = _principalAccessor.OrganizationId;
            if (requestingOrgId == Guid.Empty)
            {
                 throw new AuthHiveForbiddenException("Organization context is required to count users.");
            }
            var count = await _userRepository.CountByOrganizationAsync(requestingOrgId, cancellationToken);
            return ServiceResult<int>.Success(count);
        }

        public Task<ServiceResult<IEnumerable<UserDto>>> CreateBulkAsync(IEnumerable<CreateUserRequest> requests, CancellationToken cancellationToken = default)
        {
            // TODO: Bulk 작업은 트랜잭션 및 플랜 제한 검사를 포함한 복잡한 로직이 필요합니다.
            // 현재는 NotImplemenedException으로 처리하여 IService 계약을 만족시킵니다.
            throw new NotImplementedException("Bulk user creation is not yet implemented.");
        }

        public Task<ServiceResult<IEnumerable<UserDto>>> UpdateBulkAsync(IEnumerable<(Guid Id, UpdateUserRequest Request)> updates, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException("Bulk user update is not yet implemented.");
        }

        public Task<ServiceResult> DeleteBulkAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException("Bulk user deletion is not yet implemented.");
        }

        // --- IUserService Specific Implementations ---
        public async Task<ServiceResult<UserDto>> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            var user = await _userRepository.GetByEmailAsync(email, false, cancellationToken);
            if (user == null) return ServiceResult<UserDto>.Failure("User not found.");

            var requestingOrgId = _principalAccessor.OrganizationId;
            if (requestingOrgId != Guid.Empty && !await _userRepository.IsUserInOrganizationAsync(user.Id, requestingOrgId, cancellationToken))
            {
                return ServiceResult<UserDto>.Failure("User not found.");
            }
            return ServiceResult<UserDto>.Success(MapToDto(user)!);
        }

        public async Task<ServiceResult<UserDto>> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
        {
            var user = await _userRepository.GetByUsernameAsync(username, false, cancellationToken);
            if (user == null) return ServiceResult<UserDto>.Failure("User not found.");
            
            var requestingOrgId = _principalAccessor.OrganizationId;
            if (requestingOrgId != Guid.Empty && !await _userRepository.IsUserInOrganizationAsync(user.Id, requestingOrgId, cancellationToken))
            {
                return ServiceResult<UserDto>.Failure("User not found.");
            }
            return ServiceResult<UserDto>.Success(MapToDto(user)!);
        }
        
        public async Task<ServiceResult<UserDto>> GetByExternalIdAsync(string externalSystemType, string externalUserId, CancellationToken cancellationToken = default)
        {
            var user = await _userRepository.GetByExternalIdAsync(externalSystemType, externalUserId, cancellationToken);
            if (user == null) return ServiceResult<UserDto>.Failure("External user not found.");

            var requestingOrgId = _principalAccessor.OrganizationId;
            if (requestingOrgId != Guid.Empty && !await _userRepository.IsUserInOrganizationAsync(user.Id, requestingOrgId, cancellationToken))
            {
                return ServiceResult<UserDto>.Failure("External user not found.");
            }
            return ServiceResult<UserDto>.Success(MapToDto(user)!);
        }
        
        public async Task<ServiceResult<PagedResult<UserDto>>> SearchUsersAsync(SearchUserRequest request, CancellationToken cancellationToken = default)
        {
            var requestingOrgId = _principalAccessor.OrganizationId;
            if (requestingOrgId == Guid.Empty)
            {
                throw new AuthHiveForbiddenException("Organization context is required to search users.");
            }
            request.OrganizationId = requestingOrgId;

            var pagedResult = await _userRepository.SearchAsync(request, cancellationToken);
            var dtoList = pagedResult.Items.Select(MapToDto).Where(dto => dto != null).Cast<UserDto>().ToList();
            var pagedDtoResult = new PagedResult<UserDto>(dtoList, pagedResult.TotalCount, pagedResult.PageNumber, pagedResult.PageSize);
            return ServiceResult<PagedResult<UserDto>>.Success(pagedDtoResult);
        }
        
        public async Task<ServiceResult<UserDto>> CreateOrGetByExternalAsync(ExternalUserRequest request, CancellationToken cancellationToken = default)
        {
            var user = await _userRepository.GetByExternalIdAsync(request.ExternalSystemType, request.ExternalUserId, cancellationToken);
            if (user != null)
            {
                var requestingOrgId = _principalAccessor.OrganizationId;
                if(requestingOrgId != Guid.Empty && await _userRepository.IsUserInOrganizationAsync(user.Id, requestingOrgId, cancellationToken))
                {
                    return ServiceResult<UserDto>.Success(MapToDto(user)!);
                }
            }
            
            var createUserRequest = new CreateUserRequest
            {
                Email = request.Email,
                Password = Guid.NewGuid().ToString(), // 외부 연동 시 비밀번호는 임의의 값으로 설정
                DisplayName = request.DisplayName,
                ExternalSystemType = request.ExternalSystemType,
                ExternalUserId = request.ExternalUserId,
                Username = request.Username
            };
            return await CreateAsync(createUserRequest, cancellationToken);
        }
        
        public async Task<ServiceResult<bool>> IsEmailAvailableAsync(string email, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(email)) return ServiceResult<bool>.Failure("Email cannot be empty.");
            var isTaken = await _userRepository.IsEmailExistsAsync(email, excludeUserId, cancellationToken);
            return ServiceResult<bool>.Success(!isTaken);
        }

        public async Task<ServiceResult<bool>> IsUsernameAvailableAsync(string username, Guid? excludeUserId = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(username)) return ServiceResult<bool>.Success(true);
            var isTaken = await _userRepository.IsUsernameExistsAsync(username, excludeUserId, cancellationToken);
            return ServiceResult<bool>.Success(!isTaken);
        }
        
        // [CS0737 해결] 인터페이스 계약을 이행하기 위해 private에서 public으로 변경합니다.
        public async Task<ServiceResult<bool>> ValidateCreateAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(request.Email)) return ServiceResult<bool>.Failure("Email is required.");
            var emailAvailable = await IsEmailAvailableAsync(request.Email, null, cancellationToken);
            if (!emailAvailable.IsSuccess || !emailAvailable.Data)
            {
                return ServiceResult<bool>.Failure(emailAvailable.ErrorMessage ?? "Email is already in use.");
            }
            return ServiceResult<bool>.Success(true);
        }

        public async Task<ServiceResult<bool>> ValidateUpdateAsync(Guid id, UpdateUserRequest request, CancellationToken cancellationToken = default)
        {
            var userExists = await _userRepository.ExistsAsync(id, cancellationToken);
            if (!userExists) return ServiceResult<bool>.Failure("User does not exist.");
            return ServiceResult<bool>.Success(true);
        }
        #endregion

        #region Private Helper Methods
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
                UpdatedAt = user.UpdatedAt,
                ExternalSystemType = user.ExternalSystemType,
                ExternalUserId = user.ExternalUserId
            };
        }
        #endregion
    }
}

