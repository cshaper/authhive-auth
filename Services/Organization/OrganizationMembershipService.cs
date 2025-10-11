using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.EntityFrameworkCore;
using AutoMapper;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Auth.Permissions;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.User;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Enums.Auth;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using UserEntity = AuthHive.Core.Entities.User.User;
namespace AuthHive.Auth.Services.Organization
{
    /// <summary>
    /// 조직 멤버십 관리 서비스 구현체 - AuthHive v15
    /// </summary>
    public class OrganizationMembershipService : IOrganizationMembershipService
    {
        private readonly IOrganizationMembershipRepository _membershipRepository;
        private readonly IOrganizationRepository _organizationRepository;
        private readonly IPermissionRepository _permissionRepository;
        private readonly IRolePermissionRepository _rolePermissionRepository;
        private readonly AuthDbContext _context;
        private readonly IMapper _mapper;
        private readonly IMemoryCache _cache;
        private readonly ILogger<OrganizationMembershipService> _logger;
        private readonly IUnitOfWork _unitOfWork;

        // 캐시 키 상수
        private const string CACHE_KEY_PREFIX = "org_member:";
        private const string CACHE_KEY_ORG_MEMBERS = "org_members:";
        private const int CACHE_DURATION_MINUTES = 5;

        public OrganizationMembershipService(
            IOrganizationMembershipRepository membershipRepository,
            IOrganizationRepository organizationRepository,
            IPermissionRepository permissionRepository,
            IRolePermissionRepository rolePermissionRepository,
            AuthDbContext context,
            IMapper mapper,
            IMemoryCache cache,
            ILogger<OrganizationMembershipService> logger,
            IUnitOfWork unitOfWork)
        {
            _membershipRepository = membershipRepository;
            _organizationRepository = organizationRepository;
            _permissionRepository = permissionRepository;
            _rolePermissionRepository = rolePermissionRepository;
            _context = context;
            _mapper = mapper;
            _cache = cache;
            _logger = logger;
            _unitOfWork = unitOfWork;
        }

        #region IService Implementation

        // OrganizationMembershipService.cs

        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            try
            {
                // Pass the token to the underlying database connection check.
                return await _context.Database.CanConnectAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationMembershipService health check failed");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default) // 👈 CancellationToken added
        {
            // The method body is already optimized for returning a completed task.
            _logger.LogInformation("OrganizationMembershipService initialized");
            return Task.CompletedTask;
        }
        #endregion

        #region 멤버 초대 및 수락

        public async Task<ServiceResult<OrganizationMembershipDto>> InviteMemberAsync(
            Guid organizationId,
            string email,
            OrganizationMemberRole role,
            Guid invitedByConnectedId,
            DateTime? expiresAt = null)
        {
            try
            {
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationMembershipDto>.Failure("Organization not found");
                }

                var existingInvite = await _context.OrganizationMemberships
                    .FirstOrDefaultAsync(m => m.OrganizationId == organizationId &&
                                                m.InvitationEmail == email &&
                                                m.Status == OrganizationMembershipStatus.Invited &&
                                                !m.IsDeleted);

                if (existingInvite != null)
                {
                    existingInvite.InvitationToken = GenerateInvitationToken();
                    existingInvite.ExpiresAt = expiresAt ?? DateTime.UtcNow.AddDays(7);
                    existingInvite.UpdatedAt = DateTime.UtcNow;
                    existingInvite.UpdatedByConnectedId = invitedByConnectedId;

                    await _unitOfWork.SaveChangesAsync();
                    var updatedDto = _mapper.Map<OrganizationMembershipDto>(existingInvite);
                    return ServiceResult<OrganizationMembershipDto>.Success(updatedDto, "Invitation has been resent");
                }

                var existingConnected = await _context.ConnectedIds
                    .Include(c => c.User)
                    .FirstOrDefaultAsync(c => c.User != null && c.User.Email == email && !c.User.IsDeleted);

                if (existingConnected != null)
                {
                    var existingMembership = await _membershipRepository.GetMembershipAsync(organizationId, existingConnected.Id);
                    if (existingMembership != null && existingMembership.Status == OrganizationMembershipStatus.Active)
                    {
                        return ServiceResult<OrganizationMembershipDto>.Failure("User is already an active member of this organization");
                    }
                }

                Guid targetConnectedId;
                if (existingConnected == null)
                {
                    // ✨ 참고: 신규 유저 생성 로직은 Auth Service의 역할일 수 있으나, 현재 컨텍스트를 유지합니다.
                    var newUser = new UserEntity
                    {
                        Email = email,
                        Username = email.Split('@')[0],
                        IsEmailVerified = false,
                        CreatedByConnectedId = invitedByConnectedId
                    };
                    _context.Users.Add(newUser);

                    var newConnected = new ConnectedId
                    {
                        UserId = newUser.Id,
                        User = newUser,
                        Status = ConnectedIdStatus.Pending,
                        Provider = "Local",
                        CreatedByConnectedId = invitedByConnectedId
                    };
                    _context.ConnectedIds.Add(newConnected);
                    await _unitOfWork.SaveChangesAsync(); // 관련된 모든 변경사항을 한번에 저장
                    targetConnectedId = newConnected.Id;
                }
                else
                {
                    targetConnectedId = existingConnected.Id;
                }

                var invitationToken = GenerateInvitationToken();
                var membership = new OrganizationMembership
                {
                    OrganizationId = organizationId,
                    ConnectedId = targetConnectedId,
                    // ✨ 1. [오류 수정] CS0029: 'string'을 'OrganizationMemberRole'으로 변환할 수 없음
                    // role.ToString() 대신 Enum 값을 직접 할당합니다.
                    MemberRole = role,
                    Status = OrganizationMembershipStatus.Invited,
                    MembershipType = OrganizationMembershipType.Direct,
                    InvitationToken = invitationToken,
                    InvitationEmail = email,
                    InvitedByConnectedId = invitedByConnectedId,
                    InvitedAt = DateTime.UtcNow,
                    JoinedAt = null,
                    ExpiresAt = expiresAt ?? DateTime.UtcNow.AddDays(7),
                    CreatedByConnectedId = invitedByConnectedId
                };

                var created = await _membershipRepository.AddAsync(membership);
                await _unitOfWork.SaveChangesAsync(); // IUnitOfWork를 통한 단일 트랜잭션 보장

                InvalidateOrganizationMembersCache(organizationId);

                var dto = _mapper.Map<OrganizationMembershipDto>(created);
                _logger.LogInformation(
                    "Member invited to org: {OrganizationId}, Email: {Email}, Role: {Role}",
                    organizationId, email, role);

                return ServiceResult<OrganizationMembershipDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invite member: {Email} to organization: {OrganizationId}",
                    email, organizationId);
                return ServiceResult<OrganizationMembershipDto>.Failure("Failed to invite member");
            }
        }

        public async Task<ServiceResult<OrganizationMembershipDto>> AcceptInvitationAsync(
            string invitationToken,
            Guid connectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetByInvitationTokenAsync(invitationToken);
                if (membership == null)
                {
                    return ServiceResult<OrganizationMembershipDto>.Failure("Invalid invitation token");
                }

                if (membership.ExpiresAt.HasValue && membership.ExpiresAt.Value < DateTime.UtcNow)
                {
                    return ServiceResult<OrganizationMembershipDto>.Failure("Invitation has expired");
                }

                if (membership.Status != OrganizationMembershipStatus.Invited)
                {
                    return ServiceResult<OrganizationMembershipDto>.Failure("Invitation has already been used or is invalid");
                }

                membership.ConnectedId = connectedId;
                membership.Status = OrganizationMembershipStatus.Active;
                membership.AcceptedAt = DateTime.UtcNow;
                membership.JoinedAt = DateTime.UtcNow;
                membership.InvitationToken = null;
                membership.UpdatedByConnectedId = connectedId;

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateOrganizationMembersCache(membership.OrganizationId);
                InvalidateMemberCache(membership.OrganizationId, connectedId);

                var dto = _mapper.Map<OrganizationMembershipDto>(membership);
                _logger.LogInformation(
                    "Invitation accepted: OrganizationId: {OrganizationId}, ConnectedId: {ConnectedId}",
                    membership.OrganizationId, connectedId);

                return ServiceResult<OrganizationMembershipDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to accept invitation: {Token}", invitationToken);
                return ServiceResult<OrganizationMembershipDto>.Failure("Failed to accept invitation");
            }
        }

        #endregion

        #region 멤버 조회

        public async Task<ServiceResult<PagedResult<OrganizationMembershipDto>>> GetMembersAsync(
            Guid organizationId,
            OrganizationMembershipStatus? status = null,
            OrganizationMemberRole? role = null,
            int pageNumber = 1,
            int pageSize = 50)
        {
            try
            {
                var query = _context.OrganizationMemberships
                    .Include(m => m.Member)
                    .Where(m => m.OrganizationId == organizationId && !m.IsDeleted);

                if (status.HasValue)
                {
                    query = query.Where(m => m.Status == status.Value);
                }

                if (role.HasValue)
                {
                    // ✨ 2. [오류 수정] CS0019: '==' 연산자를 'OrganizationMemberRole' 및 'string'에 적용할 수 없음
                    // role.Value.ToString()을 사용하지 않고 Enum 값을 직접 비교합니다.
                    query = query.Where(m => m.MemberRole == role.Value);
                }

                var totalCount = await query.CountAsync();

                var items = await query
                    .OrderBy(m => m.JoinedAt)
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();

                var dtos = _mapper.Map<List<OrganizationMembershipDto>>(items);
                var pagedResult = new PagedResult<OrganizationMembershipDto>(dtos, totalCount, pageNumber, pageSize);

                return ServiceResult<PagedResult<OrganizationMembershipDto>>.Success(pagedResult);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get members for organization: {OrganizationId}", organizationId);
                return ServiceResult<PagedResult<OrganizationMembershipDto>>.Failure("Failed to retrieve members");
            }
        }

        public async Task<ServiceResult<OrganizationMembershipDto>> GetMemberAsync(
            Guid organizationId,
            Guid connectedId)
        {
            try
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}{organizationId}:{connectedId}";
                if (_cache.TryGetValue<OrganizationMembershipDto>(cacheKey, out var cachedMember) && cachedMember != null)
                {
                    return ServiceResult<OrganizationMembershipDto>.Success(cachedMember);
                }

                var membership = await _context.OrganizationMemberships
                    .Include(m => m.Member)
                    .FirstOrDefaultAsync(m => m.OrganizationId == organizationId &&
                                                m.ConnectedId == connectedId &&
                                                !m.IsDeleted);

                if (membership == null)
                {
                    return ServiceResult<OrganizationMembershipDto>.NotFound("Member not found");
                }

                var profile = await _context.OrganizationMemberProfiles
                    .FirstOrDefaultAsync(p => p.OrganizationId == organizationId &&
                                                p.ConnectedId == connectedId);

                var dto = _mapper.Map<OrganizationMembershipDto>(membership);

                if (profile != null)
                {
                    dto.JobTitle = profile.JobTitle;
                    dto.Department = profile.Department;
                }

                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(CACHE_DURATION_MINUTES)
                };
                _cache.Set(cacheKey, dto, cacheOptions);

                return ServiceResult<OrganizationMembershipDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get member: {ConnectedId} from organization: {OrganizationId}",
                    connectedId, organizationId);
                return ServiceResult<OrganizationMembershipDto>.Failure("Failed to retrieve member");
            }
        }

        #endregion

        #region 멤버 역할 및 상태 관리

        public async Task<ServiceResult<bool>> ChangeMemberRoleAsync(
            Guid organizationId,
            Guid targetConnectedId,
            OrganizationMemberRole newRole,
            Guid changedByConnectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, targetConnectedId);
                if (membership == null)
                {
                    return ServiceResult<bool>.NotFound("Member not found");
                }

                var changerMembership = await _membershipRepository.GetMembershipAsync(organizationId, changedByConnectedId);
                if (changerMembership == null)
                {
                    return ServiceResult<bool>.Failure("Changer is not a member of the organization");
                }

                // ✨ 3. [오류 수정] CS1503: 'OrganizationMemberRole'을 'string'으로 변환할 수 없음
                // CanChangeRole 헬퍼 메서드가 Enum 타입을 직접 받도록 수정되었으므로 .ToString() 없이 호출합니다.
                if (!CanChangeRole(changerMembership.MemberRole, membership.MemberRole))
                {
                    return ServiceResult<bool>.Failure("Insufficient permissions to change this member's role");
                }

                // ✨ 4. [오류 수정] CS0029: 'string'을 'OrganizationMemberRole'으로 변환할 수 없음
                // newRole.ToString() 대신 Enum 값을 직접 할당합니다.
                membership.MemberRole = newRole;
                membership.UpdatedAt = DateTime.UtcNow;
                membership.UpdatedByConnectedId = changedByConnectedId;

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateMemberCache(organizationId, targetConnectedId);

                _logger.LogInformation(
                    "Member role changed: OrganizationId: {OrganizationId}, ConnectedId: {ConnectedId}, NewRole: {NewRole}",
                    organizationId, targetConnectedId, newRole);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change member role");
                return ServiceResult<bool>.Failure("Failed to change member role");
            }
        }

        public async Task<ServiceResult<bool>> ChangeMemberStatusAsync(
            Guid organizationId,
            Guid targetConnectedId,
            OrganizationMembershipStatus newStatus,
            string? reason,
            Guid changedByConnectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, targetConnectedId);
                if (membership == null)
                {
                    return ServiceResult<bool>.NotFound("Member not found");
                }

                membership.Status = newStatus;
                membership.UpdatedAt = DateTime.UtcNow;
                membership.UpdatedByConnectedId = changedByConnectedId;

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateMemberCache(organizationId, targetConnectedId);

                _logger.LogInformation(
                    "Member status changed: OrganizationId: {OrganizationId}, ConnectedId: {ConnectedId}, NewStatus: {NewStatus}, Reason: {Reason}",
                    organizationId, targetConnectedId, newStatus, reason);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change member status");
                return ServiceResult<bool>.Failure("Failed to change member status");
            }
        }

        public async Task<ServiceResult<bool>> RemoveMemberAsync(
            Guid organizationId,
            Guid targetConnectedId,
            string reason,
            Guid removedByConnectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, targetConnectedId);
                if (membership == null)
                {
                    return ServiceResult<bool>.NotFound("Member not found");
                }

                membership.Status = OrganizationMembershipStatus.Suspended; // 또는 Left, 정책에 따라 결정
                membership.IsDeleted = true;
                membership.DeletedAt = DateTime.UtcNow;
                membership.DeletedByConnectedId = removedByConnectedId;
                membership.UpdatedAt = DateTime.UtcNow;
                membership.UpdatedByConnectedId = removedByConnectedId;

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateMemberCache(organizationId, targetConnectedId);
                InvalidateOrganizationMembersCache(organizationId);

                _logger.LogInformation(
                    "Member removed: OrganizationId: {OrganizationId}, ConnectedId: {ConnectedId}, Reason: {Reason}",
                    organizationId, targetConnectedId, reason);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove member");
                return ServiceResult<bool>.Failure("Failed to remove member");
            }
        }

        public async Task<bool> UpdateMemberStatusAsync(
            Guid organizationId,
            Guid connectedId,
            OrganizationMembershipStatus newStatus,
            Guid updatedBy)
        {
            var result = await ChangeMemberStatusAsync(organizationId, connectedId, newStatus, "Status updated via simplified method.", updatedBy);
            return result.IsSuccess && result.Data;
        }

        #endregion

        #region 일괄 작업

        public async Task<ServiceResult<BulkOperationResult>> BulkInviteMembersAsync(
            Guid organizationId,
            BulkInviteRequest request,
            Guid invitedByConnectedId)
        {
            var result = new BulkOperationResult();

            foreach (var memberInfo in request.Members)
            {
                try
                {
                    var inviteResult = await InviteMemberAsync(
                        organizationId,
                        memberInfo.Email,
                        memberInfo.Role ?? request.DefaultRole,
                        invitedByConnectedId,
                        request.ExpiresAt);

                    if (inviteResult.IsSuccess && inviteResult.Data != null)
                    {
                        result.SuccessCount++;

                        if (!string.IsNullOrEmpty(memberInfo.JobTitle) || !string.IsNullOrEmpty(memberInfo.Department))
                        {
                            var profile = await _context.OrganizationMemberProfiles
                                .FirstOrDefaultAsync(p => p.OrganizationId == organizationId &&
                                                        p.ConnectedId == inviteResult.Data.ConnectedId);

                            if (profile == null)
                            {
                                profile = new OrganizationMemberProfile
                                {
                                    OrganizationId = organizationId,
                                    ConnectedId = inviteResult.Data.ConnectedId,
                                    JobTitle = memberInfo.JobTitle,
                                    Department = memberInfo.Department,
                                    CreatedByConnectedId = invitedByConnectedId
                                };
                                _context.OrganizationMemberProfiles.Add(profile);
                            }
                            else
                            {
                                profile.JobTitle = memberInfo.JobTitle;
                                profile.Department = memberInfo.Department;
                                profile.UpdatedByConnectedId = invitedByConnectedId;
                                profile.UpdatedAt = DateTime.UtcNow;
                            }
                        }
                    }
                    else
                    {
                        result.FailureCount++;
                        result.Errors.Add(new BulkOperationError
                        {
                            EntityKey = memberInfo.Email,
                            Reason = inviteResult.ErrorMessage ?? "Unknown error",
                            ErrorCode = inviteResult.ErrorCode
                        });
                    }
                }
                catch (Exception ex)
                {
                    result.FailureCount++;
                    result.Errors.Add(new BulkOperationError
                    {
                        EntityKey = memberInfo.Email,
                        Reason = ex.Message,
                        ErrorCode = "EXCEPTION"
                    });
                }
            }

            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation(
                "Bulk invite completed: OrganizationId: {OrganizationId}, Success: {Success}, Failed: {Failed}",
                organizationId, result.SuccessCount, result.FailureCount);

            return ServiceResult<BulkOperationResult>.Success(result);
        }

        #endregion

        #region 멤버 권한 및 추가 기능

        public async Task<ServiceResult<MemberPermissionsDto>> GetMemberPermissionsAsync(
            Guid organizationId,
            Guid connectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, connectedId);
                if (membership == null)
                {
                    return ServiceResult<MemberPermissionsDto>.NotFound("Member not found");
                }

                // TODO: 실제 권한 조회 로직 구현 (Permission/RolePermission Repository 사용)
                var permissions = new MemberPermissionsDto
                {
                    OrganizationId = organizationId,
                    ConnectedId = connectedId,
                    // ✨ 5. [오류 수정] CS1503: 'string'을 'OrganizationMemberRole'으로 변환할 수 없음
                    // Enum.Parse를 사용할 필요 없이 Enum 값을 직접 할당합니다.
                    MemberRole = membership.MemberRole,
                    MembershipType = membership.MembershipType,
                    RolePermissions = new List<PermissionDto>(), // 실제 역할 권한 목록
                    AdditionalPermissions = new List<PermissionDto>(), // 추가 권한 목록
                    RestrictedPermissions = new List<PermissionDto>(), // 제한된 권한 목록
                    EffectivePermissions = new List<EffectivePermission>(), // 실효 권한 목록
                    InheritedPermissions = new List<InheritedPermission>(), // 상속된 권한 목록
                    Summary = new PermissionSummary
                    {
                        TotalPermissions = 0,
                        RolePermissionCount = 0,
                        AdditionalPermissionCount = 0,
                        RestrictedPermissionCount = 0,
                        InheritedPermissionCount = 0,
                        KeyPermissions = new List<string>(),
                        // ✨ 6. [오류 수정] CS0019: '==' 및 '!=' 연산자를 'OrganizationMemberRole' 및 'string'에 적용할 수 없음
                        // .ToString() 없이 Enum 값을 직접 비교합니다.
                        HasAdminPermissions = membership.MemberRole == OrganizationMemberRole.Admin ||
                                              membership.MemberRole == OrganizationMemberRole.Owner,
                        HasWritePermissions = membership.MemberRole != OrganizationMemberRole.Member &&
                                              membership.MemberRole != OrganizationMemberRole.Guest
                    }
                };

                return ServiceResult<MemberPermissionsDto>.Success(permissions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get member permissions");
                return ServiceResult<MemberPermissionsDto>.Failure("Failed to get permissions");
            }
        }

        public async Task<ServiceResult<bool>> LeaveOrganizationAsync(
            Guid organizationId,
            Guid connectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, connectedId);
                if (membership == null)
                {
                    return ServiceResult<bool>.NotFound("Member not found");
                }

                // ✨ 7. [오류 수정] CS0019: '==' 연산자를 'OrganizationMemberRole' 및 'string'에 적용할 수 없음
                // .ToString() 없이 Enum 값을 직접 비교합니다.
                if (membership.MemberRole == OrganizationMemberRole.Owner)
                {
                    return ServiceResult<bool>.Failure("Owner cannot leave the organization. Transfer ownership first.");
                }

                membership.Status = OrganizationMembershipStatus.Left;
                membership.IsDeleted = true;
                membership.DeletedAt = DateTime.UtcNow;
                membership.UpdatedAt = DateTime.UtcNow;
                membership.UpdatedByConnectedId = connectedId; // 자기 자신이 떠나는 행위의 주체

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateMemberCache(organizationId, connectedId);
                InvalidateOrganizationMembersCache(organizationId);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to leave organization");
                return ServiceResult<bool>.Failure("Failed to leave organization");
            }
        }

        public async Task<ServiceResult<bool>> RenewMembershipAsync(
            Guid organizationId,
            Guid connectedId,
            DateTime newExpiryDate,
            Guid renewedByConnectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, connectedId);
                if (membership == null)
                {
                    return ServiceResult<bool>.NotFound("Member not found");
                }

                membership.ExpiresAt = newExpiryDate;
                membership.UpdatedAt = DateTime.UtcNow;
                membership.UpdatedByConnectedId = renewedByConnectedId;

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateMemberCache(organizationId, connectedId);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to renew membership");
                return ServiceResult<bool>.Failure("Failed to renew membership");
            }
        }

        public async Task<ServiceResult<int>> CleanupInactiveMembersAsync(
            Guid organizationId,
            int inactiveDays,
            Guid cleanedByConnectedId)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-inactiveDays);
                var inactiveMembers = await _context.OrganizationMemberships
                    .Where(m => m.OrganizationId == organizationId &&
                                m.Status == OrganizationMembershipStatus.Active &&
                                (m.LastActivityAt == null || m.LastActivityAt < cutoffDate) &&
                                !m.IsDeleted)
                    .ToListAsync();

                if (!inactiveMembers.Any())
                {
                    return ServiceResult<int>.Success(0);
                }

                foreach (var member in inactiveMembers)
                {
                    member.Status = OrganizationMembershipStatus.Inactive;
                    member.UpdatedAt = DateTime.UtcNow;
                    member.UpdatedByConnectedId = cleanedByConnectedId;
                }

                await _unitOfWork.SaveChangesAsync();
                InvalidateOrganizationMembersCache(organizationId);

                return ServiceResult<int>.Success(inactiveMembers.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup inactive members");
                return ServiceResult<int>.Failure("Failed to cleanup inactive members");
            }
        }

        public async Task<ServiceResult<bool>> ChangeMembershipTypeAsync(
            Guid organizationId,
            Guid connectedId,
            OrganizationMembershipType newType,
            Guid changedByConnectedId)
        {
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, connectedId);
                if (membership == null)
                {
                    return ServiceResult<bool>.NotFound("Member not found");
                }

                membership.MembershipType = newType;
                membership.UpdatedAt = DateTime.UtcNow;
                membership.UpdatedByConnectedId = changedByConnectedId;

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateMemberCache(organizationId, connectedId);

                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change membership type");
                return ServiceResult<bool>.Failure("Failed to change membership type");
            }
        }

        #endregion

        #region 통계

        public async Task<ServiceResult<OrganizationMemberStatistics>> GetStatisticsAsync(Guid organizationId)
        {
            try
            {
                var organization = await _organizationRepository.GetByIdAsync(organizationId);
                if (organization == null)
                {
                    return ServiceResult<OrganizationMemberStatistics>.NotFound("Organization not found");
                }

                var allMembers = await _membershipRepository.GetMembersAsync(organizationId, true);
                var activeMembers = allMembers.Where(m => m.Status == OrganizationMembershipStatus.Active).ToList();

                var thisMonthStart = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1);
                var lastMonthStart = thisMonthStart.AddMonths(-1);

                var lastMonthMemberCount = allMembers
                    .Count(m => m.JoinedAt < thisMonthStart && m.JoinedAt >= lastMonthStart);

                var newMembersThisMonthCount = allMembers
                    .Count(m => m.JoinedAt >= thisMonthStart);

                decimal growthRate = 0;
                if (lastMonthMemberCount > 0)
                {
                    growthRate = ((decimal)newMembersThisMonthCount / lastMonthMemberCount) * 100;
                }

                var statistics = new OrganizationMemberStatistics
                {
                    OrganizationId = organizationId,
                    OrganizationName = organization.Name,
                    TotalMembers = allMembers.Count(),
                    ActiveMembers = activeMembers.Count,
                    InactiveMembers = allMembers.Count(m => m.Status == OrganizationMembershipStatus.Inactive),
                    SuspendedMembers = allMembers.Count(m => m.Status == OrganizationMembershipStatus.Suspended),
                    PendingInvitations = allMembers.Count(m => m.Status == OrganizationMembershipStatus.Invited),
                    // ✨ 8. [오류 수정] CS0029: 'Dictionary<OrganizationMemberRole, int>'를 'Dictionary<string, int>'로 변환할 수 없음
                    // DTO의 MembersByRole 속성 타입이 Dictionary<string, int>로 추정됩니다.
                    // Enum 키를 string으로 변환하여 Dictionary를 생성합니다.
                    MembersByRole = activeMembers
                        .GroupBy(m => m.MemberRole)
                        .ToDictionary(g => g.Key.ToString(), g => g.Count()),
                    NewMembersThisMonth = newMembersThisMonthCount,
                    MonthlyGrowthRate = growthRate,
                    GeneratedAt = DateTime.UtcNow,
                    PeriodStart = lastMonthStart,
                    PeriodEnd = DateTime.UtcNow
                };

                return ServiceResult<OrganizationMemberStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization statistics");
                return ServiceResult<OrganizationMemberStatistics>.Failure("Failed to get statistics");
            }
        }

        #endregion

        #region Private Helper Methods

        private string GenerateInvitationToken()
        {
            return Guid.NewGuid().ToString("N") + DateTime.UtcNow.Ticks.ToString("x");
        }

        // ✨ 9. [오류 수정] 메서드 시그니처와 내부 로직을 string 대신 OrganizationMemberRole Enum을 사용하도록 변경
        private bool CanChangeRole(OrganizationMemberRole changerRole, OrganizationMemberRole targetRole)
        {
            if (changerRole == OrganizationMemberRole.Owner)
                return true;

            if (changerRole == OrganizationMemberRole.Admin)
                return targetRole != OrganizationMemberRole.Owner;

            if (changerRole == OrganizationMemberRole.Manager)
            {
                return targetRole == OrganizationMemberRole.Member ||
                       targetRole == OrganizationMemberRole.Guest;
            }

            return false;
        }

        private void InvalidateOrganizationMembersCache(Guid organizationId)
        {
            var cacheKey = $"{CACHE_KEY_ORG_MEMBERS}{organizationId}";
            _cache.Remove(cacheKey);
        }

        private void InvalidateMemberCache(Guid organizationId, Guid connectedId)
        {
            var cacheKey = $"{CACHE_KEY_PREFIX}{organizationId}:{connectedId}";
            _cache.Remove(cacheKey);
        }

        #endregion
    }
}