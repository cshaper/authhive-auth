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

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                return await _context.Database.CanConnectAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "OrganizationMembershipService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
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

                    await _context.SaveChangesAsync();

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
                    var newUser = new User
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
                        Status = ConnectedIdStatus.Pending,
                        Provider = "Local",
                        CreatedByConnectedId = invitedByConnectedId
                    };
                    _context.ConnectedIds.Add(newConnected);
                    await _context.SaveChangesAsync();
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
                    MemberRole = role.ToString(),
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
                await _unitOfWork.SaveChangesAsync();

                InvalidateOrganizationMembersCache(organizationId);

                var dto = _mapper.Map<OrganizationMembershipDto>(created);
                _logger.LogInformation(
                    "Member invited to organization: {OrganizationId}, Email: {Email}, Role: {Role}",
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
                    string roleString = role.Value.ToString();
                    query = query.Where(m => m.MemberRole == roleString);
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

                if (!CanChangeRole(changerMembership.MemberRole, membership.MemberRole))
                {
                    return ServiceResult<bool>.Failure("Insufficient permissions to change this member's role");
                }

                membership.MemberRole = newRole.ToString();
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

                membership.Status = OrganizationMembershipStatus.Suspended;
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
            try
            {
                var membership = await _membershipRepository.GetMembershipAsync(organizationId, connectedId);
                if (membership == null)
                {
                    return false;
                }

                membership.Status = newStatus;
                membership.UpdatedAt = DateTime.UtcNow;
                membership.UpdatedByConnectedId = updatedBy;

                await _membershipRepository.UpdateAsync(membership);
                await _unitOfWork.SaveChangesAsync();

                InvalidateMemberCache(organizationId, connectedId);

                _logger.LogInformation(
                    "Member status updated: OrganizationId: {OrganizationId}, ConnectedId: {ConnectedId}, NewStatus: {NewStatus}",
                    organizationId, connectedId, newStatus);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update member status");
                return false;
            }
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

                // TODO: 실제 권한 조회 로직 구현
                var permissions = new MemberPermissionsDto
                {
                    OrganizationId = organizationId,
                    ConnectedId = connectedId,
                    MemberRole = Enum.Parse<OrganizationMemberRole>(membership.MemberRole),
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
                        HasAdminPermissions = membership.MemberRole == OrganizationMemberRole.Admin.ToString() || 
                                             membership.MemberRole == OrganizationMemberRole.Owner.ToString(),
                        HasWritePermissions = membership.MemberRole != OrganizationMemberRole.Viewer.ToString() && 
                                            membership.MemberRole != OrganizationMemberRole.Guest.ToString()
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

                if (membership.MemberRole == OrganizationMemberRole.Owner.ToString())
                {
                    return ServiceResult<bool>.Failure("Owner cannot leave the organization");
                }

                membership.Status = OrganizationMembershipStatus.Left;
                membership.IsDeleted = true;
                membership.DeletedAt = DateTime.UtcNow;
                membership.UpdatedAt = DateTime.UtcNow;

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
                               m.LastActivityAt < cutoffDate &&
                               !m.IsDeleted)
                    .ToListAsync();

                foreach (var member in inactiveMembers)
                {
                    member.Status = OrganizationMembershipStatus.Inactive;
                    member.UpdatedAt = DateTime.UtcNow;
                    member.UpdatedByConnectedId = cleanedByConnectedId;
                }

                await _context.SaveChangesAsync();
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
                
                var statistics = new OrganizationMemberStatistics
                {
                    OrganizationId = organizationId,
                    OrganizationName = organization.Name,
                    TotalMembers = allMembers.Count(),
                    ActiveMembers = activeMembers.Count,
                    InactiveMembers = allMembers.Count(m => m.Status == OrganizationMembershipStatus.Inactive),
                    SuspendedMembers = allMembers.Count(m => m.Status == OrganizationMembershipStatus.Suspended),
                    PendingInvitations = allMembers.Count(m => m.Status == OrganizationMembershipStatus.Invited),
                    GeneratedAt = DateTime.UtcNow,
                    PeriodStart = DateTime.UtcNow.AddMonths(-1),
                    PeriodEnd = DateTime.UtcNow
                };

                statistics.MembersByRole = allMembers
                    .Where(m => m.Status == OrganizationMembershipStatus.Active)
                    .GroupBy(m => m.MemberRole)
                    .ToDictionary(g => g.Key, g => g.Count());

                var thisMonthStart = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1);
                statistics.NewMembersThisMonth = allMembers
                    .Count(m => m.JoinedAt >= thisMonthStart);

                var lastMonthStart = thisMonthStart.AddMonths(-1);
                var lastMonthMembers = allMembers
                    .Count(m => m.JoinedAt < thisMonthStart && m.JoinedAt >= lastMonthStart);
                
                if (lastMonthMembers > 0)
                {
                    statistics.MonthlyGrowthRate = 
                        ((decimal)statistics.NewMembersThisMonth / lastMonthMembers) * 100;
                }

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

        private bool CanChangeRole(string changerRole, string targetRole)
        {
            if (changerRole == OrganizationMemberRole.Owner.ToString())
                return true;

            if (changerRole == OrganizationMemberRole.Admin.ToString())
                return targetRole != OrganizationMemberRole.Owner.ToString();

            if (changerRole == OrganizationMemberRole.Manager.ToString())
            {
                return targetRole == OrganizationMemberRole.Member.ToString() ||
                       targetRole == OrganizationMemberRole.Viewer.ToString() ||
                       targetRole == OrganizationMemberRole.Guest.ToString();
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