using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Application.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Interfaces.System.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Requests;
using AuthHive.Core.Models.PlatformApplication.Common;
using AuthHive.Core.Models.PlatformApplication.Responses;
using AuthHive.Core.Models.PlatformApplication;
using AuthHive.Core.Models.Audit;
using AuthHive.Core.Models.External;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Models;
using AuthHive.Core.Interfaces.Audit.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Services.PlatformApplication
{
    /// <summary>
    /// SaaS 애플리케이션 접근 권한 관리 서비스 구현
    /// 멀티테넌트 환경에서 팀 관리와 권한 제어에 집중
    /// </summary>
    public class ApplicationAccessService : IApplicationAccessService
    {
        private readonly AuthDbContext _context;

        private readonly IUserPlatformApplicationAccessRepository _accessRepository;
        private readonly IPlatformApplicationAccessTemplateRepository _templateRepository;
        private readonly IApplicationInviteRepository _inviteRepository;
        private readonly IAuditLogRepository _auditRepository;
        private readonly IPlatformApplicationRepository _applicationRepository;

        private readonly ILogger<ApplicationAccessService> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly IEmailService _emailService;
        private readonly ICacheService _cacheService;

        public ApplicationAccessService(
            AuthDbContext context,
            IUserPlatformApplicationAccessRepository accessRepository,
            IPlatformApplicationAccessTemplateRepository templateRepository,
            IApplicationInviteRepository inviteRepository,
            IAuditLogRepository auditRepository,
            IPlatformApplicationRepository applicationRepository,
            ILogger<ApplicationAccessService> logger,
            IDateTimeProvider dateTimeProvider,
            IEmailService emailService,
            ICacheService cacheService)
        {
            _context = context;
            _accessRepository = accessRepository;
            _templateRepository = templateRepository;
            _inviteRepository = inviteRepository;
            _auditRepository = auditRepository;
            _applicationRepository = applicationRepository;

            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
            _emailService = emailService;
            _cacheService = cacheService;
        }

        #region 팀원 관리 - SaaS 필수 기능

        public async Task<ServiceResult<ApplicationInviteResponse>> InviteTeamMemberAsync(
            InviteTeamMemberRequest request)
        {
            try
            {
                // 1. 초대자 권한 확인
                var inviterAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == request.InvitedByConnectedId
                         && a.ApplicationId == request.ApplicationId);

                if (inviterAccess == null || inviterAccess.AccessLevel < ApplicationAccessLevel.Admin)
                {
                    return ServiceResult<ApplicationInviteResponse>.Failure(
                        "Insufficient permissions to invite team members", "UNAUTHORIZED");
                }

                // 2. 중복 초대 확인
                var existingInvite = await _inviteRepository.FindSingleAsync(
                    i => i.Email == request.Email
                         && i.ApplicationId == request.ApplicationId
                         && i.Status == InviteStatus.Pending.ToString()
                         && i.ExpiresAt > _dateTimeProvider.UtcNow);

                if (existingInvite != null)
                {
                    return ServiceResult<ApplicationInviteResponse>.Failure(
                        "An active invite already exists for this email", "DUPLICATE_INVITE");
                }

                // 3. 초대 생성
                var invite = new ApplicationInvite
                {
                    Id = Guid.NewGuid(),
                    ApplicationId = request.ApplicationId,
                    OrganizationId = inviterAccess.OrganizationId,
                    Email = request.Email,
                    AccessLevel = request.AccessLevel,
                    RoleId = request.RoleId,
                    InvitedByConnectedId = request.InvitedByConnectedId,
                    InviteToken = Guid.NewGuid(),
                    ExpiresAt = _dateTimeProvider.UtcNow.AddDays(7),
                    Status = InviteStatus.Pending.ToString(),
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = request.InvitedByConnectedId,
                    CustomMessage = request.CustomMessage
                };

                await _inviteRepository.AddAsync(invite);

                // 4. 이메일 발송
                var inviteUrl = $"https://app.authhive.com/invite/{invite.InviteToken}";
                var emailVariables = new Dictionary<string, object>
                {
                    ["inviteUrl"] = inviteUrl,
                    ["customMessage"] = request.CustomMessage ?? "",
                    ["expiresAt"] = invite.ExpiresAt.ToString("yyyy-MM-dd HH:mm:ss")
                };

                await _emailService.SendTemplateEmailAsync(
                    request.Email,
                    "team-invite",
                    emailVariables,
                    inviterAccess.OrganizationId);

                // 5. 감사 로그
                await LogAuditAsync(
                    request.InvitedByConnectedId,
                    request.ApplicationId,
                    inviterAccess.OrganizationId,
                    "INVITE_SENT",
                    $"team_member:{request.Email}",
                    true);

                _logger.LogInformation(
                    "Team member invited: {Email} to application {AppId}",
                    request.Email, request.ApplicationId);

                return ServiceResult<ApplicationInviteResponse>.Success(
                    new ApplicationInviteResponse
                    {
                        InviteId = invite.Id,
                        InviteUrl = inviteUrl,
                        ExpiresAt = invite.ExpiresAt,
                        Status = "Pending"
                    });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invite team member");
                return ServiceResult<ApplicationInviteResponse>.Failure(
                    "Failed to send invite", "INVITE_ERROR");
            }
        }

        public async Task<ServiceResult<UserPlatformApplicationAccess>> AcceptInviteAsync(
            Guid inviteToken,
            Guid connectedId)
        {
            try
            {
                var invite = await _inviteRepository.FindSingleAsync(
                    i => i.InviteToken == inviteToken
                         && i.Status == InviteStatus.Pending.ToString()
                         && i.ExpiresAt > _dateTimeProvider.UtcNow);

                if (invite == null)
                {
                    return ServiceResult<UserPlatformApplicationAccess>.Failure(
                        "Invalid or expired invite", "INVALID_INVITE");
                }

                var existingAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == connectedId
                         && a.ApplicationId == invite.ApplicationId);

                if (existingAccess != null)
                {
                    return ServiceResult<UserPlatformApplicationAccess>.Failure(
                        "Already a member of this application", "ALREADY_MEMBER");
                }

                var access = new UserPlatformApplicationAccess
                {
                    Id = Guid.NewGuid(),
                    ConnectedId = connectedId,
                    ApplicationId = invite.ApplicationId,
                    OrganizationId = invite.OrganizationId,
                    AccessLevel = invite.AccessLevel,
                    RoleId = invite.RoleId,
                    IsActive = true,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = invite.InvitedByConnectedId
                };

                await _accessRepository.AddAsync(access);

                invite.Status = InviteStatus.Accepted.ToString();
                invite.AcceptedAt = _dateTimeProvider.UtcNow;
                invite.AcceptedByConnectedId = connectedId;

                await _inviteRepository.UpdateAsync(invite);

                await LogAuditAsync(
                    connectedId,
                    invite.ApplicationId,
                    invite.OrganizationId,
                    "INVITE_ACCEPTED",
                    $"invite:{invite.Id}",
                    true);

                return ServiceResult<UserPlatformApplicationAccess>.Success(access);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to accept invite");
                return ServiceResult<UserPlatformApplicationAccess>.Failure(
                    "Failed to accept invite", "ACCEPT_ERROR");
            }
        }

        public async Task<ServiceResult> RemoveTeamMemberAsync(
            Guid applicationId,
            Guid targetConnectedId,
            Guid removedByConnectedId)
        {
            try
            {
                var removerAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == removedByConnectedId
                         && a.ApplicationId == applicationId);

                if (removerAccess == null || removerAccess.AccessLevel < ApplicationAccessLevel.Admin)
                {
                    return ServiceResult.Failure("Insufficient permissions", "UNAUTHORIZED");
                }

                var targetAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == targetConnectedId
                         && a.ApplicationId == applicationId);

                if (targetAccess == null)
                {
                    return ServiceResult.Failure("Team member not found", "NOT_FOUND");
                }

                if (targetConnectedId == removedByConnectedId)
                {
                    return ServiceResult.Failure("Cannot remove yourself", "SELF_REMOVAL");
                }

                await _accessRepository.SoftDeleteAsync(targetAccess.Id, removedByConnectedId);

                await InvalidateAccessCacheAsync(targetConnectedId, applicationId);

                await LogAuditAsync(
                    removedByConnectedId,
                    applicationId,
                    removerAccess.OrganizationId,
                    "MEMBER_REMOVED",
                    $"user:{targetConnectedId}",
                    true);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove team member");
                return ServiceResult.Failure("Failed to remove member", "REMOVE_ERROR");
            }
        }

        public async Task<PagedResult<TeamMemberDto>> GetTeamMembersAsync(
            Guid applicationId,
            TeamMemberSearchRequest request)
        {
            try
            {
                var query = _accessRepository.GetQueryable()
                    .Include(a => a.ConnectedIdNavigation)
                        .ThenInclude(c => c.User)
                    .Include(a => a.Role)
                    .Where(a => a.ApplicationId == applicationId && a.IsActive);

                if (!string.IsNullOrEmpty(request.SearchTerm))
                {
                    query = query.Where(a =>
                        a.ConnectedIdNavigation.User.Email.Contains(request.SearchTerm) ||
                        (a.ConnectedIdNavigation.User.DisplayName != null &&
                         a.ConnectedIdNavigation.User.DisplayName.Contains(request.SearchTerm)));
                }

                if (request.FilterByAccessLevel.HasValue)
                {
                    query = query.Where(a => a.AccessLevel == request.FilterByAccessLevel.Value);
                }

                if (request.FilterByRoleId.HasValue)
                {
                    query = query.Where(a => a.RoleId == request.FilterByRoleId.Value);
                }

                var totalCount = await query.CountAsync();
                var items = await query
                    .OrderByDescending(a => a.CreatedAt)
                    .Skip(request.Skip)
                    .Take(request.Take)
                    .Select(a => new TeamMemberDto
                    {
                        Id = a.Id,
                        ConnectedId = a.ConnectedId,
                        Email = a.ConnectedIdNavigation.User.Email,
                        DisplayName = a.ConnectedIdNavigation.User.DisplayName,
                        AccessLevel = a.AccessLevel,
                        RoleId = a.RoleId,
                        RoleName = a.Role != null ? a.Role.Name : null,
                        JoinedAt = a.CreatedAt,
                        LastActivityAt = a.UpdatedAt,
                        IsActive = a.IsActive,
                        InvitedByConnectedId = a.CreatedByConnectedId
                    })
                    .ToListAsync();

                return new PagedResult<TeamMemberDto>
                {
                    Items = items,
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get team members");
                return new PagedResult<TeamMemberDto>
                {
                    Items = new List<TeamMemberDto>(),
                    TotalCount = 0,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize
                };
            }
        }

        #endregion

        #region 역할 및 권한 관리

        public async Task<ServiceResult<UserPlatformApplicationAccess>> ChangeTeamMemberRoleAsync(
            ChangeRoleRequest request)
        {
            try
            {
                var changerAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == request.ChangedByConnectedId
                         && a.ApplicationId == request.ApplicationId);

                if (changerAccess == null || changerAccess.AccessLevel < ApplicationAccessLevel.Admin)
                {
                    return ServiceResult<UserPlatformApplicationAccess>.Failure(
                        "Insufficient permissions", "UNAUTHORIZED");
                }

                var targetAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == request.TargetConnectedId
                         && a.ApplicationId == request.ApplicationId);

                if (targetAccess == null)
                {
                    return ServiceResult<UserPlatformApplicationAccess>.Failure(
                        "Team member not found", "NOT_FOUND");
                }

                var previousLevel = targetAccess.AccessLevel;
                var previousRoleId = targetAccess.RoleId;

                targetAccess.AccessLevel = request.NewAccessLevel;
                targetAccess.RoleId = request.NewRoleId;
                targetAccess.UpdatedAt = _dateTimeProvider.UtcNow;
                targetAccess.UpdatedByConnectedId = request.ChangedByConnectedId;

                await _accessRepository.UpdateAsync(targetAccess);

                await InvalidateAccessCacheAsync(request.TargetConnectedId, request.ApplicationId);

                var metadata = new Dictionary<string, object>
                {
                    ["PreviousLevel"] = previousLevel.ToString(),
                    ["NewLevel"] = request.NewAccessLevel.ToString(),
                    ["PreviousRoleId"] = previousRoleId?.ToString() ?? "null",
                    ["NewRoleId"] = request.NewRoleId?.ToString() ?? "null"
                };

                await LogAuditAsync(
                    request.ChangedByConnectedId,
                    request.ApplicationId,
                    targetAccess.OrganizationId,
                    "ROLE_CHANGED",
                    $"user:{request.TargetConnectedId}",
                    true,
                    metadata);

                return ServiceResult<UserPlatformApplicationAccess>.Success(targetAccess);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change role");
                return ServiceResult<UserPlatformApplicationAccess>.Failure(
                    "Failed to change role", "ROLE_CHANGE_ERROR");
            }
        }

        public Task<ServiceResult<UserPlatformApplicationAccess>> UpdateMemberPermissionsAsync(
            UpdatePermissionsRequest request)
        {
            throw new NotImplementedException("UpdateMemberPermissions will be implemented in next phase");
        }
        // 1. async 키워드 추가
        // ✨ 1. async 키워드를 추가해야 합니다.
        public async Task<AccessValidationResult> CheckPermissionAsync(
            Guid connectedId,
            Guid applicationId,
            string requiredPermission)
        {
            try
            {
                var cacheKey = $"perm:{connectedId}:{applicationId}:{requiredPermission}";
                var cachedResult = await _cacheService.GetAsync<AccessValidationResult>(cacheKey);
                if (cachedResult != null)
                {
                    return cachedResult;
                }

                var access = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == connectedId
                         && a.ApplicationId == applicationId
                         && a.IsActive);

                if (access == null)
                {
                    return AccessValidationResult.Failure("No access to this application", "NOT_FOUND");
                }

                bool hasPermission = CheckPermissionByAccessLevel(
                    access.AccessLevel,
                    requiredPermission);

                var result = hasPermission
                    ? AccessValidationResult.Success()
                    : AccessValidationResult.Failure("Insufficient permissions", "UNAUTHORIZED");

                result.AddContext("AccessLevel", access.AccessLevel.ToString());

                // 결과를 캐시에 저장하고 작업을 기다립니다.
                await _cacheService.SetAsync(cacheKey, result, TimeSpan.FromMinutes(5));

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check permission for ConnectedId {ConnectedId} on App {ApplicationId}",
                    connectedId, applicationId);
                return AccessValidationResult.Failure("Permission check failed due to an internal error", "INTERNAL_ERROR");
            }
        }

        public async Task<List<ApplicationAccessTemplateDto>> GetUserApplicationAccessesAsync(
            Guid connectedId)
        {
            try
            {
                var accesses = await _accessRepository.GetByConnectedIdAsync(connectedId);
                var applicationIds = accesses.Select(a => a.ApplicationId).Distinct().ToList();

                var applications = new Dictionary<Guid, Core.Entities.PlatformApplications.PlatformApplication>();
                foreach (var appId in applicationIds)
                {
                    var app = await _applicationRepository.GetByIdAsync(appId);
                    if (app != null)
                        applications[appId] = app;
                }

                return accesses.Select(a => new ApplicationAccessTemplateDto
                {
                    Id = a.Id,
                    Name = applications.ContainsKey(a.ApplicationId)
                        ? applications[a.ApplicationId].Name
                        : "Unknown Application",
                    Description = applications.ContainsKey(a.ApplicationId)
                        ? applications[a.ApplicationId].Description
                        : null,
                    Level = a.AccessLevel,
                    IsActive = a.IsActive,
                    OrganizationId = a.OrganizationId
                }).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user application accesses");
                return new List<ApplicationAccessTemplateDto>();
            }
        }

        #endregion

        #region 접근 템플릿

        public async Task<ServiceResult<UserPlatformApplicationAccess>> ApplyAccessTemplateAsync(
            Guid applicationId,
            Guid connectedId,
            Guid templateId,
            Guid appliedByConnectedId)
        {
            try
            {
                // 1. Validate that the user applying the template has Admin rights.
                var applierAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == appliedByConnectedId && a.ApplicationId == applicationId);

                if (applierAccess == null || applierAccess.AccessLevel < ApplicationAccessLevel.Admin)
                {
                    return ServiceResult<UserPlatformApplicationAccess>.Failure(
                        "Insufficient permissions to apply templates.", "UNAUTHORIZED");
                }

                // 2. Validate that the template exists.
                var template = await _templateRepository.GetByIdAsync(templateId);
                if (template == null)
                {
                    return ServiceResult<UserPlatformApplicationAccess>.Failure(
                        $"Template with ID {templateId} not found.", "TEMPLATE_NOT_FOUND");
                }

                // 3. Ensure the template and application belong to the same organization.
                var application = await _applicationRepository.GetByIdAsync(applicationId);
                if (application == null || application.OrganizationId != template.OrganizationId)
                {
                    return ServiceResult<UserPlatformApplicationAccess>.Failure(
                        "Template and application organization mismatch.", "ORGANIZATION_MISMATCH");
                }

                // 4. Find the target user's existing access record or prepare a new one.
                var targetAccess = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == connectedId && a.ApplicationId == applicationId);

                bool isNewAccess = targetAccess == null;
                if (isNewAccess)
                {
                    targetAccess = new UserPlatformApplicationAccess
                    {
                        Id = Guid.NewGuid(),
                        ConnectedId = connectedId,
                        ApplicationId = applicationId,
                        OrganizationId = application.OrganizationId,
                        IsActive = true,
                        CreatedAt = _dateTimeProvider.UtcNow,
                        CreatedByConnectedId = appliedByConnectedId
                    };
                }

                // 5. Apply the template's properties to the access record.
                targetAccess!.AccessLevel = template.Level;
                targetAccess.RoleId = template.DefaultRoleId; // Assuming the template has a DefaultRoleId
                targetAccess.AccessTemplateId = template.Id;
                targetAccess.UpdatedAt = _dateTimeProvider.UtcNow;
                targetAccess.UpdatedByConnectedId = appliedByConnectedId;

                // Optionally, reset custom permissions when applying a template
                // targetAccess.AdditionalPermissions = null;
                // targetAccess.ExcludedPermissions = null;

                // 6. Save the changes to the database.
                if (isNewAccess)
                {
                    await _accessRepository.AddAsync(targetAccess);
                }
                else
                {
                    await _accessRepository.UpdateAsync(targetAccess);
                }

                // 7. Invalidate the user's permission cache.
                await InvalidateAccessCacheAsync(connectedId, applicationId);

                // 8. Log the audit event.
                var metadata = new Dictionary<string, object>
                {
                    ["TemplateId"] = templateId,
                    ["TargetConnectedId"] = connectedId
                };
                await LogAuditAsync(
                    appliedByConnectedId,
                    applicationId,
                    application.OrganizationId,
                    "TEMPLATE_APPLIED",
                    $"user:{connectedId}",
                    true,
                    metadata);

                _logger.LogInformation("Access template {TemplateId} applied to user {UserId} for app {AppId}",
                    templateId, connectedId, applicationId);

                // 9. Return the successful result.
                return ServiceResult<UserPlatformApplicationAccess>.Success(targetAccess);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to apply access template {TemplateId} for user {UserId}",
                    templateId, connectedId);
                return ServiceResult<UserPlatformApplicationAccess>.Failure(
                    "An internal error occurred while applying the access template.", "INTERNAL_ERROR");
            }
        }

        public async Task<List<ApplicationAccessTemplateDto>> GetAccessTemplatesAsync(
            Guid applicationId)
        {
            try
            {
                // 애플리케이션의 조직 ID 조회
                var application = await _applicationRepository.GetByIdAsync(applicationId);
                if (application == null)
                    return new List<ApplicationAccessTemplateDto>();

                var templates = await _templateRepository.GetByOrganizationIdAsync(application.OrganizationId);

                return templates.Select(t => new ApplicationAccessTemplateDto
                {
                    Id = t.Id,
                    Name = t.Name,
                    Description = t.Description,
                    Level = t.Level,
                    IsActive = t.IsActive,
                    OrganizationId = t.OrganizationId
                }).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get access templates");
                return new List<ApplicationAccessTemplateDto>();
            }
        }

        #endregion

        #region 보안 및 감사

        public async Task<AccessAttemptResult> LogAccessAttemptAsync(
            Guid connectedId,
            Guid applicationId,
            string resource,
            string action,
            string ipAddress)
        {
            try
            {
                var hasAccess = await CheckPermissionAsync(connectedId, applicationId, action);
                int riskScore = CalculateRiskScore(ipAddress, action, hasAccess.IsValid);

                var access = await _accessRepository.FindSingleAsync(
                    a => a.ConnectedId == connectedId && a.ApplicationId == applicationId);

                var metadata = new Dictionary<string, object>
                {
                    ["IpAddress"] = ipAddress,
                    ["RiskScore"] = riskScore
                };

                await LogAuditAsync(
                    connectedId,
                    applicationId,
                    access?.OrganizationId,
                    action,
                    resource,
                    hasAccess.IsValid,
                    metadata);

                return new AccessAttemptResult
                {
                    IsAllowed = hasAccess.IsValid,
                    RequiresMfa = riskScore > 70,
                    BlockReason = hasAccess.IsValid ? null : hasAccess.Reason,
                    RiskScore = riskScore
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log access attempt");
                return new AccessAttemptResult
                {
                    IsAllowed = false,
                    BlockReason = "Access attempt logging failed",
                    RiskScore = 100
                };
            }
        }

        public async Task<PagedResult<AuditLogDto>> GetAccessAuditLogsAsync(
            Guid applicationId,
            AccessAuditFilterRequest filter)
        {
            try
            {
                var logs = await _auditRepository.SearchAsync(
                    null,
                    null,
                    filter.Action,
                    filter.ConnectedId,
                    applicationId,
                    filter.StartDate,
                    filter.EndDate,
                    filter.PageNumber,
                    filter.PageSize);

                return new PagedResult<AuditLogDto>
                {
                    Items = logs.Items.Select(a => new AuditLogDto
                    {
                        Id = a.Id,
                        PerformedByConnectedId = a.PerformedByConnectedId,
                        OrganizationId = a.TargetOrganizationId,
                        ApplicationId = a.ApplicationId,
                        ActionType = a.ActionType,
                        Action = a.Action,
                        ResourceType = a.ResourceType,
                        ResourceId = a.ResourceId,
                        IPAddress = a.IPAddress,
                        UserAgent = a.UserAgent,
                        RequestId = a.RequestId,
                        Success = a.Success,
                        ErrorCode = a.ErrorCode,
                        ErrorMessage = a.ErrorMessage,
                        Metadata = a.Metadata,
                        DurationMs = a.DurationMs,
                        Severity = a.Severity,
                        CreatedAt = a.CreatedAt,
                        CreatedByConnectedId = a.CreatedByConnectedId,
                        UpdatedAt = a.UpdatedAt,
                        UpdatedByConnectedId = a.UpdatedByConnectedId,
                        IsDeleted = a.IsDeleted,
                        DeletedAt = a.DeletedAt,
                        DeletedByConnectedId = a.DeletedByConnectedId
                    }).ToList(),
                    TotalCount = logs.TotalCount,
                    PageNumber = logs.PageNumber,
                    PageSize = logs.PageSize
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit logs");
                return new PagedResult<AuditLogDto>
                {
                    Items = new List<AuditLogDto>(),
                    TotalCount = 0,
                    PageNumber = filter.PageNumber,
                    PageSize = filter.PageSize
                };
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task LogAuditAsync(
            Guid connectedId,
            Guid? applicationId,
            Guid? organizationId,
            string action,
            string resource,
            bool isSuccess,
            Dictionary<string, object>? metadata = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = connectedId,
                    TargetOrganizationId = organizationId,
                    ApplicationId = applicationId,
                    Timestamp = _dateTimeProvider.UtcNow,
                    ActionType = DetermineActionType(action),
                    Action = action,
                    ResourceType = "Application",
                    ResourceId = resource,
                    IPAddress = "0.0.0.0",
                    Success = isSuccess,
                    ErrorCode = isSuccess ? null : "ACCESS_DENIED",
                    ErrorMessage = isSuccess ? null : "Operation failed",
                    Metadata = metadata != null
                        ? System.Text.Json.JsonSerializer.Serialize(metadata)
                        : null,
                    Severity = isSuccess ? AuditEventSeverity.Info : AuditEventSeverity.Warning,
                    CreatedAt = _dateTimeProvider.UtcNow,
                    CreatedByConnectedId = connectedId
                };

                await _context.AuditLogs.AddAsync(auditLog);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create audit log");
            }
        }

        private AuditActionType DetermineActionType(string action)
        {
            return action switch
            {
                "INVITE_SENT" => AuditActionType.Create,
                "INVITE_ACCEPTED" => AuditActionType.Update,
                "MEMBER_REMOVED" => AuditActionType.Delete,
                "ROLE_CHANGED" => AuditActionType.Update,
                _ => AuditActionType.Read
            };
        }

        private async Task InvalidateAccessCacheAsync(Guid connectedId, Guid applicationId)
        {
            var pattern = $"perm:{connectedId}:{applicationId}:*";
            await _cacheService.RemoveByPatternAsync(pattern);
        }

        private bool CheckPermissionByAccessLevel(
            ApplicationAccessLevel accessLevel,
            string requiredPermission)
        {
            return accessLevel switch
            {
                ApplicationAccessLevel.Owner => true,
                ApplicationAccessLevel.Admin => !requiredPermission.StartsWith("owner:"),
                ApplicationAccessLevel.User => requiredPermission.StartsWith("read:") ||
                                              requiredPermission.StartsWith("write:"),
                ApplicationAccessLevel.Viewer => requiredPermission.StartsWith("read:"),
                _ => false
            };
        }

        private int CalculateRiskScore(string ipAddress, string action, bool isAllowed)
        {
            int score = 0;

            if (!isAllowed) score += 30;
            if (action.Contains("delete") || action.Contains("remove")) score += 20;
            if (ipAddress.StartsWith("10.") || ipAddress.StartsWith("192.168.")) score -= 10;

            return Math.Max(0, Math.Min(100, score));
        }

        #endregion
    }
}