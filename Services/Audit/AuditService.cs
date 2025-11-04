// using System;
// using System.Collections.Generic;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using Microsoft.Extensions.Logging;
// using Microsoft.EntityFrameworkCore;
// using Newtonsoft.Json;
// using AuthHive.Core.Entities.Audit;
// using AuthHive.Core.Enums.Audit;
// using AuthHive.Core.Interfaces.Audit;
// using AuthHive.Core.Interfaces.Audit.Repository;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Models;
// using AuthHive.Core.Models.Audit;
// using AuthHive.Core.Models.Audit.Common; // ✅ Audit Trail 및 PerformedBy Info는 Common에서 참조
// using AuthHive.Core.Models.Audit.Responses;
// using AuthHive.Core.Models.Audit.ReadModels; // ✅ ReadModels 참조 추가
// using AuthHive.Core.Models.Common;
// using AuthHive.Core.Models.Core.Audit;
// using AuthHive.Core.Constants.Auth;
// using AuthHive.Core.Interfaces.Auth.Service;
// using AuthHive.Core.Interfaces.Infra.Cache;
// using AuthHive.Core.Enums.Core;
// using AuthHive.Core.Models.Auth.Security.Events;
// using AuthHive.Core.Entities.User;
// using AuthHive.Core.Models.Audit.Queries;

// namespace AuthHive.Auth.Services.Audit
// {
//     /// <summary>
//     /// 감사 로그 서비스 구현 - AuthHive v17 (CQRS 표준 반영)
//     /// </summary>
//     public class AuditService : IAuditService
//     {
//         #region Dependencies

//         private readonly IAuditLogRepository _auditLogRepository;
//         private readonly IConnectedIdRepository _connectedIdRepository;
//         private readonly IRoleRepository _roleRepository;
//         private readonly IUnitOfWork _unitOfWork;
//         private readonly ICacheService _cacheService;
//         private readonly IEventBus _eventBus;
//         private readonly ILogger<AuditService> _logger;

//         private const string CACHE_KEY_PREFIX = "audit:";
//         private static readonly TimeSpan DefaultCacheDuration = TimeSpan.FromMinutes(5);

//         #endregion

//         #region Constructor

//         public AuditService(
//             IAuditLogRepository auditLogRepository,
//             IConnectedIdRepository connectedIdRepository,
//             IRoleRepository roleRepository,
//             IUnitOfWork unitOfWork,
//             ICacheService cacheService,
//             IEventBus eventBus,
//             ILogger<AuditService> logger)
//         {
//             _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
//             _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
//             _roleRepository = roleRepository ?? throw new ArgumentNullException(nameof(roleRepository));
//             _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
//             _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
//             _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
//             _logger = logger ?? throw new ArgumentNullException(nameof(logger));
//         }

//         #endregion

//         #region IService Implementation

//         public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 await _auditLogRepository.Query().AnyAsync(cancellationToken);
//                 return await _cacheService.IsHealthyAsync(cancellationToken);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "AuditService health check failed.");
//                 return false;
//             }
//         }

//         public Task InitializeAsync(CancellationToken cancellationToken = default)
//         {
//             _logger.LogInformation("AuditService initialized.");
//             return Task.CompletedTask;
//         }

//         #endregion

//         #region Core Audit Operations

//         public async Task<ServiceResult<AuditLogResponse>> CreateAuditLogAsync(
//             CreateAuditLogRequest request,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
//                 if (connectedIdEntity == null)
//                 {
//                     return ServiceResult<AuditLogResponse>.Failure(
//                         "Invalid ConnectedId. All operations must be performed by a valid ConnectedId.",
//                         AuthConstants.ErrorCodes.INVALID_USER_ID);
//                 }

//                 var auditLog = new AuditLog
//                 {
//                     Id = Guid.NewGuid(),
//                     PerformedByConnectedId = connectedId,
//                     TargetOrganizationId = request.OrganizationId ?? connectedIdEntity.OrganizationId,
//                     ApplicationId = request.ApplicationId,
//                     Timestamp = DateTime.UtcNow,
//                     ActionType = request.ActionType,
//                     Action = request.Action,
//                     ResourceType = request.ResourceType,
//                     ResourceId = request.ResourceId,
//                     IpAddress = request.IpAddress,
//                     UserAgent = request.UserAgent,
//                     RequestId = request.RequestId ?? Guid.NewGuid().ToString(),
//                     Success = request.Success,
//                     ErrorCode = request.ErrorCode,
//                     ErrorMessage = request.ErrorMessage,
//                     Metadata = request.Metadata,
//                     DurationMs = request.DurationMs,
//                     Severity = request.Severity,
//                     IsArchived = false,
//                     CreatedAt = DateTime.UtcNow,
//                     CreatedByConnectedId = connectedId
//                 };

//                 await _auditLogRepository.AddAsync(auditLog, cancellationToken);
//                 await _unitOfWork.SaveChangesAsync(cancellationToken);

//                 await InvalidateOrganizationCacheAsync(auditLog.TargetOrganizationId, cancellationToken);

//                 var dto = MapToDto(auditLog);

//                 if (request.Severity >= AuditEventSeverity.Warning)
//                 {
//                     var securityEvent = new SecurityAuditEventOccurred(
//                         dto.Id,
//                         dto.OrganizationId,
//                         dto.PerformedByConnectedId,
//                         dto.Action,
//                         dto.Severity,
//                         dto.CreatedAt);

//                     await _eventBus.PublishAsync(securityEvent, cancellationToken);
//                 }

//                 _logger.LogInformation(
//                     "Audit log created: {Action} by ConnectedId {ConnectedId} for Org {OrgId}",
//                     auditLog.Action, connectedId, auditLog.TargetOrganizationId);

//                 return ServiceResult<AuditLogResponse>.Success(dto);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex,
//                     "Failed to create audit log for action {Action} by ConnectedId {ConnectedId}",
//                     request.Action, connectedId);

//                 return ServiceResult<AuditLogResponse>.Failure(
//                     "An unexpected error occurred while creating the audit log.",
//                     "AUDIT_CREATE_ERROR");
//             }
//         }

//         public async Task LogAsync(AuditLog auditLog, CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 _ = Task.Run(async () =>
//                 {
//                     try
//                     {
//                         await _auditLogRepository.AddAsync(auditLog, cancellationToken);
//                         await _unitOfWork.SaveChangesAsync(cancellationToken);
//                     }
//                     catch (Exception ex)
//                     {
//                         _logger.LogError(ex, "Background audit log creation failed for action {Action}",
//                             auditLog.Action);
//                     }
//                 });

//                 await Task.CompletedTask;
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to initiate background audit logging");
//             }
//         }


//         public async Task<ServiceResult<AuditLogResponse>> LogActionAsync(
//             AuditActionType actionType,
//             string action,
//             Guid connectedId,
//             bool success = true,
//             string? errorMessage = null,
//             string? resourceType = null,
//             string? resourceId = null,
//             Dictionary<string, object>? metadata = null,
//             CancellationToken cancellationToken = default)
//         {
//             var request = new CreateAuditLogRequest
//             {
//                 ActionType = actionType,
//                 Action = action,
//                 ResourceType = resourceType,
//                 ResourceId = resourceId,
//                 Success = success,
//                 ErrorMessage = errorMessage,
//                 Metadata = metadata != null ? JsonConvert.SerializeObject(metadata) : null,
//                 Severity = success ? AuditEventSeverity.Info : AuditEventSeverity.Error
//             };

//             return await CreateAuditLogAsync(request, connectedId, cancellationToken);
//         }

//         #endregion

//         #region Query Operations

//         public async Task<ServiceResult<AuditLogDetailResponse>> GetAuditLogAsync(
//             Guid auditLogId,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var cacheKey = $"{CACHE_KEY_PREFIX}log:{auditLogId}";

//                 var cachedLog = await _cacheService.GetAsync<AuditLogDetailResponse>(cacheKey, cancellationToken);
//                 if (cachedLog != null)
//                 {
//                     var hasAccess = await ValidateAuditLogAccessAsync(connectedId, cachedLog.OrganizationId, cancellationToken);
//                     if (hasAccess) return ServiceResult<AuditLogDetailResponse>.Success(cachedLog);
//                 }

//                 var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
//                 if (auditLog == null)
//                 {
//                     return ServiceResult<AuditLogDetailResponse>.Failure("Audit log not found.", "AUDIT_NOT_FOUND");
//                 }

//                 var canAccess = await ValidateAuditLogAccessAsync(connectedId, auditLog.TargetOrganizationId, cancellationToken);
//                 if (!canAccess)
//                 {
//                     return ServiceResult<AuditLogDetailResponse>.Failure("Access denied to audit log.", AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 var response = await MapToDetailResponseAsync(auditLog, cancellationToken);

//                 await _cacheService.SetAsync(cacheKey, response, DefaultCacheDuration, cancellationToken);

//                 return ServiceResult<AuditLogDetailResponse>.Success(response);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to get audit log {AuditLogId}", auditLogId);
//                 return ServiceResult<AuditLogDetailResponse>.Failure("Failed to retrieve audit log.", "AUDIT_RETRIEVE_ERROR");
//             }
//         }

//         public async Task<ServiceResult<AuditLogListResponse>> GetAuditLogsAsync(
//             SearchAuditLogsRequest request,
//             PaginationRequest pagination,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
//                 if (connectedIdEntity == null)
//                 {
//                     return ServiceResult<AuditLogListResponse>.Failure(
//                         "Invalid ConnectedId.",
//                         AuthConstants.ErrorCodes.INVALID_USER_ID);
//                 }

//                 var query = _auditLogRepository.Query()
//                     .Where(a => a.TargetOrganizationId == connectedIdEntity.OrganizationId);

//                 if (request.PerformedByConnectedId.HasValue)
//                     query = query.Where(a => a.PerformedByConnectedId == request.PerformedByConnectedId.Value);

//                 if (request.ApplicationId.HasValue)
//                     query = query.Where(a => a.ApplicationId == request.ApplicationId.Value);

//                 if (request.ActionType.HasValue)
//                     query = query.Where(a => a.ActionType == request.ActionType.Value);

//                 if (!string.IsNullOrEmpty(request.ResourceType))
//                     query = query.Where(a => a.ResourceType == request.ResourceType);

//                 if (!string.IsNullOrEmpty(request.ResourceId))
//                     query = query.Where(a => a.ResourceId == request.ResourceId);

//                 if (request.Severity.HasValue)
//                     query = query.Where(a => a.Severity == request.Severity.Value);

//                 if (request.Success.HasValue)
//                     query = query.Where(a => a.Success == request.Success.Value);

//                 if (request.StartDate.HasValue)
//                     query = query.Where(a => a.Timestamp >= request.StartDate.Value);

//                 if (request.EndDate.HasValue)
//                     query = query.Where(a => a.Timestamp <= request.EndDate.Value);

//                 if (!string.IsNullOrEmpty(request.Keyword))
//                 {
//                     var keyword = request.Keyword.ToLower();
//                     query = query.Where(a =>
//                         (a.Action != null && a.Action.ToLower().Contains(keyword)) ||
//                         (a.ErrorMessage != null && a.ErrorMessage.ToLower().Contains(keyword)) ||
//                         (a.Metadata != null && a.Metadata.ToLower().Contains(keyword))
//                     );
//                 }

//                 query = query.OrderByDescending(a => a.Timestamp);

//                 var totalCount = await query.CountAsync(cancellationToken);

//                 var items = await query
//                     .Skip((pagination.PageNumber - 1) * pagination.PageSize)
//                     .Take(pagination.PageSize)
//                     .Select(entity => MapToDto(entity))
//                     .ToListAsync(cancellationToken);

//                 var response = new AuditLogListResponse
//                 {
//                     Items = items,
//                     PageNumber = pagination.PageNumber,
//                     PageSize = pagination.PageSize,
//                     TotalCount = totalCount,
//                 };

//                 return ServiceResult<AuditLogListResponse>.Success(response);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to get audit logs for ConnectedId {ConnectedId}", connectedId);
//                 return ServiceResult<AuditLogListResponse>.Failure(
//                     "Failed to retrieve audit logs.",
//                     "AUDIT_LIST_ERROR");
//             }
//         }

//         public async Task<ServiceResult<List<AuditLogResponse>>> GetResourceAuditLogsAsync(
//             string resourceType,
//             string resourceId,
//             Guid connectedId,
//             int? limit = 50,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
//                 if (connectedIdEntity == null)
//                 {
//                     return ServiceResult<List<AuditLogResponse>>.Failure(
//                         "Invalid ConnectedId",
//                         AuthConstants.ErrorCodes.INVALID_USER_ID);
//                 }

//                 var query = _auditLogRepository.Query()
//                     .Where(a => a.TargetOrganizationId == connectedIdEntity.OrganizationId)
//                     .Where(a => a.ResourceType == resourceType && a.ResourceId == resourceId)
//                     .OrderByDescending(a => a.Timestamp);

//                 IQueryable<AuditLog> finalQuery = query;
//                 if (limit.HasValue)
//                     finalQuery = finalQuery.Take(limit.Value);

//                 var logs = await finalQuery.Select(a => MapToDto(a)).ToListAsync(cancellationToken);

//                 return ServiceResult<List<AuditLogResponse>>.Success(logs);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex,
//                     "Failed to get resource audit logs for {ResourceType}:{ResourceId}",
//                     resourceType, resourceId);
//                 return ServiceResult<List<AuditLogResponse>>.Failure(
//                     "Failed to retrieve resource audit logs",
//                     "RESOURCE_AUDIT_ERROR");
//             }
//         }

//         public async Task<ServiceResult<List<AuditLogResponse>>> GetUserActivityLogsAsync(
//             Guid targetConnectedId,
//             DateTime? startDate,
//             DateTime? endDate,
//             Guid requestingConnectedId,
//             int? limit = 100,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var hasAccess = await ValidateUserActivityAccessAsync(requestingConnectedId, targetConnectedId, cancellationToken);
//                 if (!hasAccess)
//                 {
//                     return ServiceResult<List<AuditLogResponse>>.Failure(
//                         "Access denied to user activity logs",
//                         AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 var query = _auditLogRepository.Query()
//                     .Where(a => a.PerformedByConnectedId == targetConnectedId);

//                 if (startDate.HasValue)
//                     query = query.Where(a => a.Timestamp >= startDate.Value);

//                 if (endDate.HasValue)
//                     query = query.Where(a => a.Timestamp <= endDate.Value);

//                 var orderedQuery = query.OrderByDescending(a => a.Timestamp);

//                 IQueryable<AuditLog> finalQuery = orderedQuery;
//                 if (limit.HasValue)
//                     finalQuery = finalQuery.Take(limit.Value);

//                 var logs = await finalQuery.Select(a => MapToDto(a)).ToListAsync(cancellationToken);

//                 return ServiceResult<List<AuditLogResponse>>.Success(logs);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex,
//                     "Failed to get user activity logs for ConnectedId {ConnectedId}",
//                     targetConnectedId);
//                 return ServiceResult<List<AuditLogResponse>>.Failure(
//                     "Failed to retrieve user activity logs",
//                     "USER_ACTIVITY_ERROR");
//             }
//         }

//         public async Task<ServiceResult<AuditLogListResponse>> GetOrganizationAuditLogsAsync(
//             Guid organizationId,
//             SearchAuditLogsQuery request,
//             PaginationRequest pagination,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
//                 if (connectedIdEntity == null || connectedIdEntity.OrganizationId != organizationId)
//                 {
//                     return ServiceResult<AuditLogListResponse>.Failure(
//                         "Access denied to organization audit logs",
//                         AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 request.OrganizationId = organizationId;

//                 return await GetAuditLogsAsync(request, pagination, connectedId, cancellationToken);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex,
//                     "Failed to get organization audit logs for Org {OrgId}",
//                     organizationId);
//                 return ServiceResult<AuditLogListResponse>.Failure(
//                     "Failed to retrieve organization audit logs",
//                     "ORG_AUDIT_ERROR");
//             }
//         }
//         #endregion

//         #region Audit Trail Details

//         public async Task<ServiceResult<AuditTrailDetailDto>> AddAuditTrailDetailAsync(
//             Guid auditLogId,
//             string fieldName,
//             string? oldValue,
//             string? newValue,
//             AuditFieldType fieldType,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
//                 if (auditLog == null)
//                 {
//                     return ServiceResult<AuditTrailDetailDto>.Failure("Parent audit log not found.", "AUDIT_NOT_FOUND");
//                 }

//                 var hasAccess = await ValidateAuditLogAccessAsync(connectedId, auditLog.TargetOrganizationId, cancellationToken);
//                 if (!hasAccess)
//                 {
//                     return ServiceResult<AuditTrailDetailDto>.Failure(
//                         "Access denied to modify this audit log.",
//                         AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 var detail = new AuditTrailDetail
//                 {
//                     Id = Guid.NewGuid(),
//                     AuditLogId = auditLogId,
//                     FieldName = fieldName,
//                     OldValue = oldValue,
//                     NewValue = newValue,
//                     FieldType = fieldType,
//                     ActionType = AuditActionType.Update,
//                     IsSecureField = IsSecureField(fieldName),
//                     CreatedAt = DateTime.UtcNow,
//                     CreatedByConnectedId = connectedId
//                 };

//                 if (detail.IsSecureField)
//                 {
//                     detail.OldValue = MaskSensitiveData(oldValue);
//                     detail.NewValue = MaskSensitiveData(newValue);
//                 }

//                 auditLog.AuditTrailDetails ??= new List<AuditTrailDetail>();
//                 auditLog.AuditTrailDetails.Add(detail);

//                 await _unitOfWork.SaveChangesAsync(cancellationToken);

//                 var dto = MapTrailDetailToDto(detail);
//                 return ServiceResult<AuditTrailDetailDto>.Success(dto);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to add audit trail detail for AuditLogId {AuditLogId}", auditLogId);
//                 return ServiceResult<AuditTrailDetailDto>.Failure(
//                     "Failed to add audit trail detail.",
//                     "TRAIL_DETAIL_ERROR");
//             }
//         }

//         public async Task<ServiceResult<List<AuditTrailDetailDto>>> AddBulkAuditTrailDetailsAsync(
//             Guid auditLogId,
//             List<AuditTrailDetailDto> details,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
//                 if (auditLog == null)
//                 {
//                     return ServiceResult<List<AuditTrailDetailDto>>.Failure("Parent audit log not found.", "AUDIT_NOT_FOUND");
//                 }

//                 var hasAccess = await ValidateAuditLogAccessAsync(connectedId, auditLog.TargetOrganizationId, cancellationToken);
//                 if (!hasAccess)
//                 {
//                     return ServiceResult<List<AuditTrailDetailDto>>.Failure(
//                         "Access denied to modify this audit log.",
//                         AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 auditLog.AuditTrailDetails ??= new List<AuditTrailDetail>();

//                 foreach (var detailDto in details)
//                 {
//                     var entity = new AuditTrailDetail
//                     {
//                         Id = Guid.NewGuid(),
//                         AuditLogId = auditLogId,
//                         FieldName = detailDto.FieldName,
//                         OldValue = detailDto.OldValue,
//                         NewValue = detailDto.NewValue,
//                         FieldType = detailDto.FieldType,
//                         ActionType = detailDto.ActionType,
//                         IsSecureField = IsSecureField(detailDto.FieldName),
//                         CreatedAt = DateTime.UtcNow,
//                         CreatedByConnectedId = connectedId
//                     };

//                     if (entity.IsSecureField)
//                     {
//                         entity.OldValue = MaskSensitiveData(detailDto.OldValue);
//                         entity.NewValue = MaskSensitiveData(detailDto.NewValue);
//                     }

//                     auditLog.AuditTrailDetails.Add(entity);
//                 }

//                 await _unitOfWork.SaveChangesAsync(cancellationToken);

//                 return ServiceResult<List<AuditTrailDetailDto>>.Success(details);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to add bulk audit trail details for AuditLogId {AuditLogId}", auditLogId);
//                 return ServiceResult<List<AuditTrailDetailDto>>.Failure(
//                     "Failed to add bulk audit trail details.",
//                     "BULK_TRAIL_ERROR");
//             }
//         }

//         #endregion

//         #region Entity Change Tracking

//         public async Task<ServiceResult<AuditLogResponse>> LogEntityChangeAsync<TEntity>(
//             TEntity? oldEntity,
//             TEntity? newEntity,
//             AuditActionType actionType,
//             Guid connectedId,
//             string? customAction = null,
//             CancellationToken cancellationToken = default) where TEntity : class
//         {
//             try
//             {
//                 var entityType = typeof(TEntity).Name;
//                 var action = customAction ?? $"{entityType}.{actionType}";

//                 var resourceId = ExtractEntityId(newEntity ?? oldEntity);

//                 var request = new CreateAuditLogRequest
//                 {
//                     ActionType = actionType,
//                     Action = action,
//                     ResourceType = entityType,
//                     ResourceId = resourceId,
//                     Success = true,
//                     Severity = AuditEventSeverity.Info
//                 };

//                 if (oldEntity != null && newEntity != null)
//                 {
//                     var changes = ExtractChanges(oldEntity, newEntity);
//                     if (changes.Any())
//                     {
//                         request.Metadata = JsonConvert.SerializeObject(new
//                         {
//                             changes,
//                             changeCount = changes.Count
//                         });
//                     }
//                 }

//                 var result = await CreateAuditLogAsync(request, connectedId, cancellationToken);

//                 if (result.IsSuccess && result.Data != null && oldEntity != null && newEntity != null)
//                 {
//                     var changes = ExtractDetailedChanges(oldEntity, newEntity);
//                     if (changes.Any())
//                     {
//                         await AddBulkAuditTrailDetailsAsync(result.Data.Id, changes, connectedId, cancellationToken);
//                     }
//                 }

//                 return result;
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to log entity change for {EntityType}", typeof(TEntity).Name);
//                 return ServiceResult<AuditLogResponse>.Failure(
//                     "Failed to log entity change",
//                     "ENTITY_CHANGE_ERROR");
//             }
//         }
//         #endregion

//         #region Specialized Logging

//         public async Task<ServiceResult<AuditLogResponse>> LogLoginAttemptAsync(
//             string? username,
//             bool success,
//             string? ipAddress,
//             string? userAgent,
//             string? errorMessage = null,
//             Guid? connectedId = null,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var request = new CreateAuditLogRequest
//                 {
//                     ActionType = success ? AuditActionType.Login : AuditActionType.FailedLogin,
//                     Action = "user.login.attempt",
//                     ResourceType = "Authentication",
//                     ResourceId = username,
//                     Success = success,
//                     ErrorMessage = errorMessage,
//                     IpAddress = ipAddress,
//                     UserAgent = userAgent,
//                     Severity = success ? AuditEventSeverity.Info : AuditEventSeverity.Warning,
//                     Metadata = JsonConvert.SerializeObject(new
//                     {
//                         username,
//                         loginTime = DateTime.UtcNow
//                     })
//                 };

//                 if (!success)
//                 {
//                     var recentFailures = await CountRecentFailedLoginsAsync(username, ipAddress, cancellationToken);
//                     if (recentFailures >= 5)
//                     {
//                         request.Severity = AuditEventSeverity.Critical;
//                     }
//                 }

//                 return await CreateAuditLogAsync(request, connectedId ?? Guid.Empty, cancellationToken);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to log login attempt for username: {Username}", username);
//                 return ServiceResult<AuditLogResponse>.Failure(
//                     "Failed to log login attempt",
//                     "LOGIN_LOG_ERROR");
//             }
//         }

//         public async Task<ServiceResult<AuditLogResponse>> LogPermissionChangeAsync(
//             string resourceType,
//             string resourceId,
//             string permission,
//             string action,
//             Guid grantedToConnectedId,
//             Guid grantedByConnectedId,
//             CancellationToken cancellationToken = default)
//         {
//             var metadata = new Dictionary<string, object>
//             {
//                 ["permission"] = permission,
//                 ["grantedTo"] = grantedToConnectedId,
//                 ["action"] = action
//             };

//             return await LogActionAsync(
//                 action.Equals("grant", StringComparison.OrdinalIgnoreCase) ? AuditActionType.Grant : AuditActionType.Revoke,
//                 $"permission.{action.ToLower()}",
//                 grantedByConnectedId,
//                 true,
//                 null,
//                 resourceType,
//                 resourceId,
//                 metadata,
//                 cancellationToken);
//         }

//         public async Task<ServiceResult<AuditLogResponse>> LogDataAccessAsync(
//             string resourceType,
//             string resourceId,
//             string accessType,
//             Guid connectedId,
//             Dictionary<string, object>? additionalInfo = null,
//             CancellationToken cancellationToken = default)
//         {
//             var metadata = additionalInfo ?? new Dictionary<string, object>();
//             metadata["accessType"] = accessType;
//             metadata["accessTime"] = DateTime.UtcNow;

//             return await LogActionAsync(
//                 AuditActionType.Read,
//                 $"data.{accessType.ToLower()}",
//                 connectedId,
//                 true,
//                 null,
//                 resourceType,
//                 resourceId,
//                 metadata,
//                 cancellationToken);
//         }

//         public async Task<ServiceResult<AuditLogResponse>> LogSettingChangeAsync(
//             string settingKey,
//             string? oldValue,
//             string? newValue,
//             Guid connectedId,
//             Guid? organizationId = null,
//             Guid? applicationId = null,
//             CancellationToken cancellationToken = default)
//         {
//             var metadata = new Dictionary<string, object>
//             {
//                 ["settingKey"] = settingKey,
//                 ["oldValue"] = MaskSensitiveData(oldValue) ?? "null",
//                 ["newValue"] = MaskSensitiveData(newValue) ?? "null"
//             };

//             var request = new CreateAuditLogRequest
//             {
//                 ActionType = AuditActionType.Update,
//                 Action = "setting.change",
//                 ResourceType = "Configuration",
//                 ResourceId = settingKey,
//                 Success = true,
//                 Metadata = JsonConvert.SerializeObject(metadata),
//                 OrganizationId = organizationId,
//                 ApplicationId = applicationId,
//                 Severity = AuditEventSeverity.Warning
//             };

//             return await CreateAuditLogAsync(request, connectedId, cancellationToken);
//         }

//         public async Task<ServiceResult<AuditLogResponse>> LogSecurityEventAsync(
//             string eventType,
//             AuditEventSeverity severity,
//             string description,
//             Guid? connectedId,
//             Dictionary<string, object>? details = null,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var request = new CreateAuditLogRequest
//                 {
//                     ActionType = AuditActionType.System,
//                     Action = $"security.alert.{eventType.ToLower()}",
//                     ResourceType = "Security",
//                     ResourceId = eventType,
//                     Success = false,
//                     ErrorMessage = description,
//                     Severity = severity,
//                     Metadata = details != null ? JsonConvert.SerializeObject(details) : null
//                 };

//                 return await CreateAuditLogAsync(request, connectedId ?? Guid.Empty, cancellationToken);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to log security event of type: {EventType}", eventType);
//                 return ServiceResult<AuditLogResponse>.Failure(
//                     "Failed to log security event.",
//                     "SECURITY_EVENT_ERROR");
//             }
//         }

//         #endregion

//         #region Statistics and Analytics

//         public async Task<ServiceResult<AuditLogStatistics>> GetAuditLogStatisticsAsync(
//             Guid? organizationId,
//             DateTime startDate,
//             DateTime endDate,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
//                 if (connectedIdEntity == null)
//                 {
//                     return ServiceResult<AuditLogStatistics>.Failure("Invalid ConnectedId.", AuthConstants.ErrorCodes.INVALID_USER_ID);
//                 }

//                 var targetOrgId = organizationId ?? connectedIdEntity.OrganizationId;
//                 if (targetOrgId != connectedIdEntity.OrganizationId)
//                 {
//                     return ServiceResult<AuditLogStatistics>.Failure("Access denied to organization statistics.", AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 var cacheKey = $"{CACHE_KEY_PREFIX}stats:{targetOrgId}:{startDate:yyyyMMdd}-{endDate:yyyyMMdd}";

//                 var cachedStats = await _cacheService.GetAsync<AuditLogStatistics>(cacheKey, cancellationToken);
//                 if (cachedStats != null)
//                 {
//                     return ServiceResult<AuditLogStatistics>.Success(cachedStats);
//                 }

//                 var logsForStats = await _auditLogRepository.Query()
//                     .Where(a => a.TargetOrganizationId == targetOrgId)
//                     .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate)
//                     .Select(a => new
//                     {
//                         a.Success,
//                         a.PerformedByConnectedId,
//                         a.Severity,
//                         a.Action,
//                         a.ResourceType
//                     })
//                     .ToListAsync(cancellationToken);

//                 var statistics = new AuditLogStatistics
//                 {
//                     TotalLogs = logsForStats.Count,
//                     SuccessfulLogs = logsForStats.Count(l => l.Success),
//                     FailedLogs = logsForStats.Count(l => !l.Success),
//                     UniqueUsers = logsForStats.Select(l => l.PerformedByConnectedId).Distinct().Count(),
//                     SecurityEvents = logsForStats.Count(l => l.Severity >= AuditEventSeverity.Warning),
//                     CriticalEvents = logsForStats.Count(l => l.Severity == AuditEventSeverity.Critical),
//                     ByAction = logsForStats
//                         .Where(l => l.Action != null)
//                         .GroupBy(l => l.Action!)
//                         .ToDictionary(g => g.Key, g => g.Count()),
//                     ByEntity = logsForStats
//                         .Where(l => l.ResourceType != null)
//                         .GroupBy(l => l.ResourceType!)
//                         .ToDictionary(g => g.Key, g => g.Count()),
//                     GeneratedAt = DateTime.UtcNow,
//                     Period = new { StartDate = startDate, EndDate = endDate }
//                 };

//                 await _cacheService.SetAsync(cacheKey, statistics, TimeSpan.FromMinutes(15), cancellationToken);

//                 return ServiceResult<AuditLogStatistics>.Success(statistics);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to get audit log statistics for Org {OrgId}", organizationId);
//                 return ServiceResult<AuditLogStatistics>.Failure(
//                     "Failed to generate statistics",
//                     "STATISTICS_ERROR");
//             }
//         }

//         #endregion

//         #region Export and Archive

//         public async Task<ServiceResult<byte[]>> ExportAuditLogsAsync(
//             SearchAuditLogsRequest request,
//             DataFormat format,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var logsResult = await GetAuditLogsAsync(
//                     request,
//                     new PaginationRequest { PageNumber = 1, PageSize = 10000 },
//                     connectedId,
//                     cancellationToken);

//                 if (!logsResult.IsSuccess || logsResult.Data == null || !logsResult.Data.Items.Any())
//                 {
//                     return ServiceResult<byte[]>.Failure(
//                         "No logs found to export for the given criteria.",
//                         "EXPORT_NO_DATA");
//                 }

//                 byte[] exportData;
//                 switch (format)
//                 {
//                     case DataFormat.Json:
//                         exportData = ExportToJson(logsResult.Data.Items);
//                         break;
//                     case DataFormat.Csv:
//                         exportData = ExportToCsv(logsResult.Data.Items);
//                         break;
//                     case DataFormat.Excel:
//                         exportData = ExportToExcel(logsResult.Data.Items);
//                         break;
//                     default:
//                         return ServiceResult<byte[]>.Failure(
//                             $"Unsupported export format: {format}",
//                             "UNSUPPORTED_FORMAT");
//                 }

//                 _logger.LogInformation(
//                     "Exported {Count} audit logs in {Format} format for ConnectedId {ConnectedId}",
//                     logsResult.Data.Items.Count, format, connectedId);

//                 return ServiceResult<byte[]>.Success(exportData);
//             }
//             catch (OperationCanceledException)
//             {
//                 _logger.LogInformation("Audit log export was canceled by the user.");
//                 return ServiceResult<byte[]>.Failure("Export operation was canceled.", "OPERATION_CANCELED");
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to export audit logs for ConnectedId {ConnectedId}", connectedId);
//                 return ServiceResult<byte[]>.Failure(
//                     "An unexpected error occurred during the export process.",
//                     "EXPORT_ERROR");
//             }
//         }

//         public async Task<ServiceResult<int>> ApplyRetentionPolicyAsync(
//             int retentionDays,
//             Guid? organizationId,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var requestingUser = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
//                 if (requestingUser == null || (organizationId.HasValue && requestingUser.OrganizationId != organizationId))
//                 {
//                     return ServiceResult<int>.Failure("Insufficient permissions to apply retention policy.", AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
//                 var query = _auditLogRepository.Query()
//                     .Where(a => a.Timestamp < cutoffDate)
//                     .Where(a => !a.IsArchived);

//                 if (organizationId.HasValue)
//                 {
//                     query = query.Where(a => a.TargetOrganizationId == organizationId);
//                 }

//                 var logsToArchive = await query.ToListAsync(cancellationToken);

//                 if (!logsToArchive.Any())
//                 {
//                     return ServiceResult<int>.Success(0, "No logs found to archive for the given policy.");
//                 }

//                 foreach (var log in logsToArchive)
//                 {
//                     cancellationToken.ThrowIfCancellationRequested();

//                     log.IsArchived = true;
//                     log.ArchivedAt = DateTime.UtcNow;
//                     log.ArchiveLocation = $"gs://authhive-archive/{log.TargetOrganizationId}/{log.Id}";
//                 }

//                 await _unitOfWork.SaveChangesAsync(cancellationToken);

//                 _logger.LogInformation(
//                     "Applied retention policy: archived {Count} logs older than {Days} days for Org {OrgId}",
//                     logsToArchive.Count, retentionDays, organizationId?.ToString() ?? "All");

//                 return ServiceResult<int>.Success(logsToArchive.Count);
//             }
//             catch (OperationCanceledException)
//             {
//                 _logger.LogInformation("Retention policy application was canceled.");
//                 return ServiceResult<int>.Failure("Operation was canceled.", "OPERATION_CANCELED");
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to apply retention policy for Org {OrgId}", organizationId);
//                 return ServiceResult<int>.Failure(
//                     "Failed to apply retention policy.",
//                     "RETENTION_ERROR");
//             }
//         }

//         public async Task<ServiceResult<int>> CleanupAuditLogsAsync(
//             DateTime beforeDate,
//             Guid? organizationId,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var query = _auditLogRepository.Query()
//                     .Where(a => a.Timestamp < beforeDate)
//                     .Where(a => a.IsArchived);

//                 if (organizationId.HasValue)
//                 {
//                     query = query.Where(a => a.TargetOrganizationId == organizationId);
//                 }

//                 var logsToDelete = await query.ToListAsync();

//                 foreach (var log in logsToDelete)
//                 {
//                     log.IsDeleted = true;
//                     log.DeletedAt = DateTime.UtcNow;
//                     log.DeletedByConnectedId = connectedId;
//                 }

//                 await _unitOfWork.SaveChangesAsync();

//                 _logger.LogInformation(
//                     "Cleaned up {Count} audit logs older than {Date}",
//                     logsToDelete.Count, beforeDate);

//                 return ServiceResult<int>.Success(logsToDelete.Count);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to cleanup audit logs");
//                 return ServiceResult<int>.Failure(
//                     "Failed to cleanup audit logs",
//                     "CLEANUP_ERROR");
//             }
//         }

//         #endregion

//         #region Real-time and Compliance

//         public async Task<ServiceResult<string>> SubscribeToAuditStreamAsync(
//             Guid? organizationId,
//             AuditEventSeverity? minSeverity,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var subscriptionId = Guid.NewGuid().ToString();

//                 var subscriptionInfo = new
//                 {
//                     SubscriptionId = subscriptionId,
//                     ConnectedId = connectedId,
//                     OrganizationId = organizationId,
//                     MinSeverity = minSeverity,
//                     CreatedAt = DateTime.UtcNow
//                 };

//                 await _cacheService.SetStringAsync(
//                    $"{CACHE_KEY_PREFIX}subscription:{subscriptionId}",
//                    JsonConvert.SerializeObject(subscriptionInfo),
//                    TimeSpan.FromHours(1),
//                    cancellationToken);

//                 return ServiceResult<string>.Success(subscriptionId);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to subscribe to audit stream");
//                 return ServiceResult<string>.Failure(
//                     "Failed to subscribe to audit stream",
//                     "SUBSCRIPTION_ERROR");
//             }
//         }

//         public async Task<ServiceResult<AuditLogIntegrityCheckResultReadModel>> VerifyAuditLogIntegrityAsync(
//             Guid auditLogId,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
//                 if (auditLog == null)
//                 {
//                     return ServiceResult<AuditLogIntegrityCheckResultReadModel>.Failure(
//                         "Audit log not found",
//                         "AUDIT_NOT_FOUND");
//                 }

//                 var result = new AuditLogIntegrityCheckResultReadModel(
//                     isValid: true,
//                     checkedAt: DateTime.UtcNow,
//                     hash: null,
//                     issues: new List<string>()
//                 );

//                 if (auditLog.Timestamp > DateTime.UtcNow.AddMinutes(5))
//                 {
//                     result = new AuditLogIntegrityCheckResultReadModel(
//                         isValid: false,
//                         checkedAt: result.CheckedAt,
//                         hash: result.Hash,
//                         issues: result.Issues.Append("Timestamp is in the future.").ToList()
//                     );
//                 }

//                 if (auditLog.PerformedByConnectedId.HasValue)
//                 {
//                     var performer = await _connectedIdRepository.GetByIdAsync(auditLog.PerformedByConnectedId.Value, cancellationToken);
//                     if (performer == null)
//                     {
//                         result = new AuditLogIntegrityCheckResultReadModel(
//                             isValid: false,
//                             checkedAt: result.CheckedAt,
//                             hash: result.Hash,
//                             issues: result.Issues.Append($"The user (ConnectedId: {auditLog.PerformedByConnectedId.Value}) who performed the action no longer exists.").ToList()
//                         );
//                     }
//                 }

//                 var dataToHash = $"{auditLog.Id}{auditLog.Timestamp:o}{auditLog.Action}{auditLog.ResourceId}";
//                 result = new AuditLogIntegrityCheckResultReadModel(
//                     isValid: result.IsValid,
//                     checkedAt: result.CheckedAt,
//                     hash: ComputeHash(dataToHash),
//                     issues: result.Issues
//                 );

//                 return ServiceResult<AuditLogIntegrityCheckResultReadModel>.Success(result);
//             }
//             catch (OperationCanceledException)
//             {
//                 _logger.LogInformation("Audit log integrity verification was canceled.");
//                 return ServiceResult<AuditLogIntegrityCheckResultReadModel>.Failure("Operation was canceled.", "OPERATION_CANCELED");
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to verify audit log integrity for AuditLogId {AuditLogId}", auditLogId);
//                 return ServiceResult<AuditLogIntegrityCheckResultReadModel>.Failure(
//                     "Failed to verify integrity.",
//                     "INTEGRITY_CHECK_ERROR");
//             }
//         }

//         public async Task<ServiceResult<AuditLogResponse>> LogSecurityAlertAsync(
//             AuditActionType actionType,
//             string description,
//             UserActivityLog activityLog,
//             CancellationToken cancellationToken = default)
//         {
//             if (activityLog == null)
//             {
//                 return ServiceResult<AuditLogResponse>.Failure("UserActivityLog cannot be null.", "INVALID_ARGUMENT");
//             }

//             try
//             {
//                 var details = new Dictionary<string, object?>
//                 {
//                     ["description"] = description,
//                     ["riskScore"] = activityLog.RiskScore,
//                     ["activityType"] = activityLog.ActivityType.ToString(),
//                     ["relatedResourceType"] = activityLog.ResourceType,
//                     ["relatedResourceId"] = activityLog.ResourceId,
//                     ["originalActivityId"] = activityLog.Id
//                 };

//                 var request = new CreateAuditLogRequest
//                 {
//                     ActionType = actionType,
//                     Action = $"security.alert.{activityLog.ActivityType.ToString().ToLower()}",
//                     ResourceType = "UserActivity",
//                     ResourceId = activityLog.UserId?.ToString(),
//                     Success = false,
//                     ErrorMessage = description,
//                     IpAddress = activityLog.IpAddress,
//                     UserAgent = activityLog.UserAgent,
//                     Severity = activityLog.RiskScore > 75 ? AuditEventSeverity.Critical : AuditEventSeverity.Error,
//                     Metadata = JsonConvert.SerializeObject(details),
//                     OrganizationId = activityLog.OrganizationId
//                 };

//                 return await CreateAuditLogAsync(request, activityLog.ConnectedId, cancellationToken);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to log security alert for UserActivityLog {ActivityId}", activityLog.Id);
//                 return ServiceResult<AuditLogResponse>.Failure(
//                     "Failed to log security alert.",
//                     "SECURITY_ALERT_ERROR");
//             }
//         }

//         public async Task<ServiceResult<ComplianceReport>> GenerateComplianceReportAsync(
//             Guid organizationId,
//             DateTime startDate,
//             DateTime endDate,
//             ComplianceReportType reportType,
//             Guid connectedId,
//             CancellationToken cancellationToken = default)
//         {
//             try
//             {
//                 var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
//                 if (connectedIdEntity == null || connectedIdEntity.OrganizationId != organizationId)
//                 {
//                     return ServiceResult<ComplianceReport>.Failure(
//                         "Access denied",
//                         AuthConstants.ErrorCodes.InsufficientPermissions);
//                 }

//                 var report = new ComplianceReport
//                 {
//                     ReportId = Guid.NewGuid(),
//                     Type = reportType,
//                     OrganizationId = organizationId,
//                     PeriodStart = startDate,
//                     PeriodEnd = endDate,
//                     GeneratedAt = DateTime.UtcNow,
//                     Data = new Dictionary<string, object>(),
//                     Violations = new List<ComplianceViolation>()
//                 };

//                 switch (reportType)
//                 {
//                     case ComplianceReportType.GDPR:
//                         await GenerateGDPRReportData(report, organizationId, startDate, endDate, cancellationToken);
//                         break;
//                     case ComplianceReportType.SOC2:
//                         await GenerateSOC2ReportData(report, organizationId, startDate, endDate, cancellationToken);
//                         break;
//                     case ComplianceReportType.ISO27001:
//                         await GenerateISO27001ReportData(report, organizationId, startDate, endDate, cancellationToken);
//                         break;
//                     default:
//                         await GenerateGeneralComplianceData(report, organizationId, startDate, endDate, cancellationToken);
//                         break;
//                 }

//                 report.ReportUrl = $"https://authhive.com/reports/{report.ReportId}";

//                 return ServiceResult<ComplianceReport>.Success(report);
//             }
//             catch (Exception ex)
//             {
//                 _logger.LogError(ex, "Failed to generate compliance report");
//                 return ServiceResult<ComplianceReport>.Failure(
//                     "Failed to generate compliance report",
//                     "COMPLIANCE_REPORT_ERROR");
//             }
//         }

//         #endregion

//         #region Private Helper Methods

//         private AuditLogResponse MapToDto(AuditLog entity)
//         {
//             // Immutable DTO 생성자에 맞게 필드를 전달하도록 수정해야 합니다.
//             // 현재는 기존 C# 10 이하 스타일의 initializer를 사용하고 있으므로,
//             // AuditLogResponse의 생성자를 맞춰서 리팩토링했다고 가정하고 이 부분은 유지합니다.
//             return new AuditLogResponse(
//                 id: entity.Id,
//                 actionType: entity.ActionType,
//                 action: entity.Action,
//                 success: entity.Success,
//                 severity: entity.Severity,
//                 createdAt: entity.CreatedAt,
//                 auditTrailDetailsCount: entity.AuditTrailDetails?.Count ?? 0,
//                 performedByConnectedId: entity.PerformedByConnectedId,
//                 organizationId: entity.TargetOrganizationId,
//                 applicationId: entity.ApplicationId,
//                 resourceType: entity.ResourceType,
//                 resourceId: entity.ResourceId,
//                 ipAddress: entity.IpAddress,
//                 userAgent: entity.UserAgent,
//                 requestId: entity.RequestId,
//                 errorCode: entity.ErrorCode,
//                 errorMessage: entity.ErrorMessage,
//                 metadata: entity.Metadata,
//                 durationMs: entity.DurationMs
//             );
//         }

//         private AuditTrailDetailDto MapTrailDetailToDto(AuditTrailDetail entity, CancellationToken cancellationToken = default)
//         {
//             // AuditTrailDetailDto의 생성자를 맞춰서 수정합니다.
//             return new AuditTrailDetailDto(
//                 id: entity.Id,
//                 auditLogId: entity.AuditLogId,
//                 fieldType: entity.FieldType,
//                 actionType: entity.ActionType,
//                 createdAt: entity.CreatedAt,
//                 isSecureField: entity.IsSecureField,
//                 fieldName: entity.FieldName,
//                 oldValue: entity.OldValue,
//                 newValue: entity.NewValue,
//                 validationResult: entity.ValidationResult
//             );
//         }

//         private async Task<AuditLogDetailResponse> MapToDetailResponseAsync(AuditLog entity, CancellationToken cancellationToken)
//         {
//             var performerInfo = (PerformedByInfo?)null;
//             if (entity.PerformedByConnectedId.HasValue)
//             {
//                 var performer = await _connectedIdRepository.GetByIdAsync(entity.PerformedByConnectedId.Value, cancellationToken);
//                 if (performer != null)
//                 {
//                     // PerformedByInfo의 생성자를 호출하도록 수정합니다.
//                     performerInfo = new PerformedByInfo(
//                         connectedId: performer.Id,
//                         displayName: performer.DisplayName,
//                         role: await GetConnectedIdRoleAsync(performer.Id) // 역할 정보 조회는 별도의 비동기 메서드로 분리될 수 있습니다.
//                     );
//                 }
//             }

//             // AuditLogResponse는 이미 Immutable 생성자를 가지고 있습니다.
//             var logResponse = MapToDto(entity);
            
//             // AuditLogDetailResponse의 생성자를 호출하도록 수정합니다.
//             return new AuditLogDetailResponse(
//                 log: logResponse,
//                 auditTrailDetails: entity.AuditTrailDetails?.Select(detail => MapTrailDetailToDto(detail)).ToList(),
//                 performedBy: performerInfo
//             );
//         }
        
//         // ConnectedId의 역할 정보를 조회하는 임시 헬퍼 메서드 (간단한 문자열 반환)
//         private async Task<string?> GetConnectedIdRoleAsync(Guid connectedId)
//         {
//              var roles = await _roleRepository.GetByConnectedIdAsync(connectedId);
//              return roles.FirstOrDefault()?.RoleKey;
//         }

//         private async Task<bool> ValidateAuditLogAccessAsync(Guid requestingConnectedId, Guid? targetOrganizationId, CancellationToken cancellationToken)
//         {
//             if (!targetOrganizationId.HasValue)
//             {
//                 return true;
//             }

//             var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(requestingConnectedId, cancellationToken);
//             if (connectedIdEntity == null) return false;

//             return connectedIdEntity.OrganizationId == targetOrganizationId.Value;
//         }
//         private async Task<bool> ValidateUserActivityAccessAsync(Guid requestingConnectedId, Guid targetConnectedId, CancellationToken cancellationToken)
//         {
//             if (requestingConnectedId == targetConnectedId)
//                 return true;

//             var requestingUser = await _connectedIdRepository.GetByIdAsync(requestingConnectedId);
//             var targetUser = await _connectedIdRepository.GetByIdAsync(targetConnectedId);

//             if (requestingUser?.OrganizationId != targetUser?.OrganizationId)
//                 return false;

//             var userRoles = await _roleRepository.GetByConnectedIdAsync(requestingConnectedId);

//             foreach (var role in userRoles)
//             {
//                 var roleKey = role.RoleKey.ToLowerInvariant();

//                 if (roleKey.Contains("admin") ||
//                     roleKey.Contains("audit") ||
//                     roleKey.Contains("manager") ||
//                     roleKey.Contains("compliance"))
//                 {
//                     return true;
//                 }
//             }

//             return false;
//         }

//         private bool IsSecureField(string? fieldName)
//         {
//             if (string.IsNullOrEmpty(fieldName)) return false;

//             var secureFields = new[] { "password", "ssn", "creditcard", "apikey", "secret", "token" };
//             return secureFields.Any(sf => fieldName.ToLower().Contains(sf));
//         }

//         private string? MaskSensitiveData(string? data)
//         {
//             if (string.IsNullOrEmpty(data)) return data;
//             if (data.Length <= 4) return "****";

//             return data.Substring(0, 2) + new string('*', data.Length - 4) + data.Substring(data.Length - 2);
//         }

//         private string? ExtractEntityId<TEntity>(TEntity? entity) where TEntity : class
//         {
//             if (entity == null) return null;

//             var idProperty = entity.GetType().GetProperty("Id");
//             return idProperty?.GetValue(entity)?.ToString();
//         }

//         private List<KeyValuePair<string, string>> ExtractChanges<TEntity>(TEntity oldEntity, TEntity newEntity)
//             where TEntity : class
//         {
//             var changes = new List<KeyValuePair<string, string>>();
//             var properties = typeof(TEntity).GetProperties();

//             foreach (var prop in properties)
//             {
//                 var oldValue = prop.GetValue(oldEntity)?.ToString();
//                 var newValue = prop.GetValue(newEntity)?.ToString();

//                 if (oldValue != newValue)
//                 {
//                     changes.Add(new KeyValuePair<string, string>(prop.Name, $"{oldValue} -> {newValue}"));
//                 }
//             }

//             return changes;
//         }

//         private List<AuditTrailDetailDto> ExtractDetailedChanges<TEntity>(TEntity oldEntity, TEntity newEntity)
//             where TEntity : class
//         {
//             var details = new List<AuditTrailDetailDto>();
//             var properties = typeof(TEntity).GetProperties();

//             foreach (var prop in properties)
//             {
//                 var oldValue = prop.GetValue(oldEntity)?.ToString();
//                 var newValue = prop.GetValue(newEntity)?.ToString();

//                 if (oldValue != newValue)
//                 {
//                     details.Add(new AuditTrailDetailDto( // 생성자로 변경
//                         id: Guid.NewGuid(), // 임시 ID
//                         auditLogId: Guid.Empty, // 부모는 핸들러에서 설정
//                         fieldType: DetermineFieldType(prop.PropertyType),
//                         actionType: AuditActionType.Update,
//                         createdAt: DateTime.UtcNow,
//                         isSecureField: IsSecureField(prop.Name),
//                         fieldName: prop.Name,
//                         oldValue: oldValue,
//                         newValue: newValue,
//                         validationResult: null // 기본값
//                     ));
//                 }
//             }

//             return details;
//         }

//         private AuditFieldType DetermineFieldType(Type type)
//         {
//             if (type == typeof(string)) return AuditFieldType.String;
//             if (type == typeof(int) || type == typeof(long) || type == typeof(decimal)) return AuditFieldType.Number;
//             if (type == typeof(DateTime) || type == typeof(DateTimeOffset)) return AuditFieldType.DateTime;
//             if (type == typeof(bool)) return AuditFieldType.Boolean;

//             return AuditFieldType.Object;
//         }

//         private async Task<int> CountRecentFailedLoginsAsync(string? username, string? ipAddress, CancellationToken cancellationToken = default)
//         {
//             var cutoff = DateTime.UtcNow.AddMinutes(-15);
//             var query = _auditLogRepository.Query()
//                 .Where(a => a.ActionType == AuditActionType.FailedLogin)
//                 .Where(a => a.Timestamp >= cutoff);

//             if (!string.IsNullOrEmpty(username))
//                 query = query.Where(a => a.ResourceId == username);

//             if (!string.IsNullOrEmpty(ipAddress))
//                 query = query.Where(a => a.IpAddress == ipAddress);

//             return await query.CountAsync();
//         }

//         private async Task InvalidateOrganizationCacheAsync(Guid? organizationId, CancellationToken cancellationToken)
//         {
//             if (!organizationId.HasValue) return;

//             var statsCacheKey = $"{CACHE_KEY_PREFIX}stats:{organizationId.Value}";
//             await _cacheService.RemoveAsync(statsCacheKey, cancellationToken);

//             _logger.LogDebug("Invalidated cache for organization {OrganizationId}", organizationId.Value);
//         }

//         private string ComputeHash(string data)
//         {
//             using var sha256 = System.Security.Cryptography.SHA256.Create();
//             var bytes = System.Text.Encoding.UTF8.GetBytes(data);
//             var hash = sha256.ComputeHash(bytes);
//             return Convert.ToBase64String(hash);
//         }

//         private byte[] ExportToJson(List<AuditLogResponse> logs)
//         {
//             var json = JsonConvert.SerializeObject(logs, Formatting.Indented);
//             return System.Text.Encoding.UTF8.GetBytes(json);
//         }

//         private byte[] ExportToCsv(List<AuditLogResponse> logs)
//         {
//             var csv = "Id,Action,Timestamp,Success\n";
//             foreach (var log in logs)
//             {
//                 csv += $"{log.Id},{log.Action},{log.CreatedAt},{log.Success}\n";
//             }
//             return System.Text.Encoding.UTF8.GetBytes(csv);
//         }

//         private byte[] ExportToExcel(List<AuditLogResponse> logs)
//         {
//             return ExportToCsv(logs);
//         }

//         private async Task GenerateGDPRReportData(
//             ComplianceReport report,
//             Guid organizationId,
//             DateTime startDate,
//             DateTime endDate,
//             CancellationToken cancellationToken = default)
//         {
//             report.Data["dataAccessLogs"] = await _auditLogRepository.Query()
//                 .Where(a => a.TargetOrganizationId == organizationId
//                             && a.Timestamp >= startDate
//                             && a.Timestamp <= endDate
//                             && a.ActionType == AuditActionType.Read)
//                 .CountAsync(cancellationToken);

//             report.Data["dataModificationLogs"] = await _auditLogRepository.Query()
//                 .Where(a => a.TargetOrganizationId == organizationId
//                             && a.Timestamp >= startDate
//                             && a.Timestamp <= endDate
//                             && (a.ActionType == AuditActionType.Update || a.ActionType == AuditActionType.Delete))
//                 .CountAsync(cancellationToken);
//         }

//         private async Task GenerateSOC2ReportData(
//             ComplianceReport report,
//             Guid organizationId,
//             DateTime startDate,
//             DateTime endDate,
//             CancellationToken cancellationToken = default)
//         {
//             report.Data["securityEvents"] = await _auditLogRepository.Query()
//                 .Where(a => a.TargetOrganizationId == organizationId
//                             && a.Timestamp >= startDate
//                             && a.Timestamp <= endDate
//                             && a.Severity >= AuditEventSeverity.Warning)
//                 .CountAsync(cancellationToken);
//         }

//         private async Task GenerateISO27001ReportData(
//             ComplianceReport report,
//             Guid organizationId,
//             DateTime startDate,
//             DateTime endDate,
//             CancellationToken cancellationToken = default)
//         {
//             report.Data["accessControlLogs"] = await _auditLogRepository.Query()
//                 .Where(a => a.TargetOrganizationId == organizationId
//                             && a.Timestamp >= startDate
//                             && a.Timestamp <= endDate
//                             && (a.ActionType == AuditActionType.Grant || a.ActionType == AuditActionType.Revoke))
//                 .CountAsync(cancellationToken);
//         }
//         private async Task GenerateGeneralComplianceData(
//             ComplianceReport report,
//             Guid organizationId,
//             DateTime startDate,
//             DateTime endDate,
//             CancellationToken cancellationToken = default)
//         {
//             report.Data["totalLogs"] = await _auditLogRepository.Query()
//                 .Where(a => a.TargetOrganizationId == organizationId
//                             && a.Timestamp >= startDate
//                             && a.Timestamp <= endDate)
//                 .CountAsync(cancellationToken);
//         }

//         #endregion
//     }
// }