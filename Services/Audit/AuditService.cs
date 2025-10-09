using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Audit.Repository;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models;
using AuthHive.Core.Models.Audit;
using AuthHive.Core.Models.Audit.Common;
using AuthHive.Core.Models.Audit.Requests;
using AuthHive.Core.Models.Audit.Responses;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Core.Audit;
using AuthHive.Core.Constants.Auth;
using AuthHive.Core.Interfaces.Auth.Service;

namespace AuthHive.Auth.Services.Audit
{
    /// <summary>
    /// 감사 로그 서비스 구현 - AuthHive v15
    /// SaaS 애플리케이션의 모든 활동을 추적하고 컴플라이언스를 지원합니다.
    /// 멀티테넌시 환경에서 조직별 로그 격리를 보장합니다.
    /// 시스템 전역 감사 기능을 제공합니다.
    /// </summary>
    public class AuditService : IAuditService
    {
        #region Dependencies

        private readonly IAuditLogRepository _auditLogRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMemoryCache _memoryCache;
        private readonly IDistributedCache _distributedCache;
        private readonly ILogger<AuditService> _logger;
        IConnectedIdRoleRepository _connectedIdRoleRepository;
        IRoleRepository _roleRepository;
        IPermissionService _permissionService;
        // 캐시 키 상수
        private const string CACHE_KEY_PREFIX = "audit:";
        private const int DEFAULT_CACHE_DURATION = 300; // 5분

        #endregion

        #region Constructor

        public AuditService(
            IAuditLogRepository auditLogRepository,
            IConnectedIdRepository connectedIdRepository,
            IUnitOfWork unitOfWork,
            IMemoryCache memoryCache,
            IDistributedCache distributedCache,
            ILogger<AuditService> logger,
            IConnectedIdRoleRepository connectedIdRoleRepository,
            IRoleRepository roleRepository,
            IPermissionService permissionService)
        {
            _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            _distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _connectedIdRoleRepository = connectedIdRoleRepository ?? throw new ArgumentNullException(nameof(connectedIdRoleRepository));
            _roleRepository = roleRepository ?? throw new ArgumentNullException(nameof(roleRepository));
            _permissionService = permissionService ?? throw new ArgumentNullException(nameof(permissionService));
        }

        #endregion

        #region IService Implementation

        /// <summary>
        /// 서비스 상태 확인
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. Repository 쿼리 준비
                var testQuery = _auditLogRepository.Query().Take(1);

                // 2. Task.Run() 대신 ORM의 Async 메서드를 사용합니다.
                // 3. CancellationToken을 직접 전달하여 쿼리 취소를 가능하게 합니다.
                await testQuery.AnyAsync(cancellationToken);

                return true;
            }
            catch (OperationCanceledException)
            {
                // 취소 요청 시 예외가 발생하면 false를 반환하거나 다시 throw 할 수 있습니다.
                return false;
            }
            catch // 데이터베이스 연결 실패 등 다른 예외
            {
                return false;
            }
        }

        /// <summary>
        /// 서비스 초기화
        /// </summary>
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            // 캐시 초기화 (로직이 없다면 로깅만 수행)
            _logger.LogInformation("AuditService initialized");

            // 🌟 즉시 완료된 Task 객체를 반환하여 인터페이스 계약을 만족시키고 오버헤드를 줄입니다.
            return Task.CompletedTask;
        }

        #endregion

        #region Core Audit Operations

        /// <summary>
        /// 감사 로그 생성 - 멀티테넌시 환경에서 조직 격리 보장
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> CreateAuditLogAsync(
            CreateAuditLogRequest request,
            Guid connectedId)
        {
            try
            {
                // 1. ConnectedId 검증 - v15 철학: ConnectedId가 모든 활동의 주체
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null)
                {
                    return ServiceResult<AuditLogDto>.Failure(
                        "Invalid ConnectedId. All operations must be performed by a valid ConnectedId.",
                        AuthConstants.ErrorCodes.INVALID_USER_ID);
                }

                // 2. 감사 로그 엔티티 생성
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = connectedId,
                    TargetOrganizationId = request.OrganizationId ?? connectedIdEntity.OrganizationId,
                    ApplicationId = request.ApplicationId,
                    Timestamp = DateTime.UtcNow,
                    ActionType = request.ActionType,
                    Action = request.Action,
                    ResourceType = request.ResourceType,
                    ResourceId = request.ResourceId,
                    IpAddress = request.IpAddress,
                    UserAgent = request.UserAgent,
                    RequestId = request.RequestId ?? Guid.NewGuid().ToString(),
                    Success = request.Success,
                    ErrorCode = request.ErrorCode,
                    ErrorMessage = request.ErrorMessage,
                    Metadata = request.Metadata,
                    DurationMs = request.DurationMs,
                    Severity = request.Severity,
                    IsArchived = false,

                    // SystemAuditableEntity 필드들
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = connectedId
                };

                // 3. 보안 이벤트인 경우 추가 검증
                if (request.Severity >= AuditEventSeverity.Warning)
                {
                    await HandleSecurityEventAsync(auditLog);
                }

                // 4. 데이터베이스에 저장
                await _auditLogRepository.AddAsync(auditLog);
                await _unitOfWork.SaveChangesAsync();

                // 5. 캐시 무효화 - 조직별 통계 캐시 클리어
                await InvalidateOrganizationCacheAsync(auditLog.TargetOrganizationId);

                // 6. DTO 변환 및 반환
                var dto = MapToDto(auditLog);

                _logger.LogInformation(
                    "Audit log created: {Action} by ConnectedId {ConnectedId} for Org {OrgId}",
                    auditLog.Action,
                    connectedId,
                    auditLog.TargetOrganizationId);

                return ServiceResult<AuditLogDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to create audit log for action {Action} by ConnectedId {ConnectedId}",
                    request.Action, connectedId);

                return ServiceResult<AuditLogDto>.Failure(
                    "Failed to create audit log",
                    "AUDIT_CREATE_ERROR");
            }
        }

        /// <summary>
        /// 감사 로그 비동기 기록 (Fire-and-forget 방식)
        /// </summary>
        public async Task LogAsync(AuditLog auditLog)
        {
            try
            {
                // Fire-and-forget 방식으로 백그라운드에서 처리
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _auditLogRepository.AddAsync(auditLog);
                        await _unitOfWork.SaveChangesAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Background audit log creation failed for action {Action}",
                            auditLog.Action);
                    }
                });

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initiate background audit logging");
            }
        }

        /// <summary>
        /// 간편 로그 메서드 - v15: ConnectedId 중심 로깅
        /// </summary>
        public async Task LogActionAsync(
           Guid? performedByConnectedId,
           string action,
           AuditActionType actionType,
           string resourceType,
           string? resourceId,
           bool success = true,
           string? metadata = null,
           CancellationToken cancellationToken = default)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = performedByConnectedId,
                    Timestamp = DateTime.UtcNow,
                    ActionType = actionType,
                    Action = action,
                    ResourceType = resourceType,
                    ResourceId = resourceId,
                    Success = success,
                    Metadata = metadata,
                    Severity = success ? AuditEventSeverity.Info : AuditEventSeverity.Warning,
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = performedByConnectedId
                };

                // 조직 정보 추가 (ConnectedId에서 추출)
                if (performedByConnectedId.HasValue)
                {
                    var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(performedByConnectedId.Value, cancellationToken);
                    if (connectedIdEntity != null)
                    {
                        auditLog.TargetOrganizationId = connectedIdEntity.OrganizationId;
                    }
                }

                await _auditLogRepository.AddAsync(auditLog, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log action {Action}", action);
                // 감사 로그 실패가 메인 비즈니스 로직을 중단시키지 않도록 함
            }
        }

        /// <summary>
        /// 감사 로그 자동 생성 (내부 시스템 사용)
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogActionAsync(
            AuditActionType actionType,
            string action,
            Guid connectedId,
            bool success = true,
            string? errorMessage = null,
            string? resourceType = null,
            string? resourceId = null,
            Dictionary<string, object>? metadata = null)
        {
            var request = new CreateAuditLogRequest
            {
                ActionType = actionType,
                Action = action,
                ResourceType = resourceType,
                ResourceId = resourceId,
                Success = success,
                ErrorMessage = errorMessage,
                Metadata = metadata != null ? JsonConvert.SerializeObject(metadata) : null,
                Severity = success ? AuditEventSeverity.Info : AuditEventSeverity.Error
            };

            return await CreateAuditLogAsync(request, connectedId);
        }

        #endregion

        #region Query Operations

        /// <summary>
        /// 감사 로그 상세 조회 - 멀티테넌시 격리 적용
        /// </summary>
        public async Task<ServiceResult<AuditLogDetailResponse>> GetAuditLogAsync(
            Guid auditLogId,
            Guid connectedId)
        {
            try
            {
                // 1. ConnectedId 권한 검증
                var hasAccess = await ValidateAuditLogAccessAsync(connectedId, auditLogId);
                if (!hasAccess)
                {
                    return ServiceResult<AuditLogDetailResponse>.Failure(
                        "Access denied to audit log",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                // 2. 캐시 확인
                var cacheKey = $"{CACHE_KEY_PREFIX}log:{auditLogId}";
                if (_memoryCache.TryGetValue<AuditLogDetailResponse>(cacheKey, out var cached))
                {
                    return ServiceResult<AuditLogDetailResponse>.Success(cached!);
                }

                // 3. 데이터베이스 조회
                var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId);
                if (auditLog == null)
                {
                    return ServiceResult<AuditLogDetailResponse>.Failure(
                        "Audit log not found",
                        "AUDIT_NOT_FOUND");
                }

                // 4. 상세 정보 구성
                var response = new AuditLogDetailResponse
                {
                    Id = auditLog.Id,
                    PerformedByConnectedId = auditLog.PerformedByConnectedId,
                    OrganizationId = auditLog.TargetOrganizationId,
                    ApplicationId = auditLog.ApplicationId,
                    ActionType = auditLog.ActionType,
                    Action = auditLog.Action,
                    ResourceType = auditLog.ResourceType,
                    ResourceId = auditLog.ResourceId,
                    IpAddress = auditLog.IpAddress,
                    UserAgent = auditLog.UserAgent,
                    RequestId = auditLog.RequestId,
                    Success = auditLog.Success,
                    ErrorCode = auditLog.ErrorCode,
                    ErrorMessage = auditLog.ErrorMessage,
                    Metadata = auditLog.Metadata,
                    DurationMs = auditLog.DurationMs,
                    Severity = auditLog.Severity,
                    CreatedAt = auditLog.CreatedAt,
                    CreatedByConnectedId = auditLog.CreatedByConnectedId,
                    UpdatedAt = auditLog.UpdatedAt,
                    UpdatedByConnectedId = auditLog.UpdatedByConnectedId,
                    IsDeleted = auditLog.IsDeleted,
                    DeletedAt = auditLog.DeletedAt,
                    DeletedByConnectedId = auditLog.DeletedByConnectedId,
                    AuditTrailDetails = new List<AuditTrailDetailDto>()
                };

                // 5. 수행자 정보 추가 (ConnectedId 엔티티에서 필요한 정보 가져오기)
                if (auditLog.PerformedByConnectedId.HasValue)
                {
                    var performer = await _connectedIdRepository.GetByIdAsync(auditLog.PerformedByConnectedId.Value);
                    if (performer != null)
                    {
                        response.PerformedBy = new PerformedByInfo
                        {
                            ConnectedId = performer.Id,
                            DisplayName = performer.DisplayName,
                            Role = null // ConnectedId 엔티티에 PrimaryRole이 없으면 null
                        };
                    }
                }

                // 6. 캐시 저장
                _memoryCache.Set(cacheKey, response, TimeSpan.FromSeconds(DEFAULT_CACHE_DURATION));

                return ServiceResult<AuditLogDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit log {AuditLogId}", auditLogId);
                return ServiceResult<AuditLogDetailResponse>.Failure(
                    "Failed to retrieve audit log",
                    "AUDIT_RETRIEVE_ERROR");
            }
        }

        /// <summary>
        /// 감사 로그 목록 조회 (페이징) - 조직별 격리 적용
        /// </summary>
        public async Task<ServiceResult<AuditLogListResponse>> GetAuditLogsAsync(
            SearchAuditLogsRequest request,
            PaginationRequest pagination,
            Guid connectedId)
        {
            try
            {
                // 1. ConnectedId의 조직 확인 (멀티테넌시 격리)
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null)
                {
                    return ServiceResult<AuditLogListResponse>.Failure(
                        "Invalid ConnectedId",
                        AuthConstants.ErrorCodes.INVALID_USER_ID);
                }

                // 2. 조직 격리 적용 - SaaS 핵심: 다른 조직의 데이터는 절대 보이지 않음
                var query = _auditLogRepository.Query()
                    .Where(a => a.TargetOrganizationId == connectedIdEntity.OrganizationId);

                // 3. 필터 적용
                if (request.ActionType.HasValue)
                    query = query.Where(a => a.ActionType == request.ActionType.Value);

                if (!string.IsNullOrEmpty(request.Keyword))
                    query = query.Where(a => a.Action.Contains(request.Keyword));

                if (!string.IsNullOrEmpty(request.ResourceType))
                    query = query.Where(a => a.ResourceType == request.ResourceType);

                if (!string.IsNullOrEmpty(request.ResourceId))
                    query = query.Where(a => a.ResourceId == request.ResourceId);

                if (request.StartDate.HasValue)
                    query = query.Where(a => a.Timestamp >= request.StartDate.Value);

                if (request.EndDate.HasValue)
                    query = query.Where(a => a.Timestamp <= request.EndDate.Value);

                if (request.Severity.HasValue)
                    query = query.Where(a => a.Severity == request.Severity.Value);

                if (request.Success.HasValue)
                    query = query.Where(a => a.Success == request.Success.Value);

                // 4. 정렬
                query = query.OrderByDescending(a => a.Timestamp);

                // 5. 통계 정보 생성
                var filterSummary = new AuditLogFilterSummary
                {
                    SuccessCount = await query.CountAsync(a => a.Success),
                    FailureCount = await query.CountAsync(a => !a.Success),
                    CountBySeverity = await query
                        .GroupBy(a => a.Severity.ToString())
                        .Select(g => new { Key = g.Key, Count = g.Count() })
                        .ToDictionaryAsync(x => x.Key, x => x.Count),
                    CountByActionType = await query
                        .GroupBy(a => a.ActionType.ToString())
                        .Select(g => new { Key = g.Key, Count = g.Count() })
                        .ToDictionaryAsync(x => x.Key, x => x.Count)
                };

                // 6. 페이징 처리
                var totalCount = await query.CountAsync();
                var items = await query
                    .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                    .Take(pagination.PageSize)
                    .Select(a => MapToDto(a))
                    .ToListAsync();

                // 7. 응답 구성
                var response = new AuditLogListResponse
                {
                    Items = items,
                    PageNumber = pagination.PageNumber,
                    PageSize = pagination.PageSize,
                    TotalCount = totalCount,
                    FilterSummary = filterSummary
                };

                return ServiceResult<AuditLogListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit logs for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<AuditLogListResponse>.Failure(
                    "Failed to retrieve audit logs",
                    "AUDIT_LIST_ERROR");
            }
        }

        /// <summary>
        /// 특정 리소스의 감사 로그 조회 - v15: ConnectedId 기반 권한 검증
        /// </summary>
        public async Task<ServiceResult<List<AuditLogDto>>> GetResourceAuditLogsAsync(
            string resourceType,
            string resourceId,
            Guid connectedId,
            int? limit = 50)
        {
            try
            {
                // ConnectedId의 조직 확인
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null)
                {
                    return ServiceResult<List<AuditLogDto>>.Failure(
                        "Invalid ConnectedId",
                        AuthConstants.ErrorCodes.INVALID_USER_ID);
                }

                // 조직 격리 적용하여 리소스 로그 조회
                var query = _auditLogRepository.Query()
                    .Where(a => a.TargetOrganizationId == connectedIdEntity.OrganizationId)
                    .Where(a => a.ResourceType == resourceType && a.ResourceId == resourceId)
                    .OrderByDescending(a => a.Timestamp);

                IQueryable<AuditLog> finalQuery = query;
                if (limit.HasValue)
                    finalQuery = finalQuery.Take(limit.Value);

                var logs = await finalQuery.Select(a => MapToDto(a)).ToListAsync();

                return ServiceResult<List<AuditLogDto>>.Success(logs);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get resource audit logs for {ResourceType}:{ResourceId}",
                    resourceType, resourceId);
                return ServiceResult<List<AuditLogDto>>.Failure(
                    "Failed to retrieve resource audit logs",
                    "RESOURCE_AUDIT_ERROR");
            }
        }

        /// <summary>
        /// 특정 사용자의 활동 로그 조회 - v15: ConnectedId 활동 추적
        /// </summary>
        public async Task<ServiceResult<List<AuditLogDto>>> GetUserActivityLogsAsync(
            Guid targetConnectedId,
            DateTime? startDate,
            DateTime? endDate,
            Guid requestingConnectedId,
            int? limit = 100)
        {
            try
            {
                // 권한 검증: 자기 자신이거나 관리자 권한 필요
                var hasAccess = await ValidateUserActivityAccessAsync(requestingConnectedId, targetConnectedId);
                if (!hasAccess)
                {
                    return ServiceResult<List<AuditLogDto>>.Failure(
                        "Access denied to user activity logs",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                var query = _auditLogRepository.Query()
                    .Where(a => a.PerformedByConnectedId == targetConnectedId);

                if (startDate.HasValue)
                    query = query.Where(a => a.Timestamp >= startDate.Value);

                if (endDate.HasValue)
                    query = query.Where(a => a.Timestamp <= endDate.Value);

                var orderedQuery = query.OrderByDescending(a => a.Timestamp);

                IQueryable<AuditLog> finalQuery = orderedQuery;
                if (limit.HasValue)
                    finalQuery = finalQuery.Take(limit.Value);

                var logs = await finalQuery.Select(a => MapToDto(a)).ToListAsync();

                return ServiceResult<List<AuditLogDto>>.Success(logs);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get user activity logs for ConnectedId {ConnectedId}",
                    targetConnectedId);
                return ServiceResult<List<AuditLogDto>>.Failure(
                    "Failed to retrieve user activity logs",
                    "USER_ACTIVITY_ERROR");
            }
        }

        /// <summary>
        /// 조직의 감사 로그 조회 - v15: 조직 격리 보장
        /// </summary>
        public async Task<ServiceResult<AuditLogListResponse>> GetOrganizationAuditLogsAsync(
            Guid organizationId,
            SearchAuditLogsRequest request,
            PaginationRequest pagination,
            Guid connectedId)
        {
            try
            {
                // ConnectedId가 해당 조직에 속하는지 검증
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null || connectedIdEntity.OrganizationId != organizationId)
                {
                    return ServiceResult<AuditLogListResponse>.Failure(
                        "Access denied to organization audit logs",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                // 조직 필터를 강제 적용
                request.OrganizationId = organizationId;

                return await GetAuditLogsAsync(request, pagination, connectedId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to get organization audit logs for Org {OrgId}",
                    organizationId);
                return ServiceResult<AuditLogListResponse>.Failure(
                    "Failed to retrieve organization audit logs",
                    "ORG_AUDIT_ERROR");
            }
        }

        #endregion

        #region Audit Trail Details

        /// <summary>
        /// 감사 추적 상세 내역 추가
        /// </summary>
        public async Task<ServiceResult<AuditTrailDetailDto>> AddAuditTrailDetailAsync(
            Guid auditLogId,
            string fieldName,
            string? oldValue,
            string? newValue,
            AuditFieldType fieldType,
            Guid connectedId)
        {
            try
            {
                // 권한 검증
                var hasAccess = await ValidateAuditLogAccessAsync(connectedId, auditLogId);
                if (!hasAccess)
                {
                    return ServiceResult<AuditTrailDetailDto>.Failure(
                        "Access denied",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                var detail = new AuditTrailDetail
                {
                    Id = Guid.NewGuid(),
                    AuditLogId = auditLogId,
                    FieldName = fieldName,
                    OldValue = oldValue,
                    NewValue = newValue,
                    FieldType = fieldType,
                    ActionType = AuditActionType.Update,
                    IsSecureField = IsSecureField(fieldName),
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = connectedId
                };

                // 민감한 필드는 마스킹 처리
                if (detail.IsSecureField)
                {
                    detail.OldValue = MaskSensitiveData(oldValue);
                    detail.NewValue = MaskSensitiveData(newValue);
                }

                // Repository에 추가
                await _auditLogRepository.AddAsync(new AuditLog()); // 실제로는 AuditTrailDetail 추가 메서드 필요
                await _unitOfWork.SaveChangesAsync();

                var dto = MapTrailDetailToDto(detail);
                return ServiceResult<AuditTrailDetailDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add audit trail detail");
                return ServiceResult<AuditTrailDetailDto>.Failure(
                    "Failed to add audit trail detail",
                    "TRAIL_DETAIL_ERROR");
            }
        }

        /// <summary>
        /// 벌크 감사 추적 상세 내역 추가
        /// </summary>
        public async Task<ServiceResult<List<AuditTrailDetailDto>>> AddBulkAuditTrailDetailsAsync(
            Guid auditLogId,
            List<AuditTrailDetailDto> details,
            Guid connectedId)
        {
            try
            {
                // 권한 검증
                var hasAccess = await ValidateAuditLogAccessAsync(connectedId, auditLogId);
                if (!hasAccess)
                {
                    return ServiceResult<List<AuditTrailDetailDto>>.Failure(
                        "Access denied",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                var entities = new List<AuditTrailDetail>();
                foreach (var detail in details)
                {
                    var entity = new AuditTrailDetail
                    {
                        Id = Guid.NewGuid(),
                        AuditLogId = auditLogId,
                        FieldName = detail.FieldName,
                        OldValue = detail.OldValue,
                        NewValue = detail.NewValue,
                        FieldType = detail.FieldType,
                        ActionType = detail.ActionType,
                        IsSecureField = IsSecureField(detail.FieldName),
                        CreatedAt = DateTime.UtcNow,
                        CreatedByConnectedId = connectedId
                    };

                    // 민감한 필드 마스킹
                    if (entity.IsSecureField)
                    {
                        entity.OldValue = MaskSensitiveData(detail.OldValue);
                        entity.NewValue = MaskSensitiveData(detail.NewValue);
                    }

                    entities.Add(entity);
                }

                // Bulk 저장 (실제로는 AuditTrailDetail 전용 메서드 필요)
                await _unitOfWork.SaveChangesAsync();

                var dtos = entities.Select(MapTrailDetailToDto).ToList();
                return ServiceResult<List<AuditTrailDetailDto>>.Success(dtos);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add bulk audit trail details");
                return ServiceResult<List<AuditTrailDetailDto>>.Failure(
                    "Failed to add bulk audit trail details",
                    "BULK_TRAIL_ERROR");
            }
        }

        #endregion

        #region Entity Change Tracking

        /// <summary>
        /// 엔티티 변경 사항 자동 감사 로그 생성
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogEntityChangeAsync<TEntity>(
            TEntity? oldEntity,
            TEntity? newEntity,
            AuditActionType actionType,
            Guid connectedId,
            string? customAction = null) where TEntity : class
        {
            try
            {
                var entityType = typeof(TEntity).Name;
                var action = customAction ?? $"{entityType}.{actionType}";

                // 리소스 ID 추출
                var resourceId = ExtractEntityId(newEntity ?? oldEntity);

                var request = new CreateAuditLogRequest
                {
                    ActionType = actionType,
                    Action = action,
                    ResourceType = entityType,
                    ResourceId = resourceId,
                    Success = true,
                    Severity = AuditEventSeverity.Info
                };

                // 변경 내역 추출 및 메타데이터 생성
                if (oldEntity != null && newEntity != null)
                {
                    var changes = ExtractChanges(oldEntity, newEntity);
                    if (changes.Any())
                    {
                        request.Metadata = JsonConvert.SerializeObject(new
                        {
                            changes = changes,
                            changeCount = changes.Count
                        });
                    }
                }

                var result = await CreateAuditLogAsync(request, connectedId);

                // 상세 변경 내역 추가
                if (result.IsSuccess && result.Data != null && oldEntity != null && newEntity != null)
                {
                    var changes = ExtractDetailedChanges(oldEntity, newEntity);
                    if (changes.Any())
                    {
                        await AddBulkAuditTrailDetailsAsync(result.Data.Id, changes, connectedId);
                    }
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log entity change for {EntityType}", typeof(TEntity).Name);
                return ServiceResult<AuditLogDto>.Failure(
                    "Failed to log entity change",
                    "ENTITY_CHANGE_ERROR");
            }
        }

        #endregion

        #region Specialized Logging

        /// <summary>
        /// 로그인 시도 감사 로그 - v15: ConnectedId 옵셔널 (로그인 실패 시)
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogLoginAttemptAsync(
            string? username,
            bool success,
            string? ipAddress,
            string? userAgent,
            string? errorMessage = null,
            Guid? connectedId = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = connectedId,
                    Timestamp = DateTime.UtcNow,
                    ActionType = success ? AuditActionType.Login : AuditActionType.FailedLogin,
                    Action = "user.login.attempt",
                    ResourceType = "Authentication",
                    ResourceId = username,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    Success = success,
                    ErrorMessage = errorMessage,
                    Severity = success ? AuditEventSeverity.Info : AuditEventSeverity.Warning,
                    Metadata = JsonConvert.SerializeObject(new
                    {
                        username = username,
                        loginTime = DateTime.UtcNow
                    }),
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = connectedId
                };

                // 실패한 로그인 시도가 많으면 보안 이벤트로 격상
                if (!success)
                {
                    var recentFailures = await CountRecentFailedLoginsAsync(username, ipAddress);
                    if (recentFailures >= 5)
                    {
                        auditLog.Severity = AuditEventSeverity.Critical;
                        await HandleSecurityEventAsync(auditLog);
                    }
                }

                await _auditLogRepository.AddAsync(auditLog);
                await _unitOfWork.SaveChangesAsync();

                var dto = MapToDto(auditLog);
                return ServiceResult<AuditLogDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log login attempt");
                return ServiceResult<AuditLogDto>.Failure(
                    "Failed to log login attempt",
                    "LOGIN_LOG_ERROR");
            }
        }

        /// <summary>
        /// 권한 변경 감사 로그
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogPermissionChangeAsync(
            string resourceType,
            string resourceId,
            string permission,
            string action,
            Guid grantedToConnectedId,
            Guid grantedByConnectedId)
        {
            var metadata = new Dictionary<string, object>
            {
                ["permission"] = permission,
                ["grantedTo"] = grantedToConnectedId,
                ["action"] = action
            };

            return await LogActionAsync(
                action == "grant" ? AuditActionType.Grant : AuditActionType.Revoke,
                $"permission.{action}",
                grantedByConnectedId,
                true,
                null,
                resourceType,
                resourceId,
                metadata);
        }

        /// <summary>
        /// 데이터 접근 감사 로그
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogDataAccessAsync(
            string resourceType,
            string resourceId,
            string accessType,
            Guid connectedId,
            Dictionary<string, object>? additionalInfo = null)
        {
            var metadata = additionalInfo ?? new Dictionary<string, object>();
            metadata["accessType"] = accessType;
            metadata["accessTime"] = DateTime.UtcNow;

            return await LogActionAsync(
                AuditActionType.Read,
                $"data.{accessType.ToLower()}",
                connectedId,
                true,
                null,
                resourceType,
                resourceId,
                metadata);
        }

        /// <summary>
        /// 설정 변경 감사 로그 - v15: 조직 및 애플리케이션 레벨 설정 지원
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogSettingChangeAsync(
            string settingKey,
            string? oldValue,
            string? newValue,
            Guid connectedId,
            Guid? organizationId = null,
            Guid? applicationId = null)
        {
            var metadata = new Dictionary<string, object>
            {
                ["settingKey"] = settingKey,
                ["oldValue"] = MaskSensitiveData(oldValue) ?? "null",
                ["newValue"] = MaskSensitiveData(newValue) ?? "null"
            };

            var request = new CreateAuditLogRequest
            {
                ActionType = AuditActionType.Update,
                Action = "setting.change",
                ResourceType = "Configuration",
                ResourceId = settingKey,
                Success = true,
                Metadata = JsonConvert.SerializeObject(metadata),
                OrganizationId = organizationId,
                ApplicationId = applicationId,
                Severity = AuditEventSeverity.Info
            };

            return await CreateAuditLogAsync(request, connectedId);
        }

        /// <summary>
        /// 보안 이벤트 감사 로그
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogSecurityEventAsync(
            string eventType,
            AuditEventSeverity severity,
            string description,
            Guid? connectedId,
            Dictionary<string, object>? details = null)
        {
            var auditLog = new AuditLog
            {
                Id = Guid.NewGuid(),
                PerformedByConnectedId = connectedId,
                Timestamp = DateTime.UtcNow,
                ActionType = AuditActionType.System,
                Action = $"security.{eventType.ToLower()}",
                ResourceType = "Security",
                ResourceId = eventType,
                Success = false, // 보안 이벤트는 기본적으로 이상 상황
                Severity = severity,
                Metadata = details != null ? JsonConvert.SerializeObject(details) : null,
                CreatedAt = DateTime.UtcNow,
                CreatedByConnectedId = connectedId
            };

            // 보안 이벤트 처리
            await HandleSecurityEventAsync(auditLog);

            await _auditLogRepository.AddAsync(auditLog);
            await _unitOfWork.SaveChangesAsync();

            var dto = MapToDto(auditLog);
            return ServiceResult<AuditLogDto>.Success(dto);
        }

        #endregion

        #region Statistics and Analytics

        /// <summary>
        /// 감사 로그 통계 조회 - 멀티테넌시 격리 적용
        /// </summary>
        public async Task<ServiceResult<AuditLogStatistics>> GetAuditLogStatisticsAsync(
            Guid? organizationId,
            DateTime startDate,
            DateTime endDate,
            Guid connectedId)
        {
            try
            {
                // ConnectedId 검증 및 조직 확인
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null)
                {
                    return ServiceResult<AuditLogStatistics>.Failure(
                        "Invalid ConnectedId",
                        AuthConstants.ErrorCodes.INVALID_USER_ID);
                }

                // 조직 격리: 자신의 조직 데이터만 조회 가능
                var targetOrgId = organizationId ?? connectedIdEntity.OrganizationId;
                if (targetOrgId != connectedIdEntity.OrganizationId)
                {
                    return ServiceResult<AuditLogStatistics>.Failure(
                        "Access denied to organization statistics",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                var query = _auditLogRepository.Query()
                    .Where(a => a.TargetOrganizationId == targetOrgId)
                    .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate);

                var statistics = new AuditLogStatistics
                {
                    TotalLogs = await query.CountAsync(),
                    SuccessfulLogs = await query.CountAsync(a => a.Success),
                    FailedLogs = await query.CountAsync(a => !a.Success),
                    UniqueUsers = await query.Select(a => a.PerformedByConnectedId).Distinct().CountAsync(),
                    SecurityEvents = await query.CountAsync(a => a.Severity >= AuditEventSeverity.Warning),
                    CriticalEvents = await query.CountAsync(a => a.Severity == AuditEventSeverity.Critical),
                    ByAction = await query
                        .GroupBy(a => a.Action)
                        .Select(g => new { g.Key, Count = g.Count() })
                        .ToDictionaryAsync(x => x.Key, x => x.Count),
                    ByEntity = await query
                        .Where(a => a.ResourceType != null)
                        .GroupBy(a => a.ResourceType!)
                        .Select(g => new { g.Key, Count = g.Count() })
                        .ToDictionaryAsync(x => x.Key, x => x.Count),
                    GeneratedAt = DateTime.UtcNow,
                    Period = new { StartDate = startDate, EndDate = endDate }
                };

                // 캐시에 저장 (조직별 캐시)
                var cacheKey = $"{CACHE_KEY_PREFIX}stats:{targetOrgId}:{startDate:yyyyMMdd}-{endDate:yyyyMMdd}";
                await _distributedCache.SetStringAsync(
                    cacheKey,
                    JsonConvert.SerializeObject(statistics),
                    new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
                    });

                return ServiceResult<AuditLogStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit log statistics");
                return ServiceResult<AuditLogStatistics>.Failure(
                    "Failed to generate statistics",
                    "STATISTICS_ERROR");
            }
        }

        #endregion

        #region Export and Archive

        /// <summary>
        /// 감사 로그 내보내기 - 조직 데이터만 내보내기
        /// </summary>
        public async Task<ServiceResult<byte[]>> ExportAuditLogsAsync(
            SearchAuditLogsRequest request,
            DataFormat format,
            Guid connectedId)
        {
            try
            {
                // 조직 격리 적용하여 로그 조회
                var logsResult = await GetAuditLogsAsync(
                    request,
                    new PaginationRequest { PageNumber = 1, PageSize = 10000 }, // 최대 10000개
                    connectedId);

                if (!logsResult.IsSuccess || logsResult.Data == null)
                {
                    return ServiceResult<byte[]>.Failure(
                        "Failed to retrieve logs for export",
                        "EXPORT_RETRIEVE_ERROR");
                }

                byte[] exportData;
                switch (format)
                {
                    case DataFormat.Json:
                        exportData = ExportToJson(logsResult.Data.Items);
                        break;
                    case DataFormat.Csv:
                        exportData = ExportToCsv(logsResult.Data.Items);
                        break;
                    case DataFormat.Excel:
                        exportData = ExportToExcel(logsResult.Data.Items);
                        break;
                    default:
                        return ServiceResult<byte[]>.Failure(
                            $"Unsupported export format: {format}",
                            "UNSUPPORTED_FORMAT");
                }

                _logger.LogInformation(
                    "Exported {Count} audit logs in {Format} format for ConnectedId {ConnectedId}",
                    logsResult.Data.Items.Count, format, connectedId);

                return ServiceResult<byte[]>.Success(exportData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export audit logs");
                return ServiceResult<byte[]>.Failure(
                    "Failed to export audit logs",
                    "EXPORT_ERROR");
            }
        }

        /// <summary>
        /// 감사 로그 보관 정책 적용
        /// </summary>
        public async Task<ServiceResult<int>> ApplyRetentionPolicyAsync(
            int retentionDays,
            Guid? organizationId,
            Guid connectedId)
        {
            try
            {
                // 관리자 권한 검증 필요
                // TODO: 권한 검증 구현

                var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
                var query = _auditLogRepository.Query()
                    .Where(a => a.Timestamp < cutoffDate)
                    .Where(a => !a.IsArchived);

                if (organizationId.HasValue)
                {
                    query = query.Where(a => a.TargetOrganizationId == organizationId);
                }

                var logsToArchive = await query.ToListAsync();

                foreach (var log in logsToArchive)
                {
                    log.IsArchived = true;
                    log.ArchivedAt = DateTime.UtcNow;
                    // TODO: 실제 아카이브 스토리지로 이동
                    log.ArchiveLocation = $"gs://authhive-archive/{log.TargetOrganizationId}/{log.Id}";
                }

                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation(
                    "Applied retention policy: archived {Count} logs older than {Days} days",
                    logsToArchive.Count, retentionDays);

                return ServiceResult<int>.Success(logsToArchive.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to apply retention policy");
                return ServiceResult<int>.Failure(
                    "Failed to apply retention policy",
                    "RETENTION_ERROR");
            }
        }

        /// <summary>
        /// 감사 로그 정리 (소프트 삭제)
        /// </summary>
        public async Task<ServiceResult<int>> CleanupAuditLogsAsync(
            DateTime beforeDate,
            Guid? organizationId,
            Guid connectedId)
        {
            try
            {
                // 관리자 권한 검증 필요
                // TODO: 권한 검증 구현

                var query = _auditLogRepository.Query()
                    .Where(a => a.Timestamp < beforeDate)
                    .Where(a => a.IsArchived); // 아카이브된 로그만 삭제 가능

                if (organizationId.HasValue)
                {
                    query = query.Where(a => a.TargetOrganizationId == organizationId);
                }

                var logsToDelete = await query.ToListAsync();

                foreach (var log in logsToDelete)
                {
                    log.IsDeleted = true;
                    log.DeletedAt = DateTime.UtcNow;
                    log.DeletedByConnectedId = connectedId;
                }

                await _unitOfWork.SaveChangesAsync();

                _logger.LogInformation(
                    "Cleaned up {Count} audit logs older than {Date}",
                    logsToDelete.Count, beforeDate);

                return ServiceResult<int>.Success(logsToDelete.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup audit logs");
                return ServiceResult<int>.Failure(
                    "Failed to cleanup audit logs",
                    "CLEANUP_ERROR");
            }
        }

        #endregion

        #region Real-time and Compliance

        /// <summary>
        /// 실시간 감사 로그 스트림 구독
        /// </summary>
        public async Task<ServiceResult<string>> SubscribeToAuditStreamAsync(
            Guid? organizationId,
            AuditEventSeverity? minSeverity,
            Guid connectedId)
        {
            try
            {
                // TODO: SignalR 또는 WebSocket 구현
                var subscriptionId = Guid.NewGuid().ToString();

                // 구독 정보를 캐시에 저장
                var subscriptionInfo = new
                {
                    SubscriptionId = subscriptionId,
                    ConnectedId = connectedId,
                    OrganizationId = organizationId,
                    MinSeverity = minSeverity,
                    CreatedAt = DateTime.UtcNow
                };

                await _distributedCache.SetStringAsync(
                    $"{CACHE_KEY_PREFIX}subscription:{subscriptionId}",
                    JsonConvert.SerializeObject(subscriptionInfo),
                    new DistributedCacheEntryOptions
                    {
                        SlidingExpiration = TimeSpan.FromHours(1)
                    });

                return ServiceResult<string>.Success(subscriptionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to subscribe to audit stream");
                return ServiceResult<string>.Failure(
                    "Failed to subscribe to audit stream",
                    "SUBSCRIPTION_ERROR");
            }
        }

        /// <summary>
        /// 감사 로그 검증 (무결성 체크)
        /// </summary>
        public async Task<ServiceResult<AuditLogIntegrityCheckResult>> VerifyAuditLogIntegrityAsync(
            Guid auditLogId,
            Guid connectedId)
        {
            try
            {
                var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId);
                if (auditLog == null)
                {
                    return ServiceResult<AuditLogIntegrityCheckResult>.Failure(
                        "Audit log not found",
                        "AUDIT_NOT_FOUND");
                }

                var result = new AuditLogIntegrityCheckResult
                {
                    IsValid = true,
                    CheckedAt = DateTime.UtcNow,
                    Issues = new List<string>()
                };

                // 무결성 검증 로직
                // 1. 타임스탬프 검증
                if (auditLog.Timestamp > DateTime.UtcNow)
                {
                    result.IsValid = false;
                    result.Issues.Add("Timestamp is in the future");
                }

                // 2. ConnectedId 존재 여부 검증
                if (auditLog.PerformedByConnectedId.HasValue)
                {
                    var performer = await _connectedIdRepository.GetByIdAsync(auditLog.PerformedByConnectedId.Value);
                    if (performer == null)
                    {
                        result.Issues.Add("PerformedByConnectedId does not exist");
                    }
                }

                // 3. 해시 계산 (간단한 예시)
                var dataToHash = $"{auditLog.Id}{auditLog.Timestamp}{auditLog.Action}{auditLog.ResourceId}";
                result.Hash = ComputeHash(dataToHash);

                return ServiceResult<AuditLogIntegrityCheckResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify audit log integrity");
                return ServiceResult<AuditLogIntegrityCheckResult>.Failure(
                    "Failed to verify integrity",
                    "INTEGRITY_CHECK_ERROR");
            }
        }

        /// <summary>
        /// 컴플라이언스 보고서 생성
        /// </summary>
        public async Task<ServiceResult<ComplianceReport>> GenerateComplianceReportAsync(
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            ComplianceReportType reportType,
            Guid connectedId)
        {
            try
            {
                // 권한 검증
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null || connectedIdEntity.OrganizationId != organizationId)
                {
                    return ServiceResult<ComplianceReport>.Failure(
                        "Access denied",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                var report = new ComplianceReport
                {
                    ReportId = Guid.NewGuid(),
                    Type = reportType,
                    OrganizationId = organizationId,
                    PeriodStart = startDate,
                    PeriodEnd = endDate,
                    GeneratedAt = DateTime.UtcNow,
                    Data = new Dictionary<string, object>(),
                    Violations = new List<ComplianceViolation>()
                };

                // 보고서 타입별 데이터 수집
                switch (reportType)
                {
                    case ComplianceReportType.GDPR:
                        await GenerateGDPRReportData(report, organizationId, startDate, endDate);
                        break;
                    case ComplianceReportType.SOC2:
                        await GenerateSOC2ReportData(report, organizationId, startDate, endDate);
                        break;
                    case ComplianceReportType.ISO27001:
                        await GenerateISO27001ReportData(report, organizationId, startDate, endDate);
                        break;
                    default:
                        await GenerateGeneralComplianceData(report, organizationId, startDate, endDate);
                        break;
                }

                // 보고서 URL 생성 (실제로는 스토리지에 저장)
                report.ReportUrl = $"https://authhive.com/reports/{report.ReportId}";

                return ServiceResult<ComplianceReport>.Success(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate compliance report");
                return ServiceResult<ComplianceReport>.Failure(
                    "Failed to generate compliance report",
                    "COMPLIANCE_REPORT_ERROR");
            }
        }

        #endregion

        #region Private Helper Methods

        private AuditLogDto MapToDto(AuditLog entity)
        {
            return new AuditLogDto
            {
                Id = entity.Id,
                PerformedByConnectedId = entity.PerformedByConnectedId,
                OrganizationId = entity.TargetOrganizationId,
                ApplicationId = entity.ApplicationId,
                ActionType = entity.ActionType,
                Action = entity.Action,
                ResourceType = entity.ResourceType,
                ResourceId = entity.ResourceId,
                IpAddress = entity.IpAddress,
                UserAgent = entity.UserAgent,
                RequestId = entity.RequestId,
                Success = entity.Success,
                ErrorCode = entity.ErrorCode,
                ErrorMessage = entity.ErrorMessage,
                Metadata = entity.Metadata,
                DurationMs = entity.DurationMs,
                Severity = entity.Severity,
                CreatedAt = entity.CreatedAt,
                CreatedByConnectedId = entity.CreatedByConnectedId,
                UpdatedAt = entity.UpdatedAt,
                UpdatedByConnectedId = entity.UpdatedByConnectedId,
                IsDeleted = entity.IsDeleted,
                DeletedAt = entity.DeletedAt,
                DeletedByConnectedId = entity.DeletedByConnectedId,
                AuditTrailDetailsCount = entity.AuditTrailDetails?.Count ?? 0
            };
        }

        private AuditTrailDetailDto MapTrailDetailToDto(AuditTrailDetail entity)
        {
            return new AuditTrailDetailDto
            {
                Id = entity.Id,
                AuditLogId = entity.AuditLogId,
                FieldName = entity.FieldName,
                FieldType = entity.FieldType,
                OldValue = entity.OldValue,
                NewValue = entity.NewValue,
                ActionType = entity.ActionType,
                IsSecureField = entity.IsSecureField,
                ValidationResult = entity.ValidationResult,
                IsSystemManaged = entity.IsSystemManaged,
                SystemCode = entity.SystemCode,
                CreatedAt = entity.CreatedAt,
                CreatedByConnectedId = entity.CreatedByConnectedId,
                UpdatedAt = entity.UpdatedAt,
                UpdatedByConnectedId = entity.UpdatedByConnectedId,
                IsDeleted = entity.IsDeleted,
                DeletedAt = entity.DeletedAt,
                DeletedByConnectedId = entity.DeletedByConnectedId
            };
        }

        private async Task<bool> ValidateAuditLogAccessAsync(Guid connectedId, Guid auditLogId)
        {
            // TODO: 실제 권한 검증 로직 구현
            // 현재는 간단한 조직 멤버십 체크만 수행
            var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId);
            if (auditLog == null) return false;

            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
            if (connectedIdEntity == null) return false;

            return auditLog.TargetOrganizationId == connectedIdEntity.OrganizationId;
        }
        private async Task<bool> ValidateUserActivityAccessAsync(Guid requestingConnectedId, Guid targetConnectedId)
        {
            // 1. 자기 자신
            if (requestingConnectedId == targetConnectedId)
                return true;

            // 2. 같은 조직인지 확인
            var requestingUser = await _connectedIdRepository.GetByIdAsync(requestingConnectedId);
            var targetUser = await _connectedIdRepository.GetByIdAsync(targetConnectedId);

            if (requestingUser?.OrganizationId != targetUser?.OrganizationId)
                return false;

            // 3. 역할 문자열로 간단히 체크
            var userRoles = await _roleRepository.GetByConnectedIdAsync(requestingConnectedId);

            foreach (var role in userRoles)
            {
                var roleKey = role.RoleKey.ToLowerInvariant();

                // 관리자나 감사 관련 역할이면 허용
                if (roleKey.Contains("admin") ||
                    roleKey.Contains("audit") ||
                    roleKey.Contains("manager") ||
                    roleKey.Contains("compliance"))
                {
                    return true;
                }
            }

            return false;
        }
        private async Task HandleSecurityEventAsync(AuditLog auditLog)
        {
            // TODO: 보안 이벤트 처리 로직
            // 1. 알림 발송
            // 2. 관리자 이메일
            // 3. 실시간 모니터링 시스템 알림
            await Task.CompletedTask;
        }

        private bool IsSecureField(string? fieldName)
        {
            if (string.IsNullOrEmpty(fieldName)) return false;

            var secureFields = new[] { "password", "ssn", "creditcard", "apikey", "secret", "token" };
            return secureFields.Any(sf => fieldName.ToLower().Contains(sf));
        }

        private string? MaskSensitiveData(string? data)
        {
            if (string.IsNullOrEmpty(data)) return data;
            if (data.Length <= 4) return "****";

            return data.Substring(0, 2) + new string('*', data.Length - 4) + data.Substring(data.Length - 2);
        }

        private string? ExtractEntityId<TEntity>(TEntity? entity) where TEntity : class
        {
            if (entity == null) return null;

            var idProperty = entity.GetType().GetProperty("Id");
            return idProperty?.GetValue(entity)?.ToString();
        }

        private List<KeyValuePair<string, string>> ExtractChanges<TEntity>(TEntity oldEntity, TEntity newEntity)
            where TEntity : class
        {
            var changes = new List<KeyValuePair<string, string>>();
            var properties = typeof(TEntity).GetProperties();

            foreach (var prop in properties)
            {
                var oldValue = prop.GetValue(oldEntity)?.ToString();
                var newValue = prop.GetValue(newEntity)?.ToString();

                if (oldValue != newValue)
                {
                    changes.Add(new KeyValuePair<string, string>(prop.Name, $"{oldValue} -> {newValue}"));
                }
            }

            return changes;
        }

        private List<AuditTrailDetailDto> ExtractDetailedChanges<TEntity>(TEntity oldEntity, TEntity newEntity)
            where TEntity : class
        {
            var details = new List<AuditTrailDetailDto>();
            var properties = typeof(TEntity).GetProperties();

            foreach (var prop in properties)
            {
                var oldValue = prop.GetValue(oldEntity)?.ToString();
                var newValue = prop.GetValue(newEntity)?.ToString();

                if (oldValue != newValue)
                {
                    details.Add(new AuditTrailDetailDto
                    {
                        FieldName = prop.Name,
                        OldValue = oldValue,
                        NewValue = newValue,
                        FieldType = DetermineFieldType(prop.PropertyType),
                        ActionType = AuditActionType.Update
                    });
                }
            }

            return details;
        }

        private AuditFieldType DetermineFieldType(Type type)
        {
            if (type == typeof(string)) return AuditFieldType.String;
            if (type == typeof(int) || type == typeof(long) || type == typeof(decimal)) return AuditFieldType.Number;
            if (type == typeof(DateTime) || type == typeof(DateTimeOffset)) return AuditFieldType.DateTime;
            if (type == typeof(bool)) return AuditFieldType.Boolean;

            return AuditFieldType.Object;
        }

        private async Task<int> CountRecentFailedLoginsAsync(string? username, string? ipAddress)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-15);
            var query = _auditLogRepository.Query()
                .Where(a => a.ActionType == AuditActionType.FailedLogin)
                .Where(a => a.Timestamp >= cutoff);

            if (!string.IsNullOrEmpty(username))
                query = query.Where(a => a.ResourceId == username);

            if (!string.IsNullOrEmpty(ipAddress))
                query = query.Where(a => a.IpAddress == ipAddress);

            return await query.CountAsync();
        }

        private async Task InvalidateOrganizationCacheAsync(Guid? organizationId)
        {
            if (!organizationId.HasValue) return;

            var cacheKey = $"{CACHE_KEY_PREFIX}org:{organizationId}:*";
            // TODO: 와일드카드 캐시 삭제 구현
            await Task.CompletedTask;
        }

        private string ComputeHash(string data)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(data);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        private byte[] ExportToJson(List<AuditLogDto> logs)
        {
            var json = JsonConvert.SerializeObject(logs, Formatting.Indented);
            return System.Text.Encoding.UTF8.GetBytes(json);
        }

        private byte[] ExportToCsv(List<AuditLogDto> logs)
        {
            // TODO: CSV 변환 로직 구현
            var csv = "Id,Action,Timestamp,Success\n";
            foreach (var log in logs)
            {
                csv += $"{log.Id},{log.Action},{log.CreatedAt},{log.Success}\n";
            }
            return System.Text.Encoding.UTF8.GetBytes(csv);
        }

        private byte[] ExportToExcel(List<AuditLogDto> logs)
        {
            // TODO: Excel 변환 로직 구현 (EPPlus 등 사용)
            return ExportToCsv(logs); // 임시로 CSV 반환
        }

        private async Task GenerateGDPRReportData(ComplianceReport report, Guid organizationId,
            DateTime startDate, DateTime endDate)
        {
            // GDPR 관련 데이터 수집
            report.Data["dataAccessLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId)
                .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate)
                .Where(a => a.ActionType == AuditActionType.Read)
                .CountAsync();

            report.Data["dataModificationLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId)
                .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate)
                .Where(a => a.ActionType == AuditActionType.Update || a.ActionType == AuditActionType.Delete)
                .CountAsync();
        }

        private async Task GenerateSOC2ReportData(ComplianceReport report, Guid organizationId,
            DateTime startDate, DateTime endDate)
        {
            // SOC2 관련 데이터 수집
            report.Data["securityEvents"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId)
                .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate)
                .Where(a => a.Severity >= AuditEventSeverity.Warning)
                .CountAsync();
        }

        private async Task GenerateISO27001ReportData(ComplianceReport report, Guid organizationId,
            DateTime startDate, DateTime endDate)
        {
            // ISO27001 관련 데이터 수집
            report.Data["accessControlLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId)
                .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate)
                .Where(a => a.ActionType == AuditActionType.Grant || a.ActionType == AuditActionType.Revoke)
                .CountAsync();
        }

        private async Task GenerateGeneralComplianceData(ComplianceReport report, Guid organizationId,
            DateTime startDate, DateTime endDate)
        {
            // 일반 컴플라이언스 데이터 수집
            report.Data["totalLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId)
                .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate)
                .CountAsync();
        }

        #endregion
    }
}