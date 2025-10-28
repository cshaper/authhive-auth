using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Audit;
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
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService를 위해 추가
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Auth.Security.Events;
using AuthHive.Core.Entities.User; // AuditLogCreatedEvent 같은 도메인 이벤트를 위해 추가

namespace AuthHive.Auth.Services.Audit
{
    /// <summary>
    /// 감사 로그 서비스 구현 - AuthHive v16
    /// SaaS 애플리케이션의 모든 활동을 추적하고 컴플라이언스를 지원합니다.
    /// 멀티테넌시 환경에서 조직별 로그 격리를 보장하며, ICacheService와 IEventBus를 통해 시스템과 연동됩니다.
    /// </summary>
    public class AuditService : IAuditService
    {
        #region Dependencies

        private readonly IAuditLogRepository _auditLogRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ICacheService _cacheService; 
        private readonly IEventBus _eventBus; 
        private readonly ILogger<AuditService> _logger;

        // 캐시 키 상수
        private const string CACHE_KEY_PREFIX = "audit:";
        private static readonly TimeSpan DefaultCacheDuration = TimeSpan.FromMinutes(5);

        #endregion

        #region Constructor

        public AuditService(
            IAuditLogRepository auditLogRepository,
            IConnectedIdRepository connectedIdRepository,
            IRoleRepository roleRepository,
            IUnitOfWork unitOfWork,
            ICacheService cacheService,
            IEventBus eventBus, 
            ILogger<AuditService> logger)
        {
            _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
            _connectedIdRepository = connectedIdRepository ?? throw new ArgumentNullException(nameof(connectedIdRepository));
            _roleRepository = roleRepository ?? throw new ArgumentNullException(nameof(roleRepository));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #endregion

        #region IService Implementation

        /// <summary>
        /// 서비스의 건강 상태를 확인합니다.
        /// 데이터베이스 및 캐시 서비스 연결을 검증합니다.
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 데이터베이스 연결 확인
                await _auditLogRepository.Query().AnyAsync(cancellationToken);

                // 2. 캐시 서비스 건강 상태 확인
                return await _cacheService.IsHealthyAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AuditService health check failed.");
                return false;
            }
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("AuditService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region Core Audit Operations

        /// <summary>
        /// 감사 로그를 생성하고, 중요 이벤트인 경우 이벤트 버스를 통해 시스템에 알립니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> CreateAuditLogAsync(
            CreateAuditLogRequest request,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 요청 주체(ConnectedId)가 유효한지 검증합니다. 모든 활동은 유효한 ConnectedId에 의해 수행되어야 합니다.
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
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
                    TargetOrganizationId = request.OrganizationId ?? connectedIdEntity.OrganizationId, // 요청에 OrgId가 없으면 주체의 OrgId를 사용
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
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = connectedId
                };

                // 3. 데이터베이스에 저장
                await _auditLogRepository.AddAsync(auditLog, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 4. 관련 캐시 무효화 (예: 조직 통계 캐시)
                await InvalidateOrganizationCacheAsync(auditLog.TargetOrganizationId, cancellationToken);

                var dto = MapToDto(auditLog);

                // 5. 중요도(Warning 이상)가 높은 보안 이벤트인 경우, 다른 서비스에 알리기 위해 이벤트를 발행합니다.
                if (request.Severity >= AuditEventSeverity.Warning)
                {
                    var securityEvent = new SecurityAuditEventOccurred(
                        dto.Id,
                        dto.OrganizationId,
                        dto.PerformedByConnectedId,
                        dto.Action,
                        dto.Severity,
                        dto.CreatedAt);

                    await _eventBus.PublishAsync(securityEvent, cancellationToken);
                }

                _logger.LogInformation(
                    "Audit log created: {Action} by ConnectedId {ConnectedId} for Org {OrgId}",
                    auditLog.Action, connectedId, auditLog.TargetOrganizationId);

                return ServiceResult<AuditLogDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to create audit log for action {Action} by ConnectedId {ConnectedId}",
                    request.Action, connectedId);

                return ServiceResult<AuditLogDto>.Failure(
                    "An unexpected error occurred while creating the audit log.",
                    "AUDIT_CREATE_ERROR");
            }
        }
        /// <summary>
        /// 감사 로그 비동기 기록 (Fire-and-forget 방식)
        /// </summary>
        public async Task LogAsync(AuditLog auditLog, CancellationToken cancellationToken = default)    
        {
            try
            {
                // Fire-and-forget 방식으로 백그라운드에서 처리 : 그 작업이 끝날 때까지 기다리거나 성공/실패 결과를 확인하지 않고 즉시 다음 일을 처리하는 방식을 말합니다.
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _auditLogRepository.AddAsync(auditLog, cancellationToken);
                        await _unitOfWork.SaveChangesAsync(cancellationToken);
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
            Dictionary<string, object>? metadata = null,
            CancellationToken cancellationToken = default)
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

            return await CreateAuditLogAsync(request, connectedId, cancellationToken);
        }

        #endregion

        #region Query Operations

        /// <summary>
        /// 감사 로그 상세 정보를 조회합니다. 캐시를 우선 확인하여 성능을 최적화합니다.- 멀티테넌시 격리 적용
        /// </summary>
        public async Task<ServiceResult<AuditLogDetailResponse>> GetAuditLogAsync(
            Guid auditLogId,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var cacheKey = $"{CACHE_KEY_PREFIX}log:{auditLogId}";

                // 1. 캐시에서 먼저 조회 (ICacheService 사용)
                var cachedLog = await _cacheService.GetAsync<AuditLogDetailResponse>(cacheKey, cancellationToken);
                if (cachedLog != null)
                {
                    // 접근 권한 검증은 캐시된 데이터로도 수행해야 함
                    var hasAccess = await ValidateAuditLogAccessAsync(connectedId, cachedLog.OrganizationId, cancellationToken);
                    if (hasAccess) return ServiceResult<AuditLogDetailResponse>.Success(cachedLog);
                }

                // 2. 데이터베이스에서 조회
                var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
                if (auditLog == null)
                {
                    return ServiceResult<AuditLogDetailResponse>.Failure("Audit log not found.", "AUDIT_NOT_FOUND");
                }

                // 3. 접근 권한 검증: 요청자가 해당 로그를 볼 수 있는 조직에 속해있는지 확인
                var canAccess = await ValidateAuditLogAccessAsync(connectedId, auditLog.TargetOrganizationId, cancellationToken);
                if (!canAccess)
                {
                    return ServiceResult<AuditLogDetailResponse>.Failure("Access denied to audit log.", AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                // 4. 상세 정보 구성 및 DTO 매핑
                var response = await MapToDetailResponseAsync(auditLog, cancellationToken);

                // 5. 조회 결과를 캐시에 저장
                await _cacheService.SetAsync(cacheKey, response, DefaultCacheDuration, cancellationToken);

                return ServiceResult<AuditLogDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit log {AuditLogId}", auditLogId);
                return ServiceResult<AuditLogDetailResponse>.Failure("Failed to retrieve audit log.", "AUDIT_RETRIEVE_ERROR");
            }
        }

        /// <summary>
        /// 감사 로그 목록을 다양한 조건으로 검색하고 페이징하여 조회합니다.
        /// 모든 조회는 요청자(ConnectedId)가 속한 조직으로 자동 격리되어 다른 조직의 로그는 절대 볼 수 없습니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogListResponse>> GetAuditLogsAsync(
            SearchAuditLogsRequest request,
            PaginationRequest pagination,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 요청자의 조직 정보를 확인하여 데이터 조회를 해당 조직으로 격리(Isolate)합니다. (SaaS의 핵심 보안)
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
                if (connectedIdEntity == null)
                {
                    return ServiceResult<AuditLogListResponse>.Failure(
                        "Invalid ConnectedId.",
                        AuthConstants.ErrorCodes.INVALID_USER_ID);
                }

                // 2. 기본 쿼리를 생성하고, 요청자의 조직 ID로 필터링을 시작합니다.
                var query = _auditLogRepository.Query()
                    .Where(a => a.TargetOrganizationId == connectedIdEntity.OrganizationId);

                // 3. SearchAuditLogsRequest의 다양한 검색 조건들을 동적으로 쿼리에 추가합니다.
                if (request.PerformedByConnectedId.HasValue)
                    query = query.Where(a => a.PerformedByConnectedId == request.PerformedByConnectedId.Value);

                if (request.ApplicationId.HasValue)
                    query = query.Where(a => a.ApplicationId == request.ApplicationId.Value);

                if (request.ActionType.HasValue)
                    query = query.Where(a => a.ActionType == request.ActionType.Value);

                if (!string.IsNullOrEmpty(request.ResourceType))
                    query = query.Where(a => a.ResourceType == request.ResourceType);

                if (!string.IsNullOrEmpty(request.ResourceId))
                    query = query.Where(a => a.ResourceId == request.ResourceId);

                if (request.Severity.HasValue)
                    query = query.Where(a => a.Severity == request.Severity.Value);

                if (request.Success.HasValue)
                    query = query.Where(a => a.Success == request.Success.Value);

                if (request.StartDate.HasValue)
                    query = query.Where(a => a.Timestamp >= request.StartDate.Value);

                if (request.EndDate.HasValue)
                    query = query.Where(a => a.Timestamp <= request.EndDate.Value);

                if (!string.IsNullOrEmpty(request.Keyword))
                {
                    var keyword = request.Keyword.ToLower();
                    query = query.Where(a =>
                        (a.Action != null && a.Action.ToLower().Contains(keyword)) ||
                        (a.ErrorMessage != null && a.ErrorMessage.ToLower().Contains(keyword)) ||
                        (a.Metadata != null && a.Metadata.ToLower().Contains(keyword))
                    );
                }

                // 4. 정렬 순서 적용 (최신순이 기본)
                query = query.OrderByDescending(a => a.Timestamp);

                // 5. 페이징 처리를 위해 전체 개수를 먼저 조회합니다.
                var totalCount = await query.CountAsync(cancellationToken);

                // 6. 실제 페이지에 해당하는 데이터를 조회합니다.
                var items = await query
                    .Skip((pagination.PageNumber - 1) * pagination.PageSize)
                    .Take(pagination.PageSize)
                    .Select(entity => MapToDto(entity)) // 가벼운 DTO로 변환
                    .ToListAsync(cancellationToken);

                // 7. 최종 응답 객체를 구성합니다.
                var response = new AuditLogListResponse
                {
                    Items = items,
                    PageNumber = pagination.PageNumber,
                    PageSize = pagination.PageSize,
                    TotalCount = totalCount,
                    // FilterSummary가 필요하다면 이 단계에서 추가적인 집계 쿼리를 수행할 수 있습니다.
                };

                return ServiceResult<AuditLogListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit logs for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<AuditLogListResponse>.Failure(
                    "Failed to retrieve audit logs.",
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
            int? limit = 50,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // ConnectedId의 조직 확인
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
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

                var logs = await finalQuery.Select(a => MapToDto(a)).ToListAsync(cancellationToken);

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
        /// <summary>
        /// 특정 사용자의 활동 로그를 조회합니다.
        /// 요청자는 자기 자신의 로그를 보거나, 대상 사용자와 같은 조직의 관리자여야 합니다.
        /// </summary>
        public async Task<ServiceResult<List<AuditLogDto>>> GetUserActivityLogsAsync(
            Guid targetConnectedId,
            DateTime? startDate,
            DateTime? endDate,
            Guid requestingConnectedId,
            int? limit = 100,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            try
            {
                // 권한 검증: 자기 자신이거나 관리자 권한 필요
                // ✅ 2. CancellationToken을 ValidateUserActivityAccessAsync에 전달
                var hasAccess = await ValidateUserActivityAccessAsync(requestingConnectedId, targetConnectedId, cancellationToken);
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

                // ✅ 3. CancellationToken을 ToListAsync에 전달
                var logs = await finalQuery.Select(a => MapToDto(a)).ToListAsync(cancellationToken);

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
        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 특정 조직의 감사 로그를 조회합니다.
        /// 요청자는 반드시 해당 조직의 멤버여야 합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogListResponse>> GetOrganizationAuditLogsAsync(
            Guid organizationId,
            SearchAuditLogsRequest request,
            PaginationRequest pagination,
            Guid connectedId,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            try
            {
                // ConnectedId가 해당 조직에 속하는지 검증
                // ✅ 2. CancellationToken을 GetByIdAsync에 전달
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
                if (connectedIdEntity == null || connectedIdEntity.OrganizationId != organizationId)
                {
                    return ServiceResult<AuditLogListResponse>.Failure(
                        "Access denied to organization audit logs",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                // 조직 필터를 강제 적용
                request.OrganizationId = organizationId;

                // ✅ 3. CancellationToken을 GetAuditLogsAsync에 전달
                return await GetAuditLogsAsync(request, pagination, connectedId, cancellationToken);
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

        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 기존 감사 로그에 상세 변경 이력(Trail)을 추가합니다.
        /// </summary>
        public async Task<ServiceResult<AuditTrailDetailDto>> AddAuditTrailDetailAsync(
            Guid auditLogId,
            string fieldName,
            string? oldValue,
            string? newValue,
            AuditFieldType fieldType,
            Guid connectedId,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            try
            {
                // 1. 상세 이력을 추가할 부모 감사 로그를 먼저 조회합니다.
                var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
                if (auditLog == null)
                {
                    return ServiceResult<AuditTrailDetailDto>.Failure("Parent audit log not found.", "AUDIT_NOT_FOUND");
                }

                // 2. 권한 검증
                // ✅ CancellationToken 전달
                var hasAccess = await ValidateAuditLogAccessAsync(connectedId, auditLog.TargetOrganizationId, cancellationToken);
                if (!hasAccess)
                {
                    return ServiceResult<AuditTrailDetailDto>.Failure(
                        "Access denied to modify this audit log.",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                // 3. 추가할 상세 이력(AuditTrailDetail) 엔티티를 생성합니다.
                var detail = new AuditTrailDetail
                {
                    Id = Guid.NewGuid(),
                    AuditLogId = auditLogId, // 부모 ID 설정
                    FieldName = fieldName,
                    OldValue = oldValue,
                    NewValue = newValue,
                    FieldType = fieldType,
                    ActionType = AuditActionType.Update,
                    IsSecureField = IsSecureField(fieldName),
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = connectedId
                };

                // 4. 민감한 필드는 마스킹 처리
                if (detail.IsSecureField)
                {
                    detail.OldValue = MaskSensitiveData(oldValue);
                    detail.NewValue = MaskSensitiveData(newValue);
                }

                // 5. ✅ [로직 수정] 부모 엔티티의 컬렉션에 새로 만든 상세 이력을 추가합니다.
                // EF Core가 변경을 감지하고 AuditTrailDetail 테이블에 INSERT 쿼리를 실행합니다.
                auditLog.AuditTrailDetails ??= new List<AuditTrailDetail>();
                auditLog.AuditTrailDetails.Add(detail);

                // 6. ✅ CancellationToken을 SaveChangesAsync에 전달
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                var dto = MapTrailDetailToDto(detail);
                return ServiceResult<AuditTrailDetailDto>.Success(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add audit trail detail for AuditLogId {AuditLogId}", auditLogId);
                return ServiceResult<AuditTrailDetailDto>.Failure(
                    "Failed to add audit trail detail.",
                    "TRAIL_DETAIL_ERROR");
            }
        }

        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 기존 감사 로그에 여러 개의 상세 변경 이력을 한 번에 추가합니다.
        /// </summary>
        public async Task<ServiceResult<List<AuditTrailDetailDto>>> AddBulkAuditTrailDetailsAsync(
            Guid auditLogId,
            List<AuditTrailDetailDto> details,
            Guid connectedId,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            try
            {
                // 1. 상세 이력을 추가할 부모 감사 로그를 먼저 조회합니다.
                var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
                if (auditLog == null)
                {
                    return ServiceResult<List<AuditTrailDetailDto>>.Failure("Parent audit log not found.", "AUDIT_NOT_FOUND");
                }

                // 2. 권한 검증
                // ✅ CancellationToken 전달
                var hasAccess = await ValidateAuditLogAccessAsync(connectedId, auditLog.TargetOrganizationId, cancellationToken);
                if (!hasAccess)
                {
                    return ServiceResult<List<AuditTrailDetailDto>>.Failure(
                        "Access denied to modify this audit log.",
                        AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                auditLog.AuditTrailDetails ??= new List<AuditTrailDetail>();

                foreach (var detailDto in details)
                {
                    var entity = new AuditTrailDetail
                    {
                        Id = Guid.NewGuid(),
                        AuditLogId = auditLogId,
                        FieldName = detailDto.FieldName,
                        OldValue = detailDto.OldValue,
                        NewValue = detailDto.NewValue,
                        FieldType = detailDto.FieldType,
                        ActionType = detailDto.ActionType,
                        IsSecureField = IsSecureField(detailDto.FieldName),
                        CreatedAt = DateTime.UtcNow,
                        CreatedByConnectedId = connectedId
                    };

                    // 민감한 필드 마스킹
                    if (entity.IsSecureField)
                    {
                        entity.OldValue = MaskSensitiveData(detailDto.OldValue);
                        entity.NewValue = MaskSensitiveData(detailDto.NewValue);
                    }

                    // 3. ✅ [로직 수정] 부모 엔티티의 컬렉션에 새로 만든 상세 이력을 추가합니다.
                    auditLog.AuditTrailDetails.Add(entity);
                }

                // 4. ✅ CancellationToken을 SaveChangesAsync에 전달
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                // 성공 시 입력으로 받은 DTO 리스트를 그대로 반환
                return ServiceResult<List<AuditTrailDetailDto>>.Success(details);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add bulk audit trail details for AuditLogId {AuditLogId}", auditLogId);
                return ServiceResult<List<AuditTrailDetailDto>>.Failure(
                    "Failed to add bulk audit trail details.",
                    "BULK_TRAIL_ERROR");
            }
        }
        #endregion

        #region Entity Change Tracking

        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 엔티티의 생성, 수정, 삭제 변경 사항을 자동으로 감지하여 감사 로그와 상세 변경 이력을 생성합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogEntityChangeAsync<TEntity>(
            TEntity? oldEntity,
            TEntity? newEntity,
            AuditActionType actionType,
            Guid connectedId,
            string? customAction = null,
            CancellationToken cancellationToken = default) where TEntity : class // ✅ 1. CancellationToken 파라미터 추가
        {
            try
            {
                var entityType = typeof(TEntity).Name;
                var action = customAction ?? $"{entityType}.{actionType}";

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
                            changes,
                            changeCount = changes.Count
                        });
                    }
                }

                // ✅ 2. CancellationToken을 CreateAuditLogAsync에 전달
                var result = await CreateAuditLogAsync(request, connectedId, cancellationToken);

                // 상세 변경 내역 추가
                if (result.IsSuccess && result.Data != null && oldEntity != null && newEntity != null)
                {
                    var changes = ExtractDetailedChanges(oldEntity, newEntity);
                    if (changes.Any())
                    {
                        // ✅ 3. CancellationToken을 AddBulkAuditTrailDetailsAsync에 전달
                        await AddBulkAuditTrailDetailsAsync(result.Data.Id, changes, connectedId, cancellationToken);
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
        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 로그인 시도(성공/실패)를 감사 로그에 기록합니다.
        /// 반복된 실패 시도는 자동으로 심각도를 'Critical'로 격상시키고 보안 이벤트를 발생시킵니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogLoginAttemptAsync(
            string? username,
            bool success,
            string? ipAddress,
            string? userAgent,
            string? errorMessage = null,
            Guid? connectedId = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. ✅ [로직 수정] CreateAuditLogRequest 객체를 사용하여 요청을 표준화합니다.
                var request = new CreateAuditLogRequest
                {
                    ActionType = success ? AuditActionType.Login : AuditActionType.FailedLogin,
                    Action = "user.login.attempt",
                    ResourceType = "Authentication",
                    ResourceId = username,
                    Success = success,
                    ErrorMessage = errorMessage,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    Severity = success ? AuditEventSeverity.Info : AuditEventSeverity.Warning, // 기본 심각도 설정
                    Metadata = JsonConvert.SerializeObject(new
                    {
                        username,
                        loginTime = DateTime.UtcNow
                    })
                };

                // 2. 실패한 로그인 시도가 짧은 시간 내에 반복되면, 보안 위협으로 간주하고 심각도를 격상시킵니다.
                if (!success)
                {
                    // ✅ CancellationToken 전달
                    var recentFailures = await CountRecentFailedLoginsAsync(username, ipAddress, cancellationToken);
                    if (recentFailures >= 5) // 임계값 (예: 5회)
                    {
                        request.Severity = AuditEventSeverity.Critical;
                    }
                }

                // 3. ✅ [로직 수정] 중앙화된 CreateAuditLogAsync 메서드를 호출합니다.
                // 이 메서드 내부에서 DB 저장, 캐시 무효화, 이벤트 발행(_eventBus)이 모두 일관되게 처리됩니다.
                // 로그인 성공 시에는 connectedId가 있지만, 실패 시에는 없으므로 Guid.Empty를 전달하여 시스템 레벨 로그로 처리합니다.
                return await CreateAuditLogAsync(request, connectedId ?? Guid.Empty, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log login attempt for username: {Username}", username);
                return ServiceResult<AuditLogDto>.Failure(
                    "Failed to log login attempt",
                    "LOGIN_LOG_ERROR");
            }
        }

        /// <summary>
        /// 특정 리소스에 대한 권한 변경(부여/해제)을 감사 로그에 기록합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogPermissionChangeAsync(
            string resourceType,
            string resourceId,
            string permission,
            string action, // "grant" or "revoke"
            Guid grantedToConnectedId,
            Guid grantedByConnectedId,
            CancellationToken cancellationToken = default)
        {
            var metadata = new Dictionary<string, object>
            {
                ["permission"] = permission,
                ["grantedTo"] = grantedToConnectedId,
                ["action"] = action
            };

            // ✅ 2. CancellationToken을 LogActionAsync에 전달
            return await LogActionAsync(
                action.Equals("grant", StringComparison.OrdinalIgnoreCase) ? AuditActionType.Grant : AuditActionType.Revoke,
                $"permission.{action.ToLower()}",
                grantedByConnectedId,
                true,
                null,
                resourceType,
                resourceId,
                metadata,
                cancellationToken);
        }

        /// <summary>
        /// 특정 데이터에 대한 접근(예: 조회)이 발생했음을 감사 로그에 기록합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogDataAccessAsync(
            string resourceType,
            string resourceId,
            string accessType,
            Guid connectedId,
            Dictionary<string, object>? additionalInfo = null,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            var metadata = additionalInfo ?? new Dictionary<string, object>();
            metadata["accessType"] = accessType;
            metadata["accessTime"] = DateTime.UtcNow;

            // ✅ 2. CancellationToken을 LogActionAsync에 전달
            return await LogActionAsync(
                AuditActionType.Read, // 데이터 접근은 'Read' 타입으로 분류
                $"data.{accessType.ToLower()}",
                connectedId,
                true,
                null,
                resourceType,
                resourceId,
                metadata,
                cancellationToken);
        }
        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 시스템, 조직, 또는 애플리케이션의 설정 변경을 감사 로그에 기록합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogSettingChangeAsync(
            string settingKey,
            string? oldValue,
            string? newValue,
            Guid connectedId,
            Guid? organizationId = null,
            Guid? applicationId = null,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
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
                // 중요 설정 변경은 'Warning'으로 기록하여 주목도를 높일 수 있습니다.
                Severity = AuditEventSeverity.Warning
            };

            // ✅ 2. CancellationToken을 CreateAuditLogAsync에 전달
            return await CreateAuditLogAsync(request, connectedId, cancellationToken);
        }

        /// <summary>
        /// 일반적인 보안 이벤트를 감사 로그에 기록합니다.
        /// 모든 보안 이벤트는 중앙화된 생성 메서드를 통해 처리되어 일관성을 보장합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogSecurityEventAsync(
            string eventType,
            AuditEventSeverity severity,
            string description,
            Guid? connectedId,
            Dictionary<string, object>? details = null,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            try
            {
                // 1. ✅ [로직 수정] CreateAuditLogRequest 객체를 사용하여 요청을 표준화합니다.
                var request = new CreateAuditLogRequest
                {
                    ActionType = AuditActionType.System,
                    Action = $"security.{eventType.ToLower()}",
                    ResourceType = "Security",
                    ResourceId = eventType,
                    Success = false, // 보안 이벤트는 기본적으로 정상 상태가 아님을 의미
                    ErrorMessage = description,
                    Severity = severity,
                    Metadata = details != null ? JsonConvert.SerializeObject(details) : null
                };

                // 2. ✅ [로직 수정] 중앙화된 CreateAuditLogAsync 메서드를 호출합니다.
                // 이 메서드는 심각도(severity)에 따라 자동으로 IEventBus를 통해 이벤트를 발행하므로,
                // 별도의 HandleSecurityEventAsync 호출이 더 이상 필요 없습니다.
                // connectedId가 없는 시스템 이벤트일 수 있으므로 Guid.Empty를 기본값으로 사용합니다.
                return await CreateAuditLogAsync(request, connectedId ?? Guid.Empty, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log security event of type: {EventType}", eventType);
                return ServiceResult<AuditLogDto>.Failure(
                    "Failed to log security event.",
                    "SECURITY_EVENT_ERROR");
            }
        }
        #endregion

        #region Statistics and Analytics

        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 지정된 기간 동안의 감사 로그 통계를 생성합니다.
        /// 캐시를 우선 확인하며, DB 조회 시 단 한 번의 쿼리로 모든 통계를 계산하여 성능을 최적화합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogStatistics>> GetAuditLogStatisticsAsync(
            Guid? organizationId,
            DateTime startDate,
            DateTime endDate,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 요청자의 조직 정보를 확인하여 접근 권한을 검증합니다.
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
                if (connectedIdEntity == null)
                {
                    return ServiceResult<AuditLogStatistics>.Failure("Invalid ConnectedId.", AuthConstants.ErrorCodes.INVALID_USER_ID);
                }

                var targetOrgId = organizationId ?? connectedIdEntity.OrganizationId;
                if (targetOrgId != connectedIdEntity.OrganizationId)
                {
                    return ServiceResult<AuditLogStatistics>.Failure("Access denied to organization statistics.", AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                var cacheKey = $"{CACHE_KEY_PREFIX}stats:{targetOrgId}:{startDate:yyyyMMdd}-{endDate:yyyyMMdd}";

                // 2. 캐시에서 먼저 통계 데이터를 조회합니다.
                var cachedStats = await _cacheService.GetAsync<AuditLogStatistics>(cacheKey, cancellationToken);
                if (cachedStats != null)
                {
                    return ServiceResult<AuditLogStatistics>.Success(cachedStats);
                }

                // 3. ✅ [성능 개선] DB에는 단 한 번만 쿼리하여 통계 계산에 필요한 최소 데이터만 가져옵니다.
                var logsForStats = await _auditLogRepository.Query()
                    .Where(a => a.TargetOrganizationId == targetOrgId)
                    .Where(a => a.Timestamp >= startDate && a.Timestamp <= endDate)
                    .Select(a => new
                    {
                        a.Success,
                        a.PerformedByConnectedId,
                        a.Severity,
                        a.Action,
                        a.ResourceType
                    })
                    .ToListAsync(cancellationToken);

                // 4. ✅ [성능 개선] 메모리로 가져온 데이터를 사용하여 모든 통계를 효율적으로 계산합니다.
                var statistics = new AuditLogStatistics
                {
                    TotalLogs = logsForStats.Count,
                    SuccessfulLogs = logsForStats.Count(l => l.Success),
                    FailedLogs = logsForStats.Count(l => !l.Success),
                    UniqueUsers = logsForStats.Select(l => l.PerformedByConnectedId).Distinct().Count(),
                    SecurityEvents = logsForStats.Count(l => l.Severity >= AuditEventSeverity.Warning),
                    CriticalEvents = logsForStats.Count(l => l.Severity == AuditEventSeverity.Critical),
                    ByAction = logsForStats
                        .Where(l => l.Action != null)
                        .GroupBy(l => l.Action!)
                        .ToDictionary(g => g.Key, g => g.Count()),
                    ByEntity = logsForStats
                        .Where(l => l.ResourceType != null)
                        .GroupBy(l => l.ResourceType!)
                        .ToDictionary(g => g.Key, g => g.Count()),
                    GeneratedAt = DateTime.UtcNow,
                    Period = new { StartDate = startDate, EndDate = endDate }
                };

                // 5. 계산된 통계 결과를 캐시에 저장합니다.
                await _cacheService.SetAsync(cacheKey, statistics, TimeSpan.FromMinutes(15), cancellationToken);

                return ServiceResult<AuditLogStatistics>.Success(statistics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit log statistics for Org {OrgId}", organizationId);
                return ServiceResult<AuditLogStatistics>.Failure(
                    "Failed to generate statistics",
                    "STATISTICS_ERROR");
            }
        }

        #endregion

        #region Export and Archive

        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 감사 로그를 지정된 형식(JSON, CSV 등)의 파일 데이터로 내보냅니다.
        /// 조회는 요청자가 속한 조직으로 격리되며, 대용량 데이터 조회 시 요청 취소가 가능합니다.
        /// </summary>
        public async Task<ServiceResult<byte[]>> ExportAuditLogsAsync(
            SearchAuditLogsRequest request,
            DataFormat format,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 조직 격리 적용하여 로그 조회
                // ✅ CancellationToken을 GetAuditLogsAsync에 전달
                var logsResult = await GetAuditLogsAsync(
                    request,
                    new PaginationRequest { PageNumber = 1, PageSize = 10000 }, // 최대 10,000개로 제한
                    connectedId,
                    cancellationToken);

                if (!logsResult.IsSuccess || logsResult.Data == null || !logsResult.Data.Items.Any())
                {
                    return ServiceResult<byte[]>.Failure(
                        "No logs found to export for the given criteria.",
                        "EXPORT_NO_DATA");
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
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Audit log export was canceled by the user.");
                return ServiceResult<byte[]>.Failure("Export operation was canceled.", "OPERATION_CANCELED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export audit logs for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<byte[]>.Failure(
                    "An unexpected error occurred during the export process.",
                    "EXPORT_ERROR");
            }
        }

        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 지정된 보관 기간(retentionDays)보다 오래된 감사 로그를 아카이브(보관) 상태로 전환합니다.
        /// 이 작업은 시스템 관리자 또는 해당 조직의 관리자만 수행할 수 있습니다.
        /// </summary>
        public async Task<ServiceResult<int>> ApplyRetentionPolicyAsync(
            int retentionDays,
            Guid? organizationId,
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. 권한 검증: 이 작업을 수행할 권한이 있는지 확인합니다.
                // (실제 구현에서는 IAuthorizationService 등을 사용하여 더 정교하게 검증해야 합니다.)
                var requestingUser = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
                if (requestingUser == null || (organizationId.HasValue && requestingUser.OrganizationId != organizationId))
                {
                    return ServiceResult<int>.Failure("Insufficient permissions to apply retention policy.", AuthConstants.ErrorCodes.InsufficientPermissions);
                }

                var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
                var query = _auditLogRepository.Query()
                    .Where(a => a.Timestamp < cutoffDate)
                    .Where(a => !a.IsArchived);

                if (organizationId.HasValue)
                {
                    query = query.Where(a => a.TargetOrganizationId == organizationId);
                }

                // ✅ 2. CancellationToken을 ToListAsync에 전달
                var logsToArchive = await query.ToListAsync(cancellationToken);

                if (!logsToArchive.Any())
                {
                    return ServiceResult<int>.Success(0, "No logs found to archive for the given policy.");
                }

                foreach (var log in logsToArchive)
                {
                    // 루프 중간에 취소 요청이 들어왔는지 확인하여 즉시 중단
                    cancellationToken.ThrowIfCancellationRequested();

                    log.IsArchived = true;
                    log.ArchivedAt = DateTime.UtcNow;
                    // TODO: 실제 아카이브 스토리지(예: Azure Blob Storage, AWS S3)로 데이터를 이동하는 로직이 필요합니다.
                    log.ArchiveLocation = $"gs://authhive-archive/{log.TargetOrganizationId}/{log.Id}";
                }

                // ✅ 3. CancellationToken을 SaveChangesAsync에 전달
                await _unitOfWork.SaveChangesAsync(cancellationToken);

                _logger.LogInformation(
                    "Applied retention policy: archived {Count} logs older than {Days} days for Org {OrgId}",
                    logsToArchive.Count, retentionDays, organizationId?.ToString() ?? "All");

                return ServiceResult<int>.Success(logsToArchive.Count);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Retention policy application was canceled.");
                return ServiceResult<int>.Failure("Operation was canceled.", "OPERATION_CANCELED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to apply retention policy for Org {OrgId}", organizationId);
                return ServiceResult<int>.Failure(
                    "Failed to apply retention policy.",
                    "RETENTION_ERROR");
            }
        }
        /// <summary>
        /// 감사 로그 정리 (소프트 삭제)
        /// </summary>
        public async Task<ServiceResult<int>> CleanupAuditLogsAsync(
            DateTime beforeDate,
            Guid? organizationId,
            Guid connectedId,
            CancellationToken cancellationToken = default)
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
            Guid connectedId,
            CancellationToken cancellationToken = default)
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

                await _cacheService.SetStringAsync(
                 $"{CACHE_KEY_PREFIX}subscription:{subscriptionId}",
                 JsonConvert.SerializeObject(subscriptionInfo),
                 TimeSpan.FromHours(1), // 만료 시간
                 cancellationToken);

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

        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// 특정 감사 로그의 무결성(데이터 변조 여부 등)을 검증합니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogIntegrityCheckResult>> VerifyAuditLogIntegrityAsync(
            Guid auditLogId,
            Guid connectedId,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            try
            {
                // ✅ 2. CancellationToken을 GetByIdAsync에 전달
                var auditLog = await _auditLogRepository.GetByIdAsync(auditLogId, cancellationToken);
                if (auditLog == null)
                {
                    return ServiceResult<AuditLogIntegrityCheckResult>.Failure(
                        "Audit log not found",
                        "AUDIT_NOT_FOUND");
                }

                // TODO: 권한 검증 로직 추가 (connectedId가 이 로그를 볼 권한이 있는지)

                var result = new AuditLogIntegrityCheckResult
                {
                    IsValid = true,
                    CheckedAt = DateTime.UtcNow,
                    Issues = new List<string>()
                };

                // 무결성 검증 로직
                // 1. 타임스탬프 검증
                if (auditLog.Timestamp > DateTime.UtcNow.AddMinutes(5)) // 5분 정도의 오차 허용
                {
                    result.IsValid = false;
                    result.Issues.Add("Timestamp is in the future.");
                }

                // 2. ConnectedId 존재 여부 검증
                if (auditLog.PerformedByConnectedId.HasValue)
                {
                    // ✅ 3. CancellationToken을 GetByIdAsync에 전달
                    var performer = await _connectedIdRepository.GetByIdAsync(auditLog.PerformedByConnectedId.Value, cancellationToken);
                    if (performer == null)
                    {
                        result.IsValid = false; // 존재하지 않는 사용자가 남긴 기록이므로 무결성 위반
                        result.Issues.Add($"The user (ConnectedId: {auditLog.PerformedByConnectedId.Value}) who performed the action no longer exists.");
                    }
                }

                // 3. 해시 계산 및 검증 (실제로는 저장된 해시와 비교해야 함)
                var dataToHash = $"{auditLog.Id}{auditLog.Timestamp:o}{auditLog.Action}{auditLog.ResourceId}";
                result.Hash = ComputeHash(dataToHash);
                // if (auditLog.StoredHash != result.Hash) { result.IsValid = false; ... }

                return ServiceResult<AuditLogIntegrityCheckResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Audit log integrity verification was canceled.");
                return ServiceResult<AuditLogIntegrityCheckResult>.Failure("Operation was canceled.", "OPERATION_CANCELED");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify audit log integrity for AuditLogId {AuditLogId}", auditLogId);
                return ServiceResult<AuditLogIntegrityCheckResult>.Failure(
                    "Failed to verify integrity.",
                    "INTEGRITY_CHECK_ERROR");
            }
        }
        // Path: AuthHive.Auth/Services/Audit/AuditService.cs

        /// <summary>
        /// UserActivityLog를 기반으로 고위험 보안 경고 감사 로그를 생성합니다.
        /// 이상 징후 탐지 시스템 등에서 감지한 위험 활동을 상세히 기록하는 데 사용됩니다.
        /// </summary>
        public async Task<ServiceResult<AuditLogDto>> LogSecurityAlertAsync(
            AuditActionType actionType,
            string description,
            UserActivityLog activityLog,
            CancellationToken cancellationToken = default)
        {
            if (activityLog == null)
            {
                return ServiceResult<AuditLogDto>.Failure("UserActivityLog cannot be null.", "INVALID_ARGUMENT");
            }

            try
            {
                // 1. UserActivityLog의 풍부한 컨텍스트를 활용하여 상세한 메타데이터를 구성합니다.
                var details = new Dictionary<string, object?> // Null 값을 허용하도록 변경
                {
                    ["description"] = description,
                    ["riskScore"] = activityLog.RiskScore,
                    ["activityType"] = activityLog.ActivityType.ToString(), // Enum은 문자열로 변환
                    ["relatedResourceType"] = activityLog.ResourceType, // 활동 대상의 타입
                    ["relatedResourceId"] = activityLog.ResourceId,     // 활동 대상의 ID
                    ["originalActivityId"] = activityLog.Id
                };

                // 2. 표준 CreateAuditLogRequest 객체를 생성합니다.
                var request = new CreateAuditLogRequest
                {
                    ActionType = actionType,
                    Action = $"security.alert.{activityLog.ActivityType.ToString().ToLower()}",
                    ResourceType = "UserActivity",
                    // 경고의 주체가 되는 UserID를 ResourceId로 사용합니다.
                    // Null일 수 있으므로 Null 조건부 연산자(?.)를 사용하여 안전하게 처리합니다.
                    ResourceId = activityLog.UserId?.ToString(),
                    Success = false, // 보안 경고는 항상 '비정상' 상태로 간주
                    ErrorMessage = description,
                    IpAddress = activityLog.IpAddress,
                    UserAgent = activityLog.UserAgent,
                    // 위험 점수에 따라 심각도를 동적으로 결정
                    Severity = activityLog.RiskScore > 75 ? AuditEventSeverity.Critical : AuditEventSeverity.Error,
                    Metadata = JsonConvert.SerializeObject(details),
                    OrganizationId = activityLog.OrganizationId
                };

                // 3. 중앙화된 CreateAuditLogAsync 메서드를 호출하여 로그를 생성하고 이벤트를 발행합니다.
                return await CreateAuditLogAsync(request, activityLog.ConnectedId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log security alert for UserActivityLog {ActivityId}", activityLog.Id);
                return ServiceResult<AuditLogDto>.Failure(
                    "Failed to log security alert.",
                    "SECURITY_ALERT_ERROR");
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
            Guid connectedId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // 권한 검증
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId, cancellationToken);
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
                        await GenerateGDPRReportData(report, organizationId, startDate, endDate, cancellationToken);
                        break;
                    case ComplianceReportType.SOC2:
                        await GenerateSOC2ReportData(report, organizationId, startDate, endDate, cancellationToken);
                        break;
                    case ComplianceReportType.ISO27001:
                        await GenerateISO27001ReportData(report, organizationId, startDate, endDate, cancellationToken);
                        break;
                    default:
                        await GenerateGeneralComplianceData(report, organizationId, startDate, endDate, cancellationToken);
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

        private AuditTrailDetailDto MapTrailDetailToDto(AuditTrailDetail entity, CancellationToken cancellationToken = default)
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

        /// <summary>
        /// AuditLog 엔티티를 상세 정보(수행자 정보, 변경 이력 포함)를 담은 AuditLogDetailResponse DTO로 비동기적으로 변환합니다.
        /// </summary>
        private async Task<AuditLogDetailResponse> MapToDetailResponseAsync(AuditLog entity, CancellationToken cancellationToken)
        {
            var response = new AuditLogDetailResponse
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
                AuditTrailDetails = entity.AuditTrailDetails?.Select(detail => MapTrailDetailToDto(detail)).ToList() ?? new List<AuditTrailDetailDto>()
            };

            // 수행자(Performer)의 상세 정보를 추가로 조회하여 채워넣습니다.
            if (entity.PerformedByConnectedId.HasValue)
            {
                var performer = await _connectedIdRepository.GetByIdAsync(entity.PerformedByConnectedId.Value, cancellationToken);
                if (performer != null)
                {
                    response.PerformedBy = new PerformedByInfo
                    {
                        ConnectedId = performer.Id,
                        DisplayName = performer.DisplayName,
                        // Role 정보가 필요하다면 _roleRepository를 통해 추가 조회 가능
                    };
                }
            }

            return response;
        }

        /// <summary>
        /// 요청자가 특정 감사 로그에 접근할 수 있는지 확인합니다.
        /// 시스템 관리자 역할을 가졌거나, 로그가 기록된 조직과 동일한 조직에 속해야 합니다.
        /// </summary>
        private async Task<bool> ValidateAuditLogAccessAsync(Guid requestingConnectedId, Guid? targetOrganizationId, CancellationToken cancellationToken)
        {
            if (!targetOrganizationId.HasValue)
            {
                // 조직 정보가 없는 시스템 레벨 로그는 일단 허용 (또는 별도 정책 적용)
                return true;
            }

            var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(requestingConnectedId, cancellationToken);
            if (connectedIdEntity == null) return false;

            // 요청자의 조직과 로그의 조직이 일치하는지 확인
            return connectedIdEntity.OrganizationId == targetOrganizationId.Value;
        }
        private async Task<bool> ValidateUserActivityAccessAsync(Guid requestingConnectedId, Guid targetConnectedId, CancellationToken cancellationToken)
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

        private async Task<int> CountRecentFailedLoginsAsync(string? username, string? ipAddress, CancellationToken cancellationToken = default)
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

        /// <summary>
        /// 조직 관련 캐시를 무효화합니다. (예: 통계 데이터)
        /// </summary>
        private async Task InvalidateOrganizationCacheAsync(Guid? organizationId, CancellationToken cancellationToken)
        {
            if (!organizationId.HasValue) return;

            // 와일드카드나 패턴 기반 삭제는 ICacheService의 구현체(예: Redis)에 따라 달라짐
            // 여기서는 특정 키를 삭제하는 예시를 보여줍니다.
            var statsCacheKey = $"{CACHE_KEY_PREFIX}stats:{organizationId.Value}";
            await _cacheService.RemoveAsync(statsCacheKey, cancellationToken);

            _logger.LogDebug("Invalidated cache for organization {OrganizationId}", organizationId.Value);
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

        private async Task GenerateGDPRReportData(
            ComplianceReport report,
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            // GDPR 관련 데이터 수집

            // 데이터 접근(Read) 로그 카운트
            report.Data["dataAccessLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId
                            && a.Timestamp >= startDate
                            && a.Timestamp <= endDate
                            && a.ActionType == AuditActionType.Read)
                .CountAsync(cancellationToken); // ✅ 2. CancellationToken 전달

            // 데이터 변경(Update/Delete) 로그 카운트
            report.Data["dataModificationLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId
                            && a.Timestamp >= startDate
                            && a.Timestamp <= endDate
                            && (a.ActionType == AuditActionType.Update || a.ActionType == AuditActionType.Delete))
                .CountAsync(cancellationToken); // ✅ 3. CancellationToken 전달
        }

        private async Task GenerateSOC2ReportData(
            ComplianceReport report,
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            // SOC2 관련 데이터 수집 (보안 이벤트 카운트)
            report.Data["securityEvents"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId
                            && a.Timestamp >= startDate
                            && a.Timestamp <= endDate
                            && a.Severity >= AuditEventSeverity.Warning)
                .CountAsync(cancellationToken); // ✅ 2. CancellationToken 전달
        }

        private async Task GenerateISO27001ReportData(
            ComplianceReport report,
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken = default) // ✅ 1. CancellationToken 파라미터 추가
        {
            // ISO27001 관련 데이터 수집 (접근 제어 로그 카운트)
            report.Data["accessControlLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId
                            && a.Timestamp >= startDate
                            && a.Timestamp <= endDate
                            && (a.ActionType == AuditActionType.Grant || a.ActionType == AuditActionType.Revoke))
                .CountAsync(cancellationToken);
        }
        private async Task GenerateGeneralComplianceData(
            ComplianceReport report,
            Guid organizationId,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken = default) 
        {
            // 일반 컴플라이언스 데이터 수집 (전체 로그 카운트)
            report.Data["totalLogs"] = await _auditLogRepository.Query()
                .Where(a => a.TargetOrganizationId == organizationId
                            && a.Timestamp >= startDate
                            && a.Timestamp <= endDate)
                .CountAsync(cancellationToken); // ✅ 2. CancellationToken 전달
        }

        #endregion
    }
}