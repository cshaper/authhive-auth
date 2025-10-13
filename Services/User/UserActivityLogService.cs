// Path: AuthHive.Auth.Services/User/UserActivityLogService.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Views;
using AuthHive.Core.Models.Base.Summaries;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Models.User.Events;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Constants.Business;
using AuthHive.Core.Models.Infra.Events;
using AuthHive.Core.Interfaces.Organization.Repository;
using System.Text.Json; // IDateTimeProvider 등을 위해 추가

namespace AuthHive.Auth.Services.User
{
    /// <summary>
    /// 사용자 활동 로그 서비스 구현체 - AuthHive v16 아키텍처 원칙 적용
    /// 활동 기록, 분석, 보안 위험 감지 및 모니터링 로직을 담당합니다.
    /// </summary>
    public class UserActivityLogService : IUserActivityLogService
    {
        // 🛠️ 핵심 의존성 주입
        private readonly IUserActivityLogRepository _activityLogRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly IEventBus _eventBus;
        private readonly IPlanRestrictionService _planRestrictionService;
        private readonly IAuditService _auditService;
        private readonly IRiskAssessmentService _riskAssessmentService;
        private readonly ILogger<UserActivityLogService> _logger;
        private readonly IConnectedIdService _connectedIdService;
        private readonly IDateTimeProvider _dateTimeProvider; // 시간 관리를 위해 추가
        private readonly IOrganizationStatisticsRepository _statisticsRepository; // 통계 조회용 Repository

        public delegate Task<ServiceResult> CheckActivityLimitDelegate(Guid organizationId, CancellationToken cancellationToken);


        public UserActivityLogService(
            IUserActivityLogRepository activityLogRepository,
            IUnitOfWork unitOfWork,
            IMapper mapper,
            IEventBus eventBus,
            IPlanRestrictionService planRestrictionService,
            IAuditService auditService,
            IRiskAssessmentService riskAssessmentService,
            IConnectedIdService connectedIdService,
            IDateTimeProvider dateTimeProvider,
            ILogger<UserActivityLogService> logger,
            IOrganizationStatisticsRepository statisticsRepository)
        {
            _activityLogRepository = activityLogRepository ?? throw new ArgumentNullException(nameof(activityLogRepository));
            _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _eventBus = eventBus ?? throw new ArgumentNullException(nameof(eventBus));
            _planRestrictionService = planRestrictionService ?? throw new ArgumentNullException(nameof(planRestrictionService));
            _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));
            _riskAssessmentService = riskAssessmentService ?? throw new ArgumentNullException(nameof(riskAssessmentService));
            _connectedIdService = connectedIdService ?? throw new ArgumentNullException(nameof(connectedIdService));
            _dateTimeProvider = dateTimeProvider ?? throw new ArgumentNullException(nameof(dateTimeProvider));
            _statisticsRepository = statisticsRepository ?? throw new ArgumentNullException(nameof(statisticsRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #region IService 계약 이행 (CS0535 해결)
        // IService의 IsHealthyAsync와 InitializeAsync는 구현체의 Base가 아닌 IUserActivityLogService에서 상속되므로 여기에 구현

        public Task<ServiceResult<ServiceHealthStatus>> GetHealthStatusAsync(CancellationToken cancellationToken = default)
        {
            // 실제 구현에서는 모든 의존성(Repo, Bus, Audit)의 상태를 확인해야 합니다.
            return Task.FromResult(ServiceResult<ServiceHealthStatus>.Success(new ServiceHealthStatus { IsHealthy = true }));
        }

        /// <summary>
        /// 서비스 상태 확인 (IService 계약 준수)
        /// Repository 및 주요 의존성의 상태를 점검하여 서비스의 건전성을 확인합니다.
        /// </summary>
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // 1. Repository 상태 체크: 가장 간단한 쿼리로 DB 연결 상태 확인 (예: AnyAsync)
                // (UserActivityLogRepository에 AnyAsync(predicate, token)가 있다고 가정)
                await _activityLogRepository.AnyAsync(log => log.Id == Guid.Empty, cancellationToken);

                // 2. 주요 비즈니스 의존성 상태 체크 (AuditService, EventBus 등)
                // IAuditService가 IService를 상속받았으므로 IsHealthyAsync를 호출할 수 있습니다.
                if (!await ((IService)_auditService).IsHealthyAsync(cancellationToken))
                {
                    _logger.LogWarning("Audit service dependency health check failed.");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UserActivityLogService core dependency or DB health check failed.");
                return false;
            }
        }
        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            // 캐시 워밍업, 이벤트 핸들러 등록 등 초기화 로직
            _logger.LogInformation("UserActivityLogService initialized.");
            return Task.CompletedTask;
        }

        #endregion

        #region 활동 로그 기록 (CS0535 해결)

        /// <summary>
        /// 활동 로그 기록 (LogActivityAsync)
        /// </summary>
        public async Task<ServiceResult<UserActivityLogResponse>> LogActivityAsync(
            LogUserActivityRequest request,
            CancellationToken cancellationToken = default)
        {
            await _unitOfWork.BeginTransactionAsync(cancellationToken);
            try
            {
                // 1. 요금제 제한 확인 (임시 헬퍼 사용)
                if (request.OrganizationId == null || request.OrganizationId == Guid.Empty)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult<UserActivityLogResponse>.Failure("OrganizationId is required for activity logging.", "INVALID_INPUT");
                }
                var checkResult = await _planRestrictionService.CheckLogActivityLimitAsync(
                         request.OrganizationId.Value,
                         cancellationToken);
                if (!checkResult.IsSuccess)
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    // 🚨 CS0103 해결: ServiceError.PlanLimitExceeded 대신 문자열 리터럴 사용
                    return ServiceResult<UserActivityLogResponse>.Failure(
                        checkResult.ErrorMessage ?? "Plan limit exceeded.", "PLAN_LIMIT_EXCEEDED");
                }
                // 2. 보안 위험 점수 계산
                var riskScore = await _riskAssessmentService.AssessActivityRiskAsync(request, cancellationToken);

                // 3. Entity 매핑 및 초기화
                var activityLog = _mapper.Map<UserActivityLog>(request);
                activityLog.RiskScore = riskScore;

                // 4. Repository 저장 및 트랜잭션 커밋
                await _activityLogRepository.AddAsync(activityLog, cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 5. 이벤트 발행 (ActivityLoggedEvent는 UserActivityEvent를 상속한다고 가정)
                var activityEvent = _mapper.Map<ActivityLoggedEvent>(activityLog);
                await _eventBus.PublishAsync(activityEvent, cancellationToken);

                // 6. 감사 로그 (고위험 활동만)
                if (activityLog.RiskScore >= 80)
                {
                    await _auditService.LogSecurityAlertAsync(
                        AuditActionType.SecurityEvent, $"High risk activity detected (Score: {riskScore})",
                        activityLog, cancellationToken);
                }

                return ServiceResult<UserActivityLogResponse>.Success(_mapper.Map<UserActivityLogResponse>(activityLog));
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to log user activity for ConnectedId: {ConnectedId}", request.ConnectedId);
                return ServiceResult<UserActivityLogResponse>.Failure("OrganizationId is required for activity logging.", "INVALID_INPUT");
            }
        }

        /// <summary>
        /// [활동 로그 제한 확인] 활동 로그 저장량이 조직의 요금제 제한을 초과하는지 검사합니다.
        /// 이 메서드는 UserActivityLogService에서 활동 기록 전 호출됩니다.
        /// </summary>
        public async Task<ServiceResult> CheckLogActivityLimitAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // 1. AuthHive 슈퍼 조직 우회
            if (organizationId == PricingConstants.AuthHiveSuperOrgId)
            {
                return ServiceResult.Success();
            }

            // 2. 현재 플랜의 스토리지 제한을 조회합니다.
            // 실제 플랜 조회 로직은 생략하고, 임시로 Basic 플랜을 가정합니다.
            const string currentPlanKey = PricingConstants.SubscriptionPlans.BASIC_KEY;
            var maxStorageGB = PricingConstants.GetStrictLimit(
                PricingConstants.SubscriptionPlans.StorageLimits, currentPlanKey, PricingConstants.DefaultStorageLimit);

            // 3. 현재 활동 로그 스토리지 사용량을 조회 (IOrganizationStatisticsRepository 등을 통해 구현되어야 함)
            var currentLogStorageUsageGB = await _statisticsRepository.GetLogStorageUsageGBAsync(
     organizationId, cancellationToken);
            // 4. 제한 검사
            if (currentLogStorageUsageGB >= maxStorageGB)
            {
                // 이벤트 발행 및 실패 응답
                await _eventBus.PublishAsync(
                    new InfraErrorEvent(organizationId, "STORAGE_LIMIT_EXCEEDED", $"활동 로그 저장 공간 제한({maxStorageGB}GB) 초과"), cancellationToken);

                return ServiceResult.Failure(
                    $"활동 로그 저장 공간 제한({maxStorageGB}GB)을 초과했습니다.",
                    PricingConstants.BusinessErrorCodes.UpgradeRequired);
            }

            return ServiceResult.Success();
        }
        /// <summary>
        /// 일괄 활동 로그 기록 (BulkLogActivitiesAsync)
        /// </summary>
        public Task<ServiceResult<BulkLogActivityResponse>> BulkLogActivitiesAsync(
            IEnumerable<LogUserActivityRequest> activities,
            CancellationToken cancellationToken = default)
        {
            // 실제로는 병렬 처리, 트랜잭션 분리, 벌크 저장 최적화 로직이 필요함.
            // 여기서는 미구현으로 처리하여 CS0535만 해결합니다.
            throw new NotImplementedException("BulkLogActivitiesAsync is not yet fully implemented.");
        }

        /// <summary>
        /// 실패 활동 기록 (LogFailedActivityAsync)
        /// </summary>
        public Task<ServiceResult<UserActivityLogResponse>> LogFailedActivityAsync(
            LogFailedActivityRequest request,
            CancellationToken cancellationToken = default)
        {
            // LogActivityAsync와 유사하나, IsSuccessful=false로 설정하고 에러코드를 기록하는 로직이 추가됩니다.
            throw new NotImplementedException("LogFailedActivityAsync is not yet implemented.");
        }

        #endregion

        #region 조회 및 검색 (CS0535 해결)

        /// <summary>
        /// 활동 로그 ID로 조회 (GetByIdAsync)
        /// </summary>
        public async Task<ServiceResult<UserActivityLogDetailResponse>> GetByIdAsync(
            Guid logId,
            CancellationToken cancellationToken = default)
        {
            // 1. 컨텍스트 확인 
            var orgIdResult = _connectedIdService.GetCurrentOrganizationId();

            if (!orgIdResult.IsSuccess || orgIdResult.Data == Guid.Empty)
            {
                return ServiceResult<UserActivityLogDetailResponse>.Forbidden("Organization context is required to view logs."); // 영어 메시지로 수정
            }
            var currentOrgId = orgIdResult.Data;
            try
            {
                // 2. Repository 호출: ID와 조직 ID를 함께 사용하여 안전하게 조회
                var activityLog = await _activityLogRepository.GetByIdAndOrganizationAsync(
                    logId, currentOrgId, cancellationToken);


                if (activityLog == null)
                {
                    return ServiceResult<UserActivityLogDetailResponse>.NotFound($"Activity log with ID {logId} not found in this organization.");
                }

                // 3. 감사 로그 기록
                await _auditService.LogActionAsync(
                    // 1. PerformedByConnectedId (GetCurrentConnectedId().Data)
                    _connectedIdService.GetCurrentConnectedId().Data,
                    // 2. Action (문자열)
                    "USER_ACTIVITY_LOG_DETAIL_READ",
                    AuditActionType.Read,
                    // 4. ResourceType 
                    resourceType: "UserActivityLog",
                    // 5. ResourceId (Guid.ToString())
                    resourceId: logId.ToString(),
                    // 6. Success (true)
                    success: true,
                    // 7. Metadata (null)
                    metadata: null,
                    // 8. CancellationToken
                    cancellationToken: cancellationToken);

                return ServiceResult<UserActivityLogDetailResponse>.Success(_mapper.Map<UserActivityLogDetailResponse>(activityLog));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving activity log details for ID {LogId}", logId);
                return ServiceResult<UserActivityLogDetailResponse>.Failure("Error retrieving activity log details.", "INTERNAL_ERROR");
            }
        }

        /// <summary>
        /// 활동 로그 검색 (SearchAsync)
        /// </summary>
        public async Task<ServiceResult<UserActivityLogListResponse>> SearchAsync(
            SearchUserActivityLogsRequest request,
            CancellationToken cancellationToken = default)
        {
            // 1. 요청 유효성 및 권한 확인

            if (!request.OrganizationId.HasValue || request.OrganizationId.Value == Guid.Empty)
            {
                return ServiceResult<UserActivityLogListResponse>.Failure("OrganizationId is required for search operations.", "INVALID_INPUT");
            }
            if (request.RequestingConnectedId == Guid.Empty || !request.RequestingConnectedId.HasValue) // ConnectedId는 Guid?이므로 널 체크
            {
                return ServiceResult<UserActivityLogListResponse>.Forbidden("Requesting ConnectedId is required for authorization.");
            }
            // 🚨 CS1503 해결: request.OrganizationId가 Guid?이므로, .Value를 사용해 Guid로 변환
            if (!await _connectedIdService.HasAdminAccessToOrganizationAsync(
              request.RequestingConnectedId.Value, // 👈 1st Arg (Assumed fixed, but repeated for safety)
              request.OrganizationId.Value,
              cancellationToken))
            {
                return ServiceResult<UserActivityLogListResponse>.Forbidden("Insufficient permissions to view activity logs for this organization.");
            }
            try
            {
                // 2. Repository 호출
                var pagedResult = await _activityLogRepository.SearchAsync(request, cancellationToken);

                // 3. 🚨 CS0029 해결: AutoMapper의 타겟 타입을 UserActivityLogResponse로 명시합니다.
                // 이는 UserActivityLogListResponse가 PaginationResponse<UserActivityLogResponse>를 상속하기 때문입니다.
                var mappedItems = _mapper.Map<IEnumerable<UserActivityLogResponse>>(pagedResult.Items);

                var response = new UserActivityLogListResponse
                {
                    Items = mappedItems.ToList(), // 👈 Now correctly List<UserActivityLogResponse>
                    TotalCount = pagedResult.TotalCount,
                    PageNumber = pagedResult.PageNumber,
                    PageSize = pagedResult.PageSize
                };

                return ServiceResult<UserActivityLogListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to search user activity logs for organization {OrganizationId}", request.OrganizationId);
                return ServiceResult<UserActivityLogListResponse>.Failure("Error occurred while searching activity logs.", "INTERNAL_ERROR");
            }

        }

        /// <summary>
        /// ConnectedId별 활동 로그 조회
        /// </summary>
        public async Task<ServiceResult<UserActivityLogListResponse>> GetByConnectedIdAsync(
            Guid connectedId,
            Guid? requestingConnectedId = null, // 권한 체크용
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            // 1. ✅ 권한 확인: 본인(connectedId == requestingConnectedId)이거나 관리자 권한이 있어야 함.
            // AuthHive Principle: Must check identity or delegated security role.
            if (requestingConnectedId.HasValue && requestingConnectedId.Value != connectedId &&
                // HasRequiredRoleAsync is called if the request is not from the owner (security:viewer is a standard audit role)
                !await _connectedIdService.HasRequiredRoleAsync(requestingConnectedId.Value, "security:viewer", cancellationToken))
            {
                return ServiceResult<UserActivityLogListResponse>.Forbidden("Insufficient permissions to view another user's activity logs.");
            }

            try
            {
                // 2. Repository 호출
                var activities = await _activityLogRepository.GetByConnectedIdAsync(
                    connectedId, startDate, endDate, limit, cancellationToken);

                // 3. 🚨 CS0266 해결: AutoMapper를 사용하여 Entity를 List의 기본 타입인 UserActivityLogResponse로 변환
                var mappedItems = _mapper.Map<IEnumerable<UserActivityLogResponse>>(activities);

                // 4. 응답 구성
                var response = new UserActivityLogListResponse
                {
                    Items = mappedItems.ToList(), // List<UserActivityLogResponse>로 명시적 변환
                    TotalCount = activities.Count(),
                    // Paging info should be calculated if limit is used, but for now we set the count.
                    PageNumber = 1,
                    PageSize = limit ?? activities.Count()
                };

                return ServiceResult<UserActivityLogListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve activities for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<UserActivityLogListResponse>.Failure("Error retrieving connected ID activity logs.", "INTERNAL_ERROR");
            }
        }


        /// <summary>
        /// 조직별 활동 로그 조회 (GetByOrganizationAsync)
        /// </summary>
        // Path: AuthHive.Auth.Services/User/UserActivityLogService.cs
        public async Task<ServiceResult<UserActivityLogListResponse>> GetByOrganizationAsync(
            Guid organizationId,
            Guid requestingConnectedId,
            DateTime? startDate = null,
            DateTime? endDate = null,
            int? limit = null,
            CancellationToken cancellationToken = default)
        {
            // 1. Authorization Check: Verify if the requester has administrative access.
            if (!await _connectedIdService.HasAdminAccessToOrganizationAsync(requestingConnectedId, organizationId, cancellationToken))
            {
                return ServiceResult<UserActivityLogListResponse>.Forbidden("Insufficient permissions to view activity logs for this organization.");
            }

            try
            {
                // 2. Repository Call (Retrieves entities)
                var activities = await _activityLogRepository.GetByOrganizationIdAsync(
                    organizationId, startDate, endDate, limit, cancellationToken);

                // 3. 🚨 CS0266 Resolution: Map entities to the base response DTO type (UserActivityLogResponse).
                var mappedItems = _mapper.Map<IEnumerable<UserActivityLogResponse>>(activities);

                // 4. Response Construction
                var response = new UserActivityLogListResponse
                {
                    Items = mappedItems.ToList(), // Convert IEnumerable to List<UserActivityLogResponse>
                    TotalCount = activities.Count(),
                    PageNumber = 1,
                    PageSize = limit ?? activities.Count()
                };

                return ServiceResult<UserActivityLogListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve activities for organization {OrganizationId}", organizationId);
                return ServiceResult<UserActivityLogListResponse>.Failure("Error retrieving organization activity logs.", "INTERNAL_ERROR");
            }
        }
        /// <summary>
        /// 최근 활동 조회 (GetRecentActivitiesAsync)
        /// </summary>
        public async Task<ServiceResult<IEnumerable<UserActivityLogSummary>>> GetRecentActivitiesAsync(
            Guid? connectedId = null,
            Guid? organizationId = null,
            int count = 10,
            CancellationToken cancellationToken = default)
        {
            // 로직: connectedId가 있다면 ConnectedId로, 없다면 OrganizationId의 최근 활동을 조회
            // (Repository의 GetRecentActivitiesAsync는 ConnectedId를 받으므로, 여기서 로직 분기)
            if (connectedId.HasValue)
            {
                var activities = await _activityLogRepository.GetRecentActivitiesAsync(connectedId.Value, count, cancellationToken);
                var summaries = _mapper.Map<IEnumerable<UserActivityLogSummary>>(activities);
                return ServiceResult<IEnumerable<UserActivityLogSummary>>.Success(summaries);
            }

            // 조직 전체 최근 활동은 Repository에 GetRecentActivitiesByOrganizationIdAsync가 없다고 가정하고 Not Implemented
            throw new NotImplementedException("Organization-wide recent activity is not yet implemented.");
        }
        // Path: AuthHive.Auth.Services/User/UserActivityLogService.cs

        /// <summary>
        /// 활동 로그 삭제 (GDPR/개인정보 삭제 요청 대응)
        /// 특정 ConnectedId의 활동 로그를 소프트 삭제(Soft Delete) 처리합니다.
        /// </summary>
        /// <param name="connectedId">활동 로그를 삭제할 주체 (Target ConnectedId)</param>
        /// <param name="beforeDate">이 날짜 이전의 로그만 삭제 (선택 사항)</param>
        public async Task<ServiceResult> DeleteLogsAsync(
            Guid connectedId,
            DateTime? beforeDate = null,
            CancellationToken cancellationToken = default)
        {
            // 1. ✅ 유효성 검사 및 컨텍스트 획득
            if (connectedId == Guid.Empty)
            {
                return ServiceResult.Failure("Target ConnectedId cannot be empty.", "INVALID_INPUT");
            }

            // 현재 요청 주체 확인 (Audit Log 기록 및 권한 체크용)
            var requestingConnectedIdResult = _connectedIdService.GetCurrentConnectedId();
            if (!requestingConnectedIdResult.IsSuccess || requestingConnectedIdResult.Data == Guid.Empty)
            {
                return ServiceResult.Forbidden("ConnectedId context missing for requester.");
            }
            var requestingConnectedId = requestingConnectedIdResult.Data;


            // 2. ✅ 권한 확인 (Authorization Check)
            // 본인의 로그를 지우거나 (requestingConnectedId == connectedId), 
            // 조직 관리자 권한(organization:admin)이 있어야 타인의 로그를 지울 수 있음.
            if (requestingConnectedId != connectedId &&
                !await _connectedIdService.HasRequiredRoleAsync(requestingConnectedId, "organization:admin", cancellationToken))
            {
                return ServiceResult.Forbidden("Insufficient permissions to delete another user's activity logs.");
            }

            // 3. ✅ 트랜잭션 시작
            await _unitOfWork.BeginTransactionAsync(cancellationToken);

            try
            {
                // 4. Repository 호출: 삭제할 로그 조회 (소프트 삭제 처리를 위해 엔티티를 가져와야 함)
                var logsToDelete = await _activityLogRepository.FindAsync(
                    log => log.ConnectedId == connectedId &&
                           (!beforeDate.HasValue || log.Timestamp < beforeDate.Value),
                    cancellationToken);

                if (!logsToDelete.Any())
                {
                    await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                    return ServiceResult.Success("No activity logs found to delete.");
                }

                // 5. 일괄 소프트 삭제 처리 및 DB 저장
                // DeleteRangeAsync는 Repository에서 Soft Delete 로직과 캐시 무효화를 포함한다고 가정합니다.
                await _activityLogRepository.DeleteRangeAsync(logsToDelete, cancellationToken);
                await _unitOfWork.CommitTransactionAsync(cancellationToken);

                // 6. ✅ 감사 로그 및 이벤트 발행
                var auditMetadata = new Dictionary<string, object>
            {
                { "LogCount", logsToDelete.Count() },
                { "BeforeDate", beforeDate?.ToString("O") ?? "None" },
                { "PrivacyComplianceReason", "GDPR/Privacy Request" }
            };

                string metadataJson = JsonSerializer.Serialize(auditMetadata); // 👈 Dictionary를 JSON string으로 변환

                await _auditService.LogActionAsync(
                    performedByConnectedId: requestingConnectedId,
                    action: "USER_ACTIVITY_LOG_PURGE",
                    actionType: AuditActionType.Delete,
                    resourceType: "UserActivityLog",
                    resourceId: connectedId.ToString(),
                    success: true,
                    metadata: metadataJson, // 👈 수정된 JSON 문자열 전달
                    cancellationToken: cancellationToken);

                // 7. 이벤트 발행 (다운스트림 시스템 알림)
                await _eventBus.PublishAsync(new UserActivityLogPurgedEvent
                {
                    TargetConnectedId = connectedId,
                    Count = logsToDelete.Count(),
                    PurgedByConnectedId = requestingConnectedId
                }, cancellationToken);

                return ServiceResult.Success($"Successfully soft-deleted {logsToDelete.Count()} activity logs for ConnectedId {connectedId}.");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync(cancellationToken);
                _logger.LogError(ex, "Failed to delete user activity logs for ConnectedId: {ConnectedId}", connectedId);
                return ServiceResult.Failure("Error occurred during activity log deletion.", "INTERNAL_ERROR");
            }
        }

        // ... (나머지 분석 및 데이터 관리 메서드 구현은 생략) ...
        #endregion

    }
}
