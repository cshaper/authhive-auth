using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using AutoMapper;
using AuthHive.Core.Interfaces.Application.Service;
using AuthHive.Core.Interfaces.PlatformApplication.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.PlatformApplication.Requests;
using AuthHive.Core.Models.PlatformApplication.Responses;
using AuthHive.Core.Models.PlatformApplication.Views;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Models.PlatformApplication.Events;
using System.Linq.Expressions;
using AuthHive.Core.Models.Audit;
// 검증 상수 사용을 위한 네임스페이스
using AuthHive.Core.Models.Core.Application.Common;
using PlatformApplicationEntity = AuthHive.Core.Entities.PlatformApplications.PlatformApplication;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Auth.Service;

namespace AuthHive.Auth.Services.PlatformApplication
{
    public class PlatformApplicationService : IPlatformApplicationService
    {
        private readonly IPlatformApplicationRepository _applicationRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly ILogger<PlatformApplicationService> _logger;
        private readonly IAuditService _auditService;
        private readonly IEventBus _eventBus;
        private readonly IPlanRestrictionService _planRestrictionService;

        public PlatformApplicationService(
            IPlatformApplicationRepository applicationRepository,
            IUnitOfWork unitOfWork,
            IMapper mapper,
            ILogger<PlatformApplicationService> logger,
            IAuditService auditService,
            IEventBus eventBus,
            IPlanRestrictionService planRestrictionService)
        {
            _applicationRepository = applicationRepository;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _logger = logger;
            _auditService = auditService;
            _eventBus = eventBus;
            _planRestrictionService = planRestrictionService;
        }

        #region CUD Operations

        public async Task<ServiceResult<ApplicationResponse>> CreateAsync(CreateApplicationRequest request, Guid organizationId, Guid createdByConnectedId, CancellationToken cancellationToken = default)
        {
            // 1. 권한 검증 (SaaS 요금제 제한)
            var canCreateResult = await CanCreateApplicationAsync(organizationId, request, cancellationToken);
            if (!canCreateResult.IsSuccess)
            {
                // [수정됨 1 - CS8604 해결]
                // ErrorMessage가 null일 경우를 대비하여 기본 오류 메시지를 제공합니다.
                return ServiceResult<ApplicationResponse>.Failure(
                    canCreateResult.ErrorMessage ?? "Failed to validate application creation permissions.", 
                    canCreateResult.ErrorCode);
            }
            
            // 2. 유효성 검증 (중복 이름 확인)
            if (await _applicationRepository.IsDuplicateNameAsync(organizationId, request.Name, null, cancellationToken))
            {
                // [수정됨 2 - CS0103 해결]
                // ApplicationErrors 클래스 대신 ApplicationValidationConstants의 상수를 사용합니다.
                string errorMessage = string.Format(
                    ApplicationValidationConstants.ValidationMessages.DUPLICATE, 
                    ApplicationValidationConstants.ValidationFields.APPLICATION_NAME);

                return ServiceResult<ApplicationResponse>.Failure(
                    errorMessage, 
                    ApplicationValidationConstants.ApplicationValidationCodes.DUPLICATE_NAME);
            }

            // 3. 엔티티 생성 및 저장
            var application = _mapper.Map<PlatformApplicationEntity>(request);
            application.OrganizationId = organizationId;
            application.ApplicationKey = $"app-{Guid.NewGuid().ToString("N").Substring(0, 12)}";
            
            await _applicationRepository.AddAsync(application, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 4. 감사 로그 및 이벤트 발행
            await _auditService.LogActionAsync(new AuditLogCreation
            {
                Action = "CreateApplication",
                EntityType = nameof(PlatformApplicationEntity),
                EntityId = application.Id.ToString(),
                PerformedByConnectedId = createdByConnectedId,
                Details = $"Application '{application.Name}' created for organization {organizationId}."
            }, cancellationToken);

            var createdEvent = new ApplicationCreatedEvent
            {
                ApplicationId = application.Id,
                OrganizationId = application.OrganizationId,
                ApplicationKey = application.ApplicationKey,
                ApplicationType = application.ApplicationType,
                CreatedByConnectedId = createdByConnectedId,
                CreatedAt = application.CreatedAt
            };
            await _eventBus.PublishAsync(createdEvent, cancellationToken);
            
            _logger.LogInformation("Application created: {ApplicationId} by {CreatedBy}", application.Id, createdByConnectedId);

            var response = _mapper.Map<ApplicationResponse>(application);
            return ServiceResult<ApplicationResponse>.Success(response);
        }
        
        #endregion

    
        #region Other Methods
        public async Task<ServiceResult<ApplicationResponse>> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var application = await _applicationRepository.GetByIdAsync(id, cancellationToken);
            if (application == null)
            {
                return ServiceResult<ApplicationResponse>.Failure("Not Found", "APPLICATION_NOT_FOUND");
            }
            var response = _mapper.Map<ApplicationResponse>(application);
            return ServiceResult<ApplicationResponse>.Success(response);
        }

        public async Task<ServiceResult<ApplicationDetailResponse>> GetDetailByIdAsync(Guid id, CancellationToken cancellationToken = default)
        {
            var application = await _applicationRepository.FindSingleAsync(app => app.Id == id, cancellationToken);
            if (application == null)
            {
                return ServiceResult<ApplicationDetailResponse>.Failure("Not Found", "APPLICATION_NOT_FOUND");
            }
            var response = _mapper.Map<ApplicationDetailResponse>(application);
            return ServiceResult<ApplicationDetailResponse>.Success(response);
        }

        public async Task<ServiceResult<ApplicationResponse>> GetByApplicationKeyAsync(string applicationKey, CancellationToken cancellationToken = default)
        {
            var application = await _applicationRepository.GetByApplicationKeyAsync(applicationKey, cancellationToken);
            if (application == null)
            {
                return ServiceResult<ApplicationResponse>.Failure("Not Found", "APPLICATION_NOT_FOUND");
            }
            var response = _mapper.Map<ApplicationResponse>(application);
            return ServiceResult<ApplicationResponse>.Success(response);
        }

        public async Task<ServiceResult<ApplicationListResponse>> GetByOrganizationAsync(Guid organizationId, PaginationRequest pagination, CancellationToken cancellationToken = default)
        {
            var pagedResult = await _applicationRepository.GetPagedAsync(
                app => app.OrganizationId == organizationId,
                pagination,
                cancellationToken);

            var response = _mapper.Map<ApplicationListResponse>(pagedResult);
            return ServiceResult<ApplicationListResponse>.Success(response);
        }

        public async Task<ServiceResult<ApplicationListResponse>> SearchAsync(ApplicationSearchRequest searchRequest, PaginationRequest pagination, CancellationToken cancellationToken = default)
        {
            Expression<Func<PlatformApplicationEntity, bool>> predicate = app =>
                (searchRequest.OrganizationId == null || app.OrganizationId == searchRequest.OrganizationId) &&
                (string.IsNullOrEmpty(searchRequest.SearchTerm) || app.Name.Contains(searchRequest.SearchTerm)) &&
                (searchRequest.Status == null || app.Status == searchRequest.Status);

            var pagedResult = await _applicationRepository.GetPagedAsync(predicate, pagination, cancellationToken);
            var response = _mapper.Map<ApplicationListResponse>(pagedResult);
            return ServiceResult<ApplicationListResponse>.Success(response);
        }
        public async Task<ServiceResult<ApplicationResponse>> UpdateAsync(Guid id, UpdateApplicationRequest request, Guid updatedByConnectedId, CancellationToken cancellationToken = default)
        {
            var application = await _applicationRepository.GetByIdAsync(id, cancellationToken);
            if (application == null)
            {
                return ServiceResult<ApplicationResponse>.Failure("Not Found", "APPLICATION_NOT_FOUND");
            }

            if (!string.IsNullOrEmpty(request.Name) && request.Name != application.Name)
            {
                if (await _applicationRepository.IsDuplicateNameAsync(application.OrganizationId, request.Name, id, cancellationToken))
                {
                    string errorMessage = string.Format(
                        ApplicationValidationConstants.ValidationMessages.DUPLICATE,
                        ApplicationValidationConstants.ValidationFields.APPLICATION_NAME);

                    return ServiceResult<ApplicationResponse>.Failure(
                        errorMessage,
                        ApplicationValidationConstants.ApplicationValidationCodes.DUPLICATE_NAME);
                }
            }

            _mapper.Map(request, application);
            await _applicationRepository.UpdateAsync(application, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            await _auditService.LogActionAsync(new AuditLogCreation { /* ... */ }, cancellationToken);
            await _eventBus.PublishAsync(new ApplicationUpdatedEvent { ApplicationId = application.Id, UpdatedByConnectedId = updatedByConnectedId, UpdatedAt = DateTime.UtcNow }, cancellationToken);

            _logger.LogInformation("Application updated: {ApplicationId} by {UpdatedBy}", id, updatedByConnectedId);

            var response = _mapper.Map<ApplicationResponse>(application);
            return ServiceResult<ApplicationResponse>.Success(response);
        }

        public async Task<ServiceResult<bool>> DeleteAsync(Guid id, Guid deletedByConnectedId, CancellationToken cancellationToken = default)
        {
            var application = await _applicationRepository.GetByIdAsync(id, cancellationToken);
            if (application == null)
            {
                return ServiceResult<bool>.Failure("Not Found", "APPLICATION_NOT_FOUND");
            }

            await _applicationRepository.SoftDeleteAsync(id, deletedByConnectedId, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            await _auditService.LogActionAsync(new AuditLogCreation { /* ... */ }, cancellationToken);
            await _eventBus.PublishAsync(new ApplicationDeletedEvent { ApplicationId = id, DeletedByConnectedId = deletedByConnectedId, DeletedAt = DateTime.UtcNow, IsSoftDelete = true }, cancellationToken);

            _logger.LogInformation("Application deleted: {ApplicationId} by {DeletedBy}", id, deletedByConnectedId);

            return ServiceResult<bool>.Success(true);
        }
        public async Task<ServiceResult<bool>> CanCreateApplicationAsync(Guid organizationId, CreateApplicationRequest request, CancellationToken cancellationToken = default)
        {
            var restrictionResult = await _planRestrictionService.CheckRestrictionAsync(organizationId, "MaxApplications", cancellationToken);
            if (restrictionResult.IsRestricted)
            {
                _logger.LogWarning("Organization {OrganizationId} failed to create application due to plan restrictions: {Reason}", organizationId, restrictionResult.Reason);
                return ServiceResult<bool>.Failure(
                    restrictionResult.Reason,
                    ApplicationValidationConstants.ApplicationValidationCodes.QUOTA_EXCEEDED);
            }
            return ServiceResult<bool>.Success(true);
        }

        public Task<ServiceResult<bool>> ActivateAsync(Guid id, Guid activatedByConnectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> DeactivateAsync(Guid id, string reason, Guid deactivatedByConnectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<ApplicationSummaryView>> GetSummaryAsync(Guid id, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<ApplicationCardView>> GetCardViewAsync(Guid id, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<ApplicationDashboardView>> GetDashboardViewAsync(Guid id, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> ResetDailyUsageAsync(Guid id, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> ResetMonthlyUsageAsync(Guid id, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> RecordApiCallAsync(Guid id, ApiCallRecord record, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> ValidateApplicationKeyAsync(string applicationKey, Guid organizationId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        #endregion
    }
}

