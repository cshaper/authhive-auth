// [AuthHive.Auth] CreateOrganizationCommandHandler.cs
// v17 CQRS "본보기": 'CreateOrganizationCommand' (조직 생성)를 처리합니다.
// [v17 철학] v16 OrganizationService.CreateAsync 로직을 이관하고,
// v17 AuthFrame 설정 및 '소유자 ConnectedId' 자동 생성 로직을 추가합니다.

using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Interfaces.Auth.Repository; // [v17] IConnectedIdRepository
using AuthHive.Core.Models.Organization.Commands;
using AuthHive.Core.Models.Organization.Responses;
using AuthHive.Core.Models.Organization.Events;
using AuthHive.Core.Models.Auth.ConnectedId.Commands; // [v17] CreateConnectedIdCommand
using AuthHive.Core.Enums.Auth; // [v17] ConnectedIdStatus
using AuthHive.Core.Enums.Core; // [v17] OrganizationStatus
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Linq; // [v17] FirstOrDefault
using System.Threading;
using System.Threading.Tasks;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Handlers.Organization
{
    /// <summary>
    /// [v17] "조직 생성" 유스케이스 핸들러 (SOP 2-Write-A)
    /// v16의 '조직 생성'과 v17의 'AuthFrame 설정', '소유자 멤버십 할당' 책임을 조립합니다.
    /// </summary>
    public class CreateOrganizationCommandHandler : IRequestHandler<CreateOrganizationCommand, CreateOrganizationResponse>
    {
        private readonly IMediator _mediator;
        private readonly ILogger<CreateOrganizationCommandHandler> _logger;
        private readonly IOrganizationRepository _orgRepository;
        private readonly IOrganizationValidator _orgValidator;
        private readonly IConnectedIdRepository _connectedIdRepository; // [v17 "본보기"] 소유자 UserId 조회를 위함
        private readonly IUnitOfWork _unitOfWork;

        public CreateOrganizationCommandHandler(
            IMediator mediator,
            ILogger<CreateOrganizationCommandHandler> logger,
            IOrganizationRepository orgRepository,
            IOrganizationValidator orgValidator,
            IConnectedIdRepository connectedIdRepository, // [v17 "본보기"]
            IUnitOfWork unitOfWork)
        {
            _mediator = mediator;
            _logger = logger;
            _orgRepository = orgRepository;
            _orgValidator = orgValidator;
            _connectedIdRepository = connectedIdRepository;
            _unitOfWork = unitOfWork;
        }

        public async Task<CreateOrganizationResponse> Handle(CreateOrganizationCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling CreateOrganizationCommand for {Key}", command.OrganizationKey);

            // 1. [v17 "본보기"] 유효성 검사 (SOP 1.6)
            // (v16 OrganizationService.ValidateCreateRequestAsync 로직 이관)
            var validationResult = await _orgValidator.ValidateCreateAsync(command);
            if (!validationResult.IsValid)
            {
                // [v17 "본보기" 수정] (v6.39) v17 ValidationResult DTO를 올바르게 처리
                var error = validationResult.Errors.FirstOrDefault()?.ErrorMessage ?? "Organization creation validation failed.";
                _logger.LogWarning("Validation failed: {Error}", error);
                throw new ValidationException(error);
            }

            // 2. 엔티티 매핑 (v16 OrganizationService.CreateAsync 로직 이관)
            var organization = new OrganizationEntity
            {
                OrganizationKey = command.OrganizationKey,
                Name = command.Name,
                Description = command.Description,
                Type = command.Type,
                Status = OrganizationStatus.Active, // [v16 로직]
                ParentId = command.ParentId,
                Region = command.Region ?? "US", // [v16 로직]
                LogoUrl = command.LogoUrl,
                BrandColor = command.BrandColor,
                Website = command.Website,
                Industry = command.Industry,
                EmployeeRange = command.EmployeeRange,
                EstablishedDate = command.EstablishedDate,
                Metadata = command.Metadata,
                PolicyInheritanceMode = command.PolicyInheritanceMode ?? PolicyInheritanceMode.Inherit, // [v16 로직]
                ActivatedAt = DateTime.UtcNow,
                CreatedByConnectedId = command.TriggeredBy // [v16 로직]
            };

            // 3. [v17 "본보기"] AuthFrame 신규 설정 (SOP 1.3)
            // v16 IsMFARequired 대신 v17 AuthFrame 정책 을 설정합니다.
            organization.AuthenticationMode = "AuthHiveManaged"; // 모드 1 (기본값) [cite: 311-312]
            organization.MfaPolicy = "Optional"; // MFA 선택 (기본값) [cite: 317-318]
            
            // 4. 데이터베이스 저장 (1/2)
            await _orgRepository.AddAsync(organization, cancellationToken);
            
            // 5. [v17 "본보기"] 소유자 ConnectedId 자동 할당 (SOP 3)
            if (!command.TriggeredBy.HasValue)
            {
                _logger.LogError("Cannot create Owner ConnectedId: TriggeredByConnectedId (Owner) is null.");
                throw new ValidationException("Cannot create organization owner: TriggeredBy (Owner) is missing.");
            }

            // [v17 "본보기"] '소유자(TriggeredBy)'의 'ConnectedId'로 'UserId'를 "확인"
            var ownerConnectedId = await _connectedIdRepository.GetByIdAsync(command.TriggeredBy.Value, cancellationToken);
            if (ownerConnectedId?.UserId == null)
            {
                _logger.LogError("Owner ConnectedId {ConnectedId} found, but its UserId is null.", command.TriggeredBy.Value);
                throw new ValidationException("Owner's UserId not found.");
            }

            // [v17 "본보기"] '소유자(Owner)' 권한으로 새 'ConnectedId'(멤버십) 생성
            var createConnectedIdCmd = new CreateConnectedIdCommand(
                userId: ownerConnectedId.UserId.Value,
                organizationId: organization.Id, // 새 조직 ID
                provider: "Internal", // (조직 생성 시 내부 생성)
                providerUserId: ownerConnectedId.UserId.Value.ToString(), // (내부 생성 시 UserId 사용)
                membershipType: MembershipType.Owner, // [v17] 소유자
                displayName: "Organization Owner", // (추후 UserDisplayName 사용)
                initialStatus: ConnectedIdStatus.Active, // [v17] 즉시 활성화
                activateImmediately: true,
                invitedByConnectedId: command.TriggeredBy // (본인 스스로)
            );
            
            // [v17] 'CreateConnectedIdCommandHandler' (SOP 3)에게 위임
            await _mediator.Send(createConnectedIdCmd, cancellationToken);
            
            // 6. 데이터베이스 저장 (2/2) - (UoW)
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Organization {OrgId} and Owner ConnectedId created successfully.", organization.Id);

            // 7. 이벤트 발행 (Notify)
            var createdEvent = new OrganizationCreatedEvent(
                organizationId: organization.Id,
                parentOrganizationId: organization.ParentId,
                createdByConnectedId: command.TriggeredBy.Value,
                organizationKey: organization.OrganizationKey,
                name: organization.Name,
                type: organization.Type
            );
            await _mediator.Publish(createdEvent, cancellationToken);

            // 8. 응답 DTO 반환
            return new CreateOrganizationResponse(
                id: organization.Id,
                name: organization.Name,
                organizationId: organization.OrganizationKey,
                isSuccess: true,
                createdAt: organization.CreatedAt,
                createdByConnectedId: command.TriggeredBy.Value,
                message: "Organization created successfully"
            );
        }
    }
}