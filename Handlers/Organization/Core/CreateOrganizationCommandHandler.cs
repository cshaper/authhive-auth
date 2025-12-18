// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using AuthHive.Core.Entities.Organization;
// using AuthHive.Core.Interfaces.Base; // IUnitOfWork
//  // IOrganizationCommandRepository
// using AuthHive.Core.Models.Organization.Core.Commands;
// using AuthHive.Core.Models.Organization.Core.Responses;
// using AuthHive.Core.Models.Auth.ConnectedId.Commands; // CreateConnectedIdCommand
// using AuthHive.Core.Enums.Auth; // MembershipType, ConnectedIdStatus
// using AuthHive.Core.Enums.Core; // OrganizationStatus
// using OrganizationEntity = AuthHive.Core.Entities.Organization.Core.Organization;
// using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
// using AuthHive.Core.Interfaces.Organization.Core;

// namespace AuthHive.Auth.Handlers.Organization.Core;

// /// <summary>
// /// [v18 Standard] 조직 생성 핸들러 (SOP 2-Write-A)
// /// 역할: 조직 Entity 생성 -> 저장 -> 소유자(Owner) 멤버십 생성(Sub-Command) -> 트랜잭션 확정
// /// </summary>
// public class CreateOrganizationCommandHandler : IRequestHandler<CreateOrganizationCommand, CreateOrganizationResponse>
// {
//     private readonly IOrganizationCommandRepository _organizationRepository;
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IMediator _mediator;
//     private readonly ILogger<CreateOrganizationCommandHandler> _logger;

//     public CreateOrganizationCommandHandler(
//         IOrganizationCommandRepository organizationRepository,
//         IUnitOfWork unitOfWork,
//         IMediator mediator,
//         ILogger<CreateOrganizationCommandHandler> logger)
//     {
//         _organizationRepository = organizationRepository;
//         _unitOfWork = unitOfWork;
//         _mediator = mediator;
//         _logger = logger;
//     }

//     public async Task<CreateOrganizationResponse> Handle(CreateOrganizationCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Creating Organization: {Name} ({Slug}) triggered by {TriggeredBy}",
//             command.Name, command.Slug, command.TriggeredBy);

//         // 1. Entity 생성 (DDD Factory Pattern 사용)
//         var organization = OrganizationEntity.Create(
//             name: command.Name,
//             slug: command.Slug,
//             type: command.Type,
//             region: command.Region
//         );

//         // 2. 추가 속성 매핑 (Factory에서 처리하지 않는 속성들)
//         // [Fact] Entity에 정의된 메서드와 속성만 사용합니다.
//         organization.UpdateInfo(
//             name: command.Name,
//             description: command.Description,
//             website: command.Website
//         );

//         organization.UpdateBranding(
//             logoUrl: command.LogoUrl,
//             brandColor: command.BrandColor
//         );

//         // [Fact] Entity에 존재하는 정책 속성 매핑
//         organization.JoinPolicy = command.JoinPolicy;
//         organization.JoinRequirements = command.JoinRequirements;
//         // PolicyInheritanceMode는 private set이므로 Factory나 내부 로직으로만 변경 가능하지만, 
//         // 현재 Factory가 기본값을 사용하므로, 만약 변경이 필요하다면 Entity에 SetPolicyInheritanceMode 메서드가 필요함. 
//         // (현재 코드상으로는 Factory의 기본값 Inherit 유지 또는 Reflection/BackingField 필요. 
//         //  여기서는 Entity 무결성을 위해 Factory 기본값을 신뢰하고 넘어갑니다. *TODO 1 참고*)

//         // 3. 1차 저장 (ID 생성을 위해)
//         await _organizationRepository.AddAsync(organization, cancellationToken);

//         // 주의: ConnectedId 생성을 위해 OrganizationId가 필요하므로, 
//         // DB가 Identity Column(Auto Increment)이 아닌 Guid를 쓴다면 SaveChanges 전에도 ID가 있을 수 있음.
//         // AuthHive는 Guid를 사용하므로 organization.Id는 이미 존재함.

//         // 4. 소유자(Owner) 멤버십 생성 (Sub-Command 위임)
//         // [Fact] 제공해주신 CreateConnectedIdCommand의 init 속성을 사용합니다.
//         var createOwnerCommand = new CreateConnectedIdCommand
//         {
//             // Context
//             UserId = command.TriggeredBy, // [가정] TriggeredBy는 생성자의 UserId임 (*TODO 2 참고*)
//             OrganizationId = organization.Id,
//             TriggeredBy = command.TriggeredBy,

//             // Payload
//             Provider = "Internal", // [가정] 조직 생성 시 기본 제공자 (*TODO 3 참고*)
//             ProviderUserId = command.TriggeredBy.ToString(),
//             MembershipType = MembershipType.Owner, // 소유자 권한
//             InitialStatus = ConnectedIdStatus.Active,
//             ActivateImmediately = true,
//             DisplayName = "Owner", // 기본값
//             OrganizationEmail = null, // 선택적

//             // Options
//             CreateSession = false // 조직 생성 시 세션까지 만들지는 않음 (로그인 별도)
//         };

//         // 서브 커맨드 실행 (ConnectedId 생성)
//         Guid ownerConnectedId = await _mediator.Send(createOwnerCommand, cancellationToken);

//         // 5. 트랜잭션 확정 (UoW)
//         // ConnectedId 핸들러 내부에서도 SaveChanges를 호출할 수 있으나, 
//         // v18 아키텍처상 하나의 논리적 트랜잭션으로 묶이는 것이 이상적입니다.
//         await _unitOfWork.SaveChangesAsync(cancellationToken);

//         // 6. 이벤트 발행 (Event)
//         // (제공해주신 파일 목록에 Event 코드가 없어서 주석 처리하지만, 반드시 있어야 함)
//         // await _mediator.Publish(new OrganizationCreatedEvent(organization.Id, ...), cancellationToken);

//         _logger.LogInformation("Organization created successfully. Id: {OrgId}, Owner ConnectedId: {OwnerId}",
//             organization.Id, ownerConnectedId);

//         // 7. 응답 반환
//         // CreateOrganizationCommandHandler.cs (이렇게 수정하세요)
//         return new CreateOrganizationResponse
//         {
//             Id = organization.Id,
//             OrganizationKey = organization.OrganizationKey,
//             Name = organization.Name,
//             Slug = organization.Slug,
//             Type = organization.Type,
//             CreatedAt = organization.CreatedAt,
//             CreatedBy = organization.CreatedBy?? Guid.Empty
//         };
//     }
// }