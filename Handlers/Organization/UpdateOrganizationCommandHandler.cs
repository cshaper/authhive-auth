// // [AuthHive.Auth] UpdateOrganizationCommandHandler.cs
// // v17 CQRS "본보기": 'UpdateOrganizationCommand' (조직 수정)를 처리합니다.
// // [v17 철학] v16 OrganizationService.UpdateAsync 로직을 이관하고,
// // IRequest<Unit> "본보기"에 따라 DTO를 반환하지 않고 이벤트를 발행(Notify)합니다.

// using AuthHive.Core.Entities.Organization;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Organization.Repository;
// using AuthHive.Core.Interfaces.Organization.Validator;
// using AuthHive.Core.Models.Organization.Commands;
// using AuthHive.Core.Models.Organization.Events;
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System.ComponentModel.DataAnnotations; // ValidationException
// using System;
// using System.Collections.Generic; // Dictionary
// using System.Linq; // FirstOrDefault
// using System.Threading;
// using System.Threading.Tasks;
// using OrganizationEntity = AuthHive.Core.Entities.Organization.Core.Organization;
// using AuthHive.Core.Enums.Core;

// namespace AuthHive.Auth.Handlers.Organization
// {
//     /// <summary>
//     /// [v17] "조직 수정" 유스케이스 핸들러 (SOP 2-Write-B)
//     /// </summary>
//     public class UpdateOrganizationCommandHandler : IRequestHandler<UpdateOrganizationCommand, Unit>
//     {
//         private readonly IMediator _mediator;
//         private readonly ILogger<UpdateOrganizationCommandHandler> _logger;
//         private readonly IOrganizationRepository _orgRepository;
//         private readonly IOrganizationValidator _orgValidator;
//         private readonly IUnitOfWork _unitOfWork;

//         public UpdateOrganizationCommandHandler(
//             IMediator mediator,
//             ILogger<UpdateOrganizationCommandHandler> logger,
//             IOrganizationRepository orgRepository,
//             IOrganizationValidator orgValidator,
//             IUnitOfWork unitOfWork)
//         {
//             _mediator = mediator;
//             _logger = logger;
//             _orgRepository = orgRepository;
//             _orgValidator = orgValidator;
//             _unitOfWork = unitOfWork;
//         }

//         public async Task<Unit> Handle(UpdateOrganizationCommand command, CancellationToken cancellationToken)
//         {
//             _logger.LogInformation("Handling UpdateOrganizationCommand for {OrgId}", command.AggregateId);

//             // 1. [v17 "본보기"] 유효성 검사 (SOP 1.6)
//             var validationResult = await _orgValidator.ValidateUpdateAsync(command);
//             if (!validationResult.IsValid)
//             {
//                 var error = validationResult.Errors.FirstOrDefault()?.ErrorMessage ?? "Organization update validation failed.";
//                 _logger.LogWarning("Validation failed: {Error}", error);
//                 throw new ValidationException(error);
//             }

//             // 2. 엔티티 조회 (v16 Service.UpdateAsync 로직)
//             var existing = await _orgRepository.GetByIdAsync(command.AggregateId, cancellationToken);
//             if (existing == null)
//             {
//                 throw new KeyNotFoundException($"Organization not found: {command.AggregateId}");
//             }

//             // 3. 변경 사항 적용 (v16 Service.UpdateAsync 로직 이관)
//             var (oldValues, newValues, updatedFields) = ApplyChanges(existing, command);

//             if (!updatedFields.Any())
//             {
//                 _logger.LogInformation("No changes detected for Organization {OrgId}", command.AggregateId);
//                 return Unit.Value; // 멱등성(Idempotency)
//             }

//             existing.UpdatedByConnectedId = command.TriggeredBy;
//             existing.UpdatedAt = DateTime.UtcNow;

//             // 4. 데이터베이스 저장
//             await _orgRepository.UpdateAsync(existing, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             _logger.LogInformation("Organization {OrgId} updated successfully.", command.AggregateId);

//             // 5. [v17 "본보기"] 이벤트 발행 (Notify) (SOP 1.7)
//             var updatedEvent = new OrganizationUpdatedEvent(
//                 organizationId: existing.Id,
//                 updatedFields: string.Join(",", updatedFields),
//                 oldValues: oldValues,
//                 newValues: newValues,
//                 updatedBy: command.TriggeredBy
//             );
//             await _mediator.Publish(updatedEvent, cancellationToken);

//             // 6. [v17 "본보기"] Unit 반환
//             return Unit.Value;
//         }
        
//         /// <summary>
//         /// [v17] v16 Service.UpdateAsync의 '내용'을 이관.
//         /// 엔티티에 변경 사항을 적용하고, 감사(Event)를 위해 변경 전/후 값을 기록합니다.
//         /// </summary>
//         private (Dictionary<string, object?>, Dictionary<string, object?>, List<string>) ApplyChanges(
//             OrganizationEntity entity, UpdateOrganizationCommand command)
//         {
//             var oldValues = new Dictionary<string, object?>();
//             var newValues = new Dictionary<string, object?>();
//             var updatedFields = new List<string>();

//             // v16 AutoMapper 로직을 수동 매핑 및 "본보기" '추적' 로직으로 대체
            
//             void UpdateField(string fieldName, object? newValue, Action<object?> setter, object? oldValue)
//             {
//                 // v16 DTO는 Required 속성이 많아 null 체크가 필요 없었음
//                 if (newValue != null && !Equals(oldValue, newValue))
//                 {
//                     oldValues[fieldName] = oldValue;
//                     newValues[fieldName] = newValue;
//                     setter(newValue);
//                     updatedFields.Add(fieldName);
//                 }
//             }

//             UpdateField(nameof(command.Name), command.Name, (val) => entity.Name = (string)val!, entity.Name);
//             UpdateField(nameof(command.Type), command.Type, (val) => entity.Type = (OrganizationType)val!, entity.Type);
//             UpdateField(nameof(command.HierarchyType), command.HierarchyType, (val) => entity.HierarchyType = (OrganizationHierarchyType)val!, entity.HierarchyType);
//             UpdateField(nameof(command.Region), command.Region, (val) => entity.Region = (string)val!, entity.Region);
//             UpdateField(nameof(command.PolicyInheritanceMode), command.PolicyInheritanceMode, (val) => entity.PolicyInheritanceMode = (PolicyInheritanceMode)val!, entity.PolicyInheritanceMode);
//             UpdateField(nameof(command.SortOrder), command.SortOrder, (val) => entity.SortOrder = (int)val!, entity.SortOrder);
            
//             UpdateField(nameof(command.Description), command.Description, (val) => entity.Description = (string?)val, entity.Description);
//             UpdateField(nameof(command.LogoUrl), command.LogoUrl, (val) => entity.LogoUrl = (string?)val, entity.LogoUrl);
//             UpdateField(nameof(command.BrandColor), command.BrandColor, (val) => entity.BrandColor = (string?)val, entity.BrandColor);
//             UpdateField(nameof(command.Website), command.Website, (val) => entity.Website = (string?)val, entity.Website);
//             UpdateField(nameof(command.EstablishedDate), command.EstablishedDate, (val) => entity.EstablishedDate = (DateTime?)val, entity.EstablishedDate);
//             UpdateField(nameof(command.EmployeeRange), command.EmployeeRange, (val) => entity.EmployeeRange = (string?)val, entity.EmployeeRange);
//             UpdateField(nameof(command.Industry), command.Industry, (val) => entity.Industry = (string?)val, entity.Industry);
//             UpdateField(nameof(command.Metadata), command.Metadata, (val) => entity.Metadata = (string?)val, entity.Metadata);

//             return (oldValues, newValues, updatedFields);
//         }
//     }
// }