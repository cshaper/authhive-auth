// using System;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR;
// using AuthHive.Core.Entities.Audit;
// using AuthHive.Core.Interfaces.Audit.Repository;
// using AuthHive.Core.Models.Audit.Commands;
// using AuthHive.Core.Models.Audit.Responses;
// using System.Collections.Generic; // List 사용을 위해 추가

// namespace AuthHive.Auth.Handlers.Audit;

// public class CreateAuditLogCommandHandler : IRequestHandler<CreateAuditLogCommand, AuditLogResponse>
// {
//     private readonly IAuditLogRepository _repository;

//     public CreateAuditLogCommandHandler(IAuditLogRepository repository)
//     {
//         _repository = repository;
//     }

//     public async Task<AuditLogResponse> Handle(CreateAuditLogCommand command, CancellationToken cancellationToken)
//     {
//         // 1. Entity 생성
//         var auditLog = new AuditLog
//         {
//             PerformedByConnectedId = command.ConnectedId,
//             TargetOrganizationId = command.OrganizationId,
//             ApplicationId = command.ApplicationId,
//             PerformedByUserId = command.UserId,

//             ActionType = command.ActionType,
//             Action = command.Action,
//             ResourceType = command.ResourceType,
//             ResourceId = command.ResourceId,

//             Success = command.Success,
//             ErrorCode = command.ErrorCode,
//             ErrorMessage = command.ErrorMessage,
//             Severity = command.Severity,
//             DurationMs = command.DurationMs,

//             IpAddress = command.IpAddress,
//             UserAgent = command.UserAgent,
//             RequestId = command.RequestId,
            
//             Metadata = command.MetadataJson
//         };

//         // 2. 상세 내역 매핑
//         if (command.Details != null && command.Details.Any())
//         {
//             foreach (var detail in command.Details)
//             {
//                 auditLog.AuditTrailDetails.Add(new AuditTrailDetail
//                 {
//                     FieldName = detail.FieldName,
//                     FieldType = detail.FieldType,
//                     OldValue = detail.OldValue,
//                     NewValue = detail.NewValue,
//                     IsSecureField = detail.IsSecureField,
//                     ActionType = command.ActionType
//                 });
//             }
//         }

//         // 3. 저장
//         await _repository.AddAsync(auditLog, cancellationToken);

//         // 4. 응답 (파라미터 이름을 Record 정의와 일치시킴: PascalCase)
//         return new AuditLogResponse(
//             Id: auditLog.Id,
//             ActionType: auditLog.ActionType,
//             Action: auditLog.Action,
//             Success: auditLog.Success,
//             Severity: auditLog.Severity,
//             CreatedAt: auditLog.CreatedAt,
            
//             // Nullable 값들
//             PerformedByConnectedId: auditLog.PerformedByConnectedId,
//             PerformedByUserId: auditLog.PerformedByUserId,
//             TargetOrganizationId: auditLog.TargetOrganizationId,
//             ApplicationId: auditLog.ApplicationId,
//             ResourceType: auditLog.ResourceType,
//             ResourceId: auditLog.ResourceId,
//             IpAddress: auditLog.IpAddress,
//             UserAgent: auditLog.UserAgent,
//             RequestId: auditLog.RequestId,
//             ErrorCode: auditLog.ErrorCode,
//             ErrorMessage: auditLog.ErrorMessage,
//             Metadata: auditLog.Metadata,
//             DurationMs: auditLog.DurationMs,
            
//             // 리스트 매핑 (빈 리스트라도 null이 아니게 처리)
//             Details: new List<AuditTrailDetailResponse>() 
//         );
//     }
// }