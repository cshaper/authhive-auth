// [AuthHive.Auth] Handlers/Audit/CreateAuditLogCommandHandler.cs
// v17 CQRS "본보기": 'CreateAuditLogCommand' (감사 로그 생성)를 처리합니다.
// (SOP 1-Write-C)
//
// 1. Command(DTO) -> Entity(Model) 매핑: 'AuditLog' 엔티티에 값을 매핑합니다.
// 2. Repository/UnitOfWork: 엔티티를 DB에 저장(Commit)합니다.
// 3. Mediator (Publish): 'AuditLogCreatedEvent'를 발행하여 후속 작업을 위임합니다.
// 4. Response(DTO) 반환: 'AuditLogResponse' DTO를 생성하여 반환합니다.

using AuthHive.Core.Entities.Audit; // [v17] AuditLog (Entity)
using AuthHive.Core.Interfaces.Audit.Repository; // [v17] IAuditLogRepository
using AuthHive.Core.Interfaces.Base; // [v17] IUnitOfWork
using AuthHive.Core.Interfaces.Infra; // [v17] IDateTimeProvider
using AuthHive.Core.Models.Audit.Commands; // [v17] CreateAuditLogCommand
using AuthHive.Core.Models.Audit.Events; // [v17] AuditLogCreatedEvent (Publish용)
using AuthHive.Core.Models.Audit.Responses; // [v17] AuditLogResponse (Return용)
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.Audit
{
    /// <summary>
    /// [v17] "감사 로그 생성" 유스케이스 핸들러 (SOP 1-Write-C)
    /// 시스템의 다른 부분(예: SessionCreatedAuditLogHandler)에서 보낸
    /// 감사 로그 생성 명령을 받아 실제 엔티티를 생성하고 DB에 저장합니다.
    /// </summary>
    public class CreateAuditLogCommandHandler : IRequestHandler<CreateAuditLogCommand, AuditLogResponse>
    {
        private readonly IMediator _mediator;
        private readonly IAuditLogRepository _auditLogRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly ILogger<CreateAuditLogCommandHandler> _logger;

        public CreateAuditLogCommandHandler(
            IMediator mediator,
            IAuditLogRepository auditLogRepository,
            IUnitOfWork unitOfWork,
            IDateTimeProvider dateTimeProvider,
            ILogger<CreateAuditLogCommandHandler> logger)
        {
            _mediator = mediator;
            _auditLogRepository = auditLogRepository;
            _unitOfWork = unitOfWork;
            _dateTimeProvider = dateTimeProvider;
            _logger = logger;
        }

        public async Task<AuditLogResponse> Handle(CreateAuditLogCommand command, CancellationToken cancellationToken)
        {
            var utcNow = _dateTimeProvider.UtcNow;

            // 1. [v17 "본보기"] Command(DTO) -> Entity(Model) 매핑
            // "계약서"에서 확인한 'CreateAuditLogCommand' DTO의 모든 속성을
            // "계약서"에서 확인한 'AuditLog' 엔티티의 속성으로 매핑합니다.
            // 'AuditLog' 엔티티는 'public set'을 사용하므로 이 매핑이 가능합니다.
            var auditLogEntity = new AuditLog
            {
                // Command Payload
                ActionType = command.ActionType,
                Action = command.Action,
                Success = command.Success,
                ResourceType = command.ResourceType,
                ResourceId = command.ResourceId,
                ErrorCode = command.ErrorCode,
                ErrorMessage = command.ErrorMessage,
                Metadata = command.Metadata, // 'new string?' 타입
                DurationMs = command.DurationMs,
                Severity = command.Severity,

                // Command Base Context
                TargetOrganizationId = command.OrganizationId, // BaseCommand.OrganizationId
                ApplicationId = command.ApplicationId, // BaseCommand.ApplicationId
                PerformedByConnectedId = command.TriggeredBy, // BaseCommand.TriggeredBy
                IpAddress = command.IpAddress, // BaseCommand.IpAddress
                UserAgent = command.UserAgent, // BaseCommand.UserAgent
                RequestId = command.RequestId, // BaseCommand.RequestId
                
                // Entity-Managed Properties
                Timestamp = utcNow, // 핸들러가 실제 DB 저장 시간을 설정

                // SystemGlobalBaseEntity Properties
                CreatedAt = utcNow,
                
                // [v17 CS0117/CS0029 해결]
                // SystemGlobalBaseEntity "계약서"는 'CreatedByConnectedId' (Guid?)를 요구합니다.
                // command.TriggeredBy (ConnectedId)는 Guid?이므로 타입이 일치합니다.
                CreatedByConnectedId = command.TriggeredBy 
            };

            // 2. [v17 "본보기"] 데이터 저장
            // 'IAuditLogRepository' "계약서"에 정의된 AddAsync를 호출하고
            // 'IUnitOfWork'로 트랜잭션을 커밋합니다.
            AuditLog createdEntity;
            try
            {
                createdEntity = await _auditLogRepository.AddAsync(auditLogEntity, cancellationToken);
                await _unitOfWork.SaveChangesAsync(cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to add AuditLogEntity to database for Action {Action}", command.Action);
                throw new InvalidOperationException("Failed to create audit log.", ex);
            }

            _logger.LogInformation("AuditLogEntity {AuditLogId} created for Action {Action}", createdEntity.Id, createdEntity.Action);

            // 3. [v17 "본보기"] 이벤트 발행 (Notify)
            // 감사 로그 생성이 "성공"했음을 시스템에 알립니다.
            // (예: 실시간 모니터링 대시보드 핸들러가 이 이벤트를 구독할 수 있음)
            // "계약서"에서 확인한 'AuditLogCreatedEvent' 생성자를 사용합니다.
            var auditLogCreatedEvent = new AuditLogCreatedEvent(
                auditLogId: createdEntity.Id,
                organizationId: createdEntity.TargetOrganizationId,
                performedByConnectedId: createdEntity.PerformedByConnectedId,
                actionType: createdEntity.ActionType,
                success: createdEntity.Success
            );
            await _mediator.Publish(auditLogCreatedEvent, cancellationToken);

            // 4. [v17 "본보기"] DTO 응답 반환
            // Command의 반환 타입인 'AuditLogResponse' "계약서"에 맞춰 응답을 생성합니다.
            // 이 응답은 'SessionCreatedAuditLogHandler'에게 (궁극적으로는 API 호출자에게) 반환됩니다.
            return new AuditLogResponse(
                id: createdEntity.Id,
                actionType: createdEntity.ActionType,
                action: createdEntity.Action,
                success: createdEntity.Success,
                severity: createdEntity.Severity,
                createdAt: createdEntity.CreatedAt,
                auditTrailDetailsCount: 0, // 이 핸들러는 상세 내역을 생성하지 않음
                performedByConnectedId: createdEntity.PerformedByConnectedId,
                organizationId: createdEntity.TargetOrganizationId,
                applicationId: createdEntity.ApplicationId,
                resourceType: createdEntity.ResourceType,
                resourceId: createdEntity.ResourceId,
                ipAddress: createdEntity.IpAddress,
                userAgent: createdEntity.UserAgent,
                requestId: createdEntity.RequestId,
                errorCode: createdEntity.ErrorCode,
                errorMessage: createdEntity.ErrorMessage,
                metadata: createdEntity.Metadata,
                durationMs: createdEntity.DurationMs
            );
        }
    }
}