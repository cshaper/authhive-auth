using Microsoft.AspNetCore.Mvc;
using MediatR;
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Audit.Commands;
using AuthHive.Core.Models.Audit.Responses;
using Asp.Versioning;

namespace AuthHive.Auth.Controllers.v1;

/// <summary>
/// [Audit Domain] 감사 로그 관리 API
/// </summary>
[ApiVersion("1.0")]
public class AuditController : BaseApiController
{
    // BaseApiController가 Mediator, Logger, PrincipalAccessor를 요구하므로
    // 자식 컨트롤러는 이를 주입받아 부모에게 전달(pass-through)해야 합니다.
    public AuditController(
        IMediator mediator,
        ILogger<AuditController> logger,
        IPrincipalAccessor principalAccessor)
        : base(mediator, logger, principalAccessor)
    {
    }

    /// <summary>
    /// 감사 로그 수동 생성
    /// (주로 내부 서비스나 관리자 도구에서 호출)
    /// </summary>
    [HttpPost]
    [ProducesResponseType(typeof(AuditLogResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CreateAuditLog([FromBody] CreateAuditLogCommand command)
    {
        // [참고]
        // 현재 CreateAuditLogCommandHandler는 'ServiceResult<T>'가 아니라 'T(AuditLogResponse)'를 직접 반환하도록 구현되어 있습니다.
        // 따라서 부모의 HandleResult() 헬퍼를 쓰지 않고 표준 Ok()를 사용합니다.
        // (만약 Handler가 ServiceResult를 반환하도록 수정된다면 HandleResult(result)를 사용하세요.)
        
        var result = await Mediator.Send(command);
        return Ok(result);
    }
}