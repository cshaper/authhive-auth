// using System;
// using MediatR;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.Extensions.Logging;
// using AuthHive.Core.Interfaces.Base;
// using Asp.Versioning;

// namespace AuthHive.Auth.Controllers.Base;

// /// <summary>
// /// [AuthHive v18] API 컨트롤러 기반 클래스
// /// 공통 의존성(Mediator, Logger, Principal)을 제공하며,
// /// ServiceResult 처리 로직은 제거되고 Exception Middleware 방식에 의존합니다.
// /// </summary>
// [ApiController]
// [Route("api/v{version:apiVersion}/[controller]")]
// public abstract class BaseApiController : ControllerBase
// {
//     private readonly IMediator _mediator;
//     private readonly ILogger _logger;
//     private readonly IPrincipalAccessor _principalAccessor;

//     protected BaseApiController(
//         IMediator mediator,
//         ILogger logger, // 제네릭 대신 ILogger 사용 (유연성)
//         IPrincipalAccessor principalAccessor)
//     {
//         _mediator = mediator ?? throw new ArgumentNullException(nameof(mediator));
//         _logger = logger ?? throw new ArgumentNullException(nameof(logger));
//         _principalAccessor = principalAccessor ?? throw new ArgumentNullException(nameof(principalAccessor));
//     }

//     #region Common Dependencies
    
//     protected IMediator Mediator => _mediator;
//     protected ILogger Logger => _logger;

//     #endregion

//     #region Current User Context

//     /// <summary>
//     /// 현재 인증된 사용자의 ID (UserId)
//     /// </summary>
//     protected Guid CurrentUserId => _principalAccessor.UserId
//         ?? throw new UnauthorizedAccessException("User context is missing.");

//     /// <summary>
//     /// 현재 활성 조직 멤버십 ID (ConnectedId)
//     /// </summary>
//     protected Guid CurrentConnectedId => _principalAccessor.ConnectedId
//         ?? throw new UnauthorizedAccessException("Organization context (ConnectedId) is missing.");

//     /// <summary>
//     /// 현재 테넌트(조직) ID - URL 경로 등에서 파싱된 값
//     /// </summary>
//     protected Guid CurrentOrganizationId => _principalAccessor.OrganizationId
//         ?? throw new UnauthorizedAccessException("Organization context is missing.");

//     #endregion
// }