using MediatR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;

namespace AuthHive.Auth.Controllers.Base
{
    /// <summary>
    /// AuthHive의 모든 API 컨트롤러를 위한 기본 클래스입니다.
    /// 공통적인 의존성(Logger, Mediator 등)과 헬퍼 속성을 제공합니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")]
    public abstract class BaseApiController : ControllerBase
    {
        private IMediator? _mediator;
        private ILogger? _logger;

        /// <summary>
        /// 의존성 주입을 통해 Mediator 인스턴스를 가져옵니다.
        /// </summary>
        protected IMediator Mediator => _mediator ??= HttpContext.RequestServices.GetService<IMediator>()!;

        /// <summary>
        /// 컨트롤러의 타입에 맞는 Logger 인스턴스를 가져옵니다.
        /// </summary>
        protected ILogger Logger => _logger ??= HttpContext.RequestServices.GetService<ILogger<ControllerBase>>()!;

        // [TODO] 향후 공통 헬퍼 메서드 추가 가능
        // 예: protected Guid GetCurrentUserId() => ...
    }
}
