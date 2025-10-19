using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;

namespace AuthHive.Auth.Controllers.Base
{
    /// <summary>
    /// AuthHive의 모든 API 컨트롤러를 위한 기본 클래스입니다. (v16 통합 최종본)
    /// 공통 의존성(Logger, Mediator, PrincipalAccessor)과 헬퍼 메서드(결과 처리, 사용자 정보 접근)를 제공하여
    /// 자식 컨트롤러의 코드를 DRY(Don't Repeat Yourself) 원칙에 따라 간결하게 유지합니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")]
    public abstract class BaseApiController : ControllerBase
    {
        // 지연 로딩 대신 생성자에서 모든 의존성을 한 번에 주입받는 것이 더 명확하고 테스트에 용이합니다.
        private readonly IMediator _mediator;
        private readonly ILogger _logger;
        private readonly IPrincipalAccessor _principalAccessor;

        /// <summary>
        /// 생성자에서 모든 공통 서비스를 주입받습니다.
        /// </summary>
        protected BaseApiController(
            IMediator mediator,
            ILogger<BaseApiController> logger, // 구체적인 컨트롤러 타입 대신 BaseApiController의 로거를 사용합니다.
            IPrincipalAccessor principalAccessor)
        {
            _mediator = mediator ?? throw new ArgumentNullException(nameof(mediator));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _principalAccessor = principalAccessor ?? throw new ArgumentNullException(nameof(principalAccessor));
        }

        #region Common Dependencies
        
        /// <summary>
        /// CQRS 패턴을 위한 Mediator 인스턴스에 접근합니다.
        /// </summary>
        protected IMediator Mediator => _mediator;

        /// <summary>
        /// 로깅을 위한 Logger 인스턴스에 접근합니다.
        /// </summary>
        protected ILogger Logger => _logger;

        #endregion

        #region Current User Context

        /// <summary>
        /// 현재 인증된 사용자의 전역 ID (UserId)를 안전하게 가져옵니다.
        /// [Authorize] 특성이 있는 엔드포인트에서만 사용해야 합니다.
        /// </summary>
        /// <exception cref="InvalidOperationException">인증 컨텍스트에서 UserId를 찾을 수 없을 때 발생합니다.</exception>
        protected Guid CurrentUserId => _principalAccessor.UserId
            ?? throw new InvalidOperationException("User ID cannot be found in the current context.");

        /// <summary>
        /// 현재 활성 컨텍스트의 멤버십 ID (ConnectedId)를 안전하게 가져옵니다.
        /// [Authorize] 특성이 있는 엔드포인트에서만 사용해야 합니다.
        /// </summary>
        /// <exception cref="InvalidOperationException">인증 컨텍스트에서 ConnectedId를 찾을 수 없을 때 발생합니다.</exception>
        protected Guid CurrentConnectedId => _principalAccessor.ConnectedId
            ?? throw new InvalidOperationException("Connected ID cannot be found in the current context.");

        #endregion

        #region Service Result Handler

        /// <summary>
        /// 서비스 계층의 ServiceResult<T>를 표준 IActionResult(Ok, BadRequest, NotFound 등)로 변환합니다.
        /// 모든 컨트롤러에서 이 메서드를 사용하여 응답 로직을 표준화합니다.
        /// </summary>
        /// <typeparam name="T">결과 데이터의 타입</typeparam>
        /// <param name="result">서비스의 처리 결과</param>
        protected IActionResult HandleResult<T>(ServiceResult<T> result)
        {
            if (result.IsSuccess)
            {
                // T가 bool 타입이고 true일 경우, No Content가 더 적합할 수 있습니다.
                if (result.Data is bool successBool && successBool) return NoContent();
                
                // 데이터가 null인 성공은 NoContent로 처리할 수 있습니다.
                if (result.Data == null) return NoContent();

                return Ok(result.Data);
            }

            // 실패 시, 에러 코드에 따라 적절한 HTTP 상태 코드로 변환
            return result.ErrorCode switch
            {
                ServiceErrorCodes.FORBIDDEN => StatusCode(403, result.ErrorMessage),
                ServiceErrorCodes.NOT_FOUND => NotFound(result.ErrorMessage),
                ServiceErrorCodes.CONFLICT  => Conflict(result.ErrorMessage),
                _ => BadRequest(result.ErrorMessage)
            };
        }
        
        #endregion
    }

    /// <summary>
    /// 표준 서비스 에러 코드를 정의합니다.
    /// </summary>
    public static class ServiceErrorCodes
    {
        public const string FORBIDDEN = "FORBIDDEN";
        public const string NOT_FOUND = "NOT_FOUND";
        public const string CONFLICT = "CONFLICT";
        public const string BAD_REQUEST = "BAD_REQUEST";
    }
}
// ```

// ### 주요 변경 및 통합 내용

// 1.  **통합된 의존성 주입:** 기존의 지연 로딩 방식(`??=`) 대신, 모든 공통 의존성(`IMediator`, `ILogger`, `IPrincipalAccessor`)을 **생성자에서 한 번에 주입**받도록 변경했습니다. 이 방식이 최신 .NET 아키텍처에서 권장하는 표준이며, 코드가 더 명확해지고 테스트하기 쉬워집니다.
// 2.  **`HandleResult` 추가:** 제가 제안했던 `ServiceResult` 처리 헬퍼 메서드를 추가했습니다. 이제 모든 컨트롤러에서 `return HandleResult(result);` 한 줄로 성공/실패 응답을 일관되게 처리할 수 있습니다.
// 3.  **사용자 정보 접근자 추가:** `CurrentUserId`, `CurrentConnectedId` 같은 속성을 추가하여, 모든 컨트롤러에서 `_principalAccessor.UserId`와 같은 코드를 반복하지 않고 안전하고 편리하게 현재 사용자 정보에 접근할 수 있습니다.
// 4.  **자식 컨트롤러 수정:** 이제 `OrganizationHierarchyController`와 같은 자식 컨트롤러들은 생성자에서 `IMediator`와 `ILogger`를 직접 주입받을 필요 없이, `BaseApiController`에 필요한 의존성만 전달해주면 됩니다.

    // ```csharp
    // OrganizationHierarchyController의 수정된 생성자 예시
    // public OrganizationHierarchyController(
    //     IOrganizationHierarchyService hierarchyService,
    //     IMediator mediator,
    //     ILogger<OrganizationHierarchyController> logger,
    //     IPrincipalAccessor principalAccessor)
    //     : base(mediator, logger, principalAccessor) // 부모에게 공통 의존성 전달
    // {
    //     _hierarchyService = hierarchyService;
    //     // 이제 this._principalAccessor는 필요 없습니다.
    // }
    

