using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Auth.External;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Common;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직별 OAuth/SSO 제공자 설정(Provider Configuration)을 관리하는 API 컨트롤러입니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/oauth/providers")]
    [Authorize]
    public class OAuthProviderController : BaseApiController
    {
        private readonly IOAuthProviderService _oauthProviderService;

        /// <summary>
        /// 생성자: IOAuthProviderService와 BaseApiController의 공통 의존성을 주입합니다.
        /// </summary>
        public OAuthProviderController(
            IOAuthProviderService oauthProviderService,
            IMediator mediator,
            ILogger<OAuthProviderController> logger,
            IPrincipalAccessor principalAccessor)
            : base(mediator, logger, principalAccessor)
        {
            _oauthProviderService = oauthProviderService;
        }

        #region 설정 조회 (Query)

        /// <summary>
        /// [GET] 현재 조직에 등록된 모든 OAuth 제공자 설정을 조회합니다.
        /// </summary>
        [HttpGet]
        [ProducesResponseType(typeof(List<OAuthProviderConfiguration>), 200)]
        public async Task<IActionResult> GetAllProviders()
        {
            var result = await _oauthProviderService.GetAllProvidersAsync(HttpContext.RequestAborted);
            // List<OAuthProviderConfiguration>은 T를 명시할 필요 없이 HandleResult가 처리 가능하나,
            // 안전을 위해 명시적으로 타입 인자를 지정합니다.
            return HandleResult<List<OAuthProviderConfiguration>>(result);
        }

        /// <summary>
        /// [GET] 특정 조직에 커스텀 등록된 OAuth 제공자 설정을 조회합니다.
        /// </summary>
        [HttpGet("{providerName}")]
        [ProducesResponseType(typeof(OAuthProviderConfiguration), 200)]
        public async Task<IActionResult> GetProviderConfig([FromRoute] string providerName)
        {
            var result = await _oauthProviderService.GetProviderConfigAsync(providerName, HttpContext.RequestAborted);
            // DTO 타입을 명시합니다.
            return HandleResult<OAuthProviderConfiguration>(result);
        }

        #endregion

        #region 설정 등록 및 관리 (Command)

        /// <summary>
        /// [POST] 새로운 OAuth 제공자 설정을 조직에 등록하거나 기존 설정을 업데이트합니다 (Upsert).
        /// </summary>
        [HttpPost]
        [ProducesResponseType(204)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> RegisterProvider(
            [FromRoute] Guid organizationId,
            [FromBody] OAuthProviderConfiguration config)
        {
            var result = await _oauthProviderService.RegisterProviderAsync(config, HttpContext.RequestAborted);

            // RegisterProviderAsync는 ServiceResult<bool> (또는 ServiceResult)을 반환하므로,
            // ✅ CS0411 해결: Non-Generic ServiceResult를 ServiceResult<bool>로 래핑하여 HandleResult에 전달합니다.
            // 성공 시 HandleResult는 204 No Content로 처리됩니다.
            var genericResult = result.IsSuccess
                ? ServiceResult<bool>.Success(true)
                : ServiceResult<bool>.Failure(result.ErrorMessage ?? "Registration failed.", result.ErrorCode ?? "BAD_REQUEST");

            return HandleResult(genericResult);
        }

        #endregion

        #region 인증 시작 (Initiate Auth Flow)

        /// <summary>
        /// [GET] 지정된 제공자를 통한 OAuth 인증 흐름을 시작하고, 리디렉션 URL을 반환합니다.
        /// </summary>
        [HttpGet("{provider}/initiate")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AuthenticationResponse), 200)]
        public async Task<IActionResult> InitiateAuth(
            [FromRoute] string provider,
            [FromQuery] string redirectUri,
            [FromQuery] List<string>? scopes)
        {
            var result = await _oauthProviderService.InitiateAuthAsync(
                provider, redirectUri, scopes, HttpContext.RequestAborted);

            // ✅ CS0411 해결: AuthenticationResponse 타입을 명시합니다.
            return HandleResult<AuthenticationResponse>(result);
        }

        /// <summary>
        /// [GET/POST] OAuth 제공자로부터의 콜백 요청을 처리합니다.
        /// </summary>
        [HttpGet("{provider}/callback")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(AuthenticationResponse), 200)]
        public async Task<IActionResult> ProcessCallback(
            [FromRoute] string provider,
            [FromQuery] string code,
            [FromQuery] string state)
        {
            var result = await _oauthProviderService.ProcessCallbackAsync(
                provider, code, state, HttpContext.RequestAborted);

            // ✅ CS0411 해결: AuthenticationResponse 타입을 명시합니다.
            return HandleResult<AuthenticationResponse>(result);
        }

        #endregion
    }
}