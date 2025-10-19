using System;
using System.Threading.Tasks;
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 정보 조회 전용 API 컨트롤러 (Query Side)
    /// IOrganizationQueryService를 사용하여 조직 검색 및 목록 조회 엔드포인트를 제공합니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")] // api/v1/OrganizationQuery
    [Authorize] // 모든 엔드포인트는 인증을 요구합니다.
    public class OrganizationQueryController : BaseApiController
    {
        // IOrganizationQueryService는 조회(Query) 서비스이므로, Command/Query 분리 원칙에 따라 Mediator 대신 직접 주입받아 사용합니다.
        private readonly IOrganizationQueryService _queryService;

        /// <summary>
        /// 생성자: 컨트롤러에 특화된 서비스(_queryService)와 BaseApiController에 필요한 공통 의존성을 주입받습니다.
        /// </summary>
        public OrganizationQueryController(
            IOrganizationQueryService queryService,
            IMediator mediator,
            ILogger<OrganizationQueryController> logger,
            IPrincipalAccessor principalAccessor)
            : base(mediator, logger, principalAccessor)
        {
            _queryService = queryService;
        }

        #region 조직 검색 및 필터링

        /// <summary>
        /// [GET] 조직 목록을 검색 조건과 페이징 정보를 사용하여 조회합니다.
        /// </summary>
        /// <param name="request">검색어, 상태, 타입, 페이징 정보 등을 포함하는 요청 객체</param>
        /// <returns>페이징된 조직 목록 (OrganizationListResponse)</returns>
        [HttpGet]
        [ProducesResponseType(typeof(OrganizationListResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> SearchOrganizations([FromQuery] OrganizationSearchRequest request)
        {
            // 서비스 계층으로 조회 요청을 전달합니다. CancellationToken은 HttpContext에서 가져와 전달합니다.
            var result = await _queryService.SearchAsync(request, HttpContext.RequestAborted);
            
            // BaseApiController의 HandleResult 메서드를 사용하여 응답을 표준화합니다.
            return HandleResult(result);
        }

        /// <summary>
        /// [GET] 현재 인증된 사용자(CurrentUserId)가 속한 조직 목록을 조회합니다.
        /// </summary>
        /// <returns>사용자가 속한 조직 DTO 목록</returns>
        [HttpGet("me")] // api/v1/OrganizationQuery/me
        [ProducesResponseType(typeof(IEnumerable<OrganizationDto>), 200)]
        public async Task<IActionResult> GetMyOrganizations()
        {
            // BaseApiController의 CurrentUserId 속성을 사용하여 현재 사용자의 ID를 안전하게 가져옵니다.
            var userId = CurrentUserId; 

            var result = await _queryService.GetUserOrganizationsAsync(userId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// [GET] 현재 활성 ConnectedId가 접근 권한을 가진 조직 목록을 조회합니다.
        /// </summary>
        /// <returns>ConnectedId가 접근 가능한 조직 DTO 목록</returns>
        [HttpGet("accessible")] // api/v1/OrganizationQuery/accessible
        [ProducesResponseType(typeof(IEnumerable<OrganizationDto>), 200)]
        public async Task<IActionResult> GetAccessibleOrganizations()
        {
            // BaseApiController의 CurrentConnectedId 속성을 사용하여 현재 요청 컨텍스트의 ConnectedId를 안전하게 가져옵니다.
            var connectedId = CurrentConnectedId;

            var result = await _queryService.GetAccessibleOrganizationsAsync(connectedId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion

        // NOTE: 특정 조직 ID로 단일 조직을 조회하는 GetById 로직은 일반적으로 CQRS Read/Query 모델의 기본이 되지만,
        // 이 로직은 IMediator를 통해 간단한 GetQuery를 처리하거나, OrganizationService/OrganizationQueryService에
        // GetByIdAsync(Guid id) 메서드를 추가하여 구현할 수 있습니다.
    }
}