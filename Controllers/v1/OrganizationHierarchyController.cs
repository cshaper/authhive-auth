using System;
using System.Threading.Tasks;
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직의 계층 구조(Hierarchy)에 대한 API 엔드포인트를 관리합니다. (v16 최종본)
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/hierarchy")]
    [Authorize]
    public class OrganizationHierarchyController : BaseApiController
    {
        private readonly IOrganizationHierarchyService _hierarchyService;

        /// <summary>
        /// 생성자: 컨트롤러에 특화된 서비스와 공통 서비스를 주입받아 BaseApiController로 전달합니다.
        /// </summary>
        // CORRECTED (CS7036): BaseApiController의 새로운 생성자 계약에 맞춰 IMediator, ILogger, IPrincipalAccessor를 주입받아 base()로 전달합니다.
        public OrganizationHierarchyController(
            IOrganizationHierarchyService hierarchyService,
            IMediator mediator,
            ILogger<OrganizationHierarchyController> logger,
            IPrincipalAccessor principalAccessor)
            : base(mediator, logger, principalAccessor)
        {
            _hierarchyService = hierarchyService;
        }

        #region 계층 조회 (Read)

        /// <summary>
        /// 지정된 조직을 루트로 하는 계층 구조를 트리 형태로 조회합니다.
        /// </summary>
        [HttpGet("tree")]
        [ProducesResponseType(typeof(OrganizationHierarchyTree), 200)]
        public async Task<IActionResult> GetOrganizationTree([FromRoute] Guid organizationId, [FromQuery] int? maxDepth)
        {
            var result = await _hierarchyService.GetOrganizationTreeAsync(organizationId, maxDepth, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 지정된 조직의 직속 부모 조직 ID를 조회합니다.
        /// </summary>
        [HttpGet("parent")]
        [ProducesResponseType(typeof(Guid?), 200)]
        public async Task<IActionResult> GetParentOrganizationId([FromRoute] Guid organizationId)
        {
            var result = await _hierarchyService.GetParentOrganizationIdAsync(organizationId, HttpContext.RequestAborted);
            return HandleResult(result);
        }
        
        #endregion

        #region 계층 관리 (Write)

        /// <summary>
        /// 지정된 조직 아래에 새로운 하위 조직을 생성합니다.
        /// </summary>
        [HttpPost("children")]
        [ProducesResponseType(typeof(OrganizationDto), 201)]
        public async Task<IActionResult> CreateChildOrganization([FromRoute] Guid organizationId, [FromBody] CreateOrganizationRequest request)
        {
            // 서비스 계층이 IPrincipalAccessor를 통해 현재 요청의 주체를 직접 확인하도록 위임합니다.
            var result = await _hierarchyService.CreateChildOrganizationAsync(organizationId, request, HttpContext.RequestAborted);

            if (result.IsSuccess && result.Data != null)
            {
                // 성공 시 201 Created 응답과 함께 생성된 리소스의 위치를 헤더에 담아 반환
                return CreatedAtAction(nameof(GetOrganizationTree), new { organizationId = result.Data.Id, version = "1" }, result.Data);
            }
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 조직을 새로운 부모 조직 아래로 이동시킵니다.
        /// </summary>
        [HttpPut("move")]
        [ProducesResponseType(204)] // 성공 시 No Content
        public async Task<IActionResult> MoveOrganization([FromRoute] Guid organizationId, [FromBody] MoveOrganizationRequest request)
        {
            // 'movedBy'와 같은 정보는 서비스 계층에서 PrincipalAccessor를 통해 직접 가져옵니다.
            var result = await _hierarchyService.MoveOrganizationAsync(organizationId, request.NewParentId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 조직의 설정을 모든 하위 조직으로 전파(상속)합니다.
        /// </summary>
        [HttpPost("inherit-settings")]
        [ProducesResponseType(typeof(int), 200)]
        public async Task<IActionResult> InheritSettings([FromRoute] Guid organizationId, [FromBody] InheritSettingsRequest request)
        {
            var result = await _hierarchyService.InheritSettingsToChildrenAsync(organizationId, request.InheritanceMode, HttpContext.RequestAborted);
            return HandleResult(result);
        }
        
        #endregion

        // REMOVED (CS0108): BaseApiController에 통합된 HandleResult가 있으므로,
        // 이 컨트롤러에만 있던 중복된 헬퍼 메서드를 제거합니다.
    }

    #region Request DTOs
    // DTO들은 별도의 파일로 분리하는 것이 좋으나, 기존 구조를 유지합니다.
    public class MoveOrganizationRequest
    {
        public Guid? NewParentId { get; set; }
    }

    public class InheritSettingsRequest
    {
        public PolicyInheritanceMode InheritanceMode { get; set; }
    }

    public class ReorderSiblingRequest
    {
        public int NewSortOrder { get; set; }
    }
    #endregion
}
