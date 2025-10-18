using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직의 계층 구조(Hierarchy)에 대한 API 엔드포인트를 관리합니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/hierarchy")]
    [Authorize]
    public class OrganizationHierarchyController : BaseApiController
    {
        private readonly IOrganizationHierarchyService _hierarchyService;
        private readonly IPrincipalAccessor _principalAccessor;

        /// <summary>
        /// 생성자: 의존성 주입(DI)을 통해 필요한 서비스들을 주입받습니다.
        /// </summary>
        public OrganizationHierarchyController(
            IOrganizationHierarchyService hierarchyService,
            IPrincipalAccessor principalAccessor)
        {
            _hierarchyService = hierarchyService;
            _principalAccessor = principalAccessor;
        }

        #region 계층 조회 (Read)

        /// <summary>
        /// 지정된 조직을 루트로 하는 계층 구조를 트리 형태로 조회합니다.
        /// </summary>
        /// <param name="organizationId">계층 트리의 루트가 될 조직의 ID입니다.</param>
        /// <param name="maxDepth">조회할 최대 깊이입니다. null일 경우 기본값으로 조회됩니다.</param>
        /// <returns>계층 구조 트리 정보를 반환합니다.</returns>
        [HttpGet("tree")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationHierarchyTree>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetOrganizationTree([FromRoute] Guid organizationId, [FromQuery] int? maxDepth)
        {
            var result = await _hierarchyService.GetOrganizationTreeAsync(organizationId, maxDepth, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 지정된 조직의 직속 부모 조직 ID를 조회합니다.
        /// </summary>
        /// <param name="organizationId">부모를 조회할 조직의 ID입니다.</param>
        /// <returns>부모 조직의 ID를 반환합니다. 최상위 조직일 경우 null이 반환됩니다.</returns>
        [HttpGet("parent")]
        [ProducesResponseType(typeof(ServiceResult<Guid?>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetParentOrganizationId([FromRoute] Guid organizationId)
        {
            var result = await _hierarchyService.GetParentOrganizationIdAsync(organizationId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 루트 조직부터 현재 조직까지의 전체 경로를 문자열로 조회합니다. (예: "Root / Division A / Team B")
        /// </summary>
        /// <param name="organizationId">경로를 조회할 조직의 ID입니다.</param>
        /// <returns>계층 경로 문자열을 반환합니다.</returns>
        [HttpGet("path")]
        [ProducesResponseType(typeof(ServiceResult<string>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetOrganizationPath([FromRoute] Guid organizationId)
        {
            var result = await _hierarchyService.GetOrganizationPathAsync(organizationId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion

        #region 계층 관리 (Write)

        /// <summary>
        /// 지정된 조직 하위에 새로운 자식 조직을 생성합니다.
        /// </summary>
        /// <param name="organizationId">부모가 될 조직의 ID입니다.</param>
        /// <param name="request">생성할 조직의 정보를 담은 요청 본문입니다.</param>
        /// <returns>성공적으로 생성된 조직의 정보를 반환합니다.</returns>
        [HttpPost("children")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationDto>), 201)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        public async Task<IActionResult> CreateChildOrganization([FromRoute] Guid organizationId, [FromBody] CreateOrganizationRequest request)
        {
            var createdBy = _principalAccessor.ConnectedId;
            var result = await _hierarchyService.CreateChildOrganizationAsync(organizationId, request, createdBy, HttpContext.RequestAborted);
            
            if (result.IsSuccess)
            {
                // 성공 시 201 Created 응답과 함께 생성된 리소스의 위치를 헤더에 담아 반환
                return CreatedAtAction(nameof(GetOrganizationTree), new { organizationId = result.Data!.Id }, result);
            }
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 조직을 새로운 부모 조직 아래로 이동시킵니다.
        /// </summary>
        /// <param name="organizationId">이동할 조직의 ID입니다.</param>
        /// <param name="request">새로운 부모 조직의 ID를 담은 요청 본문입니다.</param>
        /// <returns>성공 여부를 반환합니다.</returns>
        [HttpPut("move")]
        [ProducesResponseType(typeof(ServiceResult<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> MoveOrganization([FromRoute] Guid organizationId, [FromBody] MoveOrganizationRequest request)
        {
            var movedBy = _principalAccessor.ConnectedId;
            var result = await _hierarchyService.MoveOrganizationAsync(organizationId, request.NewParentId, movedBy, HttpContext.RequestAborted);
            return HandleResult(result);
        }
        
        /// <summary>
        /// 특정 조직의 설정을 모든 하위 조직으로 전파(상속)합니다.
        /// </summary>
        /// <param name="organizationId">설정을 전파할 부모 조직의 ID입니다.</param>
        /// <param name="request">상속 모드를 정의하는 요청 본문입니다.</param>
        /// <returns>영향받은 하위 조직의 수를 반환합니다.</returns>
        [HttpPost("inherit-settings")]
        [ProducesResponseType(typeof(ServiceResult<int>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        public async Task<IActionResult> InheritSettings([FromRoute] Guid organizationId, [FromBody] InheritSettingsRequest request)
        {
            var initiatedBy = _principalAccessor.ConnectedId;
            var result = await _hierarchyService.InheritSettingsToChildrenAsync(organizationId, request.InheritanceMode, initiatedBy, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 같은 부모를 가진 형제 조직들의 표시 순서를 변경합니다.
        /// </summary>
        /// <param name="organizationId">순서를 변경할 조직의 ID입니다.</param>
        /// <param name="request">새로운 정렬 순서를 담은 요청 본문입니다.</param>
        /// <returns>성공 여부를 반환합니다.</returns>
        [HttpPut("reorder")]
        [ProducesResponseType(typeof(ServiceResult<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        public async Task<IActionResult> ReorderSiblings([FromRoute] Guid organizationId, [FromBody] ReorderSiblingRequest request)
        {
            var reorderedBy = _principalAccessor.ConnectedId;
            var result = await _hierarchyService.ReorderSiblingsAsync(organizationId, request.NewSortOrder, reorderedBy, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion

        #region 검증 및 통계 (Validation & Statistics)

        /// <summary>
        /// 특정 조직을 다른 부모 아래로 이동시킬 경우 발생할 수 있는 문제(순환 참조, 깊이 제한)를 사전에 검증합니다.
        /// </summary>
        /// <param name="organizationId">이동을 검증할 조직의 ID입니다.</param>
        /// <param name="proposedParentId">새로운 부모 후보 조직의 ID입니다.</param>
        /// <returns>계층 구조 검증 결과를 반환합니다.</returns>
        [HttpGet("validate-move")]
        [ProducesResponseType(typeof(ServiceResult<HierarchyValidationResult>), 200)]
        public async Task<IActionResult> ValidateHierarchyMove([FromRoute] Guid organizationId, [FromQuery] Guid? proposedParentId)
        {
            var result = await _hierarchyService.ValidateHierarchyAsync(organizationId, proposedParentId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 조직의 현재 플랜에 따른 계층 구조 깊이 제한 정보를 조회합니다.
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <returns>현재 깊이, 최대 허용 깊이 등의 정보를 반환합니다.</returns>
        [HttpGet("depth-limit")]
        [ProducesResponseType(typeof(ServiceResult<HierarchyDepthLimit>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetDepthLimit([FromRoute] Guid organizationId)
        {
            var result = await _hierarchyService.GetDepthLimitAsync(organizationId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 지정된 기간 동안의 조직 및 모든 하위 조직의 통합 사용량 통계를 조회합니다.
        /// </summary>
        /// <param name="organizationId">루트 조직의 ID입니다.</param>
        /// <param name="startDate">조회 시작일입니다.</param>
        /// <param name="endDate">조회 종료일입니다.</param>
        /// <returns>계층적으로 집계된 사용량 통계를 반환합니다.</returns>
        [HttpGet("usage")]
        [ProducesResponseType(typeof(ServiceResult<HierarchyUsageDto>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetHierarchyUsage([FromRoute] Guid organizationId, [FromQuery] DateTime startDate, [FromQuery] DateTime endDate)
        {
            var result = await _hierarchyService.GetHierarchyUsageAsync(organizationId, startDate, endDate, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion
        
        #region Private Helper Methods

        private IActionResult HandleResult<T>(ServiceResult<T> result)
        {
            if (result.IsSuccess)
            {
                return Ok(result);
            }
            
            return result.ErrorCode switch
            {
                "FORBIDDEN" => StatusCode(403, result),
                "NOT_FOUND" => NotFound(result),
                _ => BadRequest(result)
            };
        }

        #endregion
    }

    #region Request DTOs

    public class MoveOrganizationRequest
    {
        /// <summary>
        /// 새로운 부모 조직의 ID입니다. 최상위 조직으로 만들려면 null로 설정합니다.
        /// </summary>
        public Guid? NewParentId { get; set; }
    }

    public class InheritSettingsRequest
    {
        /// <summary>
        /// 설정 상속 모드입니다 (Inherit, Override, Detach).
        /// </summary>
        public PolicyInheritanceMode InheritanceMode { get; set; }
    }

    public class ReorderSiblingRequest
    {
        /// <summary>
        /// 형제 조직 목록 내에서 조직이 위치할 새로운 순서(0부터 시작)입니다.
        /// </summary>
        public int NewSortOrder { get; set; }
    }

    #endregion
}
