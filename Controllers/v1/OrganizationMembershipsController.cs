// --- 1. 필요한 네임스페이스 선언 ---
using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AuthHive.Core.Interfaces.Organization.Service; // IOrganizationMembershipService
using AuthHive.Core.Interfaces.Base;                 // IPrincipalAccessor
using AuthHive.Core.Models.Common;                     // ServiceResult, PagedResult
using AuthHive.Core.Enums.Core;                      // OrganizationMemberRole 등 Enum
using AuthHive.Core.Models.Organization;               // OrganizationMembershipDto
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Models.Organization.Common;                // BaseApiController

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 멤버십(Memberships)에 대한 CRUD API 엔드포인트를 관리합니다.
    /// </summary>
    [ApiController]                                     // 이 클래스가 API 컨트롤러임을 나타냅니다.
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/members")] // API 경로를 정의합니다. (예: /api/v1/organizations/ORG_ID/members)
    [Authorize]                                         // 이 컨트롤러의 모든 액션은 기본적으로 인증된 사용자만 접근할 수 있습니다.
    public class OrganizationMembershipsController : BaseApiController
    {
        // --- 2. 의존성 필드 선언 ---
        private readonly IOrganizationMembershipService _membershipService; // 멤버십 관련 비즈니스 로직을 처리하는 서비스
        private readonly IPrincipalAccessor _principalAccessor;             // 현재 요청을 보낸 사용자의 정보(ID)에 접근하기 위한 객체

        /// <summary>
        /// 3. 생성자: 의존성 주입(DI)을 통해 필요한 서비스들을 주입받습니다.
        /// </summary>
        public OrganizationMembershipsController(
            IOrganizationMembershipService membershipService,
            IPrincipalAccessor principalAccessor)
        {
            _membershipService = membershipService;
            _principalAccessor = principalAccessor;
        }

        #region 조회 (Read) API

        /// <summary>
        /// 특정 조직의 모든 멤버 목록을 페이지 단위로 조회합니다.
        /// </summary>
        /// <param name="organizationId">멤버를 조회할 조직의 ID입니다.</param>
        /// <param name="status">필터링할 멤버의 상태입니다 (예: Active, Invited).</param>
        /// <param name="role">필터링할 멤버의 역할입니다 (예: Admin, Member).</param>
        /// <param name="pageNumber">요청할 페이지 번호입니다.</param>
        /// <param name="pageSize">한 페이지에 표시할 항목의 수입니다.</param>
        /// <returns>페이지 정보가 포함된 멤버 목록을 반환합니다.</returns>
        [HttpGet]
        [ProducesResponseType(typeof(ServiceResult<PagedResult<OrganizationMembershipDto>>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> GetMembers(
            [FromRoute] Guid organizationId,
            [FromQuery] OrganizationMembershipStatus? status = null,
            [FromQuery] OrganizationMemberRole? role = null,
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20)
        {
            // 서비스 레이어에 작업을 위임하고, 요청 취소 토큰(RequestAborted)을 전달합니다.
            var result = await _membershipService.GetMembersAsync(organizationId, status, role, pageNumber, pageSize, HttpContext.RequestAborted);
            
            // 서비스 결과를 공통 핸들러를 통해 적절한 HTTP 응답으로 변환하여 반환합니다.
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 멤버 한 명의 상세 정보를 조회합니다.
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <param name="memberId">조회할 멤버의 고유 ID (ConnectedId) 입니다.</param>
        /// <returns>멤버의 상세 정보를 반환합니다.</returns>
        [HttpGet("{memberId:guid}", Name = "GetMemberById")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationMembershipDto>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetMemberById([FromRoute] Guid organizationId, [FromRoute] Guid memberId)
        {
            // 서비스 레이어에 작업을 위임합니다.
            var result = await _membershipService.GetMemberAsync(organizationId, memberId, HttpContext.RequestAborted);
            
            // 결과를 HTTP 응답으로 변환합니다.
            return HandleResult(result);
        }

        #endregion

        #region 관리 (Management) API

        /// <summary>
        /// 조직에서 특정 멤버를 제거합니다. (Soft Delete)
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <param name="memberId">제거할 멤버의 ID (ConnectedId) 입니다.</param>
        /// <param name="request">제거 사유를 포함하는 요청 본문입니다.</param>
        [HttpDelete("{memberId:guid}")]
        [ProducesResponseType(typeof(ServiceResult<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> RemoveMember(
            [FromRoute] Guid organizationId, 
            [FromRoute] Guid memberId, 
            [FromBody] RemoveMemberRequest request)
        {
            // IPrincipalAccessor 덕분에 '누가' 제거하는지 파라미터로 받을 필요가 없습니다.
            var result = await _membershipService.RemoveMemberAsync(organizationId, memberId, request.Reason, HttpContext.RequestAborted);
            
            // 결과를 HTTP 응답으로 변환합니다.
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 멤버의 역할을 변경합니다.
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <param name="memberId">역할을 변경할 멤버의 ID (ConnectedId) 입니다.</param>
        /// <param name="request">새로운 역할을 포함하는 요청 본문입니다.</param>
        [HttpPut("{memberId:guid}/role")]
        [ProducesResponseType(typeof(ServiceResult<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> ChangeMemberRole(
            [FromRoute] Guid organizationId, 
            [FromRoute] Guid memberId, 
            [FromBody] ChangeMemberRoleRequest request)
        {
            // IPrincipalAccessor 덕분에 '누가' 변경하는지 파라미터로 받을 필요가 없습니다.
            var result = await _membershipService.ChangeMemberRoleAsync(organizationId, memberId, request.NewRole, HttpContext.RequestAborted);
            
            // 결과를 HTTP 응답으로 변환합니다.
            return HandleResult(result);
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 서비스의 결과(ServiceResult)를 분석하여 표준화된 HTTP 응답(IActionResult)으로 변환하는 헬퍼 메서드입니다.
        /// 컨트롤러의 코드를 간결하고 일관성 있게 유지해줍니다.
        /// </summary>
        private IActionResult HandleResult<T>(ServiceResult<T> result)
        {
            // 서비스 로직이 성공적으로 완료되었을 경우
            if (result.IsSuccess)
            {
                // 성공 결과(데이터 포함)와 함께 200 OK 응답을 반환합니다.
                return Ok(result);
            }
            
            // 서비스 로직이 실패했을 경우, 미리 정의된 오류 코드에 따라 적절한 HTTP 상태 코드를 반환합니다.
            return result.ErrorCode switch
            {
                // "FORBIDDEN" 오류 코드는 403 Forbidden (권한 없음)으로 매핑합니다.
                "FORBIDDEN" => StatusCode(403, result),
                // "NOT_FOUND" 오류 코드는 404 Not Found (찾을 수 없음)로 매핑합니다.
                "NOT_FOUND" => NotFound(result),
                // 그 외 모든 비즈니스 규칙 위반(예: 중복, 한도 초과 등)은 400 Bad Request (잘못된 요청)로 매핑합니다.
                _ => BadRequest(result)
            };
        }

        #endregion
    }

    #region Request DTOs (요청 본문을 위한 데이터 모델)

    /// <summary>
    /// 멤버 제거 API의 요청 본문을 위한 DTO입니다.
    /// </summary>
    public class RemoveMemberRequest
    {
        /// <summary>
        /// 멤버를 제거하는 사유입니다. (감사 로그에 기록됨)
        /// </summary>
        public string Reason { get; set; } = "No reason provided.";
    }

    /// <summary>
    /// 멤버 역할 변경 API의 요청 본문을 위한 DTO입니다.
    /// </summary>
    public class ChangeMemberRoleRequest
    {
        /// <summary>
        /// 멤버에게 새로 할당할 역할입니다.
        /// </summary>
        public OrganizationMemberRole NewRole { get; set; }
    }

    #endregion
}