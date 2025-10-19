// --- 1. 필요한 네임스페이스 선언 ---
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Models.Organization;
using AuthHive.Auth.Controllers.Base;
using MediatR; // BaseApiController에 필요
using Microsoft.Extensions.Logging; // BaseApiController에 필요
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 멤버십(Memberships)에 대한 CRUD API 엔드포인트를 관리합니다. (v16 최종본)
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/members")]
    [Authorize]
    public class OrganizationMembershipsController : BaseApiController
    {
        // --- 2. 의존성 필드 선언 ---
        private readonly IOrganizationMembershipService _membershipService; 

        /// <summary>
        /// 3. 생성자: BaseApiController의 필수 인자(Mediator, Logger, PrincipalAccessor)를 주입받아 전달합니다.
        /// </summary>
        public OrganizationMembershipsController(
            IOrganizationMembershipService membershipService,
            IMediator mediator, // ✅ CS7036 해결: BaseApiController의 필수 인자
            ILogger<OrganizationMembershipsController> logger, // ✅ BaseApiController의 필수 인자
            IPrincipalAccessor principalAccessor)
            : base(mediator, logger, principalAccessor) // ✅ BaseApiController로 공통 인자 전달
        {
            _membershipService = membershipService;
        }

        #region 조회 (Read) API

        /// <summary>
        /// 특정 조직의 모든 멤버 목록을 페이지 단위로 조회합니다.
        /// </summary>
        [HttpGet]
        [ProducesResponseType(typeof(PagedResult<OrganizationMembershipDto>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> GetMembers(
            [FromRoute] Guid organizationId,
            [FromQuery] OrganizationMembershipStatus? status = null,
            [FromQuery] OrganizationMemberRole? role = null,
            [FromQuery] int pageNumber = 1,
            [FromQuery] int pageSize = 20)
        {
            var result = await _membershipService.GetMembersAsync(organizationId, status, role, pageNumber, pageSize, HttpContext.RequestAborted);
            
            // BaseApiController의 HandleResult를 사용합니다.
            // PagedResult<OrganizationMembershipDto> 타입을 명시합니다.
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 멤버 한 명의 상세 정보를 조회합니다.
        /// </summary>
        [HttpGet("{memberId:guid}", Name = "GetMemberById")]
        [ProducesResponseType(typeof(OrganizationMembershipDto), 200)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetMemberById([FromRoute] Guid organizationId, [FromRoute] Guid memberId)
        {
            var result = await _membershipService.GetMemberAsync(organizationId, memberId, HttpContext.RequestAborted);
            
            // 결과를 HTTP 응답으로 변환합니다.
            return HandleResult(result);
        }

        #endregion

        #region 관리 (Management) API

        /// <summary>
        /// 조직에서 특정 멤버를 제거합니다. (Soft Delete)
        /// </summary>
        [HttpDelete("{memberId:guid}")]
        [ProducesResponseType(204)] // 삭제는 204 No Content가 적합합니다.
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> RemoveMember(
            [FromRoute] Guid organizationId, 
            [FromRoute] Guid memberId, 
            [FromBody] RemoveMemberRequest request)
        {
            var result = await _membershipService.RemoveMemberAsync(organizationId, memberId, request.Reason, HttpContext.RequestAborted);
            
            // bool을 반환하는 ServiceResult<bool>을 HandleResult가 204로 변환합니다.
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 멤버의 역할을 변경합니다.
        /// </summary>
        [HttpPut("{memberId:guid}/role")]
        [ProducesResponseType(204)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> ChangeMemberRole(
            [FromRoute] Guid organizationId, 
            [FromRoute] Guid memberId, 
            [FromBody] ChangeMemberRoleRequest request)
        {
            var result = await _membershipService.ChangeMemberRoleAsync(organizationId, memberId, request.NewRole, HttpContext.RequestAborted);
            
            // bool을 반환하는 ServiceResult<bool>을 HandleResult가 204로 변환합니다.
            return HandleResult(result);
        }

        #endregion

        // 🚨 CS0108 해결: BaseApiController의 HandleResult<T>(ServiceResult<T>)를 중복 정의하는 메서드를 삭제합니다.
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