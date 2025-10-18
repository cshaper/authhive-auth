// --- 1. 필요한 네임스페이스 선언 ---
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 멤버의 프로필(직책, 부서, 관리자 등)에 대한 API 엔드포인트를 관리합니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/profiles")]
    [Authorize]
    public class OrganizationMemberProfilesController : BaseApiController
    {
        // --- 2. 의존성 필드 선언 ---
        private readonly IOrganizationMemberProfileService _profileService;
        private readonly IPrincipalAccessor _principalAccessor;

        /// <summary>
        /// 3. 생성자: 의존성 주입(DI)을 통해 필요한 서비스들을 주입받습니다.
        /// </summary>
        public OrganizationMemberProfilesController(
            IOrganizationMemberProfileService profileService,
            IPrincipalAccessor principalAccessor)
        {
            _profileService = profileService;
            _principalAccessor = principalAccessor;
        }

        #region 프로필 조회 (Read)

        /// <summary>
        /// 특정 조직의 모든 멤버 프로필 목록을 페이지 단위로 조회합니다.
        /// </summary>
        /// <param name="organizationId">프로필을 조회할 조직의 ID입니다.</param>
        /// <param name="request">검색어, 정렬, 필터링 옵션을 포함하는 쿼리 파라미터입니다.</param>
        /// <returns>페이지 정보가 포함된 멤버 프로필 목록을 반환합니다.</returns>
        [HttpGet]
        [ProducesResponseType(typeof(ServiceResult<PagedResult<OrganizationMemberProfileDto>>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        public async Task<IActionResult> GetProfiles([FromRoute] Guid organizationId, [FromQuery] GetOrganizationProfileRequest request)
        {
            var result = await _profileService.GetProfilesAsync(organizationId, request, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 멤버 한 명의 상세 프로필 정보를 조회합니다.
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <param name="memberId">조회할 멤버의 고유 ID (ConnectedId) 입니다.</param>
        /// <returns>멤버의 상세 프로필 정보를 반환합니다.</returns>
        [HttpGet("{memberId:guid}", Name = "GetMemberProfileById")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationMemberProfileDto>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetProfileById([FromRoute] Guid organizationId, [FromRoute] Guid memberId)
        {
            var result = await _profileService.GetProfileAsync(organizationId, memberId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion

        #region 프로필 관리 (Write)

        /// <summary>
        /// 특정 멤버의 프로필을 생성하거나 업데이트합니다(Upsert).
        /// </summary>
        /// <remarks>
        /// 해당 멤버의 프로필이 존재하지 않으면 새로 생성하고, 존재하면 전달된 정보로 업데이트합니다.
        /// </remarks>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <param name="memberId">프로필을 생성/업데이트할 멤버의 ID (ConnectedId) 입니다.</param>
        /// <param name="request">업데이트할 프로필 정보를 포함하는 요청 본문입니다.</param>
        /// <returns>생성되거나 업데이트된 프로필 정보를 반환합니다.</returns>
        [HttpPut("{memberId:guid}")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationMemberProfileDto>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        public async Task<IActionResult> UpsertProfile([FromRoute] Guid organizationId, [FromRoute] Guid memberId, [FromBody] UpdateOrganizationProfileRequest request)
        {
            var result = await _profileService.UpsertProfileAsync(organizationId, memberId, request, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 특정 멤버의 관리자(직속 상사)를 변경합니다.
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <param name="memberId">관리자를 변경할 멤버의 ID (ConnectedId) 입니다.</param>
        /// <param name="request">새로운 관리자의 ID를 포함하는 요청 본문입니다.</param>
        /// <returns>성공 여부를 반환합니다.</returns>
        [HttpPut("{memberId:guid}/manager")]
        [ProducesResponseType(typeof(ServiceResult<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> ChangeManager([FromRoute] Guid organizationId, [FromRoute] Guid memberId, [FromBody] ChangeManagerRequest request)
        {
            var result = await _profileService.ChangeManagerAsync(organizationId, memberId, request.NewManagerId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion

        #region 계층 및 통계

        /// <summary>
        /// 조직의 멤버 보고 체계(관리자 계층)를 조회합니다.
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <returns>계층적으로 구성된 멤버 프로필 목록을 반환합니다.</returns>
        [HttpGet("hierarchy")]
        [ProducesResponseType(typeof(ServiceResult<IEnumerable<OrganizationMemberProfileDto>>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        public async Task<IActionResult> GetHierarchy([FromRoute] Guid organizationId)
        {
            var result = await _profileService.GetOrganizationHierarchyAsync(organizationId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 조직 멤버 프로필에 대한 통계(부서별, 직책별 인원 등)를 조회합니다.
        /// </summary>
        /// <param name="organizationId">통계를 조회할 조직의 ID입니다.</param>
        /// <returns>프로필 통계 정보를 반환합니다.</returns>
        [HttpGet("statistics")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationProfileStatisticsDto>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        public async Task<IActionResult> GetStatistics([FromRoute] Guid organizationId)
        {
            var result = await _profileService.GetProfileStatisticsAsync(organizationId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion
        
        #region Private Helper Methods

        /// <summary>
        /// 서비스의 결과(ServiceResult)를 분석하여 표준화된 HTTP 응답(IActionResult)으로 변환하는 헬퍼 메서드입니다.
        /// </summary>
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

    /// <summary>
    /// 관리자 변경 API의 요청 본문을 위한 DTO입니다.
    /// </summary>
    public class ChangeManagerRequest
    {
        /// <summary>
        /// 새로 지정할 관리자의 ID (ConnectedId) 입니다.
        /// 관리자를 제거하려면 null로 설정합니다.
        /// </summary>
        public Guid? NewManagerId { get; set; }
    }

    #endregion
}

