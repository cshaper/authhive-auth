using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Requests; // 실제 존재하는 DTO를 사용합니다.
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 멤버의 프로필 정보에 대한 API 엔드포인트를 관리합니다. (v16 최종본)
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/members/{memberId:guid}/profile")]
    [Authorize]
    public class OrganizationMemberProfilesController : BaseApiController
    {
        private readonly IOrganizationMemberProfileService _profileService;

        public OrganizationMemberProfilesController(
            IOrganizationMemberProfileService profileService,
            IMediator mediator,
            ILogger<OrganizationMemberProfilesController> logger,
            IPrincipalAccessor principalAccessor)
            : base(mediator, logger, principalAccessor)
        {
            _profileService = profileService;
        }

        /// <summary>
        /// 특정 조직 멤버의 프로필 정보를 조회합니다.
        /// </summary>
        [HttpGet]
        [ProducesResponseType(typeof(OrganizationMemberProfileDto), 200)]
        public async Task<IActionResult> GetMemberProfile([FromRoute] Guid organizationId, [FromRoute] Guid memberId)
        {
            var result = await _profileService.GetProfileAsync(organizationId, memberId, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// 조직 멤버의 프로필 정보를 업데이트합니다.
        /// </summary>
        [HttpPut]
        [ProducesResponseType(typeof(OrganizationMemberProfileDto), 200)]
        public async Task<IActionResult> UpdateMemberProfile(
            [FromRoute] Guid organizationId,
            [FromRoute] Guid memberId,
            [FromBody] UpdateOrganizationMemberProfileRequest request)
        {
            // CORRECTED (CS1061): 'UpdateProfileAsync'를 인터페이스에 정의된 'UpsertProfileAsync'로 변경하고,
            // 모든 필수 파라미터를 올바르게 전달합니다.
            var result = await _profileService.UpsertProfileAsync(
                organizationId: organizationId,
                targetConnectedId: memberId,
                request: request,
                updatedByConnectedId: CurrentConnectedId, // BaseApiController에서 제공하는 속성 사용
                cancellationToken: HttpContext.RequestAborted
            );

            return HandleResult(result);
        }
    }
}

