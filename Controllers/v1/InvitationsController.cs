using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Invitation.Requests;
using AuthHive.Core.Models.Auth.Invitation.Responses;
using AuthHive.Core.Models.Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 및 애플리케이션 초대 관련 API 엔드포인트를 관리합니다.
    /// </summary>
    [ApiController]
    [Route("api/v1/invitations")] // API 버전 관리를 위해 경로에 v1 추가
    [Authorize] // 모든 액션은 기본적으로 인증된 사용자만 접근 가능
    public class InvitationsController : BaseApiController
    {
        private readonly IInvitationService _invitationService;

        public InvitationsController(IInvitationService invitationService)
        {
            _invitationService = invitationService ?? throw new ArgumentNullException(nameof(invitationService));
        }

        /// <summary>
        /// 조직에 새로운 멤버를 초대합니다.
        /// </summary>
        /// <param name="request">초대에 필요한 정보를 담은 DTO입니다.</param>
        /// <returns>생성된 초대의 상세 정보를 반환합니다.</returns>
        /// <response code="201">초대가 성공적으로 생성되었습니다.</response>
        /// <response code="400">요청이 잘못되었거나 비즈니스 규칙을 위반했습니다 (예: 이미 멤버, 요금제 한도 초과).</response>
        /// <response code="401">인증되지 않은 사용자의 요청입니다.</response>
        /// <response code="403">초대를 생성할 권한이 없습니다.</response>
        [HttpPost("organization")]
        [ProducesResponseType(typeof(ServiceResult<InvitationResponse>), 201)]
        [ProducesResponseType(typeof(ServiceResult<InvitationResponse>), 400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> InviteToOrganization([FromBody] InviteToOrganizationRequest request)
        {
            // 인증된 사용자의 토큰에서 ConnectedId를 가져옵니다.
            // 이 코드는 토큰에 'cid' (ConnectedId) 클레임이 반드시 포함되어야 함을 전제합니다.
            var connectedIdClaim = User.FindFirstValue("cid");
            if (!Guid.TryParse(connectedIdClaim, out var invitedByConnectedId))
            {
                // 토큰에 cid 클레임이 없거나 유효하지 않은 GUID인 경우,
                // 이는 인증 시스템의 문제이므로 401 Unauthorized를 반환하는 것이 적절합니다.
                return Unauthorized(new { Message = "ConnectedId could not be determined from the token." });
            }

            // 서비스 레이어에 작업 위임
            var result = await _invitationService.InviteToOrganizationAsync(request, invitedByConnectedId, HttpContext.RequestAborted);

            // 서비스 결과에 따라 적절한 HTTP 응답 반환
            if (result.IsSuccess)
            {
                // 성공 시 201 Created 응답을 반환하고, 생성된 리소스의 위치(Location 헤더)를 알려주는 것이 RESTful 원칙에 맞습니다.
                // return CreatedAtAction(nameof(GetInvitationById), new { invitationId = result.Data.InvitationId }, result);
                // 지금은 GetInvitationById가 없으므로 간단히 200 OK로 처리합니다.
                return Ok(result);
            }

            // 서비스 레이어에서 정의한 오류 코드에 따라 적절한 HTTP 상태 코드 매핑
            return result.ErrorCode switch
            {
                "FORBIDDEN" => StatusCode(403, result),
                "NOT_FOUND" => NotFound(result),
                "ALREADY_MEMBER" or "DUPLICATE_INVITATION" or "PLAN_LIMIT_REACHED" => BadRequest(result),
                _ => BadRequest(result) // 그 외 모든 실패는 400 Bad Request로 처리
            };
        }

        // TODO: 나중에 구현할 기능들
        // [HttpGet("{invitationId}")]
        // public async Task<IActionResult> GetInvitationById(Guid invitationId) { ... }
        //
        // [HttpPost("{invitationCode}/accept")]
        // [AllowAnonymous] // 초대 수락은 로그아웃 상태에서도 가능해야 함
        // public async Task<IActionResult> AcceptInvitation(string invitationCode) { ... }
        //
        // [HttpPost("{invitationId}/cancel")]
        // public async Task<IActionResult> CancelInvitation(Guid invitationId) { ... }
    }
}
