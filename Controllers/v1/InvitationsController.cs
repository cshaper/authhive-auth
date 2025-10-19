using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Base; // IPrincipalAccessor를 사용하기 위해 추가
using AuthHive.Core.Models.Auth.Invitation.Requests;
using AuthHive.Core.Models.Auth.Invitation.Responses;
using AuthHive.Core.Models.Common;
using MediatR; // BaseApiController에 필요
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging; // BaseApiController에 필요
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 및 애플리케이션 초대 관련 API 엔드포인트를 관리합니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/invitations")] // 경로를 v{version:apiVersion} 형식으로 통일
    [Authorize] // 모든 액션은 기본적으로 인증된 사용자만 접근 가능
    public class InvitationsController : BaseApiController
    {
        private readonly IInvitationService _invitationService;

        /// <summary>
        /// 생성자: IInvitationService 및 BaseApiController의 필수 의존성을 주입받아 초기화합니다.
        /// </summary>
        // ✅ CS7036 오류 해결: BaseApiController가 요구하는 IMediator, ILogger, IPrincipalAccessor를 추가
        public InvitationsController(
            IInvitationService invitationService,
            IMediator mediator,
            ILogger<InvitationsController> logger,
            IPrincipalAccessor principalAccessor)
            : base(mediator, logger, principalAccessor)
        {
            _invitationService = invitationService ?? throw new ArgumentNullException(nameof(invitationService));
            // NOTE: IPrincipalAccessor는 base 클래스에서 이미 설정되었으므로 별도의 필드로 저장할 필요가 없습니다.
        }

        /// <summary>
        /// 조직에 새로운 멤버를 초대합니다.
        /// </summary>
        /// <param name="request">초대에 필요한 정보를 담은 DTO입니다.</param>
        /// <returns>생성된 초대의 상세 정보를 반환합니다.</returns>
        /// <response code="200">초대가 성공적으로 생성되었습니다. (Created 대신 OK 사용)</response>
        /// <response code="400">요청이 잘못되었거나 비즈니스 규칙을 위반했습니다 (예: 이미 멤버, 요금제 한도 초과).</response>
        /// <response code="401">인증되지 않은 사용자의 요청입니다.</response>
        /// <response code="403">초대를 생성할 권한이 없습니다.</response>
        [HttpPost("organization")]
        [ProducesResponseType(typeof(InvitationResponse), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> InviteToOrganization([FromBody] InviteToOrganizationRequest request)
        {
            // IPrincipalAccessor를 통해 현재 로그인한 사용자의 ConnectedId를 안전하게 가져오는 것이 이상적입니다.
            // 여기서는 임시로 기존 로직을 유지하지만, BaseApiController의 IPrincipalAccessor를 사용하는 것이 좋습니다.
            var connectedIdClaim = User.FindFirstValue("cid");
            if (!Guid.TryParse(connectedIdClaim, out var invitedByConnectedId))
            {
                // 토큰에서 ConnectedId를 얻을 수 없으므로, 이는 인증/토큰 시스템 문제입니다.
                return Unauthorized(new { Message = "ConnectedId could not be determined from the token." });
            }

            // 서비스 레이어에 작업 위임
            var result = await _invitationService.InviteToOrganizationAsync(request, invitedByConnectedId, HttpContext.RequestAborted);

            // BaseApiController의 HandleResult를 사용하여 결과를 처리합니다.
            // 이 메서드는 ServiceResult의 IsSuccess와 ErrorCode를 분석하여 적절한 HTTP 응답을 반환합니다.
            return HandleResult(result);

            // NOTE: 이전 코드에서 정의했던 수동 switch-case 기반의 응답 처리 로직은
            // BaseApiController.HandleResult가 처리하므로 삭제됩니다.
            // 따라서 컨트롤러 코드가 훨씬 간결해집니다.
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