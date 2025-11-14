// 📍 위치: authhive.auth/Controllers/v1/InvitationsController.cs
// (CS0117 오류 해결 및 v17 "본보기" 패턴 적용)

using MediatR;
using Microsoft.AspNetCore.Mvc;
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Models.Organization.Commands; // v17 Command 및 Payload
using AuthHive.Core.Interfaces.Base; // IPrincipalAccessor
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace AuthHive.Auth.Controllers.v1
{
    public class InvitationsController : BaseApiController
    {
        // [CS0117 해결] BaseApiController가 OrganizationId를 노출하지 않으므로,
        // IPrincipalAccessor를 이 컨트롤러에 직접 주입합니다.
        private readonly IPrincipalAccessor _principalAccessor;
        
        // [수정] v16 IInvitationService 의존성 제거

        public InvitationsController(
            IMediator mediator,
            IPrincipalAccessor principalAccessor, // [CS0117 해결] 직접 주입
            ILogger<InvitationsController> logger) 
            : base(mediator, logger, principalAccessor) // 부모 생성자 호출
        {
            // [CS0117 해결] 주입받은 Accessor를 private 필드에 보관
            _principalAccessor = principalAccessor; 
        }

        /// <summary>
        /// 조직에 새 멤버를 초대합니다 (v17 CQRS 적용)
        /// </summary>
        [HttpPost("organization")]
        [ProducesResponseType(typeof(Guid), 200)]
        public async Task<IActionResult> InviteOrganizationMember(
            // [수정] Command가 아닌 Payload DTO를 [FromBody]로 받음
            [FromBody] InviteOrganizationMemberPayload payload)
        {
            // --- 1. v17 가이드에 따라 Controller가 컨텍스트 수집  ---
            
            // [CS0117 해결] 'base.' 대신 로컬 '_principalAccessor' 필드 사용
            var inviterConnectedId = _principalAccessor.ConnectedId;
            if (inviterConnectedId == null)
            {
                return Unauthorized("User is not authenticated.");
            }

            // [CS0117 해결] 'base.' 대신 로컬 '_principalAccessor' 필드 사용
            var organizationId = _principalAccessor.OrganizationId;
            if (organizationId == null)
            {
                return BadRequest("Organization context could not be determined.");
            }

            // [근거] IPrincipalAccessor에 IpAddress 속성 존재
            var ipAddress = _principalAccessor.IpAddress;

            // --- 2. "본보기" 에 따라 Command DTO를 생성자로 생성 ---
            var command = new InviteOrganizationMemberCommand(
                organizationId: organizationId.Value,
                invitedByConnectedId: inviterConnectedId.Value,
                
                // [근거] [FromBody] payload에서 페이로드(payload)를 가져옴
                inviteeEmail: payload.InviteeEmail, 
                proposedMembershipType: payload.ProposedMembershipType,
                proposedRoleId: payload.ProposedRoleId,
                
                // [근거] Accessor에서 컨텍스트를 가져옴
                createdFromIp: ipAddress,
                customMessage: payload.CustomMessage
            );

            // --- 3. Mediator로 Command 전송 ---
            // [근거] BaseApiController의 'Mediator' 속성 사용
            var result = await base.Mediator.Send(command);

            return HandleResult(result);
        }

        // ... (기타 엔드포인트) ...
    }
}