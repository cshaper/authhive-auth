using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthHive.Auth.Controllers.Base;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Organization.Responses;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 설정(Organization Settings) 관리를 위한 API 컨트롤러입니다. (v16 최종본)
    /// 모든 데이터 접근 및 비즈니스 로직은 IOrganizationSettingsService로 위임합니다.
    /// </summary>
    [ApiController]
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/settings")]
    [Authorize]
    public class OrganizationSettingsController : BaseApiController
    {
        // ✅ 컨트롤러는 비즈니스 로직이 구현된 서비스 계층에만 의존합니다.
        private readonly IOrganizationSettingsService _settingsService; 

        /// <summary>
        /// 생성자: 컨트롤러에 특화된 서비스와 BaseApiController의 공통 서비스를 주입받아 전달합니다.
        /// </summary>
        public OrganizationSettingsController(
            IOrganizationSettingsService settingsService,
            IMediator mediator,
            ILogger<OrganizationSettingsController> logger,
            IPrincipalAccessor principalAccessor)
            : base(mediator, logger, principalAccessor) 
        {
            _settingsService = settingsService;
        }

        #region 조회 (Read) API

        /// <summary>
        /// [GET] 특정 조직의 모든 설정 목록을 조회합니다.
        /// </summary>
        [HttpGet]
        [ProducesResponseType(typeof(OrganizationSettingsListResponse), 200)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> GetAllSettings([FromRoute] Guid organizationId, [FromQuery] bool groupByCategory = true)
        {
            // 서비스 호출 시 권한 검증, 캐싱, 데이터 조회 로직이 모두 실행됩니다.
            var result = await _settingsService.GetAllSettingsAsync(organizationId, groupByCategory, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        /// <summary>
        /// [GET] 특정 설정 키의 최종 유효 설정 값을 조회합니다. (상속 규칙 적용된 결과)
        /// </summary>
        [HttpGet("{category}/{settingKey}")]
        [ProducesResponseType(typeof(OrganizationSettingsDto), 200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> GetSetting([FromRoute] Guid organizationId, [FromRoute] OrganizationSettingCategory category, [FromRoute] string settingKey)
        {
            var result = await _settingsService.GetSettingAsync(organizationId, category, settingKey, includeInherited: true, HttpContext.RequestAborted);
            return HandleResult(result);
        }

        #endregion

        #region 수정 (Write) API

        /// <summary>
        /// [PUT] 특정 설정을 생성하거나 업데이트합니다 (Upsert).
        /// </summary>
        [HttpPut]
        [ProducesResponseType(typeof(OrganizationSettingsDto), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> UpsertSetting([FromRoute] Guid organizationId, [FromBody] CreateOrUpdateOrganizationSettingRequest request)
        {
            if (request.OrganizationId != organizationId)
            {
                return BadRequest("Organization ID mismatch between route and body.");
            }

            // 1. 서비스 호출: 권한 검증, 데이터 변환, DB/UOW/Audit 로직은 모두 서비스 계층에서 처리됩니다.
            var result = await _settingsService.UpsertSettingAsync(request, HttpContext.RequestAborted);
            
            // 2. 결과 처리
            return HandleResult(result);
        }

        /// <summary>
        /// [DELETE] 특정 설정을 삭제합니다.
        /// </summary>
        [HttpDelete("{category}/{settingKey}")]
        [ProducesResponseType(204)]
        [ProducesResponseType(403)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteSetting(
            [FromRoute] Guid organizationId,
            [FromRoute] OrganizationSettingCategory category,
            [FromRoute] string settingKey)
        {
            // Service Layer가 삭제, DB/UOW, 캐시 무효화, 감사 로그 로직을 모두 처리합니다.
            var result = await _settingsService.DeleteSettingAsync(organizationId, category, settingKey, HttpContext.RequestAborted);
            
            // Non-Generic ServiceResult를 ServiceResult<bool>로 래핑하여 204 No Content를 유도합니다.
            var genericResult = result.IsSuccess 
                ? ServiceResult<bool>.Success(true) 
                : ServiceResult<bool>.Failure(result.ErrorMessage ?? "Deletion failed.", result.ErrorCode ?? "BAD_REQUEST");

            return HandleResult(genericResult);
        }

        #endregion
    }
}