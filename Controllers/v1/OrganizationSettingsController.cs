// --- 1. 필요한 네임스페이스 선언 ---
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AuthHive.Core.Interfaces.Organization.Repository.Settings; // IOrganizationSettingsQuery/CommandRepository
using AuthHive.Core.Interfaces.Base;                             // IPrincipalAccessor, IUnitOfWork
using AuthHive.Core.Models.Common;                                // ServiceResult
using AuthHive.Core.Entities.Organization;                      // OrganizationSettings
using AuthHive.Auth.Controllers.Base;                            // BaseApiController
using AuthHive.Core.Interfaces.Auth.Service;                     // IAuthorizationService
using System.Collections.Generic;
using IAuthorizationService = AuthHive.Core.Interfaces.Auth.Service.IAuthorizationService;                                 // IEnumerable

namespace AuthHive.Auth.Controllers.v1
{
    /// <summary>
    /// 조직 설정(Settings)에 대한 CRUD API 엔드포인트를 관리합니다.
    /// </summary>
    [ApiController]                                     // 이 클래스가 API 컨트롤러임을 나타냅니다.                               // API 버전을 "1.0"으로 명시합니다.
    [Route("api/v{version:apiVersion}/organizations/{organizationId:guid}/settings")] // API 경로를 정의합니다. (예: /api/v1/organizations/ORG_ID/settings)
    [Authorize]                                         // 이 컨트롤러의 모든 액션은 기본적으로 인증된 사용자만 접근할 수 있습니다.
    public class OrganizationSettingsController : BaseApiController
    {
        // --- 2. 의존성 필드 선언 ---
        private readonly IOrganizationSettingsQueryRepository _queryRepository;   // 설정 '조회' 작업을 위한 리포지토리
        private readonly IOrganizationSettingsCommandRepository _commandRepository; // 설정 '생성/수정/삭제' 작업을 위한 리포지토리
        private readonly IAuthorizationService _authorizationService;             // 현재 사용자의 작업 수행 권한을 검증하는 서비스
        private readonly IPrincipalAccessor _principalAccessor;                    // 현재 요청을 보낸 사용자의 정보(ID)에 접근하기 위한 객체
        private readonly IUnitOfWork _unitOfWork;                                 // 모든 데이터베이스 변경사항을 하나의 트랜잭션으로 묶어 최종 저장하는 역할

        /// <summary>
        /// 3. 생성자: 의존성 주입(DI)을 통해 필요한 서비스들을 주입받습니다.
        /// </summary>
        public OrganizationSettingsController(
            IOrganizationSettingsQueryRepository queryRepository,
            IOrganizationSettingsCommandRepository commandRepository,
            IAuthorizationService authorizationService,
            IPrincipalAccessor principalAccessor,
            IUnitOfWork unitOfWork)
        {
            _queryRepository = queryRepository;
            _commandRepository = commandRepository;
            _authorizationService = authorizationService;
            _principalAccessor = principalAccessor;
            _unitOfWork = unitOfWork;
        }

        #region 조회 (Read) API

        /// <summary>
        /// 특정 조직의 모든 설정을 조회합니다.
        /// </summary>
        /// <param name="organizationId">설정을 조회할 조직의 ID입니다.</param>
        /// <returns>조직 설정의 전체 목록을 반환합니다.</returns>
        [HttpGet]
        [ProducesResponseType(typeof(ServiceResult<IEnumerable<OrganizationSettings>>), 200)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> GetAllSettings([FromRoute] Guid organizationId)
        {
            // 1. 권한 검증: 현재 사용자가 이 조직의 설정을 읽을 권한('settings:read')이 있는지 확인합니다.
            if (!await _authorizationService.CanAccessOrganizationAsync(organizationId, "settings:read", HttpContext.RequestAborted))
            {
                return Forbid(); // 권한이 없으면 403 Forbidden 응답을 반환합니다.
            }
            
            // 2. 데이터 조회: 리포지토리를 통해 데이터를 조회합니다.
            var settings = await _queryRepository.GetAllSettingsAsync(organizationId, true, true, HttpContext.RequestAborted);
            
            // 3. 성공 응답: 조회된 데이터를 ServiceResult로 감싸 200 OK 응답을 반환합니다.
            return Ok(ServiceResult<IEnumerable<OrganizationSettings>>.Success(settings));
        }

        /// <summary>
        /// 특정 카테고리와 키에 해당하는 단일 설정을 조회합니다.
        /// </summary>
        /// <param name="organizationId">조직의 ID입니다.</param>
        /// <param name="category">설정의 분류입니다. (예: 'Security', 'Billing')</param>
        /// <param name="settingKey">설정의 고유 키입니다. (예: 'EnableMFA')</param>
        /// <returns>설정의 상세 정보를 반환합니다.</returns>
        [HttpGet("{category}/{settingKey}")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationSettings>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> GetSetting([FromRoute] Guid organizationId, [FromRoute] string category, [FromRoute] string settingKey)
        {
            // 권한 검증
            if (!await _authorizationService.CanAccessOrganizationAsync(organizationId, "settings:read", HttpContext.RequestAborted))
            {
                return Forbid();
            }

            // 데이터 조회
            var setting = await _queryRepository.GetSettingAsync(organizationId, category, settingKey, true, HttpContext.RequestAborted);

            // 조회 결과가 없으면 404 Not Found 응답을 반환합니다.
            if (setting == null)
            {
                return NotFound(ServiceResult.NotFound("Setting not found."));
            }

            // 성공 응답
            return Ok(ServiceResult<OrganizationSettings>.Success(setting));
        }

        #endregion

        #region 수정 (Write) API

        /// <summary>
        /// 특정 설정을 생성하거나 업데이트합니다 (Upsert).
        /// </summary>
        /// <param name="request">업데이트할 설정 값을 담은 요청 본문입니다.</param>
        [HttpPut("{category}/{settingKey}")]
        [ProducesResponseType(typeof(ServiceResult<OrganizationSettings>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 400)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> UpsertSetting(
            [FromRoute] Guid organizationId,
            [FromRoute] string category,
            [FromRoute] string settingKey,
            [FromBody] UpdateSettingRequest request)
        {
            // 1. 권한 검증: 'settings:update' 권한이 있는지 확인합니다.
            if (!await _authorizationService.CanAccessOrganizationAsync(organizationId, "settings:update", HttpContext.RequestAborted))
            {
                return Forbid();
            }
            
            // 2. 행위자 식별: IPrincipalAccessor를 통해 현재 요청을 보낸 사용자의 ID를 가져옵니다.
            var modifiedByConnectedId = _principalAccessor.ConnectedId;

            // TODO: 아래 로직은 Service Layer로 이동하는 것이 이상적입니다.
            // 컨트롤러는 DTO를 엔티티로 변환하는 책임을 지지 않는 것이 좋습니다.
            // 여기서는 아키텍처 시연을 위해 컨트롤러에 로직을 작성합니다.
            var settingToUpsert = new OrganizationSettings
            {
                OrganizationId = organizationId,
                Category = category,
                SettingKey = settingKey,
                SettingValue = request.Value,
                IsActive = request.IsActive
            };
            
            // 3. 데이터 변경: 리포지토리를 통해 데이터를 Upsert하고 결과를 받습니다.
            var upsertedSetting = await _commandRepository.UpsertSettingAsync(settingToUpsert, modifiedByConnectedId, HttpContext.RequestAborted);

            // 4. 최종 저장: UnitOfWork를 통해 모든 변경사항을 DB에 최종 반영(Commit)합니다.
            await _unitOfWork.SaveChangesAsync(HttpContext.RequestAborted);

            // 5. 성공 응답
            return Ok(ServiceResult<OrganizationSettings>.Success(upsertedSetting));
        }

        /// <summary>
        /// 특정 설정을 삭제합니다.
        /// </summary>
        [HttpDelete("{category}/{settingKey}")]
        [ProducesResponseType(typeof(ServiceResult<bool>), 200)]
        [ProducesResponseType(typeof(ServiceResult), 403)]
        [ProducesResponseType(typeof(ServiceResult), 404)]
        public async Task<IActionResult> DeleteSetting(
            [FromRoute] Guid organizationId,
            [FromRoute] string category,
            [FromRoute] string settingKey)
        {
            // 권한 검증
            if (!await _authorizationService.CanAccessOrganizationAsync(organizationId, "settings:delete", HttpContext.RequestAborted))
            {
                return Forbid();
            }
            
            // 행위자 식별
            var deletedByConnectedId = _principalAccessor.ConnectedId;

            // 데이터 삭제 (Soft Delete)
            var success = await _commandRepository.DeleteSettingAsync(organizationId, category, settingKey, deletedByConnectedId, HttpContext.RequestAborted);
            
            // 삭제할 데이터가 없었던 경우 404 Not Found를 반환합니다.
            if (!success)
            {
                return NotFound(ServiceResult.NotFound("Setting to delete was not found."));
            }
            
            // 최종 저장
            await _unitOfWork.SaveChangesAsync(HttpContext.RequestAborted);

            // 성공 응답
            return Ok(ServiceResult<bool>.Success(true));
        }

        #endregion
    }
    
    /// <summary>
    /// 설정 업데이트 API의 요청 본문(Body)을 위한 DTO(Data Transfer Object)입니다.
    /// </summary>
    public class UpdateSettingRequest
    {
        /// <summary>
        /// 설정 값입니다.
        /// </summary>
        public string? Value { get; set; }

        /// <summary>
        /// 설정의 활성화 여부입니다.
        /// </summary>
        public bool IsActive { get; set; } = true;
    }
}