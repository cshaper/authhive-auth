using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Validator;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.Organization.Commands; // [v17 수정]
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Base;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System;
using System.Net; 
using System.Threading; // [v17] CancellationToken

// (v16 DTO 참조 제거)
// using AuthHive.Core.Models.Organization.Requests; 

using ValidationResult = AuthHive.Core.Models.Common.Validation.ValidationResult;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;

namespace AuthHive.Auth.Validator
{
    /// <summary>
    /// [v17 수정] 조직 검증 구현체 - v17 CQRS
    /// v16 Request DTO를 v17 Command DTO로 대체합니다.
    /// v16 OrganizationService의 유효성 검사 로직을 이관받습니다.
    /// </summary>
    public class OrganizationValidator : IOrganizationValidator
    {
        // [v17 수정] v16 Service 로직 이관을 위해 Repository 주입
        private readonly IOrganizationRepository _repository;
        private readonly ILogger<OrganizationValidator> _logger;

        public OrganizationValidator(
            IOrganizationRepository repository, // [v17 수정]
            ILogger<OrganizationValidator> logger)
        {
            _repository = repository;
            _logger = logger;
        }

        /// <summary>
        /// [v17 수정] 조직 생성 Command 검증
        /// (v16 OrganizationService.ValidateCreateRequestAsync 로직 이관)
        /// </summary>
        public async Task<ValidationResult> ValidateCreateAsync(CreateOrganizationCommand command)
        {
            // 1. 조직 키 중복 확인 (v16 로직 이관)
            if (await _repository.IsOrganizationKeyExistsAsync(command.OrganizationKey, null, CancellationToken.None))
            {
                _logger.LogWarning("Validation failed: Organization key '{Key}' already exists.", command.OrganizationKey);
                // [v17 철학] v16의 AuthHiveException(Conflict) 대신 ValidationResult 반환
                return ValidationResult.Failure(nameof(command.OrganizationKey),
                    $"Organization key '{command.OrganizationKey}' already exists",
                    "CONFLICT");
            }

            // 2. 조직명 중복 확인 (v16 로직 이관)
            if (await _repository.IsNameExistsAsync(command.Name, null, CancellationToken.None))
            {
                _logger.LogWarning("Validation failed: Organization name '{Name}' already exists.", command.Name);
                return ValidationResult.Failure(nameof(command.Name),
                    $"Organization name '{command.Name}' already exists");
            }

            // 3. 부모 조직 확인 (v16 로직 이관)
            if (command.ParentId.HasValue)
            {
                var parent = await _repository.GetByIdAsync(command.ParentId.Value, CancellationToken.None);
                if (parent == null)
                {
                    return ValidationResult.Failure(nameof(command.ParentId),
                        "Parent organization not found",
                        "PARENT_NOT_FOUND");
                }

                if (parent.Status != OrganizationStatus.Active)
                {
                    return ValidationResult.Failure(nameof(command.ParentId),
                        "Parent organization is not active");
                }
                
                // TODO: [v17] ValidateHierarchyDepthAsync 호출 (순환 참조/깊이 검사)
            }
            
            // TODO: [v17] IPlanRestrictionService.ValidateOrganizationLimitAsync(...) 호출
            // (v16 OrganizationService의 플랜 제한 로직 이관)

            return ValidationResult.Success();
        }

        /// <summary>
        /// [v17 수정] 조직 수정 Command 검증
        /// (v16 OrganizationService.UpdateAsync 로직 이관)
        /// (CS1061, CS1503 오류 수정)
        /// </summary>
        public async Task<ValidationResult> ValidateUpdateAsync(UpdateOrganizationCommand command)
        {
            // [v17 수정] CS1503 해결: command.AggregateId (Guid) 사용
            var organizationId = command.AggregateId; 
            
            // 1. 조직 존재 여부 확인
            var existing = await _repository.GetByIdAsync(organizationId, CancellationToken.None);
            if (existing == null)
            {
                return ValidationResult.Failure("Organization", "Organization not found", "NOT_FOUND");
            }
            
            // 2. 이름 중복 검사
            if (command.Name != null && command.Name != existing.Name)
            {
                 if (await _repository.IsNameExistsAsync(command.Name, organizationId, CancellationToken.None))
                 {
                     return ValidationResult.Failure(nameof(command.Name), 
                         $"Organization name '{command.Name}' already exists");
                 }
            }
            
            // 3. [v17 수정] CS1061 해결: command.ParentId 속성이 DTO에 없으므로 관련 로직 "제거"
            /*
            if (command.ParentId.HasValue && command.ParentId != existing.ParentId)
            {
                var hierarchyResult = await ValidateHierarchyAsync(organizationId, command.ParentId);
                if (!hierarchyResult.IsValid) return hierarchyResult;
            }
            */

            return ValidationResult.Success();
        }

        // --- (v16 IOrganizationValidator의 나머지 메서드들 구현) ---
        // (v16 OrganizationService에는 이 로직이 없었으므로,
        //  v17 "본보기"에 따라 우선 기본 구현만 제공합니다.)

        public async Task<ValidationResult> ValidateDeleteAsync(Guid organizationId)
        {
            _logger.LogWarning("ValidateDeleteAsync is not yet fully implemented.");
            // TODO: v16 OrganizationService.DeleteAsync의 하위 조직 검사 로직 이관
            // var childrenCount = await _hierarchyRepository.GetChildrenAsync(organizationId, false);
            // if (childrenCount?.Count() > 0) { ... }
            await Task.CompletedTask;
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateOrganizationKeyAsync(string organizationKey, Guid? excludeOrganizationId = null)
        {
            if (await _repository.IsOrganizationKeyExistsAsync(organizationKey, excludeOrganizationId, CancellationToken.None))
            {
                return ValidationResult.Failure("OrganizationKey", $"Organization key '{organizationKey}' already exists", "CONFLICT");
            }
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateHierarchyAsync(Guid organizationId, Guid? newParentId)
        {
            _logger.LogWarning("ValidateHierarchyAsync is not yet fully implemented.");
            // TODO: v16 OrganizationHierarchyService 로직 이관 (순환 참조 검사)
            await Task.CompletedTask;
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateStatusChangeAsync(Guid organizationId, OrganizationStatus currentStatus, OrganizationStatus newStatus)
        {
            _logger.LogWarning("ValidateStatusChangeAsync is not yet fully implemented.");
            // TODO: v16 OrganizationStatusService 로직 이관
            await Task.CompletedTask;
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateTypeChangeAsync(Guid organizationId, OrganizationType currentType, OrganizationType newType)
        {
             _logger.LogWarning("ValidateTypeChangeAsync is not yet fully implemented.");
            await Task.CompletedTask;
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateChildOrganizationCreationAsync(Guid parentOrganizationId)
        {
             _logger.LogWarning("ValidateChildOrganizationCreationAsync is not yet fully implemented.");
             // TODO: v16 IPlanRestrictionService 플랜별 계층 깊이 제한 로직 이관
            await Task.CompletedTask;
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateHierarchyDepthAsync(Guid organizationId, int maxDepth = 5)
        {
            _logger.LogWarning("ValidateHierarchyDepthAsync is not yet fully implemented.");
            await Task.CompletedTask;
            return ValidationResult.Success();
        }

        public async Task<ValidationResult> ValidateBusinessRulesAsync(OrganizationEntity entity)
        {
             _logger.LogWarning("ValidateBusinessRulesAsync is not yet fully implemented.");
            await Task.CompletedTask;
            return ValidationResult.Success();
        }
    }
}