using System;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Common;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Services
{
    /// <summary>
    /// ConnectedId의 멤버십 타입 변경 및 조직 소유권 이전 로직을 구현합니다.
    /// </summary>
    public class MembershipService : IMembershipService
    {
        private readonly IConnectedIdRepository _repository;
        private readonly AuthDbContext _context; // 트랜잭션 관리를 위해 DbContext를 직접 사용
        private readonly ILogger<MembershipService> _logger;

        public MembershipService(
            IConnectedIdRepository repository,
            AuthDbContext context,
            ILogger<MembershipService> logger)
        {
            _repository = repository;
            _context = context;
            _logger = logger;
        }

        #region IService Implementation
        public Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            // Repository와 DbContext가 정상적인지 확인
            var isHealthy = _repository != null && _context.Database.CanConnect();
            return Task.FromResult(isHealthy);
        }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("MembershipService initialized.");
            return Task.CompletedTask;
        }
        #endregion

        #region Membership Management

        public async Task<ServiceResult> ChangeMembershipTypeAsync(Guid id, MembershipType newType)
        {
            try
            {
                var connectedId = await _repository.GetByIdAsync(id);
                if (connectedId == null)
                {
                    return ServiceResult.Failure("ConnectedId not found.");
                }

                if (newType == MembershipType.Owner)
                {
                    return ServiceResult.Failure("Ownership can only be changed via the TransferOwnership method.");
                }

                var oldType = connectedId.MembershipType;
                connectedId.MembershipType = newType;

                await _repository.UpdateAsync(connectedId);
                _logger.LogInformation("MembershipType of ConnectedId {Id} changed from {OldType} to {NewType}", id, oldType, newType);

                // TODO: 캐시 무효화 로직 호출
                return ServiceResult.Success("Membership type changed successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change membership type for ConnectedId {Id}", id);
                return ServiceResult.Failure("An error occurred while changing membership type.");
            }
        }

        public async Task<ServiceResult> TransferOwnershipAsync(Guid organizationId, Guid fromConnectedId, Guid toConnectedId)
        {
            // 데이터 정합성을 위해 트랜잭션 사용
            await using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                var currentOwner = await _repository.GetByIdAsync(fromConnectedId);
                if (currentOwner == null || currentOwner.OrganizationId != organizationId || currentOwner.MembershipType != MembershipType.Owner)
                {
                    await transaction.RollbackAsync();
                    return ServiceResult.Failure("Current owner is not valid.");
                }

                var newOwner = await _repository.GetByIdAsync(toConnectedId);
                if (newOwner == null || newOwner.OrganizationId != organizationId)
                {
                    await transaction.RollbackAsync();
                    return ServiceResult.Failure("New owner not found in the organization.");
                }

                // 소유권 이전
                currentOwner.MembershipType = MembershipType.Admin; // 기존 소유자는 관리자로 강등
                newOwner.MembershipType = MembershipType.Owner;

                await _repository.UpdateAsync(currentOwner);
                await _repository.UpdateAsync(newOwner);

                // 모든 변경사항을 DB에 커밋
                await transaction.CommitAsync();

                _logger.LogInformation("Ownership of organization {OrgId} transferred from {FromId} to {ToId}",
                    organizationId, fromConnectedId, toConnectedId);

                // TODO: 캐시 무효화 로직 호출
                return ServiceResult.Success("Ownership transferred successfully.");
            }
            catch (Exception ex)
            {
                // 오류 발생 시 모든 변경사항을 롤백
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Failed to transfer ownership for organization {OrgId}", organizationId);
                return ServiceResult.Failure("An error occurred during ownership transfer.");
            }
        }
        #endregion
    }
}