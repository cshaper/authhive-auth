// Path: AuthHive.Auth/Services/ConnectedId/ConnectedIdService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Auth.ConnectedId;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using AuthHive.Core.Models.Auth.ConnectedId.Cache;
using AuthHive.Core.Entities.Auth;
using AuthHive.Auth.Data.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;
using AuthHive.Core.Models.Base.Summaries;

namespace AuthHive.Auth.Services.ConnectedId
{
    /// <summary>
    /// ConnectedId 서비스 구현 - AuthHive v15
    /// 조직 멤버십과 소셜 로그인을 통합 관리
    /// </summary>
    public class ConnectedIdService : IConnectedIdService
    {
        private readonly AuthDbContext _context;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IMemoryCache _cache;
        private readonly ILogger<ConnectedIdService> _logger;

        // 캐시 키 상수
        private const string CACHE_PREFIX = "connected_id:";
        private const string USER_CACHE_PREFIX = "user_connected_ids:";
        private const string ORG_CACHE_PREFIX = "org_connected_ids:";

        public ConnectedIdService(
            AuthDbContext context,
            IConnectedIdRepository connectedIdRepository,
            IMemoryCache cache,
            ILogger<ConnectedIdService> logger)
        {
            _context = context;
            _connectedIdRepository = connectedIdRepository;
            _cache = cache;
            _logger = logger;
        }

        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                return await _context.Database.CanConnectAsync() &&
                       await _connectedIdRepository.CountAsync() >= 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConnectedIdService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdService initialized");
            return Task.CompletedTask;
        }

        #endregion

        #region CRUD 작업
        public async Task<ServiceResult<ConnectedIdResponse>> CreateAsync(CreateConnectedIdRequest request)
        {
            try
            {
                _logger.LogInformation("Creating ConnectedId for User {UserId} in Organization {OrganizationId}",
                    request.UserId, request.OrganizationId);

                // 1. 기본 검증
                var validationResult = await ValidateCreateRequestAsync(request);
                if (!validationResult.IsSuccess)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure(validationResult.ErrorMessage ?? "Validation failed");
                }

                // 2. 중복 확인
                var existingConnectedId = await _context.ConnectedIds
                    .FirstOrDefaultAsync(c =>
                        c.UserId == request.UserId &&
                        c.OrganizationId == request.OrganizationId &&
                        !c.IsDeleted);

                if (existingConnectedId != null)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure(
                        "User is already a member of this organization");
                }

                // 3. ConnectedId 엔티티 생성 (토큰 필드 제거)
                var connectedIdEntity = new AuthHive.Core.Entities.Auth.ConnectedId
                {
                    UserId = request.UserId,
                    OrganizationId = request.OrganizationId,
                    Provider = request.Provider,
                    ProviderUserId = request.ProviderUserId,
                    MembershipType = request.MembershipType,
                    DisplayName = request.DisplayName,
                    Status = request.InitialStatus,
                    JoinedAt = DateTime.UtcNow,
                    InvitedByConnectedId = request.InvitedByConnectedId,
                    InvitedAt = request.InvitedByConnectedId.HasValue ? DateTime.UtcNow : null,
                    IsDeleted = false
                };

                // 4. 활성화 처리
                if (request.ActivateImmediately && connectedIdEntity.Status == ConnectedIdStatus.Pending)
                {
                    connectedIdEntity.Status = ConnectedIdStatus.Active;
                }

                // 5. 데이터베이스 저장
                await _connectedIdRepository.AddAsync(connectedIdEntity);

                // 6. OAuth 토큰이 있는 경우 별도 처리 (옵션)
                // if (!string.IsNullOrEmpty(request.Provider))
                // {
                //     await _oAuthTokenService.StoreTokenAsync(connectedIdEntity.Id, oauthToken);
                // }

                // 7. 캐시 무효화
                InvalidateUserCache(request.UserId);
                InvalidateOrganizationCache(request.OrganizationId);

                // 8. 응답 생성
                var response = MapToConnectedIdResponse(connectedIdEntity);

                _logger.LogInformation("ConnectedId {ConnectedId} created successfully", connectedIdEntity.Id);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create ConnectedId for User {UserId}", request.UserId);
                return ServiceResult<ConnectedIdResponse>.Failure("Failed to create ConnectedId");
            }
        }

        public async Task<ServiceResult<ConnectedIdDetailResponse>> GetByIdAsync(Guid id)
        {
            try
            {
                _logger.LogDebug("Getting ConnectedId {ConnectedId}", id);

                // 1. 캐시 확인
                var cacheKey = $"{CACHE_PREFIX}{id}";
                if (_cache.TryGetValue<ConnectedIdDetailResponse>(cacheKey, out var cachedResponse) && cachedResponse != null)
                {
                    return ServiceResult<ConnectedIdDetailResponse>.Success(cachedResponse);
                }

                // 2. 데이터베이스에서 조회 (관련 데이터 포함)
                var connectedId = await _context.ConnectedIds
                    .Include(c => c.User)
                    .Include(c => c.Organization)
                    .FirstOrDefaultAsync(c => c.Id == id && !c.IsDeleted);

                if (connectedId == null)
                {
                    return ServiceResult<ConnectedIdDetailResponse>.Failure("ConnectedId not found");
                }

                // 3. DetailResponse 매핑
                var response = MapToConnectedIdDetailResponse(connectedId);

                // 4. 캐시에 저장 (10분)
                _cache.Set(cacheKey, response, TimeSpan.FromMinutes(10));

                return ServiceResult<ConnectedIdDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get ConnectedId {ConnectedId}", id);
                return ServiceResult<ConnectedIdDetailResponse>.Failure("Failed to get ConnectedId");
            }
        }
        public async Task<ServiceResult<ConnectedIdResponse>> UpdateAsync(Guid id, UpdateConnectedIdRequest request)
        {
            try
            {
                _logger.LogInformation("Updating ConnectedId {ConnectedId}", id);

                var connectedId = await _connectedIdRepository.GetByIdAsync(id);
                if (connectedId == null)
                {
                    return ServiceResult<ConnectedIdResponse>.Failure("ConnectedId not found");
                }

                // 업데이트 가능한 필드들 수정 (토큰 관련 필드 제거)
                if (!string.IsNullOrWhiteSpace(request.DisplayName))
                {
                    connectedId.DisplayName = request.DisplayName;
                }

                connectedId.LastActiveAt = DateTime.UtcNow;
                connectedId.UpdatedAt = DateTime.UtcNow;

                await _connectedIdRepository.UpdateAsync(connectedId);

                // 캐시 무효화
                InvalidateConnectedIdCache(id);
                InvalidateUserCache(connectedId.UserId);

                var response = MapToConnectedIdResponse(connectedId);
                return ServiceResult<ConnectedIdResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update ConnectedId {ConnectedId}", id);
                return ServiceResult<ConnectedIdResponse>.Failure("Failed to update ConnectedId");
            }
        }
        public async Task<ServiceResult> DeleteAsync(Guid id)
        {
            try
            {
                _logger.LogInformation("Deleting ConnectedId {ConnectedId}", id);

                var connectedId = await _connectedIdRepository.GetByIdAsync(id);
                if (connectedId == null)
                {
                    return ServiceResult.Failure("ConnectedId not found");
                }

                // 소프트 삭제
                connectedId.IsDeleted = true;
                connectedId.Status = ConnectedIdStatus.Inactive;
                connectedId.UpdatedAt = DateTime.UtcNow;

                await _connectedIdRepository.UpdateAsync(connectedId);

                // 캐시 무효화
                InvalidateConnectedIdCache(id);
                InvalidateUserCache(connectedId.UserId);
                InvalidateOrganizationCache(connectedId.OrganizationId);

                return ServiceResult.Success("ConnectedId deleted successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete ConnectedId {ConnectedId}", id);
                return ServiceResult.Failure("Failed to delete ConnectedId");
            }
        }

        #endregion

        #region 조회 작업

        public async Task<ServiceResult<ConnectedIdListResponse>> GetByOrganizationAsync(
            Guid organizationId, SearchConnectedIdsRequest request)
        {
            try
            {
                _logger.LogDebug("Getting ConnectedIds for Organization {OrganizationId}", organizationId);

                var query = _context.ConnectedIds
                    .Include(c => c.User)
                    .Include(c => c.Organization) // Organization 정보도 포함
                    .Where(c => c.OrganizationId == organizationId && !c.IsDeleted);

                // 상태 필터
                if (request.Statuses != null && request.Statuses.Any())
                {
                    query = query.Where(c => request.Statuses.Contains(c.Status));
                }

                // 멤버십 타입 필터
                if (request.MembershipTypes != null && request.MembershipTypes.Any())
                {
                    query = query.Where(c => request.MembershipTypes.Contains(c.MembershipType));
                }

                // 전체 개수
                var totalCount = await query.CountAsync();

                // 페이징 및 정렬
                var pagedQuery = query
                    .OrderByDescending(c => c.CreatedAt)
                    .Skip((request.PageNumber - 1) * request.PageSize)
                    .Take(request.PageSize);

                // connectedIds 변수 정의
                var connectedIds = await pagedQuery.ToListAsync();

                // ConnectedIdResponse 사용 (ConnectedIdListItem 대신)
                var items = connectedIds.Select(MapToConnectedIdResponse).ToList();

                var response = new ConnectedIdListResponse
                {
                    Items = items,
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize,

                    // 추가 메타데이터
                    SearchSummary = new SearchSummary
                    {
                        MembershipTypes = request.MembershipTypes,
                        Statuses = request.Statuses,
                        AppliedFiltersCount = (request.MembershipTypes?.Count ?? 0) + (request.Statuses?.Count ?? 0)
                    },
                    ResponseTime = DateTime.UtcNow
                };

                return ServiceResult<ConnectedIdListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get ConnectedIds for organization {OrganizationId}", organizationId);
                return ServiceResult<ConnectedIdListResponse>.Failure("Failed to get organization members");
            }
        }
        public async Task<ServiceResult<IEnumerable<ConnectedIdResponse>>> GetByUserAsync(Guid userId)
        {
            try
            {
                _logger.LogDebug("Getting ConnectedIds for User {UserId}", userId);

                // 캐시 확인
                var cacheKey = $"{USER_CACHE_PREFIX}{userId}";
                if (_cache.TryGetValue<List<ConnectedIdResponse>>(cacheKey, out var cachedResponses) && cachedResponses != null)
                {
                    return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(cachedResponses);
                }

                var connectedIds = await _context.ConnectedIds
                    .Include(c => c.Organization)
                    .Where(c => c.UserId == userId && !c.IsDeleted)
                    .OrderByDescending(c => c.LastActiveAt)
                    .ToListAsync();

                var responses = connectedIds.Select(MapToConnectedIdResponse).ToList();

                // 캐시 저장 (5분)
                _cache.Set(cacheKey, responses, TimeSpan.FromMinutes(5));

                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(responses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get ConnectedIds for user {UserId}", userId);
                return ServiceResult<IEnumerable<ConnectedIdResponse>>.Failure("Failed to get user memberships");
            }
        }

        #endregion

        #region 상태 관리

        public async Task<ServiceResult<StatusChangeResponse>> ChangeStatusAsync(
            Guid id, ChangeConnectedIdStatusRequest request)
        {
            try
            {
                _logger.LogInformation("Changing status of ConnectedId {ConnectedId} to {Status}",
                    id, request.NewStatus);

                var connectedId = await _connectedIdRepository.GetByIdAsync(id);
                if (connectedId == null)
                {
                    return ServiceResult<StatusChangeResponse>.Failure("ConnectedId not found");
                }

                var oldStatus = connectedId.Status;
                connectedId.Status = request.NewStatus;
                connectedId.UpdatedAt = DateTime.UtcNow;

                if (request.NewStatus == ConnectedIdStatus.Active)
                {
                    connectedId.LastActiveAt = DateTime.UtcNow;
                }

                await _connectedIdRepository.UpdateAsync(connectedId);

                // 캐시 무효화
                InvalidateConnectedIdCache(id);

                var response = new StatusChangeResponse
                {
                    ConnectedId = id,
                    PreviousStatus = oldStatus,
                    CurrentStatus = request.NewStatus,
                    ChangedAt = DateTime.UtcNow,
                    Reason = request.Reason
                };

                return ServiceResult<StatusChangeResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change status of ConnectedId {ConnectedId}", id);
                return ServiceResult<StatusChangeResponse>.Failure("Failed to change status");
            }
        }

        public async Task<ServiceResult> ActivateAsync(Guid id)
        {
            var request = new ChangeConnectedIdStatusRequest
            {
                NewStatus = ConnectedIdStatus.Active,
                Reason = "Activated by system"
            };

            var result = await ChangeStatusAsync(id, request);
            return result.IsSuccess
                ? ServiceResult.Success("ConnectedId activated")
                : ServiceResult.Failure(result.ErrorMessage ?? "Validation failed");
        }

        public async Task<ServiceResult> DeactivateAsync(Guid id)
        {
            var request = new ChangeConnectedIdStatusRequest
            {
                NewStatus = ConnectedIdStatus.Inactive,
                Reason = "Deactivated by system"
            };

            var result = await ChangeStatusAsync(id, request);
            return result.IsSuccess
                ? ServiceResult.Success("ConnectedId deactivated")
                : ServiceResult.Failure(result.ErrorMessage ?? "Validation failed");
        }

        public async Task<ServiceResult> SuspendAsync(Guid id, string reason)
        {
            var request = new ChangeConnectedIdStatusRequest
            {
                NewStatus = ConnectedIdStatus.Suspended,
                Reason = reason
            };

            var result = await ChangeStatusAsync(id, request);
            return result.IsSuccess
                ? ServiceResult.Success("ConnectedId suspended")
                : ServiceResult.Failure(result.ErrorMessage ?? "Validation failed");
        }

        #endregion

        #region 초대 관리 (기본 구현)

        public async Task<ServiceResult<InvitationResponse>> InviteToOrganizationAsync(InviteToOrganizationRequest request)
        {
            // TODO: 초대 로직 구현
            _logger.LogInformation("Invitation to organization requested (not implemented)");
            return await Task.FromResult(ServiceResult<InvitationResponse>.Failure("Invitation feature not implemented"));
        }

        public async Task<ServiceResult<ConnectedIdResponse>> AcceptInvitationAsync(Guid invitationId)
        {
            // TODO: 초대 수락 로직 구현
            return await Task.FromResult(ServiceResult<ConnectedIdResponse>.Failure("Invitation feature not implemented"));
        }

        public async Task<ServiceResult> DeclineInvitationAsync(Guid invitationId)
        {
            // TODO: 초대 거절 로직 구현
            return await Task.FromResult(ServiceResult.Failure("Invitation feature not implemented"));
        }

        public async Task<ServiceResult> CancelInvitationAsync(Guid invitationId)
        {
            // TODO: 초대 취소 로직 구현
            return await Task.FromResult(ServiceResult.Failure("Invitation feature not implemented"));
        }

        #endregion

        #region 멤버십 관리

        public async Task<ServiceResult> ChangeMembershipTypeAsync(Guid id, MembershipType newType)
        {
            try
            {
                _logger.LogInformation("Changing membership type of ConnectedId {ConnectedId} to {MembershipType}",
                    id, newType);

                var connectedId = await _connectedIdRepository.GetByIdAsync(id);
                if (connectedId == null)
                {
                    return ServiceResult.Failure("ConnectedId not found");
                }

                connectedId.MembershipType = newType;
                connectedId.UpdatedAt = DateTime.UtcNow;

                await _connectedIdRepository.UpdateAsync(connectedId);

                // 캐시 무효화
                InvalidateConnectedIdCache(id);
                InvalidateOrganizationCache(connectedId.OrganizationId);

                return ServiceResult.Success("Membership type changed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to change membership type of ConnectedId {ConnectedId}", id);
                return ServiceResult.Failure("Failed to change membership type");
            }
        }

        public async Task<ServiceResult> TransferOwnershipAsync(Guid organizationId, Guid fromConnectedId, Guid toConnectedId)
        {
            try
            {
                _logger.LogInformation("Transferring ownership in organization {OrganizationId} from {FromConnectedId} to {ToConnectedId}",
                    organizationId, fromConnectedId, toConnectedId);

                // 트랜잭션 사용
                using var transaction = await _context.Database.BeginTransactionAsync();

                try
                {
                    // 현재 소유자
                    var currentOwner = await _context.ConnectedIds
                        .FirstOrDefaultAsync(c => c.Id == fromConnectedId && c.OrganizationId == organizationId);

                    if (currentOwner == null || currentOwner.MembershipType != MembershipType.Owner)
                    {
                        return ServiceResult.Failure("Current owner not found");
                    }

                    // 새로운 소유자
                    var newOwner = await _context.ConnectedIds
                        .FirstOrDefaultAsync(c => c.Id == toConnectedId && c.OrganizationId == organizationId);

                    if (newOwner == null)
                    {
                        return ServiceResult.Failure("New owner not found");
                    }

                    // 소유권 이전
                    currentOwner.MembershipType = MembershipType.Admin;
                    newOwner.MembershipType = MembershipType.Owner;

                    var now = DateTime.UtcNow;
                    currentOwner.UpdatedAt = now;
                    newOwner.UpdatedAt = now;

                    await _context.SaveChangesAsync();
                    await transaction.CommitAsync();

                    // 캐시 무효화
                    InvalidateConnectedIdCache(fromConnectedId);
                    InvalidateConnectedIdCache(toConnectedId);
                    InvalidateOrganizationCache(organizationId);

                    return ServiceResult.Success("Ownership transferred successfully");
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to transfer ownership");
                return ServiceResult.Failure("Failed to transfer ownership");
            }
        }

        #endregion

        #region 활동 추적

        public async Task UpdateLastActivityAsync(Guid id)
        {
            try
            {
                var connectedId = await _connectedIdRepository.GetByIdAsync(id);
                if (connectedId != null)
                {
                    connectedId.LastActiveAt = DateTime.UtcNow;
                    await _connectedIdRepository.UpdateAsync(connectedId);

                    // 캐시 무효화
                    InvalidateConnectedIdCache(id);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to update last activity for ConnectedId {ConnectedId}", id);
                // 활동 업데이트 실패는 시스템을 중단시키지 않음
            }
        }

        public async Task<ServiceResult<int>> CleanupInactiveAsync(Guid organizationId, DateTime inactiveSince)
        {
            try
            {
                var inactiveConnectedIds = await _context.ConnectedIds
                    .Where(c =>
                        c.OrganizationId == organizationId &&
                        !c.IsDeleted &&
                        (c.LastActiveAt == null || c.LastActiveAt < inactiveSince))
                    .ToListAsync();

                foreach (var connectedId in inactiveConnectedIds)
                {
                    connectedId.Status = ConnectedIdStatus.Inactive;
                    connectedId.UpdatedAt = DateTime.UtcNow;
                }

                await _context.SaveChangesAsync();

                // 캐시 무효화
                InvalidateOrganizationCache(organizationId);

                _logger.LogInformation("Cleaned up {Count} inactive ConnectedIds", inactiveConnectedIds.Count);
                return ServiceResult<int>.Success(inactiveConnectedIds.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cleanup inactive ConnectedIds");
                return ServiceResult<int>.Failure("Failed to cleanup inactive ConnectedIds");
            }
        }

        #endregion

        #region 검증

        public async Task<ServiceResult<bool>> ValidateAsync(Guid id)
        {
            try
            {
                var connectedId = await _connectedIdRepository.GetByIdAsync(id);
                var isValid = connectedId != null && !connectedId.IsDeleted && connectedId.Status == ConnectedIdStatus.Active;
                return ServiceResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate ConnectedId {ConnectedId}", id);
                return ServiceResult<bool>.Success(false);
            }
        }

        public async Task<ServiceResult<bool>> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId)
        {
            try
            {
                var exists = await _context.ConnectedIds
                    .AnyAsync(c =>
                        c.UserId == userId &&
                        c.OrganizationId == organizationId &&
                        !c.IsDeleted &&
                        c.Status == ConnectedIdStatus.Active);

                return ServiceResult<bool>.Success(exists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check membership");
                return ServiceResult<bool>.Success(false);
            }
        }

        #endregion

        #region 통계

        public async Task<ServiceResult<ConnectedIdStatistics>> GetStatisticsAsync(Guid organizationId)
        {
            try
            {
                var stats = await _context.ConnectedIds
                    .Where(c => c.OrganizationId == organizationId && !c.IsDeleted)
                    .GroupBy(c => 1)
                    .Select(g => new ConnectedIdStatistics
                    {
                        OrganizationId = organizationId,
                        TotalMemberCount = g.Count(),
                        ActiveMemberCount = g.Count(c => c.Status == ConnectedIdStatus.Active),
                        InactiveMemberCount = g.Count(c => c.Status == ConnectedIdStatus.Inactive),
                        PendingCount = g.Count(c => c.Status == ConnectedIdStatus.Pending),
                        SuspendedCount = g.Count(c => c.Status == ConnectedIdStatus.Suspended),

                        // Dictionary 초기화는 LINQ에서 직접 할 수 없으므로 별도 처리
                        LastJoinedAt = g.Max(c => c.JoinedAt),
                        GeneratedAt = DateTime.UtcNow
                    })
                    .FirstOrDefaultAsync();

                if (stats == null)
                {
                    stats = new ConnectedIdStatistics
                    {
                        OrganizationId = organizationId,
                        GeneratedAt = DateTime.UtcNow
                    };
                }
                else
                {
                    // Dictionary 필드들을 별도로 채워줌
                    var connectedIds = await _context.ConnectedIds
                        .Where(c => c.OrganizationId == organizationId && !c.IsDeleted)
                        .ToListAsync();

                    // MembershipType별 카운트
                    stats.CountByMembershipType = connectedIds
                        .GroupBy(c => c.MembershipType)
                        .ToDictionary(g => g.Key, g => g.Count());

                    // Status별 카운트
                    stats.CountByStatus = connectedIds
                        .GroupBy(c => c.Status)
                        .ToDictionary(g => g.Key, g => g.Count());

                    // 30일 내 신규 멤버
                    var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
                    stats.NewMembersLast30Days = connectedIds
                        .Count(c => c.JoinedAt >= thirtyDaysAgo);

                    // 7일 내 활성 사용자
                    var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);
                    stats.ActiveUsersLast7Days = connectedIds
                        .Count(c => c.LastActiveAt >= sevenDaysAgo);

                    // 오늘 활성 사용자
                    var today = DateTime.UtcNow.Date;
                    stats.ActiveUsersToday = connectedIds
                        .Count(c => c.LastActiveAt >= today);

                    // TODO: 2FA 활성화 비율과 평균 세션 수는 별도 테이블 조인 필요
                    stats.TwoFactorEnabledPercentage = 0.0; // 추후 구현
                    stats.AverageSessionsPerUser = 0.0; // 추후 구현
                }

                return ServiceResult<ConnectedIdStatistics>.Success(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get statistics for organization {OrganizationId}", organizationId);
                return ServiceResult<ConnectedIdStatistics>.Failure("Failed to get statistics");
            }
        }

        #endregion

        #region 캐시 관리

        public async Task<ServiceResult> ClearConnectedIdCacheAsync(Guid connectedId)
        {
            try
            {
                InvalidateConnectedIdCache(connectedId);
                return await Task.FromResult(ServiceResult.Success("Cache cleared"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear cache for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult.Failure("Failed to clear cache");
            }
        }

        public async Task<ServiceResult<int>> ClearOrganizationConnectedIdCacheAsync(Guid organizationId)
        {
            try
            {
                InvalidateOrganizationCache(organizationId);
                return await Task.FromResult(ServiceResult<int>.Success(1)); // 캐시 항목 수 반환은 구현 복잡
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear cache for organization {OrganizationId}", organizationId);
                return ServiceResult<int>.Failure("Failed to clear organization cache");
            }
        }

        public async Task<ServiceResult<ConnectedIdCacheStatistics>> GetCacheStatisticsAsync()
        {
            try
            {
                // TODO: 실제 캐시 통계 구현
                var stats = new ConnectedIdCacheStatistics
                {
                    TotalCachedItems = 0,
                    HitRate = 0.0,
                    MissRate = 0.0,
                    GeneratedAt = DateTime.UtcNow
                };

                return await Task.FromResult(ServiceResult<ConnectedIdCacheStatistics>.Success(stats));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get cache statistics");
                return ServiceResult<ConnectedIdCacheStatistics>.Failure("Failed to get cache statistics");
            }
        }

        #endregion

        #region Private Helper Methods

        private async Task<ServiceResult> ValidateCreateRequestAsync(CreateConnectedIdRequest request)
        {
            if (request.UserId == Guid.Empty)
                return ServiceResult.Failure("UserId is required");

            if (request.OrganizationId == Guid.Empty)
                return ServiceResult.Failure("OrganizationId is required");

            if (string.IsNullOrWhiteSpace(request.Provider))
                return ServiceResult.Failure("Provider is required");

            if (string.IsNullOrWhiteSpace(request.ProviderUserId))
                return ServiceResult.Failure("ProviderUserId is required");

            // 사용자 존재 확인
            var userExists = await _context.Users.AnyAsync(u => u.Id == request.UserId);
            if (!userExists)
                return ServiceResult.Failure("User not found");

            // 조직 존재 확인
            var orgExists = await _context.Organizations.AnyAsync(o => o.Id == request.OrganizationId);
            if (!orgExists)
                return ServiceResult.Failure("Organization not found");

            return ServiceResult.Success();
        }
        private ConnectedIdResponse MapToConnectedIdResponse(Core.Entities.Auth.ConnectedId entity)
        {
            return new ConnectedIdResponse
            {
                Id = entity.Id,
                OrganizationId = entity.OrganizationId,
                UserId = entity.UserId,
                Provider = entity.Provider,
                MembershipType = entity.MembershipType,
                Status = entity.Status,
                DisplayName = entity.DisplayName,
                JoinedAt = entity.JoinedAt,
                LastActiveAt = entity.LastActiveAt,
                InvitedByConnectedId = entity.InvitedByConnectedId,
                InvitedAt = entity.InvitedAt,
                CreatedAt = entity.CreatedAt,
                UpdatedAt = entity.UpdatedAt,

                // Navigation Property 정보 (Include된 경우에만)
                UserName = entity.User?.Email ?? entity.User?.DisplayName,
                OrganizationName = entity.Organization?.Name,

                // Count 필드들은 별도 쿼리나 Include로 채워야 함
                RoleAssignmentsCount = 0, // TODO: 실제 카운트 조회
                ActiveSessionsCount = 0,  // TODO: 실제 카운트 조회  
                AccessibleApplicationsCount = 0, // TODO: 실제 카운트 조회
                HasProfile = false // TODO: 실제 프로필 존재 여부 확인
            };
        }

        private ConnectedIdDetailResponse MapToConnectedIdDetailResponse(Core.Entities.Auth.ConnectedId entity)
        {
            var basicResponse = MapToConnectedIdResponse(entity);

            return new ConnectedIdDetailResponse
            {
                // 기본 정보 복사
                Id = basicResponse.Id,
                OrganizationId = basicResponse.OrganizationId,
                UserId = basicResponse.UserId,
                Provider = basicResponse.Provider,
                ProviderUserId = basicResponse.ProviderUserId,
                MembershipType = basicResponse.MembershipType,
                Status = basicResponse.Status,
                DisplayName = basicResponse.DisplayName,
                JoinedAt = basicResponse.JoinedAt,
                LastActiveAt = basicResponse.LastActiveAt,
                InvitedByConnectedId = basicResponse.InvitedByConnectedId,
                InvitedAt = basicResponse.InvitedAt,
                CreatedAt = basicResponse.CreatedAt,
                UpdatedAt = basicResponse.UpdatedAt,
                UserName = basicResponse.UserName,
                OrganizationName = basicResponse.OrganizationName,
                RoleAssignmentsCount = basicResponse.RoleAssignmentsCount,
                ActiveSessionsCount = basicResponse.ActiveSessionsCount,
                AccessibleApplicationsCount = basicResponse.AccessibleApplicationsCount,
                HasProfile = basicResponse.HasProfile,

                // TODO: 실제 관련 데이터들을 별도 쿼리로 조회해서 채워야 함
                User = entity.User != null ? new UserBasicInfo
                {
                    Id = entity.User.Id,
                    Email = entity.User.Email,
                    DisplayName = entity.User.DisplayName
                    // ... 다른 User 필드들
                } : null,

                Organization = entity.Organization != null ? new OrganizationBasicInfo
                {
                    OrganizationId = entity.Organization.Id,
                    Name = entity.Organization.Name

                } : null

                // RoleAssignments, ActiveSessions, ApplicationAccess 등은
                // 별도 Include나 쿼리로 조회해야 함
            };
        }

        private void InvalidateConnectedIdCache(Guid connectedId)
        {
            var cacheKey = $"{CACHE_PREFIX}{connectedId}";
            _cache.Remove(cacheKey);
        }

        private void InvalidateUserCache(Guid userId)
        {
            var cacheKey = $"{USER_CACHE_PREFIX}{userId}";
            _cache.Remove(cacheKey);
        }

        private void InvalidateOrganizationCache(Guid organizationId)
        {
            var cacheKey = $"{ORG_CACHE_PREFIX}{organizationId}";
            _cache.Remove(cacheKey);
        }

        #endregion
    }
}