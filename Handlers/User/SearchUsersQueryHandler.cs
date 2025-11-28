using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.EntityFrameworkCore;

// [Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Cache;

// [Models]
using AuthHive.Core.Models.User.Queries.Profile; // [v18] Namespace 변경 반영
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Responses.Profile; // [v18] UserListResponse 위치

// [Alias]
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Handlers.User;

/// <summary>
/// [v18] 사용자 검색 쿼리 핸들러
/// </summary>
public class SearchUsersQueryHandler : IRequestHandler<SearchUsersQuery, UserListResponse>
{
    private readonly IRepository<UserEntity> _repository;
    private readonly ICacheService _cacheService;

    public SearchUsersQueryHandler(
        IRepository<UserEntity> repository,
        ICacheService cacheService)
    {
        _repository = repository;
        _cacheService = cacheService;
    }

    public async Task<UserListResponse> Handle(SearchUsersQuery request, CancellationToken cancellationToken)
    {
        // 1. [Cache Read] 검색 조건이 없는 '기본 조회'인 경우 캐시 우선 확인
        bool isDefaultQuery = string.IsNullOrEmpty(request.SearchTerm) && request.Status == null;
        string cacheKey = $"SearchUsers:Page{request.PageNumber}:Size{request.PageSize}";

        if (isDefaultQuery)
        {
            // [Fix] 반환 타입을 UserListResponse로 변경
            var cachedResult = await _cacheService.GetAsync<UserListResponse>(cacheKey, cancellationToken);
            if (cachedResult != null) return cachedResult;
        }

        // 2. [Query Init]
        var query = _repository.Query().AsNoTracking();

        // 3. [Filtering]
        if (!string.IsNullOrWhiteSpace(request.SearchTerm))
        {
            var term = request.SearchTerm.ToLower();
            query = query.Where(u =>
                u.Email.ToLower().Contains(term) ||
                (u.Username != null && u.Username.ToLower().Contains(term)) ||
                (u.PhoneNumber != null && u.PhoneNumber.Contains(term)));
        }

        if (request.Status.HasValue)
        {
            query = query.Where(u => u.Status == request.Status.Value);
        }

        // 4. [Count]
        var totalCount = await query.CountAsync(cancellationToken);

        // 5. [Paging & Projection]
        var items = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip((request.PageNumber - 1) * request.PageSize)
            .Take(request.PageSize)
            .Select(u => new UserResponse
            {
                Id = u.Id,
                Email = u.Email,
                Username = u.Username,
                IsEmailVerified = u.IsEmailVerified,
                PhoneNumber = u.PhoneNumber,
                IsTwoFactorEnabled = u.IsTwoFactorEnabled,
                Status = u.Status,
                CreatedAt = u.CreatedAt,
                LastLoginAt = u.LastLoginAt
            })
            .ToListAsync(cancellationToken);

        // 6. [Response] 응답 생성 (Factory Method 사용)
        // [Fix] PaginationResponse -> UserListResponse.Create() 사용
        var response = UserListResponse.Create(items, totalCount, request.PageNumber, request.PageSize);

        // 7. [Cache Write]
        if (isDefaultQuery)
        {
            await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(1), cancellationToken);
        }

        return response;
    }
}