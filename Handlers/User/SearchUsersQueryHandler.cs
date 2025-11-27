using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.EntityFrameworkCore;

// [Interfaces]
using AuthHive.Core.Interfaces.Base; // IRepository
using AuthHive.Core.Interfaces.Infra.Cache; // ICacheService

// [Models]
using AuthHive.Core.Models.Base; // PaginationResponse
using AuthHive.Core.Models.User.Queries;
using AuthHive.Core.Models.User.Responses;

// [Alias]
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Handlers.User;

public class SearchUsersQueryHandler : IRequestHandler<SearchUsersQuery, PaginationResponse<UserResponse>>
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

    public async Task<PaginationResponse<UserResponse>> Handle(SearchUsersQuery request, CancellationToken cancellationToken)
    {
        // 1. [Cache Read] 검색 조건이 없는 '기본 조회'인 경우 캐시 우선 확인 (Hot Path)
        // 필터가 있는 경우 캐시 키 조합이 무한대로 늘어나므로, 기본 목록만 캐싱하는 전략
        bool isDefaultQuery = string.IsNullOrEmpty(request.SearchTerm) && request.Status == null;
        string cacheKey = $"SearchUsers:Page{request.PageNumber}:Size{request.PageSize}";

        if (isDefaultQuery)
        {
            var cachedResult = await _cacheService.GetAsync<PaginationResponse<UserResponse>>(cacheKey, cancellationToken);
            if (cachedResult != null) return cachedResult;
        }

        // 2. [Query Init] 쿼리 빌더 시작 (이 부분이 누락되어 수정됨)
        var query = _repository.Query().AsNoTracking();

        // 3. [Filtering] 동적 필터 적용
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

        // 4. [Count] 전체 개수 조회 (페이징 계산용)
        var totalCount = await query.CountAsync(cancellationToken);

        // 5. [Paging & Projection] 페이징 및 DTO 변환
        var items = await query
            .OrderByDescending(u => u.CreatedAt) // 최신순 기본 정렬
            .Skip((request.PageNumber - 1) * request.PageSize)
            .Take(request.PageSize)
            .Select(u => new UserResponse(
                u.Id,
                u.Email,
                u.Username,
                u.IsEmailVerified,
                u.PhoneNumber,
                u.IsTwoFactorEnabled,
                u.Status,
                u.CreatedAt,
                u.LastLoginAt
            ))
            .ToListAsync(cancellationToken);

        // 6. [Response] 결과 생성
        var response = PaginationResponse<UserResponse>.Create(items, totalCount, request.PageNumber, request.PageSize);

        // 7. [Cache Write] 기본 조회인 경우 결과 캐싱 (TTL 1분 - 짧게 유지하여 정합성 확보)
        if (isDefaultQuery)
        {
            await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(1), cancellationToken);
        }

        return response;
    }
}