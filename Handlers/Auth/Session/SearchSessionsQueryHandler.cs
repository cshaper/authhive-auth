// [AuthHive.Auth] Handlers/Auth/Session/SearchSessionsQueryHandler.cs
// v17 CQRS "본보기": 'SearchSessionsQuery' (세션 검색)를 처리합니다.
// (SOP 2-Read-R)
//
// 1. Logic (v16 이관): SessionService.GetSessionsAsync의 복잡한 IQueryable 필터링 로직을 이관합니다.
// 2. Optimization: .Select() 프로젝션을 사용하여 SessionEntity를 SessionListItemReadModel로 직접 매핑합니다.
// 3. Response: v17 표준 SessionListResponse(PaginationResponse 상속 제거)로 데이터를 반환합니다.

using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Models.Auth.Session.Queries;
using AuthHive.Core.Models.Auth.Session.ReadModels;
using AuthHive.Core.Models.Auth.Session.Responses;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using static AuthHive.Core.Enums.Infra.Security.SecurityEnums;

namespace AuthHive.Auth.Handlers.Auth.Session
{
    /// <summary>
    /// [v17] "세션 검색" 유스케이스 핸들러 (SOP 2-Read-R)
    /// v16 SessionService.GetSessionsAsync 로직 이관
    /// </summary>
    public class SearchSessionsQueryHandler : IRequestHandler<SearchSessionsQuery, SessionListResponse>
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly ILogger<SearchSessionsQueryHandler> _logger;
        // TODO: .Select()에서 User.DisplayName 등을 가져오려면 IConnectedIdRepository 주입 필요

        public SearchSessionsQueryHandler(
            ISessionRepository sessionRepository,
            ILogger<SearchSessionsQueryHandler> logger)
        {
            _sessionRepository = sessionRepository;
            _logger = logger;
        }

        public async Task<SessionListResponse> Handle(SearchSessionsQuery query, CancellationToken cancellationToken)
        {
            // 1. [SOP 2.3.2] 기본 쿼리 생성
            // ISessionRepository 계약서의 GetQueryable 사용
           var queryable = _sessionRepository.Query();

            // 2. [SOP 2.3.3] 필터링 (v16 SessionService.GetSessionsAsync 로직 이관)
            // v17 SearchSessionsQuery DTO의 속성을 기반으로 IQueryable 빌드
            
            // BaseQuery 필터 (Organization)
            queryable = queryable.Where(s => s.OrganizationId == query.OrganizationId);
            // TODO: query.IncludeSubOrganizations 로직 구현 (HierarchyRepository 필요)

            // ConnectedId / UserId 필터
            if (query.ConnectedId.HasValue)
            {
                queryable = queryable.Where(s => s.ConnectedId == query.ConnectedId.Value);
            }
            if (query.UserId.HasValue)
            {
                // TODO: Admin 권한 검증 필요
                queryable = queryable.Where(s => s.UserId == query.UserId.Value);
            }

            // Status 필터 (v17 DTO 로직 반영: 기본값 Active)
            if (query.Statuses != null && query.Statuses.Any())
            {
                queryable = queryable.Where(s => query.Statuses.Contains(s.Status));
            }
            else if (!query.IncludeTerminated)
            {
            // v16 기본값: Active 세션만 [cite: 563-567]
                queryable = queryable.Where(s => s.Status == SessionStatus.Active);
            }
            
            // IP 주소 필터 [cite: 569-573]
            if (!string.IsNullOrWhiteSpace(query.IpAddress))
            {
                // TODO: Admin 권한 검증 필요
                queryable = queryable.Where(s => s.IpAddress != null && s.IpAddress.Contains(query.IpAddress));
            }
            
            // 위치 필터 [cite: 602-606]
            if (!string.IsNullOrWhiteSpace(query.Location))
            {
                queryable = queryable.Where(s => s.Location != null && s.Location.Contains(query.Location));
            }

            // 날짜 범위 필터 [cite: 608-634]
            if (query.CreatedAfter.HasValue)
            {
                queryable = queryable.Where(s => s.CreatedAt >= query.CreatedAfter.Value);
            }
            if (query.CreatedBefore.HasValue)
            {
                queryable = queryable.Where(s => s.CreatedAt <= query.CreatedBefore.Value);
            }
            if (query.LastActiveAfter.HasValue)
            {
                queryable = queryable.Where(s => s.LastActivityAt >= query.LastActiveAfter.Value);
            }
            if (query.LastActiveBefore.HasValue)
            {
                queryable = queryable.Where(s => s.LastActivityAt <= query.LastActiveBefore.Value);
            }
            if (query.ExpiringBefore.HasValue)
            {
                queryable = queryable.Where(s => s.ExpiresAt <= query.ExpiringBefore.Value);
            }

            // 위험도 점수 필터 [cite: 636-647]
            if (query.MinRiskScore.HasValue)
            {
                queryable = queryable.Where(s => s.RiskScore >= query.MinRiskScore.Value);
            }
            if (query.MaxRiskScore.HasValue)
            {
                queryable = queryable.Where(s => s.RiskScore <= query.MaxRiskScore.Value);
            }

            // 잠긴 세션 필터 
            if (query.LockedOnly.HasValue)
            {
                queryable = query.LockedOnly.Value
                    ? queryable.Where(s => s.IsLocked)
                    : queryable.Where(s => !s.IsLocked);
            }

            // TODO: v17 DTO의 신규 필터(DeviceTypes, BrowserTypes, OSTypes 등) 로직 추가
            
            // 현재 세션 제외 옵션 [cite: 660-664]
            if (!query.IncludeCurrentSession && query.CurrentSessionId.HasValue)
            {
                queryable = queryable.Where(s => s.Id != query.CurrentSessionId.Value);
            }

            // 3. [SOP 2.3.4] 전체 개수 조회
            long totalCount = 0;
            if (query.CountOnly)
            {
                totalCount = await queryable.CountAsync(cancellationToken);
                return new SessionListResponse(new List<SessionListItemReadModel>(), totalCount, 1, 1);
            }
            
            totalCount = await queryable.CountAsync(cancellationToken);
            if (totalCount == 0)
            {
                return new SessionListResponse(new List<SessionListItemReadModel>(), 0, query.PageNumber, query.PageSize);
            }

            // 4. [SOP 2.3.5] 정렬 (v16 로직 이관) [cite: 667-684]
            // v17 BaseQuery의 SortBy, SortDescending 사용
            var orderedQuery = query.SortBy?.ToLower() switch
            {
                "lastactivityat" => query.SortDescending
                    ? queryable.OrderByDescending(s => s.LastActivityAt)
                    : queryable.OrderBy(s => s.LastActivityAt),
                "expiresat" => query.SortDescending
                    ? queryable.OrderByDescending(s => s.ExpiresAt)
                    : queryable.OrderBy(s => s.ExpiresAt),
                "riskscore" => query.SortDescending
                    ? queryable.OrderByDescending(s => s.RiskScore)
                    : queryable.OrderBy(s => s.RiskScore),
                _ => query.SortDescending
                    ? queryable.OrderByDescending(s => s.CreatedAt)
                    : queryable.OrderBy(s => s.CreatedAt)
            };

            // 5. [SOP 2.3.6] 페이징 및 프로젝션 (v17 최적화)
            var pagedEntities = orderedQuery
                .Skip((query.PageNumber - 1) * query.PageSize)
                .Take(query.PageSize);

            // [v17] .Select()를 사용하여 Entity -> ReadModel로 직접 프로젝션
            // v16의 MapToSessionResponse  로직을 .Select()로 이관
            var items = await pagedEntities.Select(s => 
                // SessionListItemReadModel 생성자 계약서 준수 
                new SessionListItemReadModel(
                    s.Id,
                    s.ConnectedId ?? Guid.Empty, // ConnectedId는 Nullable
                    s.SessionType,
                    s.Status,
                    s.CreatedAt,
                    s.LastActivityAt,
                    s.ExpiresAt,
                    s.RiskScore,
                    s.PageViews,
                    s.ApiCalls,
                    s.Id == query.CurrentSessionId, // IsCurrent 계산
                    false, // TODO: IsTrustedDevice 로직 필요
                    s.IsLocked,
                    (RiskLevel)s.RiskScore, // TODO: RiskLevel 계산 로직 필요
                    null,
                    s.DeviceInfo,
                    s.Browser,
                    s.OperatingSystem,
                    s.IpAddress, // TODO: 마스킹 처리 필요
                    s.Location
                )
            ).ToListAsync(cancellationToken);

            // 6. [SOP 2.3.7] 응답 반환
            // v17 SessionListResponse 계약서 준수 
            
            // TODO: v16 로직의 통계(Statistics), 그룹화(DeviceGroups) 로직 이관 필요 [cite: 686-742]
            
            var response = new SessionListResponse(
                items: items,
                totalCount: totalCount,
                pageNumber: query.PageNumber,
                pageSize: query.PageSize,
                fromCache: false, // TODO: 캐시 로직 구현
                statistics: null, // TODO: 통계 로직 이관
                deviceGroups: null, // TODO: 그룹화 로직 이관
                locationGroups: null, // TODO: 그룹화 로직 이관
                securitySummary: null, // TODO: 요약 로직 이관
                filterSummary: null // TODO: 요약 로직 이관
            );

            _logger.LogInformation(
                "Retrieved {Count} sessions for Organization {OrganizationId} (Page {Page}/{TotalPages})",
                items.Count, query.OrganizationId, query.PageNumber, response.TotalPages);

            return response;
        }
    }
}