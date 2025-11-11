// [AuthHive.Auth] SearchUsersQueryHandler.cs
// v17 CQRS "본보기": 'SearchUsersQuery'를 처리하여 사용자 목록을 조회합니다.
// v16 UserService의 조직 강제 로직을 제거하고, Query DTO를 Repository로 직접 전달합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Models.User.Queries;
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq; // .Select()
using System.Threading;
using System.Threading.Tasks;
using UserEntity = AuthHive.Core.Entities.User.User; // 별칭(Alias)

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "사용자 검색" 유스케이스 핸들러 (SOP 1-Read-E)
    /// </summary>
    public class SearchUsersQueryHandler : IRequestHandler<SearchUsersQuery, UserListResponse>
    {
        private readonly IUserRepository _userRepository;
        private readonly ILogger<SearchUsersQueryHandler> _logger;

        public SearchUsersQueryHandler(
            IUserRepository userRepository,
            ILogger<SearchUsersQueryHandler> logger)
        {
            _userRepository = userRepository;
            _logger = logger;
        }

        public async Task<UserListResponse> Handle(SearchUsersQuery query, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling SearchUsersQuery: {SearchTerm}, Page: {Page}", query.SearchTerm, query.PageNumber);

            // 1. v17 철학 적용:
            // v16 UserService의 '조직 강제' 로직(IPrincipalAccessor)을 "제거"함.
            // Query DTO에 OrganizationId가 있으면 Repository가 필터링하고,
            // 없으면 전역 검색 (슈퍼 어드민)을 수행함.

            // 2. Repository 호출 (v17 수정된 시그니처 사용)
            // (v16 UserService.SearchUsersAsync 로직 이관)
            var (items, totalCount) = await _userRepository.SearchUsersAsync(query, cancellationToken);

            // 3. 엔티티 -> 응답 DTO 매핑
            // (v16 UserService.MapToDto 로직 활용)
            var userDtos = items.Select(MapToDto).ToList();

            // 4. v17 Response DTO 생성 (v17 수정된 생성자 사용)
            var response = new UserListResponse(
                items: userDtos,
                totalCount: totalCount,
                pageNumber: query.PageNumber,
                pageSize: query.PageSize
            );

            return response;
        }

        /// <summary>
        /// 엔티티를 v17 응답 DTO (UserResponse)로 매핑
        /// </summary>
        private UserResponse MapToDto(UserEntity user)
        {
            return new UserResponse
            {
                Id = user.Id, // required
                Status = user.Status,
                Email = user.Email,
                Username = user.Username,
                DisplayName = user.DisplayName,
                EmailVerified = user.IsEmailVerified,
                IsTwoFactorEnabled = user.IsTwoFactorEnabled,
                LastLoginAt = user.LastLoginAt,
                CreatedAt = user.CreatedAt,
                // IsDeleted, DeletedAt은 BaseDto에 있으나 UserResponse는 상속 안 함
            };
        }
    }
}