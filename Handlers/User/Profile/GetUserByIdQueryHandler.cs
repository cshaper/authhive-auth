// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR;

// // [Interfaces]
// using AuthHive.Core.Interfaces.User.Repositories;
// using AuthHive.Core.Interfaces.Infra.Cache; // [New] 캐시 서비스

// // [Models]
// using AuthHive.Core.Models.User.Queries;
// using AuthHive.Core.Models.User.Responses;
// using AuthHive.Core.Models.User.Queries.Profile;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;

// namespace AuthHive.Auth.Handlers.User;

// public class GetUserByIdQueryHandler : IRequestHandler<GetUserByIdQuery, UserResponse?>
// {
//     private readonly IUserRepository _userRepository;
//     private readonly ICacheService _cacheService; // [New]

//     public GetUserByIdQueryHandler(
//         IUserRepository userRepository,
//         ICacheService cacheService)
//     {
//         _userRepository = userRepository;
//         _cacheService = cacheService;
//     }

//     public async Task<UserResponse?> Handle(GetUserByIdQuery request, CancellationToken cancellationToken)
//     {
//         // 1. [Cache Read] DTO 캐시 확인 (Fastest Path)
//         // Key Format: "UserResponse:{Guid}"
//         string cacheKey = $"UserResponse:{request.UserId}";
//         var cachedResponse = await _cacheService.GetAsync<UserResponse>(cacheKey, cancellationToken);

//         if (cachedResponse != null)
//         {
//             return cachedResponse;
//         }

//         // 2. [DB Read] 캐시 없으면 DB 조회
//         var user = await _userRepository.GetByIdAsync(request.UserId, cancellationToken);

//         if (user == null)
//         {
//             return null; // 404 처리는 Controller의 몫
//         }

//         // 3. [Mapping] Entity -> DTO 변환
//         var response = new UserResponse
//         {
//             Id = user.Id,
//             Email = user.Email,
//             Username = user.Username,
//             IsEmailVerified = user.IsEmailVerified,
//             PhoneNumber = user.PhoneNumber,
//             IsTwoFactorEnabled = user.IsTwoFactorEnabled,
//             Status = user.Status,
//             CreatedAt = user.CreatedAt,
//             LastLoginAt = user.LastLoginAt
//         };

//         // 4. [Cache Write] 조회된 DTO 캐싱 (TTL 15분)
//         // 변경(Update/Delete) 발생 시 Handler에서 이 키를 무효화해야 함을 명심해야 합니다.
//         await _cacheService.SetAsync(cacheKey, response, TimeSpan.FromMinutes(15), cancellationToken);

//         return response;
//     }
// }