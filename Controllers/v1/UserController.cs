// using System;
// using System.Threading.Tasks;
// using MediatR;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.Extensions.Logging;
// using Asp.Versioning;

// // [Base]
// using AuthHive.Auth.Controllers.Base;
// using AuthHive.Core.Interfaces.Base;

// // [Models]
// using AuthHive.Core.Models.User.Commands;
// using AuthHive.Core.Models.User.Queries;
// using AuthHive.Core.Models.User.Responses;
// using AuthHive.Core.Models.User.Commands.Lifecycle;
// using AuthHive.Core.Models.User.Queries.Profile;
// using AuthHive.Core.Models.User.Commands.Profile;

// namespace AuthHive.Auth.Controllers.v1;

// /// <summary>
// /// [Identity Core] 사용자 관리 API (v18 Standard)
// /// </summary>
// [ApiVersion("1.0")]
// public class UserController : BaseApiController
// {
//     public UserController(
//         IMediator mediator,
//         ILogger<UserController> logger,
//         IPrincipalAccessor principalAccessor)
//         : base(mediator, logger, principalAccessor)
//     {
//     }

//     /// <summary>
//     /// 사용자 생성 (회원가입)
//     /// </summary>
//     [HttpPost]
//     [ProducesResponseType(typeof(UserResponse), StatusCodes.Status201Created)]
//     [ProducesResponseType(StatusCodes.Status400BadRequest)]
//     public async Task<IActionResult> CreateUser([FromBody] CreateUserCommand command)
//     {
//         // [v18] ServiceResult 확인 로직 없음. 
//         // 예외 발생 시 Middleware가 처리하므로, 성공 케이스만 작성.
//         var result = await Mediator.Send(command);

//         // RESTful 표준: 201 Created + Location Header
//         return CreatedAtAction(nameof(GetUserById), new { userId = result.Id }, result);
//     }

//     /// <summary>
//     /// ID로 사용자 조회
//     /// </summary>
//     [HttpGet("{userId:guid}")]
//     [ProducesResponseType(typeof(UserResponse), StatusCodes.Status200OK)]
//     [ProducesResponseType(StatusCodes.Status404NotFound)]
//     public async Task<IActionResult> GetUserById(Guid userId)
//     {
//         var query = new GetUserByIdQuery(userId);
//         var result = await Mediator.Send(query);

//         // [v18] QueryHandler가 null을 반환하면 404 처리
//         // (또는 Handler가 NotFoundException을 던지도록 통일 가능)
//         if (result == null) return NotFound();

//         return Ok(result);
//     }
    
//     // [New] Update
//     [HttpPut("{userId:guid}")]
//     [ProducesResponseType(typeof(UserResponse), StatusCodes.Status200OK)]
//     public async Task<IActionResult> UpdateUser(Guid userId, [FromBody] UpdateUserCommand command)
//     {
//         if (userId != command.UserId) return BadRequest("ID mismatch");
//         var result = await Mediator.Send(command);
//         return Ok(result);
//     }
// }