using MediatR;
using Microsoft.AspNetCore.Mvc;
using MiniValidation;
using AuthHive.Core.Models.User.Responses;
using AuthHive.Core.Models.User.Commands.Registration; // Command 위치
using AuthHive.Auth.Models.Requests; // Request DTO 위치

namespace AuthHive.Auth.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        // 공통 경로 그룹 (/api/v1/users)
        var group = app.MapGroup("/api/v1/users")
                       .WithTags("Users");
                       
        // -------------------------------------------------------------
        // [1] 이메일 가입: POST /api/v1/users/registration/email
        // -------------------------------------------------------------
        // 여기서 "RegisterWithEmail" 함수를 연결합니다.
        group.MapPost("/registration/email", RegisterWithEmail)
             .WithName("RegisterWithEmail")
             .Produces<UserResponse>(201)
             .ProducesValidationProblem(400);
    }

    // ★ [수정됨] 함수 이름을 MapPost에서 부르는 이름과 똑같이 맞춰야 합니다.
    private static async Task<IResult> RegisterWithEmail(
        [FromBody] CreateUserRequest request, 
        [FromServices] IMediator mediator,
        HttpContext httpContext)
    {
        // 1. 유효성 검사
        if (!MiniValidator.TryValidate(request, out var errors))
        {
            return Results.ValidationProblem(errors);
        }

        // 2. Command 조립
        var command = new RegisterWithEmailCommand
        {
            // [User Input]
            Email = request.Email,
            Password = request.Password,
            DisplayName = request.DisplayName,
            PhoneNumber = request.PhoneNumber,

            // [System Input]
            CommandId = Guid.NewGuid(),
            IpAddress = httpContext.Connection.RemoteIpAddress?.ToString(),
            TriggeredBy = null,
            OrganizationId = null,
            CorrelationId = Guid.NewGuid(),
            OccurredAt = DateTime.UtcNow
        };

        // 3. 파이프라인 전송 (반환 타입 <UserResponse> 명시 필수)
        UserResponse result = await mediator.Send<UserResponse>(command);

        // 4. 결과 반환
        return Results.Created($"/api/v1/users/{result.Id}", result);
    }
}