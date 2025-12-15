using MediatR;
using Microsoft.AspNetCore.Mvc;
using AuthHive.Core.Models.User.Commands.Lifecycle; // Command 위치
using AuthHive.Auth.Models.Requests; // 방금 만든 Request 위치
using AuthHive.Core.Models.User.Responses;
using MiniValidation;

namespace AuthHive.Auth.Endpoints;


public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/users")
                       .WithTags("Users")
                       .WithOpenApi();

        // POST 요청 연결
        group.MapPost("/", CreateUser)
             .WithName("CreateUser")
             .Produces<UserResponse>(201)
             .ProducesValidationProblem(400);
    }

    // ★ 핵심: Request를 받아서 Command로 변환하는 "매핑(Mapping)" 구간
    private static async Task<IResult> CreateUser(
        [FromBody] CreateUserRequest request,
        [FromServices] IMediator mediator,
        HttpContext httpContext)
    {
        if (!MiniValidator.TryValidate(request, out var errors))
        {
            return Results.ValidationProblem(errors);
        }
        // 1. Command 조립 (수동 매핑)
        // - 사용자가 보낸 값(request) + 시스템이 아는 값(context)을 합칩니다.
        var command = new CreateUserCommand
        {
            // [User Input]
            Email = request.Email,
            Password = request.Password,
            Username = request.Username,
            PhoneNumber = request.PhoneNumber,
            DisplayName = request.DisplayName,

            // [System Input] - 보안/감사 데이터 주입
            CommandId = Guid.NewGuid(),
            IpAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
            TriggeredBy = null, // 회원가입은 아직 로그인 전이므로 null
            OrganizationId = null, // 필요시 헤더에서 추출
            CorrelationId = Guid.NewGuid(), // 추후 TraceId로 대체 가능
            OccurredAt = DateTime.UtcNow
        };

        // 2. 파이프라인 태우기 (Validation -> Idempotency -> Transaction -> Handler)
        // 이렇게 명시하면, 만약 타입이 안 맞을 경우 더 구체적인 에러 메시지를 뱉습니다.
        UserResponse result = await mediator.Send<UserResponse>(command);

        // 3. 결과 반환 (201 Created)
        return Results.Created($"/api/v1/users/{result.Id}", result);
    }
}