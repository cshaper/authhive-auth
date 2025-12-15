using AuthHive.ServiceDefaults;
using AuthHive.Infra.Extensions; // AddInfrastructureServices
using AuthHive.Infra.Middleware;
using AuthHive.Auth.Endpoints;   // UserEndpoints
using MediatR;
using AuthHive.Auth.Handlers.User.Lifecycle; // CreateUserCommandHandler 네임스페이스만

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// 1. Infrastructure DI 등록
builder.Services.AddInfrastructureServices(builder.Configuration);

// 2. MediatR 등록 (CreateUserCommandHandler만 Assembly 스캔)
builder.Services.AddMediatR(cfg =>
{
    cfg.RegisterServicesFromAssemblyContaining<CreateUserCommandHandler>();
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "AuthHive Identity API", Version = "v1" });
});

var app = builder.Build();

app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseMiddleware<ExceptionHandlingMiddleware>();
app.MapUserEndpoints();

app.Run();
