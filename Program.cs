using AuthHive.ServiceDefaults;
using AuthHive.Infra.Middleware;
using AuthHive.Auth.Endpoints;
using MediatR;

// [확장 메서드 네임스페이스]
using AuthHive.Infra.Extensions;           // AuthDependencyInjection
using AuthHive.Business.Infra.Extensions;  // BizDependencyInjection
using AuthHive.Shared.Extensions;          // SharedDependencyInjection

// [서비스 및 인터페이스]
using AuthHive.Core.Interfaces.Security;
using AuthHive.Shared.Providers.Hashing;
using AuthHive.Core.Interfaces.User.Services;
using AuthHive.Auth.Services;
using AuthHive.Auth.Handlers.User.Registration;

var builder = WebApplication.CreateBuilder(args);

// 1. .NET Aspire 기본 설정
builder.AddServiceDefaults();

// 2. 계층별 인프라 등록 (통일된 네이밍 사용)
builder.Services.AddSharedInfrastructure();                  // Shared (EventChannel 등)
builder.Services.AddInfrastructureServices(builder.Configuration); // Auth (AuthDb, IAuthUnitOfWork)
builder.Services.AddBusinessInfra(builder.Configuration);          // Business (BusinessDb, IBusinessUnitOfWork)

// 3. Auth 도메인 전용 서비스 등록
builder.Services.AddScoped<IPasswordHashProvider, Argon2PasswordHashProvider>();
builder.Services.AddScoped<IUserRegistrationService, UserRegistrationService>();

// 4. MediatR 설정 (모든 핸들러 위치 스캔)
builder.Services.AddMediatR(cfg =>
{
    // Auth 핸들러 스캔
    cfg.RegisterServicesFromAssemblyContaining<RegisterWithEmailCommandHandler>();
    // Business 핸들러 스캔 (BizDependencyInjection이 포함된 어셈블리)
    cfg.RegisterServicesFromAssembly(typeof(BizDependencyInjection).Assembly);
});

// 5. API 및 Swagger 설정
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "AuthHive Identity API", Version = "v1" });
});

var app = builder.Build();

// 6. 미들웨어 및 파이프라인
app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseMiddleware<ExceptionHandlingMiddleware>(); 

// 7. 엔드포인트 매핑
app.MapUserEndpoints();

app.Run();