using Serilog;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;
using Amazon.SimpleEmail;
using System.Reflection;

// [v18 Namespaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Security;
// (나머지 인터페이스 네임스페이스들...)

using AuthHive.Infra.Persistence.Context; // [중요] AuthDbContext 위치 변경됨
using AuthHive.Infra.Persistence.Repositories;
using AuthHive.Infra.Cache; // Redis Cache 구현체


// [Legacy Middleware & Services - 유지]
using AuthHive.Auth.Middleware;
using AuthHive.Auth.Providers;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Infra.Services.Auth;
using Asp.Versioning;
using AuthHive.Auth.Providers.Hashing;
using AuthHive.Infra.Providers.Tokens;
using AuthHive.Infra.Persistence.Repositories.Auth.Authentication;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // 1. Serilog 설정
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .WriteTo.Console());

    // 2. 기본 ASP.NET Core 서비스
    builder.Services.AddControllers()
        .AddJsonOptions(options =>
        {
            // Enum 문자열 변환 (선택)
            // options.JsonSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        });

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new() { Title = "AuthHive Identity API (v18)", Version = "v18" });
        // (필요시 JWT 인증 헤더 설정 추가)
    });

    builder.Services.AddHttpClient();
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddMemoryCache();
    builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
    builder.Services.AddApiVersioning(options =>
    {
        options.DefaultApiVersion = new ApiVersion(1, 0);
        options.AssumeDefaultVersionWhenUnspecified = true;
        options.ReportApiVersions = true;
    }).AddMvc();
    // 3. Database Contexts (v18 Infra)
    var dbConnectionString = builder.Configuration.GetConnectionString("AuthDb");

    // [Identity Core DB]
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseNpgsql(dbConnectionString, b => b.MigrationsAssembly("AuthHive.Infra")));

    // [Money Core DB - 필요시 추가]
    // builder.Services.AddDbContext<BusinessDbContext>(...);

    // 4. Redis (Cache & Pub/Sub)
    builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
    {
        var configuration = ConfigurationOptions.Parse(
            builder.Configuration.GetConnectionString("Redis") ?? "localhost:6379",
            true);
        return ConnectionMultiplexer.Connect(configuration);
    });

    // 5. AWS SES (Email)
    var awsOptions = builder.Configuration.GetAWSOptions();
    builder.Services.AddDefaultAWSOptions(awsOptions);
    builder.Services.AddAWSService<IAmazonSimpleEmailService>();

    // 6. [Core Services] DI 등록
    // (주의: 삭제된 엔티티와 관련된 Repository는 여기서 제거해야 에러가 안 남)

    // --- MediatR (v18 핵심) ---
    builder.Services.AddMediatR(cfg =>
    {
        cfg.RegisterServicesFromAssembly(typeof(Program).Assembly); // API 프로젝트 핸들러
        // cfg.RegisterServicesFromAssembly(typeof(AuthHive.Core.Entities.User.User).Assembly); // Core 핸들러 (만약 있다면)
    });

    // --- Repositories (Infra 구현체 연결) ---
    // (아직 Infra에 구현체가 없다면, 일단 주석 처리하거나 Mock으로 대체해야 빌드됨)
    // builder.Services.AddScoped<IUserRepository, UserRepository>();
    // builder.Services.AddScoped<IOrganizationRepository, OrganizationRepository>();
    // --- Providers & Security ---
    // (기존 Auth 프로젝트에 있는 것들 활용)
    builder.Services.AddScoped<ITokenProvider, PasetoTokenProvider>();
    builder.Services.AddSingleton<ITokenService, TokenService>();
    builder.Services.AddSingleton<IPasswordHashProvider, Argon2PasswordHashProvider>();
    builder.Services.AddScoped<ISSOConfigurationRepository, SSOConfigurationRepository>();

    // --- Context Accessors ---
    // (Middleware가 채워준 값을 꺼내 쓰는 서비스들)
    // builder.Services.AddScoped<IOrganizationContext, OrganizationContext>();
    // builder.Services.AddScoped<IPrincipalAccessor, ConnectedIdContextAccessor>();

    // --- Unit of Work ---
    // builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

    // 7. CORS 설정
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowAll", policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        });
    });

    var app = builder.Build();

    // ============================================================================
    // 8. HTTP Request Pipeline (Middleware 순서 중요)
    // ============================================================================

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    // 1) 에러 핸들링 (가장 바깥쪽)
    app.UseMiddleware<ExceptionHandlingMiddleware>();

    // 2) 로깅
    app.UseSerilogRequestLogging();

    // 3) 보안 헤더 & CORS
    app.UseHttpsRedirection();
    app.UseCors("AllowAll");

    // 4) 인증 (Authentication) - "누구인가?"
    // Paseto 토큰을 검사하여 UserContext를 설정
    app.UseMiddleware<PasetoAuthenticationMiddleware>();

    // 5) 테넌트 식별 (Tenant Resolution) - "어느 조직인가?"
    // URL이나 헤더에서 Organization ID를 추출하여 OrganizationContext 설정
    app.UseMiddleware<TenantResolutionMiddleware>();

    // 6) 인가 (Authorization) - "권한이 있는가?"
    // (ASP.NET Core 기본 인가 미들웨어를 쓸 경우 필요)
    // app.UseAuthorization(); 

    // 7) 컨트롤러 실행
    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}