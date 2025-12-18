using AuthHive.ServiceDefaults;
using AuthHive.Infra.Middleware;
using AuthHive.Auth.Endpoints;
using MediatR;
using Microsoft.EntityFrameworkCore;

// 핵심 네임스페이스 (누락 방지)
using AuthHive.Auth.Handlers.User.Registration; 
using AuthHive.Core.Interfaces.User.Services;
using AuthHive.Auth.Services;
using AuthHive.Business.Core.Interfaces.Commerce.Wallets.Repository;
using AuthHive.Business.Infra.Persistence.Repositories.Point;
using AuthHive.Infra.Persistence.Context;

// [에러 해결을 위해 추가된 리포지토리 인터페이스 및 구현체]
using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
using AuthHive.Infra.Persistence.Repositories.User.Lifecycle;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Business.Infra.Services;
using AuthHive.Core.Interfaces.Security;
using AuthHive.Shared.Providers.Hashing;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Shared.Providers.Infra;
using AuthHive.Business.Infra.Extensions;
using AuthHive.Business.Infra.Persistence.Context;
using AuthHive.Infra.Extensions;

var builder = WebApplication.CreateBuilder(args);


builder.AddServiceDefaults();

// -----------------------------------------------------------------------
// 2. 데이터베이스 컨텍스트 등록 (Aspire 표준 방식)
// -----------------------------------------------------------------------

// [Auth DB]
builder.Services.AddInfrastructureServices(builder.Configuration);
// [Business DB]
builder.Services.AddBusinessInfra(builder.Configuration);

// -----------------------------------------------------------------------
// 3. 의존성 주입 (DI)
// -----------------------------------------------------------------------

// [핵심] 비밀번호 암호화 도구 (IPasswordHashProvider)
builder.Services.AddScoped<IPasswordHashProvider, Argon2PasswordHashProvider>();

// [핵심] DB 트랜잭션 관리 도구 (IUnitOfWork)
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
builder.Services.AddSingleton<IDateTimeProvider, DateTimeProvider>();

// ✅ [추가됨] 로컬 이벤트 채널 (반드시 Singleton이어야 함)
// 핸들러(Write)와 API(Read)가 동일한 인스턴스를 공유해야 하기 때문입니다.
builder.Services.AddSingleton<IEventChannel, LocalEventChannel>();

// [이전 단계 추가분] 유저 관련 리포지토리
builder.Services.AddScoped<IUserQueryRepository, UserQueryRepository>();
builder.Services.AddScoped<IUserCommandRepository, UserCommandRepository>();

// [이전 단계 추가분] 지갑 리포지토리 및 가입 서비스
builder.Services.AddScoped<IPointWalletCommandRepository, PointWalletCommandRepository>();
builder.Services.AddScoped<IUserRegistrationService, UserRegistrationService>();

// MediatR 등록
builder.Services.AddMediatR(cfg =>
{
    cfg.RegisterServicesFromAssemblyContaining<RegisterWithEmailCommandHandler>();
});

// -----------------------------------------------------------------------
// 4. API 설정
// -----------------------------------------------------------------------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "AuthHive Identity API", Version = "v1" });
});

var app = builder.Build();

// 5. 미들웨어 파이프라인
app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseMiddleware<ExceptionHandlingMiddleware>(); // 예외 로그 추적 필수

// 6. 엔드포인트 매핑
app.MapUserEndpoints();

app.Run();