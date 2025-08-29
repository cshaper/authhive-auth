using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Auth.Services.Authentication;
using AuthHive.Auth.Repositories;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;
using Serilog;
using AuthHive.Auth.Services.Session;
using AuthHive.Auth.Providers;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Auth.Data;
using AuthHive.Auth.Services.Context;

// Serilog 설정
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Serilog 사용
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .WriteTo.Console());

    // Services 추가
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddHttpClient();
    
    // Memory Cache 추가
    builder.Services.AddMemoryCache();
    
    // Database
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseNpgsql(builder.Configuration.GetConnectionString("AuthDb")));

    // Repositories
    builder.Services.AddScoped<IUserRepository, UserRepository>();
    builder.Services.AddScoped<ISessionRepository, SessionRepository>(); 
    builder.Services.AddScoped<IConnectedIdRepository, ConnectedIdRepository>();
    builder.Services.AddScoped<IOrganizationContext, OrganizationContext>();
    builder.Services.AddScoped<IConnectedIdContext, ConnectedIdContext>();
    
    builder.Services.AddScoped<ISessionService, SessionService>();
    //Provider 등록 
    builder.Services.AddScoped<ITokenProvider, PasetoTokenProvider>();
    builder.Services.AddSingleton<ITokenService, TokenService>();
    builder.Services.AddScoped<IPasswordProvider, Argon2PasswordProvider>();
    builder.Services.AddScoped<ISessionRepository, SessionRepository>();
    builder.Services.AddScoped<ISessionActivityLogRepository, SessionActivityLogRepository>();
    builder.Services.AddScoped<IOAuthTokenRepository, OAuthTokenRepository>();
    builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
    // Redis
    builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
    {
        var configuration = ConfigurationOptions.Parse(
            builder.Configuration.GetConnectionString("Redis") ?? "localhost:6379", 
            true);
        return ConnectionMultiplexer.Connect(configuration);
    });

    // CORS
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

    // Pipeline 설정
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseSerilogRequestLogging();
    app.UseHttpsRedirection();
    app.UseCors("AllowAll");
    app.UseAuthorization();
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