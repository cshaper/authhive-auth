using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Provider;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Organization.Service.Settings;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Repository.Settings;
using AuthHive.Auth.Services.Authentication;
using AuthHive.Auth.Services.Session;
using AuthHive.Auth.Services.Context;
using AuthHive.Auth.Services.Organization;
using AuthHive.Auth.Services.Organization.Settings;
using AuthHive.Auth.Repositories;
using AuthHive.Auth.Repositories.Organization;
using AuthHive.Auth.Providers;
using AuthHive.Auth.Data;
using AuthHive.Auth.Middleware;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;
using Serilog;
using AuthHive.Infrastructure.Events;
using AuthHive.Business.Services.Organization;
using AuthHive.Auth.Services.Authorization;
using AuthHive.Auth.Services.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using Amazon.SimpleEmail;
using AuthHive.Infrastructure.Services.UserExperience;
using AuthHive.Auth.Services.ConnectedId;



Log.Logger = new LoggerConfiguration()
   .WriteTo.Console()
   .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .WriteTo.Console());

    // Core Services
    builder.Services.AddSingleton<IEventBus, InMemoryEventBus>();
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddHttpClient();
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddMemoryCache();
    builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

    // Database
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseNpgsql(builder.Configuration.GetConnectionString("AuthDb")));

    // Redis
    builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
    {
        var configuration = ConfigurationOptions.Parse(
            builder.Configuration.GetConnectionString("Redis") ?? "localhost:6379",
            true);
        return ConnectionMultiplexer.Connect(configuration);
    });
    // Email 
    var awsOptions = builder.Configuration.GetAWSOptions();
    builder.Services.AddDefaultAWSOptions(awsOptions);
    builder.Services.AddAWSService<IAmazonSimpleEmailService>();
    builder.Services.AddScoped<IEmailService, EmailService>();
    builder.Services.AddScoped<IInvitationService, InvitationService>();
    // Auth Repositories
    builder.Services.AddScoped<IUserRepository, UserRepository>();
    builder.Services.AddScoped<IConnectedIdRepository, ConnectedIdRepository>();
    builder.Services.AddScoped<ISessionRepository, SessionRepository>();
    builder.Services.AddScoped<ISessionActivityLogRepository, SessionActivityLogRepository>();
    builder.Services.AddScoped<IAccessTokenRepository, AccessTokenRepository>();

    // Organization Repositories
    builder.Services.AddScoped<IOrganizationRepository, OrganizationRepository>();
    builder.Services.AddScoped<IOrganizationHierarchyRepository, OrganizationHierarchyRepository>();
    builder.Services.AddScoped<IOrganizationSettingsRepository, OrganizationSettingsRepository>();
    builder.Services.AddScoped<IOrganizationSettingsQueryRepository>(sp =>
        sp.GetRequiredService<OrganizationSettingsRepository>());
    builder.Services.AddScoped<IOrganizationSettingsCommandRepository>(sp =>
        sp.GetRequiredService<OrganizationSettingsRepository>());

    // Providers
    builder.Services.AddScoped<ITokenProvider, PasetoTokenProvider>();
    builder.Services.AddSingleton<ITokenService, TokenService>();
    builder.Services.AddScoped<IPasswordProvider, Argon2PasswordProvider>();

    // Contexts
    builder.Services.AddScoped<IOrganizationContext, OrganizationContext>();
    builder.Services.AddScoped<IConnectedIdContext, ConnectedIdContext>();

    // Services
    builder.Services.AddScoped<ISessionService, SessionService>();
    builder.Services.AddScoped<IOrganizationService, OrganizationService>();
    builder.Services.AddScoped<IOrganizationHierarchyService, OrganizationHierarchyService>();
    builder.Services.AddScoped<IOrganizationSettingsService, OrganizationSettingsService>();
    
    builder.Services.AddScoped<IPlanRestrictionService, PlanRestrictionService>();
    builder.Services.AddTransient<ICacheWarmupStrategy, PermissionCacheWarmupStrategy>();
    // Handlers
    builder.Services.AddScoped<IOrganizationSettingsHierarchyHandler, OrganizationSettingsHierarchyHandler>();
    builder.Services.AddScoped<IOrganizationSettingsLifecycleHandler, OrganizationSettingsLifecycleHandler>();

    // Unit of Work
    builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

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

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseMiddleware<ExceptionHandlingMiddleware>();
    app.UseSerilogRequestLogging();
    app.UseHttpsRedirection();
    app.UseCors("AllowAll");
    app.UseMiddleware<PasetoAuthenticationMiddleware>();
    app.UseMiddleware<TenantResolutionMiddleware>();
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