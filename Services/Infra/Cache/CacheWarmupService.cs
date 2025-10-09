using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Services.Infra.Cache;

public class CacheWarmupService : IHostedService
{
    private readonly IEnumerable<ICacheWarmupStrategy> _strategies;
    private readonly ILogger<CacheWarmupService> _logger;

    public CacheWarmupService(
        IEnumerable<ICacheWarmupStrategy> strategies,
        ILogger<CacheWarmupService> logger)
    {
        _strategies = strategies;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting cache warmup for {Count} strategies", _strategies.Count());

        foreach (var strategy in _strategies)
        {
            await strategy.WarmUpAsync(cancellationToken);
        }

        _logger.LogInformation("Cache warmup completed");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}