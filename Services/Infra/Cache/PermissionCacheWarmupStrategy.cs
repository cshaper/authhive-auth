using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Services.Infra.Cache;

public class PermissionCacheWarmupStrategy : ICacheWarmupStrategy
{
    private readonly IPlanRestrictionService _planRestrictionService;
    private readonly ILogger<PermissionCacheWarmupStrategy> _logger;

    public string StrategyName => "PlanRestrictions";

    public PermissionCacheWarmupStrategy(
        IPlanRestrictionService planRestrictionService,
        ILogger<PermissionCacheWarmupStrategy> logger)
    {
        _planRestrictionService = planRestrictionService;
        _logger = logger;
    }

    public async Task WarmUpAsync(CancellationToken cancellationToken = default)
    {
        await _planRestrictionService.WarmUpCacheAsync(cancellationToken);
    }
}