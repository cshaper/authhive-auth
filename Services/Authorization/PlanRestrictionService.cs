using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Infra.Cache;

namespace AuthHive.Auth.Services.Authorization;

public class PlanRestrictionService : IPlanRestrictionService
{
    private readonly ICacheService _cacheService;
    private readonly ILogger<PlanRestrictionService> _logger;
    private static readonly string[] DefaultTiers = { "free", "standard", "business", "enterprise" };

    public PlanRestrictionService(
        ICacheService cacheService,
        ILogger<PlanRestrictionService> logger)
    {
        _cacheService = cacheService;
        _logger = logger;
    }

    public async Task<HashSet<string>> GetRestrictionsAsync(
        string pricingTier, 
        Guid organizationId,
        CancellationToken cancellationToken = default)
    {
        var cacheKey = $"plan_restrictions:{pricingTier}:{organizationId}";
        var cached = await _cacheService.GetAsync<HashSet<string>>(cacheKey, cancellationToken);

        if (cached != null)
        {
            return cached;
        }

        var restrictions = BuildRestrictions(pricingTier);

        await _cacheService.SetAsync(cacheKey, restrictions, TimeSpan.FromHours(1), cancellationToken);
        return restrictions;
    }

    public async Task WarmUpCacheAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogDebug("Warming up plan restriction cache...");

            var warmUpTasks = DefaultTiers.Select(tier =>
                GetRestrictionsAsync(tier, Guid.Empty, cancellationToken)
            );

            await Task.WhenAll(warmUpTasks);

            _logger.LogInformation("Plan restriction cache warmed up for {Count} tiers.", DefaultTiers.Length);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to warm up plan restriction cache");
        }
    }

    private static HashSet<string> BuildRestrictions(string? pricingTier)
    {
        var restrictions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        switch (pricingTier?.ToLower())
        {
            case "free":
                restrictions.Add("bulk:*");
                restrictions.Add("export:*");
                restrictions.Add("api:unlimited");
                restrictions.Add("analytics:advanced");
                restrictions.Add("integration:premium");
                break;

            case "standard":
                restrictions.Add("api:unlimited");
                restrictions.Add("analytics:advanced");
                restrictions.Add("integration:premium");
                break;

            case "business":
                restrictions.Add("integration:premium");
                break;

            case "enterprise":
                break;

            default:
                restrictions.Add("bulk:*");
                restrictions.Add("export:*");
                restrictions.Add("api:*");
                break;
        }

        return restrictions;
    }
}