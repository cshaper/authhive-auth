using Microsoft.AspNetCore.Mvc;
using AuthHive.Auth.Data.Context;
using StackExchange.Redis;

namespace AuthHive.Auth.Controllers.v1
{
    [ApiController]
    [Route("api/v1/[controller]")]
    public class HealthController : ControllerBase
    {
        private readonly AuthDbContext _context;
        private readonly IConnectionMultiplexer _redis;
        private readonly ILogger<HealthController> _logger;

        public HealthController(
            AuthDbContext context, 
            IConnectionMultiplexer redis,
            ILogger<HealthController> logger)
        {
            _context = context;
            _redis = redis;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var dbConnected = false;
            var redisConnected = false;
            
            try
            {
                dbConnected = await _context.Database.CanConnectAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database connection failed");
            }

            try
            {
                redisConnected = _redis.IsConnected;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Redis connection failed");
            }

            var health = new
            {
                Status = dbConnected && redisConnected ? "Healthy" : "Unhealthy",
                Timestamp = DateTime.UtcNow,
                Services = new
                {
                    Database = dbConnected ? "Connected" : "Disconnected",
                    Redis = redisConnected ? "Connected" : "Disconnected"
                }
            };

            return Ok(health);
        }
    }
}
