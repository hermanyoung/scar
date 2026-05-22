using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Net.Http;
using System.Threading.RateLimiting;

namespace CorpusApp.Controllers
{
    // ok: cwe-693 — rate limiter and anti-forgery protection in place
    [Authorize]
    [ApiController]
    public class PoemServiceController : Controller
    {
        private readonly HttpClient _httpClient;
        private static readonly RateLimiter _limiter = new TokenBucketRateLimiter(
            new TokenBucketRateLimiterOptions
            {
                TokenLimit = 5,
                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                TokensPerPeriod = 5,
            });

        public PoemServiceController(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        // ok: cwe-693 — rate-limited external API call
        [HttpGet("api/Contacts/{id}/poem")]
        [EnableRateLimiting("ai-calls")]
        public async Task<IActionResult> GetContactPoem([FromRoute] string id)
        {
            using var lease = await _limiter.AcquireAsync();
            if (!lease.IsAcquired)
                return StatusCode(429, "Rate limit exceeded");

            var response = await _httpClient.PostAsJsonAsync(
                "https://api.openai.com/v1/chat/completions",
                new { model = "gpt-4", messages = new[] { new { role = "user", content = "Write a poem" } } }
            );
            return Ok(await response.Content.ReadAsStringAsync());
        }

        // ok: cwe-693 — anti-forgery validation present
        [HttpPost("api/Contacts")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateContact([FromBody] object contact)
        {
            return Ok(contact);
        }
    }
}
