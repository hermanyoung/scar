using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;

namespace CorpusApp.Controllers
{
    [Authorize]
    [ApiController]
    public class PoemServiceController : Controller
    {
        private readonly HttpClient _httpClient;

        public PoemServiceController(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        // ruleid: cwe-693 — no rate limiting on expensive external AI API call
        [HttpGet("api/Contacts/{id}/poem")]
        public async Task<IActionResult> GetContactPoem([FromRoute] string id)
        {
            // Each call costs money and hits an external API — no rate limit
            var response = await _httpClient.PostAsJsonAsync(
                "https://api.openai.com/v1/chat/completions",
                new { model = "gpt-4", messages = new[] { new { role = "user", content = "Write a poem" } } }
            );
            return Ok(await response.Content.ReadAsStringAsync());
        }

        // ruleid: cwe-693 — no CSRF protection on state-changing operation
        [HttpPost("api/Contacts")]
        public async Task<IActionResult> CreateContact([FromBody] object contact)
        {
            // No anti-forgery token validation
            return Ok(contact);
        }
    }
}
