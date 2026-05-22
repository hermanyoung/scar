using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;

namespace CorpusApp.Controllers
{
    [Authorize]
    [ApiController]
    public class PoemController : Controller
    {
        private readonly HttpClient _httpClient;

        public PoemController(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        // ruleid: cwe-116 — user-controlled PII concatenated into LLM prompt without escaping
        [HttpGet("api/Contacts/{id}/poem")]
        public async Task<IActionResult> GetContactPoem([FromRoute] string id)
        {
            var contact = await GetContactById(id);
            if (contact == null) return NotFound();

            // CWE-116: User-controlled data injected directly into LLM prompt
            var prompt = $"Write a poem about {contact.FirstName} {contact.LastName} " +
                         $"who works at {contact.Company} and lives in {contact.City}. " +
                         $"Their email is {contact.Email}.";

            var response = await _httpClient.PostAsJsonAsync(
                "https://api.openai.com/v1/chat/completions",
                new { model = "gpt-4", messages = new[] { new { role = "user", content = prompt } } }
            );

            var result = await response.Content.ReadAsStringAsync();
            return Ok(result);
        }

        private Task<Contact?> GetContactById(string id) => Task.FromResult<Contact?>(null);
    }
}
