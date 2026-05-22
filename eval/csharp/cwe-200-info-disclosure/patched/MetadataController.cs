using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;

namespace CorpusApp.Controllers
{
    // ok: cwe-200 — [Authorize] protects metadata, no sensitive data exposed
    [Authorize(Roles = "Admin")]
    [ApiController]
    public class AppMetadataController : Controller
    {
        // ok: cwe-200 — authorized, returns only safe build info
        [HttpGet("api/metadata")]
        public IActionResult GetMetadata()
        {
            var assembly = Assembly.GetExecutingAssembly();
            return Ok(new
            {
                Version = assembly.GetName().Version?.ToString(),
            });
        }
    }
}
