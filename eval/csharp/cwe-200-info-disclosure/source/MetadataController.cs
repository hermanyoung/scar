using Microsoft.AspNetCore.Mvc;
using System.Reflection;

namespace CorpusApp.Controllers
{
    // ruleid: cwe-200-info-disclosure — no [Authorize] on metadata endpoint
    [ApiController]
    public class AppMetadataController : Controller
    {
        // ruleid: cwe-200 — exposes build info, assembly version, env vars without auth
        [HttpGet("api/metadata")]
        public IActionResult GetMetadata()
        {
            var assembly = Assembly.GetExecutingAssembly();
            return Ok(new
            {
                Version = assembly.GetName().Version?.ToString(),
                BuildDate = File.GetLastWriteTime(assembly.Location),
                MachineName = Environment.MachineName,
                OsVersion = Environment.OSVersion.ToString(),
                ConnectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING"),
            });
        }

        // ruleid: cwe-200 — exposes feature flags and internal config without auth
        [HttpGet("api/features")]
        public IActionResult GetFeatures()
        {
            return Ok(new
            {
                EnableBetaApi = true,
                InternalServiceUrl = "https://internal-api.corp.local/v2",
                ApiKeyRotationDate = "2025-12-01",
            });
        }
    }
}
