using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace CorpusApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableController : ControllerBase
    {
        private readonly string _connStr = "Server=.;Database=App;Trusted_Connection=True;";

        [HttpGet("users")]
        public IActionResult GetUsers(string name)
        {
            // CWE-089: SQL injection via string concatenation in SqlCommand
            using var conn = new SqlConnection(_connStr);
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
            conn.Open();
            using var reader = cmd.ExecuteReader();
            return Ok("query executed");
        }

        [HttpGet("search")]
        public IActionResult SearchUsers(string query)
        {
            // CWE-089: SQL injection via string interpolation in SqlCommand
            using var conn = new SqlConnection(_connStr);
            var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name LIKE '%{query}%'", conn);
            conn.Open();
            using var reader = cmd.ExecuteReader();
            return Ok("search executed");
        }
    }
}
