using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace SecureApp.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        private readonly AppDbContext _context;

        public SecureController(AppDbContext context) => _context = context;

        // Safe: EF Core LINQ query (parameterised by framework)
        [HttpGet("user/{id}")]
        public async Task<IActionResult> GetUser(int id)
        {
            var userId = User.FindFirst("sub")?.Value;
            var user = await _context.Users
                .Where(u => u.Id == id && u.OwnerId == userId)
                .FirstOrDefaultAsync();
            return user == null ? NotFound() : Ok(user);
        }

        // Safe: System.Text.Json (no type handling vulnerabilities)
        [HttpPost("deserialize")]
        public IActionResult DeserializeJson([FromBody] JsonElement json)
        {
            var dto = JsonSerializer.Deserialize<UserDto>(json.GetRawText());
            return Ok(dto);
        }

        // Safe: SHA256 (not weak)
        public byte[] HashData(byte[] data)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            return sha256.ComputeHash(data);
        }
    }

    public class UserDto { public string Name { get; set; } }
}
