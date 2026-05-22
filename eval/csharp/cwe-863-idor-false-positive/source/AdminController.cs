using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace CorpusApp.Controllers
{
    // ok: cwe-863-idor — Admin role has intentionally unscoped access
    [Authorize(Roles = "Admin")]
    [ApiController]
    public class AdminContactsController : Controller
    {
        private readonly IContactsService _service;

        public AdminContactsController(IContactsService service)
        {
            _service = service;
        }

        // ok: Admin endpoint — intentionally returns all contacts for admin management
        [HttpGet("api/Admin/Contacts")]
        public async Task<ActionResult<List<Contact>>> GetAllContacts()
        {
            var contacts = await _service.GetContacts();
            return Ok(contacts);
        }

        // ok: Admin endpoint — intentionally allows admin to view any contact
        [HttpGet("api/Admin/Contacts/{id:guid}")]
        public async Task<ActionResult<Contact>> GetContact([FromRoute] string id)
        {
            var result = await _service.GetContact(id);
            if (result == null) return NotFound();
            return Ok(result);
        }

        // ok: Admin endpoint — intentionally allows admin to delete any contact
        [HttpDelete("api/Admin/Contacts/{id:guid}")]
        public async Task<ActionResult<bool>> DeleteContact([FromRoute] string id)
        {
            var success = await _service.DeleteContact(id);
            return Ok(success);
        }
    }
}
