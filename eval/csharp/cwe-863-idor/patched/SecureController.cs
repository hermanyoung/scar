using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace CorpusApp.Controllers
{
    // ok: cwe-863-idor — all operations verify ownership via CreatedBy
    [Authorize]
    [ApiController]
    public class ContactsController : Controller
    {
        private readonly IContactsService _service;

        public ContactsController(IContactsService service)
        {
            _service = service;
        }

        // ok: GET list filtered by authenticated user
        [HttpGet("api/Contacts")]
        public async Task<ActionResult<List<Contact>>> GetContacts()
        {
            var userEmail = User.Identity?.Name ?? "";
            var contacts = await _service.GetContactsByOwner(userEmail);
            return Ok(contacts);
        }

        // ok: GET by ID with ownership check
        [HttpGet("api/Contacts/{id:guid}")]
        public async Task<ActionResult<Contact>> GetContact([FromRoute] string id)
        {
            var userEmail = User.Identity?.Name ?? "";
            var result = await _service.GetContact(id);
            if (result == null) return NotFound();
            if (result.CreatedBy != userEmail) return Forbid();
            return Ok(result);
        }

        // ok: PUT with ownership check
        [HttpPut("api/Contacts/{id:guid}")]
        public async Task<ActionResult<Contact>> UpdateContact(
            [FromRoute] string id, [FromBody] Contact contact)
        {
            if (id != contact.Id) return BadRequest();
            var userEmail = User.Identity?.Name ?? "";
            var existing = await _service.GetContact(id);
            if (existing == null) return NotFound();
            if (existing.CreatedBy != userEmail) return Forbid();
            var result = await _service.UpsertContact(contact);
            return Ok(result);
        }

        // ok: DELETE with ownership check
        [HttpDelete("api/Contacts/{id:guid}")]
        public async Task<ActionResult<bool>> DeleteContact([FromRoute] string id)
        {
            var userEmail = User.Identity?.Name ?? "";
            var existing = await _service.GetContact(id);
            if (existing == null) return NotFound();
            if (existing.CreatedBy != userEmail) return Forbid();
            var success = await _service.DeleteContact(id);
            return Ok(success);
        }
    }
}
