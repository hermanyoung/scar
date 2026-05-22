using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace CorpusApp.Controllers
{
    // ruleid: cwe-863-idor — [Authorize] present but no ownership verification
    [Authorize]
    [ApiController]
    public class ContactsController : Controller
    {
        private readonly IContactsService _service;

        public ContactsController(IContactsService service)
        {
            _service = service;
        }

        // ruleid: cwe-863-idor — GET list returns ALL contacts, no user filter
        [HttpGet("api/Contacts")]
        public async Task<ActionResult<List<Contact>>> GetContacts()
        {
            var contacts = await _service.GetContacts();
            return Ok(contacts);
        }

        // ruleid: cwe-863-idor — GET by ID without ownership check
        [HttpGet("api/Contacts/{id:guid}")]
        public async Task<ActionResult<Contact>> GetContact([FromRoute] string id)
        {
            var result = await _service.GetContact(id);
            if (result == null) return NotFound();
            return Ok(result);
        }

        [HttpPost("api/Contacts")]
        public async Task<ActionResult<Contact>> AddContact([FromBody] Contact contact)
        {
            contact.CreatedBy = User.Identity?.Name ?? "";
            var result = await _service.UpsertContact(contact);
            return Ok(result);
        }

        // ruleid: cwe-863-idor — PUT updates any contact without ownership check
        [HttpPut("api/Contacts/{id:guid}")]
        public async Task<ActionResult<Contact>> UpdateContact(
            [FromRoute] string id, [FromBody] Contact contact)
        {
            if (id != contact.Id) return BadRequest();
            var existing = await _service.GetContact(id);
            if (existing == null) return NotFound();
            // No ownership check: existing.CreatedBy != User.Identity.Name
            var result = await _service.UpsertContact(contact);
            return Ok(result);
        }

        // ruleid: cwe-863-idor — DELETE removes any contact without ownership check
        [HttpDelete("api/Contacts/{id:guid}")]
        public async Task<ActionResult<bool>> DeleteContact([FromRoute] string id)
        {
            var success = await _service.DeleteContact(id);
            return Ok(success);
        }
    }
}
