using Microsoft.EntityFrameworkCore;

namespace CorpusApp.Services
{
    public interface IContactsService
    {
        Task<List<Contact>> GetContacts();
        Task<Contact?> GetContact(string id);
        Task<Contact?> UpsertContact(Contact contact);
        Task<bool> DeleteContact(string id);
    }

    public class ContactsService : IContactsService
    {
        private readonly AppDbContext _db;

        public ContactsService(AppDbContext db) { _db = db; }

        // ruleid: cwe-863-idor — returns ALL contacts, no user-scoped filter
        public async Task<List<Contact>> GetContacts()
        {
            return await _db.Contacts.AsNoTracking().ToListAsync();
        }

        // ruleid: cwe-863-idor — fetches by ID without ownership predicate
        public async Task<Contact?> GetContact(string id)
        {
            return await _db.Contacts.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Id == id);
        }

        public async Task<Contact?> UpsertContact(Contact contact)
        {
            var existing = await _db.Contacts.FirstOrDefaultAsync(c => c.Id == contact.Id);
            if (existing == null)
                await _db.Contacts.AddAsync(contact);
            else
            {
                _db.Contacts.Remove(existing);
                await _db.Contacts.AddAsync(contact);
            }
            await _db.SaveChangesAsync();
            return contact;
        }

        public async Task<bool> DeleteContact(string id)
        {
            var contact = await _db.Contacts.FirstOrDefaultAsync(c => c.Id == id);
            if (contact == null) return false;
            _db.Contacts.Remove(contact);
            await _db.SaveChangesAsync();
            return true;
        }
    }

    public record Contact
    {
        public string Id { get; set; } = "";
        public string FullName { get; set; } = "";
        public string Email { get; set; } = "";
        public string CreatedBy { get; set; } = "";  // Ownership field — never checked in queries
    }
}
