namespace CorpusApp.Models
{
    // ruleid: cwe-312-cleartext — secrets stored as plaintext string properties
    public class AppAdOptions
    {
        public string TenantId { get; set; } = "";
        public string ClientId { get; set; } = "";
        // ruleid: cwe-312 — OAuth client secret stored in plain text
        public string ClientSecret { get; set; } = "";
        public string Instance { get; set; } = "https://login.microsoftonline.com/";
    }

    // ruleid: cwe-312 — PII stored as plaintext in entity model
    public class Contact
    {
        public string Id { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public string Email { get; set; } = "";
        public string PhoneNumber { get; set; } = "";
        public string SocialSecurityNumber { get; set; } = "";
        public string CreatedBy { get; set; } = "";
    }
}
