using Azure.Security.KeyVault.Secrets;
using System.Security.Cryptography;

namespace CorpusApp.Models
{
    // ok: cwe-312 — secrets loaded from Key Vault, PII encrypted at rest
    public class AppAdOptions
    {
        public string TenantId { get; set; } = "";
        public string ClientId { get; set; } = "";
        // ok: cwe-312 — secret loaded from Azure Key Vault at runtime
        public SecretClient SecretClient { get; set; } = default!;
        public string Instance { get; set; } = "https://login.microsoftonline.com/";

        public async Task<string> GetClientSecretAsync()
        {
            var secret = await SecretClient.GetSecretAsync("app-client-secret");
            return secret.Value.Value;
        }
    }

    // ok: cwe-312 — PII fields use encrypted columns
    public class Contact
    {
        public string Id { get; set; } = "";
        public byte[] FirstNameEncrypted { get; set; } = Array.Empty<byte>();
        public byte[] LastNameEncrypted { get; set; } = Array.Empty<byte>();
        public byte[] EmailEncrypted { get; set; } = Array.Empty<byte>();
        public string CreatedBy { get; set; } = "";
    }
}
