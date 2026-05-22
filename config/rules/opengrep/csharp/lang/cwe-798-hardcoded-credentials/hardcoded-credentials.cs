public class HardcodedCredentialExamples
{
    // ruleid: csharp.lang.security.cwe-798.hardcoded-credentials
    private string ApiKey = "sk-proj-abc123def456";

    // ruleid: csharp.lang.security.cwe-798.hardcoded-credentials
    private string ConnectionString = "Server=db;Database=App;Password=SuperSecret123!;";

    // ok: csharp.lang.security.cwe-798.hardcoded-credentials
    public string GetApiKey(IConfiguration config)
    {
        return config["ApiKey"];
    }

    // ok: csharp.lang.security.cwe-798.hardcoded-credentials
    public string GetPassword()
    {
        return Environment.GetEnvironmentVariable("DB_PASSWORD");
    }
}
