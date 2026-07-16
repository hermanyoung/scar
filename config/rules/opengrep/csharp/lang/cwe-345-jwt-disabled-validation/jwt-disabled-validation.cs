public class Startup
{
    public void ConfigureJwt()
    {
        var parameters = new TokenValidationParameters
        {
            // ruleid: csharp.lang.security.cwe-345.validate-issuer-false
            ValidateIssuer = false,
            // ruleid: csharp.lang.security.cwe-345.validate-audience-false
            ValidateAudience = false,
            // ruleid: csharp.lang.security.cwe-345.validate-lifetime-false
            ValidateLifetime = false,
        };

        var goodParameters = new TokenValidationParameters
        {
            // ok: csharp.lang.security.cwe-345.validate-issuer-false
            ValidateIssuer = true,
            ValidIssuer = "https://issuer.example.com",
            // ok: csharp.lang.security.cwe-345.validate-audience-false
            ValidateAudience = true,
            ValidAudience = "my-api",
            // ok: csharp.lang.security.cwe-345.validate-lifetime-false
            ValidateLifetime = true,
        };
    }
}
