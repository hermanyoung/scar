using System.Text;
using Microsoft.IdentityModel.Tokens;

public class JwtServiceExamples
{
    public void Configure(IConfiguration configuration)
    {
        // ruleid: csharp.lang.security.cwe-321.hardcoded-jwt-key
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my-super-secret-key-12345"));

        // ok: csharp.lang.security.cwe-321.hardcoded-jwt-key
        var envKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
    }
}
