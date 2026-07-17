using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace CorpusApp.Services
{
    public class JwtService
    {
        // CWE-321: hardcoded HS256 signing key
        public SymmetricSecurityKey BuildSigningKey()
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my-super-secret-key-12345"));
        }

        public SymmetricSecurityKey BuildSigningKeyFromConfig(IConfiguration configuration)
        {
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
        }
    }
}
