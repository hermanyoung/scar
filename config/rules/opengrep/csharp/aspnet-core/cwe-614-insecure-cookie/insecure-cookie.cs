using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.Cookies;

public class InsecureCookieExamples
{
    public void Vulnerable(HttpResponse response)
    {
        // ruleid: csharp.aspnet.security.cwe-614.insecure-cookie
        var options = new CookieOptions { Secure = false, HttpOnly = true };
        response.Cookies.Append("session", token, options);

        // ruleid: csharp.aspnet.security.cwe-614.insecure-cookie
        var opts2 = new CookieOptions { Secure = true, HttpOnly = false };

        // ruleid: csharp.aspnet.security.cwe-614.insecure-cookie
        options.Secure = false;

        // ruleid: csharp.aspnet.security.cwe-614.insecure-cookie
        options.Cookie.SecurePolicy = CookieSecurePolicy.None;
    }

    public void Safe(HttpResponse response)
    {
        // ok: csharp.aspnet.security.cwe-614.insecure-cookie
        var options = new CookieOptions { Secure = true, HttpOnly = true };
        response.Cookies.Append("session", token, options);

        // ok: csharp.aspnet.security.cwe-614.insecure-cookie
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    }
}
