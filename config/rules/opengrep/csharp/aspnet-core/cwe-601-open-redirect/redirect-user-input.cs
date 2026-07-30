using Microsoft.AspNetCore.Mvc;

public class OpenRedirectExamples : Controller
{
    public IActionResult VulnerableRedirect(string returnUrl)
    {
        // ruleid: csharp.aspnet-core.security.cwe-601.redirect-user-input
        return Redirect(returnUrl);
    }

    public IActionResult SafeRedirect(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
            // ok: csharp.aspnet-core.security.cwe-601.redirect-user-input
            return Redirect(returnUrl);
        return RedirectToAction("Index");
    }

    public IActionResult SafeRedirectToAction()
    {
        // ok: csharp.aspnet-core.security.cwe-601.redirect-user-input
        return RedirectToAction("Index", "Home");
    }
}
