using Microsoft.AspNetCore.Mvc;

public class OpenRedirectExamples : Controller
{
    // ruleid: csharp.aspnet-core.security.cwe-601.redirect-user-input
    public IActionResult VulnerableRedirect(string returnUrl)
    {
        return Redirect(returnUrl);
    }

    // ok: csharp.aspnet-core.security.cwe-601.redirect-user-input
    public IActionResult SafeRedirect(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
            return Redirect(returnUrl);
        return RedirectToAction("Index");
    }

    // ok: csharp.aspnet-core.security.cwe-601.redirect-user-input
    public IActionResult SafeRedirectToAction()
    {
        return RedirectToAction("Index", "Home");
    }
}
