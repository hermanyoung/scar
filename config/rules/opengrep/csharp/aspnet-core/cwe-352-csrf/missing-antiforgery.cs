using Microsoft.AspNetCore.Mvc;

public class CsrfExamples : Controller
{
    // ruleid: csharp.aspnet-core.security.cwe-352.missing-antiforgery
    [HttpPost]
    public IActionResult UpdateProfile(ProfileModel model)
    {
        return Ok();
    }

    // ok: csharp.aspnet-core.security.cwe-352.missing-antiforgery
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult SafeUpdate(ProfileModel model)
    {
        return Ok();
    }

    // ok: csharp.aspnet-core.security.cwe-352.missing-antiforgery
    [HttpGet]
    public IActionResult GetProfile()
    {
        return Ok();
    }
}
