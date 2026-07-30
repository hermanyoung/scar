using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

public class XssExamples : Controller
{
    public IActionResult VulnerableContent(string userInput)
    {
        // ruleid: csharp.lang.security.cwe-079.raw-html-output
        return Content($"<div>{userInput}</div>");
    }

    public IHtmlContent VulnerableHtmlString(string userInput)
    {
        // ruleid: csharp.lang.security.cwe-079.raw-html-output
        return new HtmlString($"<p>{userInput}</p>");
    }

    // Known limitation: encoding into a local and then interpolating it still
    // reports, because telling an encoded value from a raw one needs taint
    // tracking and no rule in this set uses taint mode. Encoding inline, as
    // below, is what the rule can actually recognise as safe.
    public IActionResult SafeEncoded(string userInput)
    {
        // ok: csharp.lang.security.cwe-079.raw-html-output
        return Content(System.Text.Encodings.Web.HtmlEncoder.Default.Encode(userInput));
    }
}
