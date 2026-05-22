using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

public class XssExamples : Controller
{
    // ruleid: csharp.lang.security.cwe-079.raw-html-output
    public IActionResult VulnerableContent(string userInput)
    {
        return Content($"<div>{userInput}</div>");
    }

    // ruleid: csharp.lang.security.cwe-079.raw-html-output
    public IHtmlContent VulnerableHtmlString(string userInput)
    {
        return new HtmlString($"<p>{userInput}</p>");
    }

    // ok: csharp.lang.security.cwe-079.raw-html-output
    public IActionResult SafeEncoded(string userInput)
    {
        var encoded = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(userInput);
        return Content($"<div>{encoded}</div>");
    }
}
