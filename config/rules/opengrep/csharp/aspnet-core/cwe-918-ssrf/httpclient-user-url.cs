using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

public class SsrfExamples : Controller
{
    private readonly HttpClient _client = new();

    // ruleid: csharp.aspnet-core.security.cwe-918.httpclient-user-url
    public async Task<IActionResult> VulnerableFetch(string url)
    {
        var response = await _client.GetAsync(url);
        return Ok(await response.Content.ReadAsStringAsync());
    }

    // ruleid: csharp.aspnet-core.security.cwe-918.httpclient-user-url
    public async Task<IActionResult> VulnerablePost(string url, string data)
    {
        var content = new StringContent(data);
        var response = await _client.PostAsync(url, content);
        return Ok();
    }

    // ok: csharp.aspnet-core.security.cwe-918.httpclient-user-url
    public async Task<IActionResult> SafeHardcodedUrl()
    {
        var response = await _client.GetAsync("https://api.internal.example.com/health");
        return Ok();
    }
}
