using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

public class SsrfExamples : Controller
{
    private readonly HttpClient _client = new();

    public async Task<IActionResult> VulnerableFetch(string url)
    {
        // ruleid: csharp.aspnet-core.security.cwe-918.httpclient-user-url
        var response = await _client.GetAsync(url);
        return Ok(await response.Content.ReadAsStringAsync());
    }

    public async Task<IActionResult> VulnerablePost(string url, string data)
    {
        var content = new StringContent(data);
        // ruleid: csharp.aspnet-core.security.cwe-918.httpclient-user-url
        var response = await _client.PostAsync(url, content);
        return Ok();
    }

    public async Task<IActionResult> SafeHardcodedUrl()
    {
        // ok: csharp.aspnet-core.security.cwe-918.httpclient-user-url
        var response = await _client.GetAsync("https://api.internal.example.com/health");
        return Ok();
    }
}
