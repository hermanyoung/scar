using Microsoft.Extensions.Logging;
using System;

public class SensitiveLoggingExamples
{
    private readonly ILogger _logger;

    public void Vulnerable(string password, string token)
    {
        // ruleid: csharp.lang.security.cwe-532.sensitive-logging
        _logger.LogInformation($"Login attempt with password={password}");

        // ruleid: csharp.lang.security.cwe-532.sensitive-logging
        _logger.LogDebug($"API call with token={token}");

        // ruleid: csharp.lang.security.cwe-532.sensitive-logging
        Console.WriteLine($"Debug: secret={apiSecret}");
    }

    public void Safe(string userId)
    {
        // ok: csharp.lang.security.cwe-532.sensitive-logging
        _logger.LogInformation("Login attempt for user {UserId}", userId);

        // ok: csharp.lang.security.cwe-532.sensitive-logging
        _logger.LogDebug("Request completed in {Duration}ms", duration);

        // ok: csharp.lang.security.cwe-532.sensitive-logging
        Console.WriteLine($"Processing user {userId}");
    }
}
