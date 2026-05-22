using Microsoft.AspNetCore.Builder;

public class DebugModeExamples
{
    public void Vulnerable(WebApplication app)
    {
        // ruleid: csharp.aspnet.security.cwe-215.debug-enabled
        app.UseDeveloperExceptionPage();

        // ruleid: csharp.aspnet.security.cwe-215.debug-enabled
        app.UseDatabaseErrorPage();
    }

    public void Safe(WebApplication app)
    {
        // ok: csharp.aspnet.security.cwe-215.debug-enabled
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
        }

        // ok: csharp.aspnet.security.cwe-215.debug-enabled
        app.UseExceptionHandler("/Error");
    }
}
