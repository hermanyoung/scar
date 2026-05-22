using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

public class CorsExamples
{
    public void Vulnerable(IServiceCollection services, WebApplication app)
    {
        // ruleid: csharp.aspnet.security.cwe-942.permissive-cors
        services.AddCors(options =>
        {
            options.AddPolicy("open", builder => builder.AllowAnyOrigin());
        });

        // ruleid: csharp.aspnet.security.cwe-942.permissive-cors
        app.UseCors(policy => policy.AllowAnyOrigin());

        // ruleid: csharp.aspnet.security.cwe-942.permissive-cors
        app.UseCors(builder => builder.WithOrigins("*"));
    }

    public void Safe(IServiceCollection services)
    {
        // ok: csharp.aspnet.security.cwe-942.permissive-cors
        services.AddCors(options =>
        {
            options.AddPolicy("strict", builder =>
                builder.WithOrigins("https://myapp.example.com")
                       .AllowAnyMethod()
                       .AllowAnyHeader());
        });

        // ok: csharp.aspnet.security.cwe-942.permissive-cors
        services.AddCors(options =>
        {
            options.AddDefaultPolicy(builder =>
                builder.WithOrigins("https://admin.example.com"));
        });
    }
}
