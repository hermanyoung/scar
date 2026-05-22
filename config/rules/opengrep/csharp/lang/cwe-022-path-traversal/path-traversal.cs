using System.IO;

public class PathTraversalExamples
{
    public void Vulnerable(string userInput)
    {
        // ruleid: csharp.lang.security.cwe-022.path-traversal
        var content = System.IO.File.ReadAllText("/uploads/" + userInput + ".txt");

        // ruleid: csharp.lang.security.cwe-022.path-traversal
        var content2 = System.IO.File.ReadAllText($"/data/{userInput}");

        // ruleid: csharp.lang.security.cwe-022.path-traversal
        var path = System.IO.Path.Combine("/uploads", userInput, "file.txt");

        // ruleid: csharp.lang.security.cwe-022.path-traversal
        var reader = new StreamReader("/files/" + userInput + ".csv");
    }

    public void Safe()
    {
        // ok: csharp.lang.security.cwe-022.path-traversal
        var content = System.IO.File.ReadAllText("config/appsettings.json");

        // ok: csharp.lang.security.cwe-022.path-traversal
        var path = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data", "static.json");
    }
}
