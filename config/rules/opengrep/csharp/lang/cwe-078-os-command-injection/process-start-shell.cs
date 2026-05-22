using System.Diagnostics;

public class CommandInjectionExamples
{
    // ruleid: csharp.lang.security.cwe-078.process-start-shell
    public void VulnerableShellExecute(string userInput)
    {
        var psi = new ProcessStartInfo();
        psi.UseShellExecute = true;
        psi.FileName = "cmd";
        psi.Arguments = $"/c dir {userInput}";
        Process.Start(psi);
    }

    // ruleid: csharp.lang.security.cwe-078.process-start-shell
    public void VulnerableInterpolatedArgs(string userInput)
    {
        var psi = new ProcessStartInfo("app.exe");
        psi.Arguments = $"--input {userInput}";
        Process.Start(psi);
    }

    // ok: csharp.lang.security.cwe-078.process-start-shell
    public void SafeNoShell()
    {
        var psi = new ProcessStartInfo("myapp.exe")
        {
            UseShellExecute = false,
            Arguments = "--flag value"
        };
        Process.Start(psi);
    }
}
