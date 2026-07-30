using System.Diagnostics;

public class CommandInjectionExamples
{
    // The rule flags each shell indicator independently, so a method that sets
    // several of them reports one finding per line.
    public void VulnerableShellExecute(string userInput)
    {
        var psi = new ProcessStartInfo();
        // ruleid: csharp.lang.security.cwe-078.process-start-shell
        psi.UseShellExecute = true;
        // ruleid: csharp.lang.security.cwe-078.process-start-shell
        psi.FileName = "cmd";
        // ruleid: csharp.lang.security.cwe-078.process-start-shell
        psi.Arguments = $"/c dir {userInput}";
        Process.Start(psi);
    }

    public void VulnerableInterpolatedArgs(string userInput)
    {
        var psi = new ProcessStartInfo("app.exe");
        // ruleid: csharp.lang.security.cwe-078.process-start-shell
        psi.Arguments = $"--input {userInput}";
        Process.Start(psi);
    }

    public void SafeNoShell()
    {
        var psi = new ProcessStartInfo("myapp.exe")
        {
            // ok: csharp.lang.security.cwe-078.process-start-shell
            UseShellExecute = false,
            Arguments = "--flag value"
        };
        Process.Start(psi);
    }
}
