using System.Data.SqlClient;

public class SqliExamples
{
    public void VulnerableInterpolation(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        // ruleid: csharp.lang.security.cwe-089.ado-net-string-concat
        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = '{userInput}'", conn);
    }

    public void VulnerableConcatenation(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        // ruleid: csharp.lang.security.cwe-089.ado-net-string-concat
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + userInput + "'", conn);
    }

    public void VulnerableStringFormat(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        // ruleid: csharp.lang.security.cwe-089.ado-net-string-concat
        var cmd = new SqlCommand(string.Format("SELECT * FROM Users WHERE Name = '{0}'", userInput), conn);
    }

    public void SafeParameterised(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        // ok: csharp.lang.security.cwe-089.ado-net-string-concat
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", userInput);
    }
}
