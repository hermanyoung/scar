using System.Data.SqlClient;

public class SqliExamples
{
    // ruleid: csharp.lang.security.cwe-089.ado-net-string-concat
    public void VulnerableInterpolation(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name = '{userInput}'", conn);
    }

    // ruleid: csharp.lang.security.cwe-089.ado-net-string-concat
    public void VulnerableConcatenation(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + userInput + "'", conn);
    }

    // ruleid: csharp.lang.security.cwe-089.ado-net-string-concat
    public void VulnerableStringFormat(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        var cmd = new SqlCommand(string.Format("SELECT * FROM Users WHERE Name = '{0}'", userInput), conn);
    }

    // ok: csharp.lang.security.cwe-089.ado-net-string-concat
    public void SafeParameterised(string userInput)
    {
        var conn = new SqlConnection("Server=.;Database=App;");
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", userInput);
    }
}
