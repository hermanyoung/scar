using Dapper;
using System.Data.SqlClient;

public class DapperSqliExamples
{
    public void VulnerableQuery(SqlConnection conn, string userInput)
    {
        // ruleid: csharp.lang.security.cwe-089.dapper-raw-sql
        var users = conn.Query($"SELECT * FROM Users WHERE Name = '{userInput}'");
    }

    public void VulnerableConcat(SqlConnection conn, string userInput)
    {
        // ruleid: csharp.lang.security.cwe-089.dapper-raw-sql
        var users = conn.Query("SELECT * FROM Users WHERE Name = '" + userInput + "'");
    }

    public void SafeParameterised(SqlConnection conn, string userInput)
    {
        // ok: csharp.lang.security.cwe-089.dapper-raw-sql
        var users = conn.Query("SELECT * FROM Users WHERE Name = @Name", new { Name = userInput });
    }
}
