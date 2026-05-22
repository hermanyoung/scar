using Dapper;
using System.Data.SqlClient;

public class DapperSqliExamples
{
    // ruleid: csharp.lang.security.cwe-089.dapper-raw-sql
    public void VulnerableQuery(SqlConnection conn, string userInput)
    {
        var users = conn.Query($"SELECT * FROM Users WHERE Name = '{userInput}'");
    }

    // ruleid: csharp.lang.security.cwe-089.dapper-raw-sql
    public void VulnerableConcat(SqlConnection conn, string userInput)
    {
        var users = conn.Query("SELECT * FROM Users WHERE Name = '" + userInput + "'");
    }

    // ok: csharp.lang.security.cwe-089.dapper-raw-sql
    public void SafeParameterised(SqlConnection conn, string userInput)
    {
        var users = conn.Query("SELECT * FROM Users WHERE Name = @Name", new { Name = userInput });
    }
}
