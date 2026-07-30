using Microsoft.EntityFrameworkCore;

public class EfCoreSqliExamples
{
    private readonly AppDbContext _ctx;

    public void VulnerableFromSqlRaw(string userInput)
    {
        // ruleid: csharp.ef-core.security.cwe-089.ef-raw-sql
        var users = _ctx.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{userInput}'").ToList();
    }

    public void VulnerableExecuteSqlRaw(string userInput)
    {
        // ruleid: csharp.ef-core.security.cwe-089.ef-raw-sql
        _ctx.Database.ExecuteSqlRaw($"DELETE FROM Users WHERE Name = '{userInput}'");
    }

    public void SafeFromSqlInterpolated(string userInput)
    {
        // ok: csharp.ef-core.security.cwe-089.ef-raw-sql
        var users = _ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {userInput}").ToList();
    }

    public void SafeLinq(string userInput)
    {
        // ok: csharp.ef-core.security.cwe-089.ef-raw-sql
        var users = _ctx.Users.Where(u => u.Name == userInput).ToList();
    }
}
