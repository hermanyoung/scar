using Microsoft.EntityFrameworkCore;

public class EfCoreSqliExamples
{
    private readonly AppDbContext _ctx;

    // ruleid: csharp.ef-core.security.cwe-089.ef-raw-sql
    public void VulnerableFromSqlRaw(string userInput)
    {
        var users = _ctx.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{userInput}'").ToList();
    }

    // ruleid: csharp.ef-core.security.cwe-089.ef-raw-sql
    public void VulnerableExecuteSqlRaw(string userInput)
    {
        _ctx.Database.ExecuteSqlRaw($"DELETE FROM Users WHERE Name = '{userInput}'");
    }

    // ok: csharp.ef-core.security.cwe-089.ef-raw-sql
    public void SafeFromSqlInterpolated(string userInput)
    {
        var users = _ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {userInput}").ToList();
    }

    // ok: csharp.ef-core.security.cwe-089.ef-raw-sql
    public void SafeLinq(string userInput)
    {
        var users = _ctx.Users.Where(u => u.Name == userInput).ToList();
    }
}
