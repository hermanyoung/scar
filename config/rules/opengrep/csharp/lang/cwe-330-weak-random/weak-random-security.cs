using System;
using System.Security.Cryptography;

public class WeakRandomExamples
{
    public void Vulnerable()
    {
        // ruleid: csharp.lang.security.cwe-330.weak-random-security
        var rng = new Random();
        var token = rng.Next();

        // ruleid: csharp.lang.security.cwe-330.weak-random-security
        var rng2 = new System.Random(42);

        // ruleid: csharp.lang.security.cwe-330.weak-random-security
        var value = Random.Shared.Next(100000, 999999);

        // ruleid: csharp.lang.security.cwe-330.weak-random-security
        var d = Random.Shared.NextDouble();
    }

    public void Safe()
    {
        // ok: csharp.lang.security.cwe-330.weak-random-security
        var bytes = RandomNumberGenerator.GetBytes(32);

        // ok: csharp.lang.security.cwe-330.weak-random-security
        var number = RandomNumberGenerator.GetInt32(100000, 999999);

        // ok: csharp.lang.security.cwe-330.weak-random-security
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
    }
}
