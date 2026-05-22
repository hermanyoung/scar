---
applyTo: "**/*.cs"
---

# C# Security Review Instructions

When reviewing C# code in this repository:

- Flag any use of `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`, `ObjectStateFormatter` as CRITICAL. These are obsolete and enable RCE.
- Flag `SqlCommand` with string concatenation/interpolation. Require `SqlParameter`.
- Flag `TypeNameHandling` != `None` without a `SerializationBinder` whitelist.
- Flag `Process.Start` with `UseShellExecute = true` or interpolated arguments.
- Flag `MD5`, `SHA1`, `DES`, `TripleDES`, `RC2`, `ECB` mode as weak crypto.
- Flag controllers without `[Authorize]` on state-changing endpoints.
- Flag `AllowAnyOrigin().AllowCredentials()` as invalid CORS configuration.
- Verify `FromSqlRaw` is not used with interpolated strings (use `FromSqlInterpolated`).
