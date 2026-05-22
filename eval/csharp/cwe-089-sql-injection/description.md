# CWE-089: SQL Injection (C# / ADO.NET)

Vulnerable controller uses string concatenation and interpolation to build SQL queries
via `SqlCommand`. Both `GetUsers` and `SearchUsers` endpoints are exploitable.

Expected findings:
- Line 17: SqlCommand with string concatenation
- Line 26: SqlCommand with string interpolation
