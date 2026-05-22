# Research Prompt: PostgreSQL Knowledge Graph for Security Code Analysis

Copy everything below the line into claude.ai.

---

You are a senior software architect researching whether PostgreSQL with graph extensions can improve a security code review tool's ability to explore, understand, and analyze code repositories. This is a feasibility study — I need concrete answers, not hand-waving.

## The Tool (SCAR)

SCAR is a Python CLI tool that performs automated security code reviews of C# (.NET) and Python codebases. It runs on macOS/Windows, is invoked locally, and produces SARIF reports. There is no server component, no web UI, no existing database.

### Current Pipeline

```
Pass 1: INVENTORY — file discovery, language detection, security-weight scoring
Pass 2: DETERMINISTIC SAST — OpenGrep, Bandit, Roslyn, gitleaks, Trivy (pattern matching)
Pass 3: TRIAGE (LLM) — confirm/refute each SAST finding with full-file context
Pass 4: CWE-DRIVEN REVIEW (LLM) — one LLM call per CWE (26 checks), each targeting specific file types
Pass 5: CONFIG REVIEW (LLM) — review config files for security misconfigurations
MERGE — combine all findings into SARIF + markdown + audit log
```

### Current Code Analysis (In-Memory, No Database)

SCAR already has a code analysis layer that:

1. **Parses source files** using tree-sitter (Python + C# grammars) to extract:
   - Classes, methods, functions, constants (with qualified names, line numbers, params, return types, base classes, decorators)
   - Import statements
   - Unsafe call detection (BinaryFormatter, Process.Start, Assembly.Load, etc.)

2. **Builds an in-memory dependency graph** (`ReferenceGraph` with `ReferenceEdge` objects):
   - Nodes = module qualified names + symbol qualified names
   - Edges = import relationships, inheritance (base classes), type references in parameters/return types
   - Resolves imports against known modules, resolves type names against a symbol index

3. **Computes PageRank** on the dependency graph to rank nodes by centrality (damping=0.85, iterative power method, normalized 0.0-1.0).

4. **Selects files for each CWE check** using a keyword-based matcher:
   ```python
   _FILE_TYPE_MATCHERS = {
       "controller": ["controller", "views", "endpoints", "api", "routes"],
       "auth": ["auth", "identity", "login", "oauth", "jwt", "token"],
       "crypto": ["crypto", "cipher", "encrypt", "hash", "key", "cert", "ssl", "tls"],
       "service": ["services", "handlers", "managers", "processors"],
       # ... 16 categories total
   }
   ```
   If keyword matching yields no results, it falls back to files with security_weight >= 3.

5. **Inlines file content** into LLM prompts with a token budget (100k max, 30k reserved for response). Files are included sequentially until budget is exhausted; remaining files are omitted.

### Current Limitations I Want to Explore

**A. File selection is keyword-based, not relationship-aware.** When checking CWE-89 (SQL Injection), SCAR selects files matching "models", "repositories", "dal", "data", "services", "controllers". But the actual data flow is: `Controller.CreateUser()` → `UserService.Save()` → `UserRepository.Insert()` → raw SQL. If the repository is in a folder called `Infrastructure/Persistence/`, the keyword matcher misses it entirely. The fallback (security_weight >= 3) is a blunt instrument.

**B. Cross-file data flow is invisible.** SCAR knows that `UserController` imports `UserService` (from the dependency graph), but doesn't know that `CreateUser(string name)` calls `service.Save(name)` which calls `repo.Insert(name)` which builds a SQL string with `name`. The LLM is asked to find SQL injection in controller files — but the actual vulnerability is 3 hops away in a file it may never see.

**C. No taint tracking.** User input enters at controller parameters (decorated with `[FromBody]`, `[FromQuery]`, or FastAPI `Query()`, `Body()`). SCAR doesn't trace that input through method calls to sinks (SQL, filesystem, subprocess, deserialization). The LLM has to do this reasoning from inlined source code — but only if all relevant files happen to be in the prompt.

**D. PageRank is computed but underutilized.** It exists but isn't used to prioritize file ordering in prompts or to improve file selection. High-centrality nodes (heavily-imported base classes, shared utilities) are likely security-relevant but aren't prioritized.

**E. No cross-run memory.** Every run is ephemeral. If I review the same repo weekly, SCAR rediscovers everything from scratch — same parsing, same graph, same LLM calls. There's no way to say "what changed since last review" or "track this finding over time."

**F. Import alias resolution is incomplete.** Python `from foo import Bar as Baz` and C# `using Baz = Foo.Bar` create aliases that the graph builder doesn't fully resolve, leading to duplicate or missing edges.

## What I Want You to Research

I'm willing to install PostgreSQL locally (via Homebrew on macOS) with extensions if it materially improves SCAR's code analysis capabilities. The key question is: **does a persistent, queryable graph database give SCAR capabilities that its current in-memory graph cannot practically achieve?**

### Q1 — Schema Design for a Code Knowledge Graph

Design a PostgreSQL schema (with Apache AGE for graph queries) that models a parsed codebase. Consider:

- **Vertex types:** File, Module, Class, Method, Function, Parameter, Import, Namespace/Package
- **Edge types:** CONTAINS (file→class), DEFINES (class→method), CALLS (method→method), IMPORTS (module→module), INHERITS (class→class), PARAMETER_OF (param→method), RETURNS_TYPE (method→class), INSTANTIATES (method→class)
- **Properties on vertices:** qualified_name, file_path, line_number, end_line, language, security_weight, decorators/attributes, visibility (public/private/internal), is_entry_point, is_sink
- **Properties on edges:** call_site_line, argument_position (for taint tracking)

What does the AGE (openCypher) schema look like? What relational tables sit alongside it (findings, runs, CWE taxonomy)? What indexes are needed for the query patterns below?

### Q2 — Taint-Aware File Selection

Given the graph from Q1, can I replace the keyword-based file selector with a graph query that:

1. For CWE-89 (SQL Injection): Start from known SQL sinks (methods calling `FromSqlRaw`, `raw()`, `text()`, `Query()`, `Execute()`). Walk backwards N hops along CALLS edges to find all methods that can reach a sink. Select the files containing those methods.
2. For CWE-862 (Missing Authorization): Start from entry points (methods with `[HttpPost]`, `[HttpPut]`, `[HttpDelete]`, `@app.route(..., methods=["POST"])` decorators). Walk forward to find what data they modify. Select the controller files + the service/repo files they call.
3. For CWE-502 (Deserialization): Start from deserialization sinks (`pickle.loads`, `BinaryFormatter.Deserialize`, `JsonConvert.DeserializeObject` with TypeNameHandling). Walk backwards to find the HTTP entry points that supply the data.

Write the openCypher queries. How many hops? What's the performance at 5k files / 50k symbols / 200k edges?

### Q3 — Call Graph Construction

The current graph only has import-level and type-reference edges. To do taint tracking (Q2), I need method-level call edges. Research:

1. **What can tree-sitter extract?** Can I get `method A calls method B` from the AST? For Python (name resolution is dynamic) and C# (overloads, interfaces, extension methods)?
2. **What are the limits?** Virtual dispatch, dependency injection, reflection, dynamic imports — where does static analysis fail?
3. **Is there a Python tool that builds call graphs from tree-sitter ASTs?** (Not a full LSP — something lightweight that I can run in batch.)
4. **For C#, can I extract call relationships from Roslyn's semantic model** (which SCAR doesn't currently use — it only uses tree-sitter for structural parsing)? What would it take to add a Roslyn-based call graph extractor that outputs edges I can load into the graph?
5. **What's the realistic precision?** If the call graph has 30% false edges (calls that can't actually happen), does that degrade file selection worse than the current keyword approach?

### Q4 — Cross-Run Persistence and Diff-Based Review

If the graph persists in PostgreSQL between runs:

1. **Incremental updates:** When 5 files change in a 500-file repo, can I update only those files' subgraph (delete old vertices/edges, insert new ones) without rebuilding the whole graph? What does the AGE query look like?
2. **Diff-aware CWE checks:** Can I query "which CWE checks need to re-run" by finding CWE-relevant sinks reachable (within N hops) from the changed files?
3. **Finding persistence:** Design a schema for storing findings across runs. I want: "this SQL injection in UserRepository.cs:45 was first detected on run X, confirmed on run Y, still present on run Z." Fingerprinting strategy?
4. **Performance:** Incremental graph update for 5 changed files in a 500-file repo — latency estimate?

### Q5 — pgvector for Semantic File Selection

Currently file selection is keyword-based. Could I embed each file (or each method/class) using a code embedding model and store the vectors in pgvector? Use case:

1. Given a CWE check prompt like "Check for SQL queries built with string formatting using user input", embed it and find the top-K most semantically similar methods/files.
2. Combine with graph reachability: vector search finds candidate sinks, graph traversal finds the files that can reach those sinks.

**Is this actually better than keyword matching + graph traversal?** Or is it over-engineering — would the graph-based sink-backwards-walk from Q2 already solve the file selection problem without vectors?

Give me a honest cost-benefit. Embedding 50k methods with a code model costs what? How much accuracy does it add over graph traversal alone?

### Q6 — Practical Implementation Path

If the answer to Q1-Q4 is "yes, do it", give me:

1. **Minimum viable implementation:** What's the smallest useful thing? Just the graph with import/inheritance edges + AGE queries for file selection? Or do I need call edges (Q3) to get real value?
2. **PostgreSQL setup:** Homebrew install, AGE extension, pgvector, connection from Python (psycopg, asyncpg, or what?). Any gotchas on macOS ARM64?
3. **Python libraries for AGE:** What's the state of the art? Is there a good Python driver for openCypher on AGE, or do I need to use raw SQL with `ag_catalog` function calls?
4. **Migration path:** How do I go from the current in-memory `ReferenceGraph` to a persistent AGE graph without a big-bang rewrite? Can I keep the in-memory graph as the fast path and sync to PG asynchronously for cross-run persistence?
5. **Data lifecycle:** When does the graph get stale? Should it rebuild on every run, or persist and incrementally update? What's the cache invalidation strategy — git diff? File mtime?

### Q7 — What NOT to Do

I've already assessed and rejected:
- **Neo4j sidecar** — too much operational complexity for a CLI tool
- **Microsoft GraphRAG** — designed for natural language documents, not source code
- **Full LSP integration** — too heavy, too slow, requires language servers running

Tell me if there are other things in this space that look attractive but are traps. SQLite + recursive CTEs vs. PostgreSQL + AGE? NetworkX in-memory vs. AGE persistent? Any Python graph libraries (igraph, graph-tool) that would be better than PostgreSQL for this use case?

### Q8 — The Honest "Don't Do It" Case

Make the strongest case AGAINST adding PostgreSQL. What are the scenarios where the current in-memory graph + better heuristics (PageRank-weighted file ordering, community detection for file clustering, improved keyword matchers) would get 80% of the benefit at 10% of the complexity? Where is the point of diminishing returns?

## Constraints

- **Platform:** macOS ARM64 (Apple Silicon), must also work on Windows. Python 3.12+.
- **No cloud services.** This runs locally. No Azure PG, no managed databases, no network calls for graph queries.
- **Startup time matters.** SCAR currently starts a review in <2 seconds. If PostgreSQL adds 5+ seconds of connection overhead, that's a problem.
- **The LLM is the bottleneck.** Each CWE check takes 30-120 seconds (LLM inference). If graph queries add <1 second total, it's free. If they add 30 seconds, they need to save at least one LLM call to break even.
- **I'm one developer.** Implementation effort matters. A 2-week project that improves file selection accuracy by 30% is worth it. A 2-month project that improves it by 35% is not.
- **Tree-sitter is already installed** for Python and C# parsing. I'd prefer to extend the existing parsers rather than add a new parsing dependency.
- **PydanticAI is the agent framework.** Agents return plain text, parsed by `output_parser.py`. No changes to the LLM layer.

## Output Format

For each question (Q1-Q8), give me:
1. A direct answer (yes/no/it depends, with the key condition)
2. A concrete code example or schema snippet (Cypher queries, Python code, SQL DDL)
3. Risks and gotchas specific to this use case
4. Your confidence level (high/medium/low) and what would change your assessment

End with a single **recommended implementation plan** — phased, with clear go/no-go criteria between phases. Phase 1 should be achievable in 1-2 weeks and deliver measurable improvement to file selection accuracy.
