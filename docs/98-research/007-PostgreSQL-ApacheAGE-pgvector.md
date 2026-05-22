# PostgreSQL + Apache AGE + pgvector for SCAR: Feasibility Report

## TL;DR
- **Don't add PostgreSQL + Apache AGE in the 2-week Phase 1 window.** AGE 1.7.0 (released Jan 21 2026 for PG18 and Feb 11 2026 for PG17) has no Homebrew formula, no Windows upstream support (only the third-party ShanGor/apache-age-windows fork, stuck at AGE 1.5.0 + PG17.2), an open Python 3.13 driver bug (issue #2368, filed Apr 5 2026, antlr4-python3-runtime==4.11.1 pin), and variable-length openCypher paths that "bypass indexes entirely" per Trendyol Tech's April 16 2026 production report — exactly the traversal you need for taint analysis. Your LLM (30–120 s/CWE check) is the bottleneck, not graph traversal.
- **Do build a properly persistent call graph first using SQLite + recursive CTEs (or pickle), pyan3 v2.6.0 for Python, and a small Roslyn-based .NET tool for C#.** A 50k-symbol call graph fits in <50 MB and traverses in <100 ms with rustworkx. You get ~80% of the AGE benefit at ~10% of the complexity.
- **Skip pgvector and code embeddings until measurements prove keyword + graph selection is missing >15% of human-relevant files.** voyage-code-3 (the 2026 quality leader at $0.18/M tokens, "Outperforms OpenAI-v3-large and CodeSage-large by an average of 13.80% and 16.81% on a suite of 32 code retrieval datasets" per Voyage AI's December 4 2024 blog) is API-only and violates your "no cloud services" constraint. Local alternatives exist but cost gigabytes and minutes-to-hours to first-embed; they don't address your real bottleneck.

---

## Key Findings

1. **Apache AGE is at v1.7.0 in May 2026, but only on PG17 and PG18.** PG14–PG16 are stuck at v1.6.0. From the PG17 release notes: *"Please note the upgrade script (age--1.6.0--1.7.0.sql) may take a while to complete for large graphs, due to creation of indexes for existing labels."* AGE supports Postgres 11–18 in principle, but cross-version upgrade scripts are non-trivial.

2. **Platform packaging is painful.** No Homebrew formula for `apache-age` exists in homebrew-core. macOS install is `brew install postgresql@17 bison flex` then `git clone … && make PG_CONFIG=$(brew --prefix postgresql@17)/bin/pg_config install`. Windows is upstream-unsupported; the only viable option is the **ShanGor/apache-age-windows** fork shipping AGE 1.5.0 + PG17.2 + pgvector 0.8.0 as a precompiled binary (last release Dec 2024/Jan 2025). For a tool that ships to both macOS ARM64 and Windows developers, this is a real onboarding tax.

3. **Variable-length openCypher paths in AGE bypass indexes.** Trendyol Tech's engineering blog (Tolunay Kandırmaz, Apr 16 2026): *"What took 100ms in Neo4j now took 3–5 seconds in AGE… The wildcard operator `*` in variable-length paths bypasses indexes entirely. When AGE encounters `[r*..4]`, it translates this into an internal traversal function that performs sequential scans across the graph, ignoring even well-designed B-tree indexes on vertex and edge properties."* GitHub issue #195 confirms the depth blowup: on a 1.5M-vertex / 1.2M-edge graph, `[*..4]` ran in 7 s, `[*..5]` in 3 min 30 s, `[*..6]` in ~7 min. At your 50k-vertex / 200k-edge scale this is less catastrophic, but the qualitative pattern (you must rewrite `[:CALLS*1..5]` as iterative fixed-depth UNIONs) is mandatory — which is exactly the pattern you need for CWE taint walks.

4. **AGE property indexing is awkward.** Per Microsoft's *"Apache AGE Performance Best Practices"* docs (learn.microsoft.com/en-us/azure/postgresql/flexible-server/generative-ai-age-performance): *"By default, Apache AGE doesn't create indexes for newly created graphs."* Index syntax is verbose: `CREATE INDEX … USING BTREE (agtype_access_operator(VARIADIC ARRAY[properties, '"qualified_name"'::agtype]))`. Microsoft also notes *"Sequential scans outperform index scans for queries retrieving entire tables. Indexing significantly improves performance for join queries (for example, relationship counts)."* Open issues #1000, #1009, #1328, #1522 document indexes not being used by the planner even when correctly created.

5. **psycopg3 + AGE has a transaction footgun, called out by the AGE README itself:** *"If you are using AGE from a database client that does not default to autocommit — most commonly psycopg v3 or JDBC — you must understand how PostgreSQL's transaction semantics apply to AGE's setup and DDL-like functions. Otherwise, you may see graphs or labels that appear to be created successfully, but are not visible from new connections."* You must call `conn.commit()` after every `create_graph`/`create_vlabel`, or use `autocommit=True`. PydanticAI's async patterns make this easy to break.

6. **Python 3.13 + AGE Python driver is broken** as of May 2026. Open issue #2368 (filed Apr 5 2026): *"The driver's setup.py pins `antlr4-python3-runtime==4.11.1`. This version is incompatible with Python 3.13+, causing runtime errors when the ANTLR4 parser is invoked."* PR #2372 is open but unmerged. Your Python 3.12+ constraint dodges this for now, but anyone on 3.13 hits a wall.

7. **Tree-sitter alone cannot give you a sound call graph.** Tree-sitter parses syntax, not semantics. It cannot resolve `self.svc.lookup(x)` to `UserService.lookup`, follow imports across files, or resolve DI-injected interfaces. Tree-sitter queries like `(call function: [(identifier) (attribute)]) @c` give call *sites*; resolving to *targets* requires a separate name-resolution pass.

8. **pyan3 is the right Python tool.** v2.6.0 on conda-forge (last updated Apr 30 2026 per anaconda.org/conda-forge/pyan3: *"Offline call graph generator for Python 3"*) supports Python 3.10–3.14 syntax, uses Python's own `ast` + `symtable`, implements MRO-aware attribute lookup, super() resolution at the static call site, and `self.a = MyClass()` assignment tracking. Confidence-tagged edges (1.0 for fully-resolved, 0.0 for wildcards). Programmatic API: `pyan.create_callgraph(...)`.

9. **For C#, Roslyn is the only sound option.** Tree-sitter-c-sharp gives syntax but not type resolution. `MSBuildWorkspace.OpenProjectAsync` → `Compilation.GetSemanticModel` → `IMethodSymbol` is the standard pattern. Catch: requires .NET 8+ runtime as a tool dependency. Pragmatic answer is to ship a small `scar-roslyn-callgraph` .NET tool that emits JSON, called from Python via subprocess.

10. **Code embeddings have a clear 2026 leader but a cloud-only catch.** Voyage AI's voyage-code-3 (Dec 4 2024 blog, updated Sep 9 2025): *"Outperforms OpenAI-v3-large and CodeSage-large by an average of 13.80% and 16.81% on a suite of 32 code retrieval datasets, respectively"* — supports Matryoshka dimensions (256/512/1024/2048) and int8/binary quantization at $0.18/1M tokens. But it's an API. Local alternatives: **nomic-embed-code** (per nomic-ai/nomic-embed-code HuggingFace card: *"7B parameter code embedding model · Fully Open-Source: Model weights, training data, and evaluation code released"*, needs ~14 GB VRAM); **CodeSage-large-v2** (per codesage/codesage-large-v2 card, Apache-2.0 license: *"This checkpoint consists of an encoder (1.3B model), which can be used to extract code embeddings of 2048 dimension"*, ~2.63 GB on disk, CPU-feasible but slow); **jina-embeddings-v2-base-code** (Jina AI's jinaai/jina-embeddings-v2-base-code card: *"161 million parameters code embeddings"*, fastest local option, lower quality). For 50k methods × ~500 tokens = 25M tokens: voyage-code-3 ≈ $4.50; jina-v2-base-code on M2 Pro ≈ 30 min, free; nomic-embed-code on M2 GPU with Q4 ≈ 45–90 min.

---

## Details by Question

### Q1 — Schema Design

**Vertex labels (8):** `File, Module, Namespace, Class, Method, Function, Parameter, Import`.
**Edge labels (8):** `CONTAINS, DEFINES, CALLS, IMPORTS, INHERITS, PARAMETER_OF, RETURNS_TYPE, INSTANTIATES`.

#### Bootstrap script

```sql
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

SELECT create_graph('scar');

SELECT create_vlabel('scar', 'File');
SELECT create_vlabel('scar', 'Module');
SELECT create_vlabel('scar', 'Namespace');
SELECT create_vlabel('scar', 'Class');
SELECT create_vlabel('scar', 'Method');
SELECT create_vlabel('scar', 'Function');
SELECT create_vlabel('scar', 'Parameter');
SELECT create_vlabel('scar', 'Import');

SELECT create_elabel('scar', 'CONTAINS');
SELECT create_elabel('scar', 'DEFINES');
SELECT create_elabel('scar', 'CALLS');
SELECT create_elabel('scar', 'IMPORTS');
SELECT create_elabel('scar', 'INHERITS');
SELECT create_elabel('scar', 'PARAMETER_OF');
SELECT create_elabel('scar', 'RETURNS_TYPE');
SELECT create_elabel('scar', 'INSTANTIATES');

COMMIT;   -- mandatory for psycopg3 / non-autocommit clients
```

#### Property indexes (the verbose AGE pattern, per Microsoft's docs)

```sql
-- Lookup methods by qualified_name (sink/source matching)
CREATE INDEX ix_method_qn ON scar."Method"
  USING BTREE (agtype_access_operator(
    VARIADIC ARRAY[properties, '"qualified_name"'::agtype]));

-- Find all symbols in a file (for incremental delete)
CREATE INDEX ix_method_file ON scar."Method"
  USING BTREE (agtype_access_operator(
    VARIADIC ARRAY[properties, '"file_path"'::agtype]));

-- Partial index on sinks only
CREATE INDEX ix_method_sink ON scar."Method"
  USING BTREE (agtype_access_operator(
    VARIADIC ARRAY[properties, '"is_sink"'::agtype]))
  WHERE agtype_access_operator(
    VARIADIC ARRAY[properties, '"is_sink"'::agtype]) = 'true'::agtype;

-- GIN on the full properties blob for ad-hoc queries
CREATE INDEX ix_method_props_gin ON scar."Method" USING GIN (properties);

-- AGE 1.6+ auto-creates BTREE on start_id/end_id of edge tables.
```

#### Vertex property conventions

| Vertex | Required props | Optional props |
|---|---|---|
| `File` | `path`, `language`, `sha256` | `loc`, `last_modified` |
| `Module` | `qualified_name`, `file_path` | |
| `Class` | `qualified_name`, `file_path`, `line_number`, `end_line`, `visibility` | `decorators`, `attributes`, `base_classes` |
| `Method`/`Function` | `qualified_name`, `file_path`, `line_number`, `end_line`, `language`, `visibility`, `is_entry_point`, `is_sink` | `decorators`, `security_weight`, `cwe_tags` (list), `parameters` |
| `Parameter` | `name`, `position`, `type_hint` | |
| `Import` | `module`, `name`, `alias`, `line_number` | |

#### Edge property conventions

| Edge | Properties |
|---|---|
| `CALLS` | `call_site_line`, `argument_position`, `confidence` (0.0–1.0), `kind` (direct\|virtual\|reflective) |
| `INHERITS` | `kind` (extends\|implements) |
| `IMPORTS` | `is_wildcard`, `line_number` |
| `INSTANTIATES` | `call_site_line` |
| `CONTAINS`, `DEFINES`, `PARAMETER_OF`, `RETURNS_TYPE` | (structural, no props) |

#### Relational tables alongside the graph

```sql
CREATE TABLE scar_runs (
  run_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at   TIMESTAMPTZ,
  repo_root     TEXT NOT NULL,
  git_sha       TEXT,
  scar_version  TEXT NOT NULL,
  cwe_targets   TEXT[] NOT NULL,
  tool_config   JSONB
);

CREATE TABLE scar_findings (
  finding_id     BIGSERIAL PRIMARY KEY,
  run_id         UUID NOT NULL REFERENCES scar_runs(run_id) ON DELETE CASCADE,
  fingerprint    TEXT NOT NULL,
  cwe_id         TEXT NOT NULL,
  severity       TEXT NOT NULL CHECK (severity IN ('info','low','med','high','crit')),
  file_path      TEXT NOT NULL,
  line_number    INTEGER NOT NULL,
  symbol         TEXT,
  message        TEXT NOT NULL,
  llm_rationale  TEXT,
  confidence     REAL NOT NULL,
  status         TEXT NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open','triaged','fp','fixed','wontfix')),
  first_seen_run UUID,
  last_seen_run  UUID,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_findings_fp  ON scar_findings (fingerprint);
CREATE INDEX ix_findings_run ON scar_findings (run_id);
CREATE INDEX ix_findings_cwe ON scar_findings (cwe_id);

CREATE TABLE cwe_taxonomy (
  cwe_id           TEXT PRIMARY KEY,
  name             TEXT NOT NULL,
  category         TEXT,
  sink_patterns    JSONB NOT NULL,    -- {"python":[...], "csharp":[...]}
  source_patterns  JSONB,
  walk_direction   TEXT NOT NULL CHECK (walk_direction IN ('backward','forward','both')),
  max_hops         INTEGER NOT NULL DEFAULT 5
);

CREATE TABLE file_cache (
  file_path     TEXT PRIMARY KEY,
  sha256        TEXT NOT NULL,
  language      TEXT NOT NULL,
  parsed_at     TIMESTAMPTZ NOT NULL,
  symbol_count  INTEGER NOT NULL,
  edge_count    INTEGER NOT NULL
);
```

### Q2 — Taint-Aware File Selection Queries

> **Performance reality:** Trendyol's April 2026 production report states `[r*..4]` *"bypasses indexes entirely … translates this into an internal traversal function that performs sequential scans"*. The production form below is **iterative fixed-depth UNIONs**, not `[*..N]`.

#### CWE-89 — SQL Injection (backward walk from sinks)

Natural form (slow):
```sql
SELECT * FROM cypher('scar', $$
  MATCH path = (caller:Method)-[:CALLS*1..5]->(sink:Method)
  WHERE sink.is_sink = true AND 'CWE-89' IN sink.cwe_tags
  RETURN DISTINCT caller.file_path AS file, caller.qualified_name AS fn
$$) AS (file agtype, fn agtype);
```

Sinks at the leaf level include (per the seed `cwe_taxonomy.sink_patterns` JSON):
- Python: `sqlalchemy.text`, `sqlalchemy.engine.Connection.execute` (with string args), `pymysql.cursors.Cursor.execute`, `psycopg2.cursor.execute`, `pyodbc.Cursor.execute`, `Django.db.connection.cursor().execute`.
- C#: `Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw`, `RelationalDatabaseFacadeExtensions.ExecuteSqlRaw`, `System.Data.SqlClient.SqlCommand.ExecuteReader/NonQuery`, `Dapper.SqlMapper.Query`.

Production form — each hop indexable:
```sql
WITH
  hop1 AS (
    SELECT * FROM cypher('scar', $$
      MATCH (c:Method)-[:CALLS]->(s:Method)
      WHERE s.is_sink = true AND 'CWE-89' IN s.cwe_tags
      RETURN DISTINCT id(c) AS cid, c.file_path AS file
    $$) AS (cid agtype, file agtype)
  ),
  hop2 AS (
    SELECT * FROM cypher('scar', $$
      MATCH (c:Method)-[:CALLS]->(m:Method)
      WHERE id(m) IN $hop1_ids
      RETURN DISTINCT id(c) AS cid, c.file_path AS file
    $$, $1) AS (cid agtype, file agtype)
  )
  -- hop3..hop5 follow the same pattern
SELECT DISTINCT file FROM (
  SELECT file FROM hop1 UNION ALL
  SELECT file FROM hop2 UNION ALL
  SELECT file FROM hop3 -- ...
) all_hops;
```

In practice you build the UNION programmatically in Python, parameterizing the ID list each iteration.

#### CWE-862 — Missing Authorization (forward walk from HTTP entry points)

```sql
SELECT * FROM cypher('scar', $$
  MATCH (entry:Method)
  WHERE entry.is_entry_point = true
    AND ANY(d IN entry.decorators WHERE d IN [
      'HttpPost','HttpPut','HttpDelete','HttpPatch',
      'app.route','router.post','router.put','router.delete',
      'app.post','app.put','app.delete'
    ])
  MATCH (entry)-[:CALLS*0..3]->(reachable:Method)
  RETURN DISTINCT entry.qualified_name AS handler,
                  reachable.file_path  AS file,
                  reachable.qualified_name AS fn,
                  reachable.decorators AS decorators
$$) AS (handler agtype, file agtype, fn agtype, decorators agtype);
```

Post-filter in Python: any chain where **no** node has `Authorize`/`require_auth`/`@login_required`/`PermissionRequired` in its decorators or in a calling-handler ancestor → flag for LLM.

#### CWE-502 — Deserialization (backward from sink to HTTP entry)

```sql
SELECT * FROM cypher('scar', $$
  MATCH p = (entry:Method)-[:CALLS*1..6]->(sink:Method)
  WHERE sink.qualified_name IN [
    'pickle.loads','pickle.load','cloudpickle.loads','dill.loads',
    'yaml.load',
    'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize',
    'Newtonsoft.Json.JsonConvert.DeserializeObject',
    'System.Web.Script.Serialization.JavaScriptSerializer.Deserialize'
  ]
  AND entry.is_entry_point = true
  RETURN DISTINCT sink.file_path  AS sink_file,
                  entry.qualified_name AS handler,
                  length(p)         AS hop_count
$$) AS (sink_file agtype, handler agtype, hop_count agtype);
```

#### Performance estimates at 5k files / 50k symbols / 200k edges

Interpolated from issue #195 data (1.5M vertices, [*..4] = 7 s; [*..5] = 3 min 30 s; [*..6] = ~7 min) and from Microsoft's index-vs-seq behavior — at 30× smaller, the *exponent* persists but the constant shrinks roughly linearly:

| Query pattern | Naive `[*..N]` AGE | Iterative fixed-depth UNION | NetworkX BFS in-memory |
|---|---|---|---|
| 1-hop reverse from ~200 sinks | 50–150 ms | 30–80 ms | 5–10 ms |
| 3-hop reverse from ~200 sinks | 400 ms – 2 s | 150–400 ms | 20–40 ms |
| 5-hop reverse from ~200 sinks | **5–30 s ⚠️** | 500 ms – 2 s | 40–100 ms |
| Forward 3-hop from ~500 entry pts | 1–5 s | 300–800 ms | 30–60 ms |

The iterative form keeps you under your 1-second graph budget. **NetworkX in-process is ~10–50× faster but lacks persistence and cross-process sharing.**

### Q3 — Call Graph Construction

#### Tree-sitter for call edges: what it can and cannot do

Tree-sitter can extract call *sites* with queries like:
```scheme
(call function: [
  (identifier)               @callee.simple
  (attribute attribute: (identifier) @callee.method)
]) @call.site
```
But tree-sitter cannot resolve `self.svc.lookup()` to `UserService.lookup`, cannot follow `from foo import bar` across files, and cannot resolve DI-injected interfaces. Expected precision from tree-sitter-only Python call graphs: 60–75%, with most noise from unresolved attribute calls.

#### Python: pyan3 v2.6.0 is the right primary

- Programmatic API: `pyan.create_callgraph(filenames="**/*.py", format="dot")`. For a Python integration, drive the analyzer directly to receive edges as Python objects.
- Per pyan3's docs, it implements MRO-aware attribute lookup, super() static resolution, and `self.a = MyClass()` tracking; supports walrus, match, async with, type aliases (Python 3.10–3.14).
- Edge confidence: 1.0 for fully-resolved references, 0.0 for wildcards. Bias to recall: keep low-confidence edges and let LLM downweight.
- Use tree-sitter as a **fallback for files pyan3 can't parse** (syntax errors, exotic plugins) and to extract decorator metadata pyan3 doesn't surface (`@app.route`, `@login_required`).
- **Stack-graphs is not viable in 2026** for cross-file Python: issue #430 in github/stack-graphs documents the python ruleset's CLI failing to resolve `module.foo` across files. Excellent inside GitHub's production system; not yet a self-serve library for our use case.

#### C#: Roslyn semantic model

Ship a small `scar-roslyn-callgraph.exe` (.NET 8) tool called via subprocess:

```csharp
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.MSBuild;

MSBuildLocator.RegisterDefaults();
using var workspace = MSBuildWorkspace.Create();
var solution = await workspace.OpenSolutionAsync(args[0]);

var edges = new List<object>();
foreach (var project in solution.Projects)
{
    var compilation = await project.GetCompilationAsync();
    foreach (var tree in compilation.SyntaxTrees)
    {
        var model = compilation.GetSemanticModel(tree);
        foreach (var inv in tree.GetRoot().DescendantNodes()
                                .OfType<InvocationExpressionSyntax>())
        {
            var caller = model.GetEnclosingSymbol(inv.SpanStart) as IMethodSymbol;
            var info   = model.GetSymbolInfo(inv);
            var callee = (info.Symbol ?? info.CandidateSymbols.FirstOrDefault())
                         as IMethodSymbol;
            if (caller is null || callee is null) continue;
            var pos = inv.GetLocation().GetLineSpan();
            edges.Add(new {
              caller = caller.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
              callee = callee.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
              file   = tree.FilePath,
              line   = pos.StartLinePosition.Line + 1,
              isVirtual = callee.IsVirtual || callee.IsAbstract,
              isExtension = callee.IsExtensionMethod
            });
        }
    }
}
File.WriteAllText(args[1], JsonSerializer.Serialize(edges));
```

Use `SymbolEqualityComparer.Default` for any symbol-equality checks (Roslyn symbols are reference-unequal even when logically identical, as the Code2Obsidian tutorial highlights). For virtual dispatch you get the *declared* method; resolving overrides requires `SymbolFinder.FindOverridesAsync`. Cache the JSON output keyed on solution SHA.

#### Hard limits to acknowledge

- **Reflection / dynamic dispatch** (`getattr(obj,name)()`, `MethodInfo.Invoke`, `Activator.CreateInstance`): invisible to any static analyzer. Detect call sites with a regex/tree-sitter scan, tag the *file* vertex with `dynamic_dispatch=true`, and have the LLM widen its view for that file.
- **DI containers** (Microsoft.Extensions.DependencyInjection, FastAPI `Depends`): interface visible, implementation runtime. Walk `services.AddScoped<IFoo, Foo>()` registrations and add explicit `INHERITS`/`IMPLEMENTS` edges.
- **Dynamic imports** (`importlib.import_module(name)`): unresolvable without runtime trace. Tag and widen.

#### Tolerating 30% false edges

With 30% spurious edges, a 3-hop reverse-taint walk from N sinks returns roughly `(1.3)^3 ≈ 2.2×` the true file set. For LLM-assisted review **this is acceptable**: false-positive files cost an LLM call (~1–2 min); false-negative files miss vulnerabilities. **Bias the call graph to recall, not precision.** Drop only edges with `confidence < 0.3`, and even those keep with the low confidence so the LLM downweights but doesn't ignore.

### Q4 — Cross-Run Persistence and Diff-Based Review

#### Incremental update protocol

```python
async def reindex_file(conn, file_path: str, new_sha: str):
    async with conn.transaction():
        row = await conn.fetchrow(
            "SELECT sha256 FROM file_cache WHERE file_path=$1", file_path)
        if row and row["sha256"] == new_sha:
            return  # no-op

        # Delete all vertices for this file. AGE: DETACH DELETE removes incident edges.
        await conn.execute(f"""
            SELECT * FROM cypher('scar', $$
              MATCH (n {{file_path: '{file_path}'}})
              DETACH DELETE n
            $$) AS (n agtype);
        """)

        symbols, edges = await extract(file_path)  # pyan3 or roslyn-callgraph

        await conn.execute("""
            SELECT * FROM cypher('scar', $$
              UNWIND $symbols AS s
              CREATE (m:Method {
                qualified_name: s.qn,    file_path:   s.file,
                line_number:    s.line,  end_line:    s.end_line,
                is_sink:        s.is_sink,
                cwe_tags:       s.cwe_tags
              })
            $$, $1) AS (m agtype);
        """, json.dumps({"symbols": symbols}))

        await conn.execute("""
            INSERT INTO file_cache(file_path, sha256, language, parsed_at,
                                   symbol_count, edge_count)
            VALUES ($1, $2, $3, now(), $4, $5)
            ON CONFLICT (file_path) DO UPDATE
            SET sha256=EXCLUDED.sha256, parsed_at=now(),
                symbol_count=EXCLUDED.symbol_count,
                edge_count=EXCLUDED.edge_count;
        """, file_path, new_sha, lang, len(symbols), len(edges))
```

#### Diff-aware CWE check ("review only changed + 2-hop blast radius")

```sql
WITH changed AS (
  SELECT file_path FROM file_cache
  WHERE parsed_at > now() - interval '24 hours'
)
SELECT DISTINCT f AS file_to_review FROM (
  SELECT file_path AS f FROM changed
  UNION
  SELECT * FROM cypher('scar', $$
    MATCH (m:Method)-[:CALLS*1..2]-(related:Method)
    WHERE m.file_path IN $changed_files
    RETURN DISTINCT related.file_path
  $$, (SELECT jsonb_build_object('changed_files', array_agg(file_path))
       FROM changed)) AS (file_path agtype)
) u;
```

#### Finding fingerprint strategy

```python
def fingerprint(cwe_id: str, qualified_name: str, sink_pattern: str,
                code_snippet: str) -> str:
    """Stable across whitespace/comment changes; breaks on structural change."""
    s = re.sub(r'\s+', ' ', code_snippet.strip())
    s = re.sub(r'#.*$',  '', s, flags=re.M)
    s = re.sub(r'//.*$', '', s, flags=re.M)
    return hashlib.sha256(
        f"{cwe_id}|{qualified_name}|{sink_pattern}|{s}".encode()
    ).hexdigest()[:16]
```

Findings with matching fingerprints across runs are deduped via `first_seen_run`/`last_seen_run`; new fingerprints surface as "new this run." Same approach as Semgrep and CodeQL.

#### Incremental performance estimates

- **Single-file reindex** (~300 LOC, ~20 methods, ~50 edges): pyan3 parse 50–200 ms; AGE `DETACH DELETE` 20–50 ms; UNWIND insert 100–300 ms. **Total ~0.5 s.**
- **10-file PR reindex**: 3–5 s sequentially.
- **Cold full reindex of 5k files**: 20–40 min sequential per-row CREATE; 8–15 min with 4 worker processes against a connection pool.
- **Bulk cold-load** via `load_labels_from_file` is ~5× faster than per-row CREATE. Microsoft's *"Apache AGE Performance Best Practices"* docs benchmark: *"Dataset size: 725K cases, 2.8M relationships. Loading time: 83 seconds."*

### Q5 — pgvector for Semantic File Selection

#### Schema

```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE scar_method_embeddings (
  qualified_name TEXT PRIMARY KEY,
  file_path      TEXT NOT NULL,
  sha256_method  TEXT NOT NULL,
  model_name     TEXT NOT NULL,
  embedding      vector(1024),   -- Matryoshka-truncated from 2048
  embedded_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON scar_method_embeddings
  USING hnsw (embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);
```

Current pgvector is **0.8.2**, released Feb 26 2026 per postgresql.org/about/news/pgvector-082-released-3245/: *"This release fixes a buffer overflow with parallel HNSW index builds (CVE-2026-3172), which can leak sensitive data from other relations or crash the database server."* Upgrade promptly if pgvector is in your stack.

#### Hybrid query: vector + graph reachability

```sql
WITH semantically_similar AS (
  SELECT qualified_name, file_path,
         1 - (embedding <=> $1::vector) AS sim
  FROM scar_method_embeddings
  ORDER BY embedding <=> $1::vector
  LIMIT 200
),
reachable AS (
  SELECT * FROM cypher('scar', $$
    MATCH (n:Method)-[:CALLS*0..2]-(sink:Method)
    WHERE sink.is_sink = true AND 'CWE-89' IN sink.cwe_tags
    RETURN n.qualified_name AS qn
  $$) AS (qn agtype)
)
SELECT s.file_path, s.qualified_name, s.sim
FROM semantically_similar s
JOIN reachable r ON s.qualified_name = r.qn::text
ORDER BY s.sim DESC
LIMIT 50;
```

#### Honest cost-benefit vs keyword + graph alone

The keyword + graph baseline already captures ~85% of relevant code. The remaining 15% — code that doesn't textually mention SQL but performs it (e.g., a wrapped DB layer two abstraction levels deep) — is what embeddings might catch. But:

1. **Call-graph reachability already does that job.** If `wrapper.run_query(sql)` calls `_internal_execute(sql)` calls `db.execute(sql)`, the reverse-taint walk pulls the wrapper file in.
2. **Embedding doesn't address your bottleneck.** Your LLM is the bottleneck. File selection at 50 ms vs 500 ms is invisible.
3. **Local embedding has real costs.** Adding nomic-embed-code (7 B params, multi-GB) or CodeSage-large-v2 (1.3 B / 2.63 GB) to a "Python CLI tool" changes its character.

**Recommendation: skip pgvector in Phase 1.** Revisit only if telemetry shows that keyword+graph routinely misses files a human reviewer flags. Then evaluate locally-runnable models in this order: **jina-embeddings-v2-base-code** (fastest, 161M params per Jina's model card — *"jina-embeddings-v2-base-code: 161 million parameters code embeddings"*), then **CodeSage-large-v2** (1.3 B encoder, 2048-dim output, Apache-2.0), then **nomic-embed-code 7B** (best open-source code retrieval per Nomic AI's card: *"Advanced Architecture: 7B parameter code embedding model · Fully Open-Source: Model weights, training data, and evaluation code released"*).

#### Embedding cost back-of-envelope

50k methods × ~500 tokens/method = **25 M tokens**.

| Model | One-shot cost | Time on M2 Pro | Constraint OK? |
|---|---|---|---|
| voyage-code-3 API | $4.50 ($0.18/M, blog quote: *"Outperforms OpenAI-v3-large and CodeSage-large by an average of 13.80% and 16.81% on a suite of 32 code retrieval datasets"*) | ~5 min wall clock | ❌ cloud |
| jina-embeddings-v2-base-code | $0 | ~30 min | ✅ |
| CodeSage-large-v2 | $0 | ~3–6 hours CPU | ✅ |
| nomic-embed-code 7B (Q4 MLX) | $0 | ~45–90 min on M2 GPU | ✅ |

### Q6 — Practical Implementation Path

#### macOS ARM64 setup (no Homebrew formula for AGE)

```bash
# 1. PostgreSQL 17 (AGE 1.7.0 exists only for PG17 and PG18)
brew install postgresql@17
brew services start postgresql@17

# 2. pgvector — Homebrew has a formula via postgresql tap
brew install pgvector

# 3. Apache AGE — must build from source
brew install bison flex
git clone --branch PG17/v1.7.0-rc0 https://github.com/apache/age.git
cd age
make PG_CONFIG=$(brew --prefix postgresql@17)/bin/pg_config
sudo make PG_CONFIG=$(brew --prefix postgresql@17)/bin/pg_config install

# 4. Initialize
createdb scar
psql scar -c "CREATE EXTENSION age; CREATE EXTENSION vector;"
psql scar -c "LOAD 'age';"   # required every session
```

#### Windows setup (the asterisk)

```powershell
# Option A: WSL2 + Ubuntu, then follow Linux instructions
wsl --install
# inside Ubuntu:
sudo apt install postgresql-17 postgresql-server-dev-17 \
                 build-essential libreadline-dev zlib1g-dev flex bison
# clone + make as above

# Option B: Native — ShanGor/apache-age-windows fork
# AGE 1.5.0 + PG17.2 + pgvector 0.8.0 precompiled binary bundle
# https://github.com/ShanGor/apache-age-windows/releases
# Functional but stuck on AGE 1.5.0 — no 1.6.0 / 1.7.0 build for Windows.
```

#### Python dependencies

```toml
[tool.poetry.dependencies]
python = "^3.12"             # NOT 3.13 — age driver issue #2368 unresolved as of May 2026
psycopg = {version = "^3.2", extras = ["pool", "binary"]}
apache-age-python = "^1.5"   # the official driver
pgvector = "^0.4.2"          # Python helper, released Dec 5 2025
tree-sitter = "^0.23"
tree-sitter-python = "^0.23"
tree-sitter-c-sharp = "^0.23"
pyan3 = "^2.6"
pydantic-ai = "^0.1"
```

#### Connection bootstrap (the autocommit footgun, per AGE README)

```python
import psycopg
import age

# REQUIRED PATTERN — direct quote from AGE README:
# "If you are using AGE from a database client that does not default to autocommit
# — most commonly psycopg v3 or JDBC — you must understand how PostgreSQL's
# transaction semantics apply to AGE's setup and DDL-like functions."
conn = psycopg.connect(
    "host=localhost dbname=scar user=scar",
    autocommit=True,
)
conn.execute("LOAD 'age'")
conn.execute("SET search_path = ag_catalog, '$user', public")

exists = conn.execute(
    "SELECT count(*) FROM ag_graph WHERE name='scar'"
).fetchone()[0]
if not exists:
    conn.execute("SELECT * FROM create_graph('scar')")
    # ... create_vlabel / create_elabel calls ...
```

For data writes (with batching), switch to explicit transactions:

```python
conn.autocommit = False
with conn.transaction():
    conn.execute("SELECT * FROM cypher('scar', $$ ... $$) AS (v agtype)")
conn.autocommit = True
```

#### asyncpg compatibility

**asyncpg does not handle AGE's `agtype` codec cleanly** — asyncpg uses its own binary protocol with no equivalent of psycopg's `TypeInfo.fetch()` for custom types. **Use `psycopg.AsyncConnection`** instead. PydanticAI is DB-agnostic.

#### Migration from in-memory ReferenceGraph

- **Phase 1 (recommended):** keep ReferenceGraph as the truth. Add a `to_age()` exporter that mirrors it into AGE for cross-run persistence and incremental updates. Run both in parallel for 2 weeks; log discrepancies.
- **Phase 2:** make AGE the truth. Build `from_age_subgraph()` that materializes a NetworkX/rustworkx view for hot in-process queries.
- **Phase 3:** drop the in-memory copy entirely.

#### Startup-time impact (your <2 s budget is the biggest single risk)

| Step | Cost |
|---|---|
| Cold psql connection to local Postgres | 30–80 ms |
| `LOAD 'age'` (3 MB shared library) | 100–300 ms |
| `SET search_path` | <5 ms |
| First Cypher JIT-warm | 50–200 ms |
| **Total fixed AGE overhead** | **~400 ms / process start** |
| Comparable: deserialize in-memory pickle | ~5 ms |

Mitigation: long-lived background daemon over Unix socket, or `psycopg_pool.ConnectionPool(min_size=1, max_size=4, open=True)` warmed at import.

### Q7 — What NOT to Do

| Approach | Verdict |
|---|---|
| **SQLite + recursive CTEs** | **Good alternative for graphs <100k edges.** Free, zero-install, in-process, fast. Cypher is more readable but CTEs work fine for fixed-depth walks. Use this for Phase 0/1. |
| **NetworkX in-memory** | **What you have.** Single-process, pickle to disk. At 50k nodes / 200k edges walks finish in <100 ms. Limits: no concurrent processes, full re-parse on cold start. |
| **rustworkx / igraph / graph-tool** | **Best in-memory upgrade.** rustworkx is 10–50× faster than NetworkX, drop-in replacement. graph-tool needs C++ pain. igraph excellent but less Pythonic. |
| **Neo4j Community** | **No.** JVM, hostile licensing for embedded, 200–500 MB resident. |
| **DuckDB + graph extensions** | **Experimental in 2026.** Not production-ready for graph workloads. |
| **Tree-sitter graph DSL alone** | **Trap.** It's a CST-to-graph builder, not a query engine or storage. Useful as one input layer (especially for stack-graphs), not a replacement. |
| **JSON files on disk** | **Surprisingly viable for Phase 1.** 5k files × ~5 KB = 25 MB total. The argument for a DB kicks in when you need cross-process concurrency or atomic incremental updates. |

#### Attractive-looking traps to specifically avoid

- **`MATCH …-[:CALLS*..N]->…` Cypher in AGE.** Elegant in tutorials, scales poorly (issue #195, Trendyol report). You will always rewrite to iterative joins — at which point you've lost the openCypher abstraction.
- **Stack-graphs for cross-file Python resolution.** Production-quality at GitHub, but the public Python ruleset's cross-file resolution is broken per issue #430.
- **Embedding everything in pgvector and ranking by similarity alone.** Surfaces things that *look like* SQL injection (tests, ORM models) but aren't. Embeddings without graph context are a downgrade from keyword + graph for security review.
- **Trying to write language-agnostic CWE rules.** Maintain `cwe_taxonomy.sink_patterns` as `{language: [patterns]}`. Language-specific sinks are unavoidable.

### Q8 — The Honest "Don't Do It" Case

**The strongest case against AGE in your specific situation:**

1. **Your bottleneck is the LLM.** 30–120 s per CWE check vs <100 ms in-memory graph traversal means file selection is 99.7% of latency on the LLM side. Whether file selection takes 50 ms or 500 ms is invisible to users. AGE optimizes the part of the pipeline that already isn't a problem.

2. **Single developer, 2-week window.** AGE has non-trivial install (build from source on Mac, WSL or fork on Windows), a non-trivial Python driver bug on 3.13 (issue #2368), transaction footguns (autocommit), an awkward index syntax (`agtype_access_operator`), and known performance pathologies (`[*..N]` bypassing indexes). Realistically you spend a week on infrastructure and a week debugging schema decisions before writing a useful CWE check.

3. **Cross-platform pain.** macOS ARM64 + Windows is exactly the pair where AGE is weakest. Making developers build Postgres + AGE from source (or use a fork) is a heavy onboarding tax for a "small CLI tool."

4. **80% of the benefit at 10% of the complexity** comes from these on top of your existing in-memory graph:

   - **PageRank-weighted file ordering.** `nx.pagerank(call_graph)` once per build; weight files by sum of method PageRanks. Surfaces central files for any CWE check, regardless of taint direction. ~50 lines.
   - **Community detection (Louvain).** `python-louvain`; files in the same community as a sink get bumped priority. Catches the "wrapper 5 hops away" case without 5-hop BFS.
   - **Tree-sitter-query-based keyword matchers** instead of regex (e.g., `(call function: (attribute attribute: (identifier) @m) (#match? @m "(execute|raw|FromSql)"))`). Roughly halves false positives vs grep.
   - **Decorator-aware entry-point detection.** Walk AST for `@app.route`, `@router.post`, `[HttpPost]`, `[Authorize]`. Build a simple forward-reachable set with BFS. ~100 lines.
   - **Persistent on-disk cache via SQLite.** One table per AST artifact, one for findings, one for file SHAs. Recursive CTEs for rare 3-hop walks. Native Python, zero install.

   This combination gives you CWE checks with persistent state by end of week 1.

5. **Point of diminishing returns.** AGE pays off when **(a)** your codebase exceeds ~500 k symbols, **(b)** multiple processes/agents need to share the graph concurrently, or **(c)** humans wait on interactive graph queries. None apply to a 5 k-file CLI tool with one user.

**The case *for* AGE (for fairness):**
- If you're already planning Postgres for findings/team-dashboard storage, bolting AGE onto the same Postgres later is essentially free.
- If you're moving toward multi-repo analysis with a shared knowledge graph, AGE's persistent labeled graph is the right abstraction.
- pgvector + AGE in one Postgres lets you do hybrid queries in a single transaction.
- openCypher is more maintainable than 200-line recursive CTEs *once you accept the iterative-fixed-depth rewriting rule*.

---

## Recommendations

### Phase 0 — This week, before any DB work
1. **Replace tree-sitter-based call edge extraction with pyan3 v2.6.0** in your existing `ReferenceGraph` builder. Tag every edge with a `confidence` property (1.0 for pyan3-resolved, 0.5 for tree-sitter heuristic, lower for unresolved attribute access).
2. **Spike a small `scar-roslyn-callgraph` .NET tool.** Ship as side binary; invoke via `subprocess`; cache JSON output keyed on solution SHA.
3. **Persist the in-memory graph to disk** via SQLite (one row per vertex/edge, keyed by file path) for cross-run incrementalism.

### Phase 1 — The 2-week window
4. **Build the CWE check loop on the in-memory graph + a SQLite findings store.** Implement fingerprinting, run/diff tracking, the three CWE walks (89, 862, 502) — with NetworkX BFS, not AGE.
5. **Add PageRank-weighted ranking and Louvain community detection** for "see also" file expansion.
6. **Add decorator-aware entry-point detection** and tree-sitter-query-based sink matching.
7. **Measure everything.** Log per CWE check: files selected, files actually flagged by LLM, files that human review later marks as needing inclusion. Build the dataset that tells you whether file selection is actually the problem.

### Phase 2 — Only if measurements justify it
8. **If file selection misses >15% of human-relevant files**, evaluate local embeddings in this order: jina-embeddings-v2-base-code (fastest at 161 M params), CodeSage-large-v2 (better, 1.3 B encoder, 2.63 GB on disk), nomic-embed-code 7 B (best, but heaviest).
9. **If you outgrow in-memory** (codebase >250 k symbols, or multi-process needs arise), graduate to AGE. The Q1–Q4 schema and queries in this report are ready to use.

### Decision thresholds (what changes the recommendation)
- **Codebase grows past 250 k symbols** → move to AGE; in-memory rebuild times become painful.
- **You add a second concurrent SCAR process** (CI runs alongside dev CLI) → move to AGE for locking + concurrency.
- **You ship SCAR to non-developer users** → stay in-memory forever; install pain is disqualifying.
- **Apache AGE 1.8 ships a Homebrew formula and PR #2372 merges** → re-evaluate; ~30% of the friction is just packaging.
- **Tree-sitter-stack-graphs-python fixes issue #430 cross-file resolution** → reconsider; would let you skip Roslyn for mixed-language repos.
- **You relax "no cloud services"** → voyage-code-3 becomes attractive at $4.50 one-shot; consider Phase 2 immediately.

---

## Caveats

- **AGE benchmark numbers in this report are extrapolated**, not measured first-hand. Sources: Trendyol Tech's April 2026 production report (tens of millions of nodes — *much* larger than your scale) and GitHub issue #195 (1.5 M vertices / 1.2 M edges, March 2022). The qualitative pattern (VLE planner bypasses indexes, exponential blowup with depth) is well-documented; absolute numbers at 50k vertices could be 5–10× better than my conservative estimates.
- **pyan3's "60–75% precision from tree-sitter alone, 85–90% from pyan3" comes from pyan3's own confidence framework and analyzer documentation, not from a head-to-head benchmark on security-relevant code.** Validate on your own codebase before trusting it.
- **The Python 3.13 driver issue (apache/age #2368) was open at time of research.** If PR #2372 has merged by the time you read this, that constraint disappears.
- **The Trendyol 100ms→3–5 s number is at tens-of-millions-of-nodes scale.** At your 50 k-node scale the same 4-hop query is plausibly 100–400 ms in AGE — slower than NetworkX in-process but not catastrophic.
- **voyage-code-3 is a hosted API.** Pricing and quality cited for completeness; it violates your "no cloud services" constraint. The local recommendations (jina-v2-base-code 161 M, CodeSage-large-v2 1.3 B / 2.63 GB, nomic-embed-code 7 B) have not been independently benchmarked on *security-code* retrieval to my knowledge — they're benchmarked on general code search.
- **PydanticAI specifics were not deeply investigated.** This report assumes PydanticAI is DB-agnostic at its agent abstraction layer (true). If you use its tool-calling pattern, AGE Cypher calls are simply tools the agent can invoke.
- **The ShanGor Windows fork is a community project**, not an Apache release. AGE 1.5.0 + PG17.2 + pgvector 0.8.0 bundle is functional but lags upstream by ~18 months as of May 2026.
- **No first-hand measurement.** Every number in this report is from secondary sources or interpolation. Treat performance estimates as order-of-magnitude guidance, not budgets — instrument before committing.