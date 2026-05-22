# Knowledge Graph Applicability Assessment for SCAR

**Date:** 2026-05-12
**Source:** Knowledge Graph Feasibility Assessment for Azure Database for PostgreSQL Flexible Server (PG 16/17) — May 2026
**Context:** The source research was conducted for a regulated Microsoft stack (.NET, MAF, Azure PG Flexible Server). This document assesses what transfers to SCAR.

---

## Platform Comparison

| Dimension | Source Research (Microsoft Stack) | SCAR |
|---|---|---|
| Runtime | .NET / MAF (C#) | Python CLI |
| Database | Azure PG Flexible Server | None — ephemeral per run |
| Graph engine | Apache AGE (openCypher) | In-memory `ReferenceGraph` + PageRank |
| Vector store | pgvector / DiskANN | None |
| LLM integration | MAF agents with tools | PydanticAI agents, no tools, inline context |
| Persistence | ACID transactions, cross-run | SARIF files per run, no cross-run state |
| Scale | 10k-100k nodes, 4-5 hop traversals | Typically <5k files, <500 symbols of interest |
| Workload | Dependency chains, impact analysis, compliance traceability | Point-in-time security review, CWE-driven |

**Bottom line:** The source research solves a persistent, multi-hop, transactional graph problem at scale. SCAR solves a batch, single-run, focused-prompt problem. The architectures are fundamentally different.

---

## What Transfers

### 1. GraphRAG Entity Extraction Pattern (High Value)

**Source finding:** Microsoft GraphRAG's pipeline (chunk → extract entities/relationships → resolve duplicates → community detection → summarize) is best used as an **offline indexing pipeline** whose outputs are loaded into a runtime store.

**SCAR application:** SCAR's Pass 4 (CWE-Driven Review) already does a simplified version of this pattern:
- `code_analysis/parsers/` extracts structural entities (classes, methods, imports)
- `code_analysis/graph.py` builds a `ReferenceGraph` with `ReferenceEdge` relationships
- `compute_pagerank()` ranks nodes by centrality
- `context_builder.py` inlines relevant files into LLM prompts

**Transferable improvement:** GraphRAG's **entity resolution / deduplication** stage could improve SCAR's cross-file reasoning. Currently, SCAR's graph resolves imports and type references but doesn't deduplicate entities that appear under different names (e.g., an imported class alias vs. its qualified name, or a C# `using` alias). Adding a lightweight deduplication pass to `build_reference_graph()` would improve file selection accuracy for CWE checks that depend on tracing data flow across modules.

**What NOT to do:** Don't adopt GraphRAG as a dependency. It's Python-only (which fits), but it's research code with breaking changes between minor versions, expensive LLM-driven indexing ($33k on large corpora per Microsoft's own warning), and designed for natural-language document corpora — not source code. SCAR's tree-sitter-based structural extraction is deterministic, free, and more precise for code.

### 2. Hybrid Graph + Focused Query (High Value)

**Source finding:** The recommended "Vector → Graph" and "Graph → Vector" patterns use graph traversal to narrow the search space, then apply focused analysis to the subgraph.

**SCAR application:** This is exactly what SCAR already does — but it validates the approach. The CWE taxonomy's `file_types` field selects relevant files (the "graph filter"), then the LLM analyzes only those files (the "focused query"). The research confirms this is architecturally sound, even at much larger scale.

**Transferable improvement:** Use PageRank scores (already computed in `graph.py`) to **prioritize file ordering** within each CWE check. Files with higher centrality (more callers, more dependents) should appear first in the prompt — they're more likely to be security-relevant entry points. This is a direct application of the research's "Graph → Vector (path-filtered similarity)" pattern, adapted for SCAR's inline-context architecture.

### 3. Recursive CTE Performance Characteristics (Low Value — Informational)

**Source finding:** Recursive CTEs degrade super-linearly beyond depth 3-4 on branching graphs; AGE/Neo4j outperform for variable-depth traversals.

**SCAR application:** SCAR's `compute_pagerank()` is an iterative algorithm on an in-memory adjacency list, not a recursive CTE. The performance characteristics don't directly apply. However, the finding reinforces that SCAR's current approach (in-memory graph, Python-native iteration) is appropriate for its scale (<5k files, <500 symbols). There is no reason to move to a database.

### 4. Cross-Run Finding Persistence (Future — Currently Out of Scope)

**Source finding:** Single-database ACID transactions across relational + graph data enable compliance traceability and impact analysis across time.

**SCAR application:** The spec explicitly excludes graph persistence (Section 1.4, item 10). Findings are ephemeral per run. However, if SCAR ever needs:
- **Regression tracking** across commits (did this CWE appear/disappear?)
- **Finding deduplication** across runs (is this the same SQL injection we saw last week?)
- **Compliance traceability** (show me the history of CWE-862 findings for this repo)

...then a lightweight persistence layer would be needed. The research's recommendation of **AGE on PostgreSQL** is the right architecture for that future state — but only if SCAR moves to a server deployment model. For the current CLI model, SQLite with recursive CTEs or even flat JSON/SARIF diff would suffice.

**Do not build this now.** The spec says no, and the current use case (point-in-time review) doesn't need it.

### 5. Community Detection for File Grouping (Medium Value)

**Source finding:** GraphRAG's hierarchical Leiden community detection groups related entities into communities, enabling "global search" (corpus-level answers via community summaries).

**SCAR application:** SCAR groups files by `file_types` (controller, auth, crypto, etc.) — a manually-curated taxonomy. Community detection on the existing `ReferenceGraph` could automatically identify **clusters of tightly-coupled files** that should be reviewed together, regardless of their naming conventions. This would be particularly useful for:
- C# codebases where the controller/service/repository pattern isn't consistently followed
- Python codebases with non-standard project layouts
- Cross-cutting concerns (e.g., a custom auth middleware imported by 15 files that don't match the `auth` file_type pattern)

**Implementation:** Use a simple connected-components or label-propagation algorithm on the existing `ReferenceGraph` — no need for Leiden. Add a `community` field to the graph nodes and expose it to the CWE file selection logic as a fallback when `file_types` matching yields too few files.

### 6. NuGet Package Vetting Pattern (Low Value — Process)

**Source finding:** Community NuGet packages (`Npgsql.Age`, `ApacheAGE`) require supply-chain vetting before adoption in regulated environments.

**SCAR application:** SCAR's Trivy integration already scans for vulnerable dependencies. The research reinforces the principle that SCAR should flag community-maintained packages with low download counts or no publisher verification — but this is a detection rule improvement, not an architectural change.

---

## What Does NOT Transfer

| Research Recommendation | Why It Doesn't Apply to SCAR |
|---|---|
| Apache AGE on Azure PG Flexible Server | SCAR has no database. Graph is in-memory. |
| Neo4j sidecar with CDC pipeline | Massive over-engineering for a CLI tool. |
| pgvector / DiskANN for similarity search | SCAR doesn't do embedding-based retrieval. Files are selected by type, not similarity. |
| EF Core + raw Cypher split | SCAR is Python, not .NET. No ORM. |
| `Npgsql.Age` / `Neo4j.Driver` NuGet packages | Wrong language ecosystem entirely. |
| MCP server for PostgreSQL | SCAR agents have zero tools by design (Rule 10). |
| Azure Foundry Claude deployment | SCAR uses direct provider SDKs, not Azure Foundry routing. |
| ACID transactions across graph + relational | No database to transact against. |
| DiskANN Advanced Filtering | No vector index to filter. |
| Major-version upgrade planning for AGE | No database to upgrade. |

---

## Recommended Actions

### Do Now (v1 improvements)

1. **PageRank-weighted file ordering in CWE prompts.** Files with higher centrality appear first in the inline context. Change is in `context_builder.py` — sort `file_paths` by PageRank score descending before truncating to token budget. Estimated effort: ~20 lines.

2. **Import alias deduplication in `graph.py`.** When building the symbol index, resolve `using` aliases and Python import aliases to their canonical qualified names. Reduces duplicate edges and improves PageRank accuracy. Estimated effort: ~40 lines in `_build_symbol_index()` and `_resolve_name()`.

### Do Later (v2, if cross-run tracking is needed)

3. **Finding fingerprinting.** Hash each finding by (CWE, file, line-range, snippet) to enable cross-run deduplication without a database. Store fingerprints in a `.scar-history.json` sidecar file in the target repo. This is the minimal viable "persistence" that doesn't require a database.

4. **Community-based file grouping.** Run connected-components on `ReferenceGraph` to automatically discover file clusters. Use as a fallback file selector when `file_types` matching returns <3 files for a CWE check.

### Do Not Do

5. **Do not add a database.** SCAR is a CLI tool. Ephemeral findings are a feature, not a limitation.
6. **Do not adopt Microsoft GraphRAG.** SCAR's tree-sitter parsing is more precise for code than LLM-based entity extraction. GraphRAG is designed for natural-language documents.
7. **Do not add vector search.** File selection by type + PageRank centrality is more deterministic and cheaper than embedding-based retrieval for security review.

---

## Summary

The research validates SCAR's existing architecture: **graph-based file selection → focused LLM analysis** is the right pattern, even at much larger scale. The two immediately transferable improvements are PageRank-weighted context building and import deduplication. Everything else is either already done (hybrid graph+focused query), out of scope (persistence), or wrong ecosystem (.NET/Azure PG).
