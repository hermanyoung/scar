# The 2025–2026 Command-Line Web Application Penetration Testing Toolchain, with LLM-Assisted Verification

## TL;DR
- **Build the toolchain around three layers**: (1) a Katana-based authenticated crawler that exports browser session state, feeding (2) a ProjectDiscovery scanning pipeline (httpx → Arjun/x8 → Nuclei + targeted exploiters like sqlmap/Dalfox/SSRFmap/jwt_tool), and orchestrating it with reconFTW or Osmedeus; then bolt on (3) an LLM-verification layer — Burp AI's "Explore Issue"/BAC false-positive reduction in Pro 2025.2+ for interactive triage, and a custom PydanticAI/Claude pipeline for headless CI triage of JSONL findings.
- **The single biggest 2025 shift is LLM-assisted triage moving from research to production**: PortSwigger shipped Burp AI in Burp Suite Pro 2025.2 (Explore Issue, Explainer, BAC false-positive reduction); ProjectDiscovery shipped `nuclei -ai` for template generation; Caido shipped an AI SDK with the Shift Agents plugin; and Cybersecurity AI (CAI) and Vulnhuntr emerged as serious open-source agentic frameworks. PentestGPT remains the canonical reference (12.5k GitHub stars, v1.0.0 released December 24, 2025, with a reported 86.5% success rate on the XBOW benchmark — 90/104) but independent benchmarks show end-to-end autonomy still tops out around 21–31% success — treat LLMs as **verifiers and amplifiers, not replacements**.
- **For authentication**, the modern best practice is to log in once through a real browser, export cookie/header/JWT state, and propagate that state via `-H` flags or `Authorization`/`Cookie` headers to every CLI tool; for short-lived OAuth2 tokens, use ZAP's HTTP Sender scripts or a Caido workflow as the single source-of-truth that refreshes and re-injects bearer tokens on 401.

---

## Key Findings

1. **Katana is now the default authenticated crawler** for both server-rendered and SPA targets. It supports `-headless`, `-jc/-jsl` (JS crawl + JSLuice), `-aff` (auto form-fill), `-xhr` extraction, and — critically — can attach to an already-authenticated Chrome remote-debugging session, side-stepping all complex login flows including MFA. ZAP remains the right tool when you need a managed authentication context with session verification and credential refresh; Burp Suite Pro is the right tool when you need AI-assisted triage and Shadow Repeater payload mutation.
2. **Nuclei's template library passed 1,496 unique KEV-flagged templates** in November 2025 and continues to ship ~200 new templates per release, including production coverage for 2025's worst RCEs (CVE-2025-61882 Oracle EBS, CVE-2025-59287 WSUS, CVE-2025-49844 Redis, CVE-2025-64446 FortiWeb). Nuclei's `-ai` flag and `nuclei-templates-ai` repo generate YAML templates from natural-language prompts but ProjectDiscovery itself labels those AI-generated templates "AI-generated and not verified."
3. **For parameter discovery, the three-tool stack is Arjun + x8 + ParamSpider/GAU**, with Arjun's `--passive` mode pulling from Wayback/CommonCrawl, x8 (Rust) being fastest for brute-force, and Param-Miner (Burp) catching cache-poisoning vectors the CLI tools miss. LinkFinder + SecretFinder + subjs/getJS form the JS-mining pipeline; jsluice (now built into Katana via `-jsl`) is the modern replacement for many of these.
4. **LLM verification of scanner findings is most production-ready inside Burp AI's "Explore Issue" and "Broken Access Control False Positive Reduction"** (Burp Suite Pro 2025.2). For CLI/CI pipelines, the practical pattern is JSONL output → Python orchestrator → Anthropic or OpenAI API with structured-output (PydanticAI) for triage. Vulnhuntr (Protect AI, ~2.6k stars, Feb 2025) does LLM-driven SAST for Python codebases and is useful for code-level verification of findings. CAI (Alias Robotics) is the most mature open-source agentic framework with multiple peer-reviewed papers.
5. **The single most-overlooked authentication primitive in 2025** is Katana's `-cdp` connection to a running Chrome with `--remote-debugging-port=9222`. This bypasses MFA, captcha, OAuth redirects, SSO, and client certificates because you're literally re-using the browser's authenticated state. Pair this with ZAP's `ZAP_AUTH_HEADER_VALUE` environment variable or `httpx -H "Authorization: Bearer …"` for downstream tools.

---

## Details

### 1. Authenticated Web Crawling Tools

**Katana (ProjectDiscovery, Go)** — The dominant CLI crawler in 2025. Two modes: `standard` (fast raw HTTP) and `-headless` (real Chrome, handles React/Angular/Vue SPAs). Key auth methods:
- **Cookie/session**: `-H cookie.txt` or `-H "Cookie: PHPSESSID=…"`.
- **Bearer tokens**: `-H "Authorization: Bearer eyJ…"`.
- **Active browser session (MFA, OAuth, client certs, SSO)**: start Chrome with `--remote-debugging-port=9222`, log in manually, then `katana -cdp ws://127.0.0.1:9222/devtools/browser/…`. Per the docs: "Katana can also connect to active browser session where user is already logged in and authenticated."
- Output: JSONL via `-j`, with fields like `url`, `path`, `qurl`, `kv` etc. Scope filters: `-cs include-regex`, `-cos out-of-scope-regex`, `-fs rdn|fqdn|dn`, `-iqp` (ignore-query-params dedup), `-fst` (path-segment normalization threshold).
- Recommended starter: `katana -u https://target -headless -system-chrome -jc -jsl -aff -xhr -d 5 -em json,js,html -j -o out.jsonl`.

**OWASP ZAP (2.16.x, Java)** — Best when you need *managed* authentication with re-authentication on session expiry. The Automation Framework (YAML-driven `zap.sh -cmd -autorun plan.yaml`) is now the recommended automation path; the older zap-baseline.py/zap-full-scan.py wrappers are migrating to it. Auth: form-based, JSON-based, HTTP/NTLM, script-based (Nashorn/Graal.js). For OAuth2 bearer tokens, write an Authentication Script that POSTs to the IdP and stores `loginToken` in a global var, then an HTTPSender script that injects `Authorization: Bearer ${loginToken}` and re-fires the auth script on 401. For headless CI, `ZAP_AUTH_HEADER_VALUE` env var injects a static header into every request without scripting. AJAX Spider handles SPAs.

**Burp Suite Professional (2025.2+, Java)** — Per AppSec Santa's 2026 review, Burp Suite Professional is priced at $499/user/year (effective March 1, 2025): "Professional — $499/year. Full automated scanner, unthrottled Intruder, all manual tools, BApp Store access, Burp AI." In 2025 it gained AI features that no OSS tool yet matches: **Explore Issue** (autonomous follow-up on Scanner findings, generates PoCs, hunts escalation paths), **Explainer** (security-focused commentary on unfamiliar headers/JS), **AI-generated recorded login sequences**, and **Broken Access Control false-positive reduction**. Per PortSwigger docs: "Burp enhances Broken Access Control scan checks by intelligently filtering out false positives before they're reported." Headless Burp runs via `burpsuite_pro --user-config-file --project-file --unpause-spider-and-scanner`; the REST API drives crawls and scans. Shadow Repeater (free BApp Store extension) mutates Repeater payloads with AI.

**Caido (0.50.x, Rust)** — Burp's modern alternative. Workflows (visual, no-code) replace BChecks. Now ships an AI SDK with the Shift Agents community plugin; Assistant (paid tier) integrates GPT-4o/4o-mini/3.5-Turbo for traffic Q&A and CSRF PoC generation. The Bugcrowd guide notes: "The Assistant is Caido's security-focused AI LLM integration… The Assistant is also able to generate proofs of concept for Cross-Site Request Forgery attacks." Headless mode is limited compared to Burp, so most users still pair Caido for manual work with CLI tools for automation.

**gospider / hakrawler** — Legacy Go crawlers; both still useful for fast non-JS recon but Katana has surpassed them. hakrawler is essentially a thin wrapper for quick "what URLs exist?" runs.

**httpx (ProjectDiscovery)** — Not a crawler but the canonical glue between everything. `cat subs.txt | httpx -H "Cookie: …" -mc 200 -sc -tech-detect -title -ip -jsonl > probe.jsonl`. Use it after subdomain enum, after crawling, after parameter discovery, after wayback fetches.

**feroxbuster (Rust)** — Recursive content discovery; superior to gobuster for API endpoint mining because of its built-in link extraction and clean output. Authenticated API discovery: `feroxbuster -u https://api.target/ -w raft-medium-directories.txt -H "Authorization: Bearer eyJ…" -x json -C 404`.

**ffuf (Go)** — The workhorse fuzzer for parameters, vhosts, paths, raw-request replay. Supports client-cert auth (`-cc`/`-ck`), cookie strings (`-b`), arbitrary headers, JSON output (`-o results.json -of json`), and recursive mode.

### 2. Parameter and Link Extraction

**Arjun (Python, s0md3v)** — Default for GET/POST/JSON parameter discovery. Critical flags: `-m POST`, `--passive` (Wayback/CommonCrawl), `--include "token=xyz"`, `--casing camel`, `--headers "Authorization: Bearer …"`, `-oB` (Burp-friendly). Wordlists derive from CommonCrawl + SecLists + param-miner merge. `msarjun` wraps it for mass parallel runs.

**x8 (Rust, Sh1Yo)** — Fastest hidden-parameter scanner; integrates with Burp via Custom Send-To. Strongest detector when responses reflect with different counts (where Arjun and Param-Miner often fail per Sh1Yo's own comparison). Per the docs: "Most of the time param miner and arjun fails to detect parameters with a different number of reflections."

**Param-Miner (Burp ext, PortSwigger)** — Right-click → "Guess (cookies|headers|params)". Best for cache-poisoning and unkeyed-header discovery; CLI cannot replicate.

**ParamSpider / GAP (GetAllParams) / waybackurls / gau** — Historical parameter mining from archive.org, AlienVault OTX, and CommonCrawl. Pipeline: `gau --subs < subs.txt | grep -E '\.js$' | sort -u > js.txt`.

**LinkFinder (Python)** — Regex-based endpoint extraction from JS. Sample: `python linkfinder.py -i 'Desktop/*.js' -r ^/api/ -o results.html`.

**SecretFinder (Python, m4ll0k)** — LinkFinder-based regex pack for API keys, JWTs, OAuth tokens. CLI mode: `python3 SecretFinder.py -i https://example.com/1.js -o cli`.

**subjs / getJS (Go, lc / 003random)** — Pull JS file URLs from a list of hosts; pipe to LinkFinder/SecretFinder/jsluice.

**Katana `-jsl` (JSLuice integration)** — Modern unified JS analysis built into Katana itself; obviates many of the standalone tools above for routine work.

**API-specific**:
- **Swagger/OpenAPI**: Nuclei has `exposures/apis/swagger-api.yaml`-style templates; ZAP's OpenAPI add-on imports specs; RESTler consumes them for stateful fuzzing.
- **GraphQL**: GraphQLmap (introspection + injection), Nuclei has graphql-introspection templates, Burp's InQL ext.
- **WSDL/SOAP**: ZAP's SOAP Scanner add-on, WSScanner, or wfuzz with raw envelopes.

### 3. Comprehensive Vulnerability Scanning

**Nuclei (ProjectDiscovery, Go)** — The keystone scanner. Per the official repo: "Total unique KEV templates: 1496 - Use nuclei -tags kev,vkev to scan for actively exploited vulnerabilities." Coverage spans OWASP Top 10, CVEs (197 new templates in November 2025 alone), exposures, misconfigurations, default creds, takeovers, cloud config review, GraphQL, and SSRF/SSTI/XSS/SQLi probes. Auth: `-H` headers, `-c` cookies, custom matchers. Output: JSONL with `-jle`. Update with `nuclei -ut`.

**sqlmap (Python, stamparm)** — The de facto SQLi exploiter. sqlmap v1.10 was released January 2, 2026, and as of May 2, 2026 the latest stable is v1.10.5 (per PyPI: pypi.org/project/sqlmap/). Accepts Burp/ZAP request logs (`-r request.txt`), cookie strings (`--cookie`), CSRF tokens (`--csrf-token`, `--csrf-url`), and parses any GET/POST/header/cookie/JSON parameter. Switches: `--batch`, `--risk=3 --level=5`, `--os-shell`, `--dump`, `--tamper=between,space2comment`. Pip-installable.

**XSStrike / Dalfox** — Dalfox (Go, hahwul) is the modern XSS scanner: reflected, stored, DOM, blind XSS with callback URLs. February 2025 Help Net Security writeup notes: "The uniqueness of Dalfox lies in its speed and ability to easily integrate into pipelines." Output formats: plain, json, jsonl, markdown, sarif, toml — and it now exposes an MCP stdio server (`scan_with_dalfox`, `get_results_dalfox`, etc.) for LLM agent integration. Cookie auth: `-C "PHPSESSID=…"`. Pipeline: `cat urls.txt | dalfox pipe -b https://callback.xss.ht --format jsonl`.

**commix (Python)** — All-in-one OS command injection (GET, POST, headers, cookies, file upload). Pair with Nuclei's `command-injection` tags.

**tplmap (Python, epinna)** — SSTI detector (Jinja2, Twig, Smarty, Mako, etc.). Less maintained but still works against most targets.

**SSRFmap (Python, swisskyrepo)** — Takes a Burp request file (`-r`) and parameter (`-p url`), tries modules (`readfiles`, `portscan`, `redis`, `gopher`, `aws`, `smtp`). Can spawn a reverse-shell listener with `-l`.

**dalfox + corsy + crlfuzz + jwt_tool**:
- **Corsy (Python, s0md3v)** — CORS misconfiguration scanner; tests dynamic origin reflection, null origin, trusted-prefix bypasses.
- **CRLFuzz (Go, dwisiswant0)** — `subfinder | httpx | crlfuzz`; tests header injection.
- **jwt_tool (Python, ticarpi)** — JWT cracker, alg=none bypass, key confusion (HS256/RS256), claim tampering, embedded-jwk and kid injection tests.

**API fuzzing**:
- **RESTler (Microsoft Research)** — Stateful OpenAPI/Swagger fuzzer. Four modes: compile → test → fuzz-lean → fuzz. Infers producer-consumer dependencies; finds 500s + custom checkers for resource leaks, hierarchy violations.
- **Newman / Postman CLI** — replay Postman collections in CI.
- **wfuzz / ffuf** — generic API parameter fuzzing.

**Race conditions**: Burp Repeater "send group in parallel" (single-packet attack) since 2023. CLI equivalents: **Turbo Intruder** (Burp ext, but Jython scripts can be invoked outside Burp), **h2spacex** (Python/Scapy library for HTTP/2 single-packet attacks, implements James Kettle's BH 2024 timing variant), and **h3spacex** for HTTP/3-over-QUIC. Per PortSwigger: "The single-packet attack is a new technique for triggering web race conditions. It works by completing multiple HTTP/2 requests with a single TCP packet."

**File-upload**: fuxploider (almandin), upload-bypass-tool.

**Deserialization**:
- **ysoserial (Java, frohoff)** — Generates Java serialized payloads (CommonsCollections1–7, Spring, Groovy, JRE chains).
- **ysoserial.net (pwntester)** — .NET payloads (BinaryFormatter, ObjectStateFormatter, SoapFormatter, LosFormatter, Json.Net, NetDataContractSerializer, XmlSerializer); covers ObjectDataProvider, PSObject, WindowsIdentity, TypeConfuseDelegate chains.
- **PHPGGC (ambionics)** — PHP gadget chains for Laravel/Symfony/Yii/Drupal.
- **NotSoSecure Serialized Payload Generator (2025 release)** — web UI wrapper around all three.
- **marshalsec** — Java non-native (Jackson, XStream, SnakeYAML, Hessian) deserialization.

**WebSocket**: ZAP's WebSocket fuzzer, PortSwigger's WebSocket Turbo Intruder (Sept 2025), wsrepl.

**Business logic** is still mostly manual, but Burp AI's Explore Issue and Caido Shift Agents are the first AI tools attempting it.

### 4. LLM-Assisted Verification and Analysis

**Burp AI (Burp Suite Pro 2025.2/2025.3)** — Currently the most production-ready LLM-pentest integration. Five features:
1. **Explore Issue** — per PortSwigger docs: "Explore Issue is an AI-powered pentesting assistant that performs automated follow-up investigations on vulnerabilities identified by Burp Scanner. It helps you to efficiently validate issues, generate proof-of-concept (PoC) exploits, and uncover additional attack vectors."
2. **Explainer** — instant security-focused explanations of headers/cookies/JS.
3. **AI-generated recorded login sequences**.
4. **Broken Access Control false-positive reduction** — directly attacks the highest-volume FP source in DAST.
5. **AI-powered extensions via Montoya API** — third-party devs can route through PortSwigger's trust boundary; data is not retained by the AI provider.

Pricing is via AI credits. Per PortSwigger's official 2025.2 release notes: "we've given you 10,000 free AI credits. This is equivalent to 5 US dollars worth of AI requests." Per the AI credits documentation (portswigger.net/burp/documentation/desktop/burp-ai/ai-credits): "Unused credits expire 12 months after purchase." Shadow Repeater (free BApp) mutates Repeater payloads automatically every 5 requests and reports anomalies via the Organizer.

**PentestGPT (GreyDGL, 12.5k GitHub stars as of May 2026)** — The canonical academic LLM-pentest framework, USENIX Security 2024 Distinguished Artifact. Tripartite design: Reasoning Module (Pentesting Task Tree), Generation Module, Parsing Module. The 2024 paper reports 228.6% task-completion uplift over GPT-3.5 baselines. v1.0.0 was released December 24, 2025 with a self-reported "86.5% success rate on XBOW benchmark (90/104)" per the release notes. However, independent benchmarks tell a more cautious story (see below). **Treat as a reasoning copilot, not an autonomous tester.**

**Cybersecurity AI / CAI (aliasrobotics, open-source)** — The most mature open-source agentic framework for offensive security. Supports 300+ LLMs (OpenAI, Anthropic, DeepSeek, Ollama). Top-10 in Dragos OT CTF 2025, top-1 AI team in "AI vs Human" CTF 2025. The April 2025 paper claims CAI "outperforms state-of-the-art results in CTF benchmarks… up to 3,600× faster than humans in specific tasks." Built-in guardrails against prompt injection. CAI PRO adds the alias1 cybersecurity-tuned LLM.

**Vulnhuntr (Protect AI, ~2.6k stars, Feb 2025)** — LLM-driven SAST. Per the README: "Vulnhuntr leverages the power of LLMs to automatically create and analyze entire code call chains starting from remote user input and ending at server output for detection of complex, multi-step, security-bypassing vulnerabilities that go far beyond what traditional static code analysis tools are capable of performing." Python-only (a fork `xvulnhuntr` adds C#/Java/Go/Ollama). Finds LFI/AFO/RCE/XSS/SQLi/SSRF/IDOR. CLI: `vulnhuntr -r /path/to/repo -l claude`.

**ProjectDiscovery Nuclei AI** — Added via PR #6041 (Feb 2025); ships in Nuclei v3.3.x. The `-ai` flag and the `nuclei-ai-extension` browser plugin call PDCP's hosted template-generation API. Per the official repo: "Using ProjectDiscoveryAI API, we automatically generate Nuclei templates for newly disclosed CVEs and existing vulnerabilities… These templates are AI-generated and not verified." This is **generation, not finding-triage** — use it to quickly write a one-off template, not to filter results.

**ReconAIzer (hisxo, Burp ext, v0.7)** — Jython Burp extension calling the OpenAI Chat Completions API to brainstorm potential GET/POST/JSON parameter names, endpoints, and subdomains from a selected request. Project is essentially in maintenance mode (v0.1 release notes literally read "First release of ReconAizer (and probably the only one)"). Useful as a recon brainstorm, not for finding triage.

**Caido Assistant + Shift Agents (2025)** — Assistant (paid tier) is Caido's security-focused LLM chat using GPT-4o/4o-mini/3.5-Turbo. Shift Agents (community plugin via the Caido Plugin Store) lets users build "domain-specific agents that can run autonomous tests while you work on other things." The Caido AI SDK (introduced mid-2025) provides "first-class AI support for plugins."

**Building a custom LLM verification pipeline (the practical recipe)**:
1. Run scanners with structured output: `nuclei -jle nuclei.jsonl`, `dalfox … --format jsonl`, `katana -j`.
2. Python orchestrator reads JSONL and chunks per-finding.
3. For each finding, send a structured prompt to Anthropic/OpenAI: include the request, response, scanner reasoning, and a few-shot of known true/false positives. Use **PydanticAI** to enforce typed output: `class Triage(BaseModel): verdict: Literal["true_positive","false_positive","needs_human"]; confidence: float; reasoning: str; suggested_followup: str`.
4. Persist results to a DuckDB/SQLite ledger; emit only `true_positive` + `needs_human` to your reporting layer.
5. Add a verifier step: have the LLM generate a targeted curl/Python verification request, execute it, feed the response back into a second prompt.

The right prompt-engineering pattern is **role + scope + structured output + verification step**: tell the model it's a senior pentester reviewing scanner output, give it the exact request/response, force structured JSON output, and never trust a "true positive" without an executed verification request. The Smarttecs review of Burp's AIHTTPAnalyzer found that vague prompts produced generic SQLi descriptions and non-working PoCs — specificity and context are everything.

**What does NOT belong in this layer**: Garak, NeMo Guardrails, and PyRIT are LLM-application red-team tools, not web-application finding triagers. NVIDIA's own framing: "NVIDIA uses LLM red teaming as part of its Trustworthy AI process to assess risks before releasing models." Keep them out of your web pentest pipeline unless your target *is* an LLM endpoint.

### 5. Toolchain Integration

**Output formats** that interoperate:
- JSONL is the de facto standard (Katana, Nuclei, Dalfox, httpx, ffuf).
- SARIF for IDE/GitHub integration (Dalfox supports it natively).
- Burp/ZAP XML for replay into other proxies.
- OpenAPI/Postman collections for API tools.

**reconFTW (six2dez, Bash)** — The most popular all-in-one CLI orchestrator. Modular config (`reconftw.cfg`), AX/Axiom distributed scanning, adaptive rate-limiting (`ADAPTIVE_RATE_LIMIT` with 429/503 backoff), incremental scanning, BBRF integration, Faraday reporting, and an `AI_MODEL` setting that generates Markdown reports via Ollama (default `llama3:8b`) with `executive`, `brief`, or `bug hunter` profiles.

**Osmedeus (j3ssie, Go)** — Declarative YAML workflow engine. Master-worker via Redis, webhook triggers, 80+ utility functions including TypeScript/Python scripting, SARIF parsing, CDN/WAF classification. Best for teams running continuous scans against large attack surfaces.

**Ax Framework (formerly Axiom)** — Cloud orchestration; spins up VPS fleets across Hetzner/Linode/AWS for distributed scanning. Per the reconFTW wiki: "The Ax Framework is the successor to Axiom, which is now in maintenance mode."

**Orchestration patterns**:
- **Bash one-liners for ad-hoc**: `katana -u $T -H @cookies -jc -j | jq -r .url | httpx -silent | nuclei -jle out.jsonl`.
- **Python orchestrators for production**: subprocess + asyncio + a Pydantic schema for findings; write a single SQLite database that every tool writes into.
- **Temporal/Prefect workflows for enterprise**: each scanner becomes a workflow activity with retries, timeouts, and human-approval steps for destructive scans.

**Feeding crawl into scanners**:
```bash
katana -u https://target -headless -H @auth.txt -jc -j -o crawl.jsonl
jq -r '.url' crawl.jsonl | sort -u | httpx -mc 200,401,403 -silent > live.txt
jq -r 'select(.endpoint_type=="form") | .url' crawl.jsonl > forms.txt
cat live.txt | nuclei -H @auth.txt -severity medium,high,critical -jle nuclei.jsonl
cat forms.txt | xargs -I {} arjun -u {} --headers "$(cat auth.txt)" -oJ params/
```

### 6. Authentication Handling Best Practices

**Browser-state-first strategy** (recommended default):
1. Open Chrome with `--remote-debugging-port=9222 --user-data-dir=/tmp/pentest-profile`.
2. Log in manually, including any MFA.
3. Export cookies + storage with a browser extension (EditThisCookie, Cookie-Editor) or use the CDP API.
4. Save as `auth.txt`:
   ```
   Cookie: sessionid=…; csrftoken=…
   Authorization: Bearer eyJ…
   X-API-KEY: …
   ```
5. Reuse `auth.txt` via `-H @auth.txt` everywhere (Katana, httpx, Nuclei, ffuf, feroxbuster, Arjun via `--headers`).
6. For Katana, alternatively use `-cdp ws://127.0.0.1:9222/devtools/browser/…` to inherit the live session including JS execution context.

**Token-refresh for long scans**: Write an OAuth2 refresh sidecar in Python that writes a fresh token to `auth.txt` every N minutes; tools re-read on each invocation. For tools that load headers once at startup (Nuclei), break large target lists into chunks shorter than your token lifetime. ZAP's HTTPSender script with Verification Strategy is the canonical solution and will re-auth on 401 automatically.

**CSRF tokens**:
- sqlmap: `--csrf-token=csrf_token --csrf-url=https://target/form`.
- ZAP: Anti-CSRF Token configuration in the Context → Session Properties.
- Burp: macros + session handling rules.
- Custom tools: write a wrapper that GETs the form, extracts the token, then POSTs.

**Cookie jar sharing**: standardize on Netscape format (`cookies.txt`) which curl, wget, and most Go/Python tools accept; or HTTPie's `--session` JSON for HTTPie/requests.

**Client certificates**: ffuf (`-cc`/`-ck`), curl (`--cert`/`--key`), nuclei (`-cc`/`-ck`), ZAP (Network → Client Certificates).

---

## Recommendations

### Stage 1 — The minimum credible CLI toolchain (do this first)

Install: `katana`, `httpx`, `nuclei` (+ updated templates), `subfinder`, `ffuf`, `feroxbuster`, `dalfox`, `sqlmap`, `arjun`, `x8`, `gau`, `subjs`, `linkfinder`, `secretfinder`, `jwt_tool`, `ysoserial`, `ysoserial.net`. Add `jq`, `anew`, `qsreplace`, `gf` for plumbing.

Baseline pipeline (~10 min for a small target):
```bash
# 1. Recon
subfinder -d $T -all -silent | httpx -silent -H @auth.txt > live.txt

# 2. Crawl (authenticated, headless for SPAs)
katana -list live.txt -headless -system-chrome -jc -jsl -xhr \
  -H @auth.txt -d 5 -em json,js,html -j -o crawl.jsonl

# 3. Parameter mining
jq -r '.url' crawl.jsonl | sort -u | gau --subs | sort -u > urls.txt
arjun -i urls.txt --headers "$(cat auth.txt)" --passive -oJ params.json

# 4. Vulnerability scan
nuclei -list urls.txt -H @auth.txt -severity medium,high,critical \
  -tags cve,kev,oast -jle nuclei.jsonl

# 5. XSS sweep
cat urls.txt | qsreplace FUZZ | dalfox pipe -C "$(grep Cookie auth.txt)" \
  --format jsonl -o dalfox.jsonl

# 6. SQLi on interesting params
cat params.json | jq -r '.[] | .url' | \
  xargs -I{} sqlmap -u {} --cookie="$(grep Cookie auth.txt)" --batch --risk=2 --level=3
```

### Stage 2 — Add LLM verification

For interactive engagements: use **Burp Suite Pro 2025.2+** with Burp AI enabled (Explore Issue + BAC false-positive reduction). The free 10,000-credit allocation is officially worth exactly $5 (per PortSwigger's 2025.2 release notes); refill as needed and remember unused credits expire 12 months after purchase.

For headless CI/CD or large-scope bug bounty: build a **Python + PydanticAI triage pipeline** against Claude or GPT-4. Estimate ~$0.01–0.03 per finding to triage with Claude Sonnet; ~$0.001 with Haiku. The pipeline should:
1. Consume `nuclei.jsonl`, `dalfox.jsonl`, ZAP JSON.
2. Send per-finding (request + response + scanner reasoning) with structured output schema.
3. Execute LLM-suggested verification requests where safe.
4. Emit a deduplicated, ranked Markdown report.

For agentic exploration: pilot **CAI** on out-of-scope HTB labs first, then carefully scope it to authorized engagements with rate-limits and a non-destructive policy.

### Stage 3 — Orchestrate

Use **reconFTW** for solo bug bounty and small consulting engagements. Switch to **Osmedeus** (or a Temporal-based custom orchestrator) when you have > 100 targets, multiple operators, or compliance-driven evidence requirements.

### Benchmarks that should change your recommendations
- **Switch to Burp AI in active scans** when your false-positive rate on access-control findings exceeds ~30% — the BAC FP reducer is purpose-built for that.
- **Add a custom LLM triage layer** when you exceed ~50 Nuclei findings per engagement, where manual triage becomes the bottleneck.
- **Adopt CAI or PentestGPT** only after you've validated against your own benchmark (e.g., your last 5 engagements re-played as evaluations). Independent benchmarks report fully-autonomous success rates of only 21–31%, so expect to spend more time supervising than the marketing suggests.
- **Move from Bash to Python/Temporal** when your shell pipeline exceeds ~200 lines or you need multi-tenant evidence retention.

---

## Caveats

1. **AI-generated artifacts are unverified by default.** ProjectDiscovery itself labels its AI-generated Nuclei templates "AI-generated and not verified"; Burp AI is explicit that it augments but does not replace the tester; Vulnhuntr's README notes "you should not consider this a high-fidelity tool." Treat every LLM output as a hypothesis until verified by a real request.
2. **Autonomous LLM pentesting is still early.** The December 2025 PentestEval benchmark (arXiv:2512.14233) reports: "End-to-end pipelines reach only 31% success rate, and existing LLM-powered systems such as PentestGPT, PentestAgent, and VulnBot exhibit similar limitations, with autonomous agents failing almost entirely." AutoPenBench (Gioacchini et al., arXiv:2410.03225, EMNLP 2025 industry track) found: "the fully autonomous agent demonstrates limited effectiveness, achieving only a 21% Success Rate (SR) across our benchmark… the assisted agent demonstrates substantial improvements, attaining 64% of success rate." PentestGPT-Auto specifically scored 31% in PentestEval, vs 39% with human-in-the-loop. These are research numbers, not production SLAs.
3. **License and cost**: Burp Suite Pro is $499/user/year (effective March 1, 2025, per AppSec Santa's 2026 review) with AI credits billed separately. Caido Pro is cheaper but its AI features require a paid tier. Nuclei/sqlmap/Dalfox/ZAP and the Python tools are free.
4. **Source freshness varies.** ReconAIzer is essentially unmaintained; tplmap is several years stale; gospider commits are infrequent. Katana, Nuclei, sqlmap (v1.10.5 as of May 2026), Dalfox, ZAP, ffuf, feroxbuster, Caido, and Burp are all actively maintained as of 2026.
5. **Authentication assumptions**: Many CLI tools load headers once at startup. For OAuth2 access tokens shorter than your scan duration, you either need ZAP's HTTPSender pattern, a sidecar refresher, or to split scans into time-bounded chunks. Test this before kicking off a 24-hour scan.
6. **Legal/ethical**: Every tool here can cause outages, data corruption, or audit-log floods. RESTler's docs explicitly warn its `Fuzz` mode "may create outages in the service under test." Authorization in writing, in scope, before any active scanning — full stop.
7. **Source quality**: Some of the GitHub stars, version numbers, and ranking claims cited above come from vendor or project self-reports; PentestGPT's 86.5% XBOW benchmark claim, for example, is the project's self-reported number on its own validation suite, while independent benchmarks (PentestEval, AutoPenBench) consistently show lower autonomous success rates. Trust peer-reviewed benchmarks over vendor marketing for capability sizing.