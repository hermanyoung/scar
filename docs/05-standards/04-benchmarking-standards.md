# Benchmarking Standards

## Purpose

Benchmark CWE detection accuracy across providers using a fixed reference target. The benchmark measures recall per CWE, not precision (false positive testing requires the corpus-based evaluation harness — see TODO.md).

## Reference Target

**Repository:** `../example-target` (never changes — fixed benchmark)
**Baseline run:** `var/output/2026-05-05-example-target-b7eb11f5/`
**Baseline findings:** 18 holistic findings, 22 SAST findings, 40 total

Any difference in scan results between runs is a regression or improvement in SCAR itself, not a change in the target.

## Baseline CWEs

11 CWEs with known true positives in the reference target:

| CWE | Description | Expected min | Key findings |
|-----|-------------|:---:|---|
| 863 | IDOR — Missing Authorization | 2 | DeleteContact, UpdateContact, GetContacts lack ownership check |
| 200 | Information Exposure | 3 | AppMetadata/Features unauthenticated, PII to OpenAI, GetContacts unfiltered |
| 312 | Cleartext Storage | 1 | AppAdOptions.ClientSecret, Contact PII plaintext |
| 693 | Protection Mechanism Failure | 1 | No rate limiting on AI endpoint, build metadata exposed |
| 116 | Improper Encoding | 1 | User PII concatenated into LLM prompt without escaping |
| 209 | Error Message Exposure | 1 | GetContactPoem missing try/catch on external service call |
| 522 | Insufficiently Protected Credentials | 1 | AppAdOptions.ClientSecret plain string property |
| 311 | Missing Encryption | 1 | Contact PII fields not encrypted at column level |
| 319 | Cleartext Transmission | 1 | APIClientGenerator fetches spec over HTTP |
| 400 | Resource Consumption | 1 | GetContacts fetches all records without pagination |
| 668 | Resource Exposure | 1 | Health check endpoint exposes system state without auth |

## Running Benchmarks

```bash
# Full benchmark — all 11 CWEs, all default providers
python scripts/benchmark_cwes.py --target ../example-target

# Single CWE across all providers
python scripts/benchmark_cwes.py --cwes 863

# Specific providers only
python scripts/benchmark_cwes.py --providers claude:claude-opus,anthropic:claude-opus

# With finding details for failures
python scripts/benchmark_cwes.py --details

# Override temperature
python scripts/benchmark_cwes.py --temperature 0.1

# Multi-run for variance assessment (copilot especially)
python scripts/benchmark_cwes.py --providers copilot:claude-opus --runs 3

# A/B test SDK versions
python scripts/benchmark_cwes.py --ab-sdk 0.2.2,0.3.0 --runs 3 --providers copilot:claude-opus

# Single CWE with trace (debugging)
python scar.py test-cwe --cwe 863 --target ../example-target --provider copilot:claude-opus --trace
```

## Pass/Fail Criteria

| Result | Meaning |
|--------|---------|
| **PASS** | Finding count ≥ expected minimum |
| **PART** | Finding count > 0 but < expected minimum |
| **FAIL** | Finding count = 0 |
| **ERR** | Provider error (session crash, missing API key, timeout) |

A provider's **score** is the count of PASS results out of total non-ERR CWEs tested.

## Interpreting Results

- **FAIL on one run, PASS on re-run** = LLM variance, not a systematic issue. Use `--runs 3` to confirm.
- **FAIL on all runs** = systematic detection gap. Investigate the holistic prompt for that CWE.
- **ERR** = provider infrastructure issue (not a detection problem). Check auth, rate limits, session config.
- **PART** = model finds something but not enough. May be consolidating findings (see ADR-006) or missing cross-file patterns.

## Variance by Provider

| Provider | Variance | Reason |
|----------|----------|--------|
| `claude:claude-opus` | Low | Respects temperature=0.2 |
| `anthropic:claude-opus` | Low | Respects temperature=0.2, native JSON |
| `copilot:claude-opus` | **Medium** | Temperature ignored (hardcoded 0.1, ADR-002), SDK session reliability |
| `codex:gpt` | Medium | Different model family (GPT), different reasoning patterns |
| `openai:gpt` | Low | Respects temperature, native JSON |

## Updating Baselines

When a CWE consistently produces more findings than the current `expected_min` across multiple providers and runs, update the baseline in `scripts/benchmark_cwes.py:BASELINE`. Do not lower `expected_min` without understanding why detection regressed.
