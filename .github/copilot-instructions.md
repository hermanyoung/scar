# Copilot Instructions — Security Review Module

When reviewing PRs to this repository, focus on:

1. **Subprocess safety:** Verify no new subprocess calls exist outside `tools/runner.py`. Never approve `shell=True`.
2. **Output schema compliance:** All agent outputs must use typed Pydantic models, never raw strings.
3. **CWE accuracy:** Verify CWE IDs in rules and findings match the actual vulnerability class.
4. **SARIF compliance:** Check that `external/cwe/cwe-NNN` tags are present on all rules.
5. **Secret safety:** No API keys, passwords, or tokens in committed code. Check `.env` patterns.
6. **Test coverage:** New rules must have matching test files with `ruleid:` and `ok:` annotations.
7. **Budget safety:** No hardcoded pricing or model strings. These come from YAML config.
