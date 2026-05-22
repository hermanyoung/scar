---
applyTo: "**/*.py"
---

# Python Security Review Instructions

When reviewing Python code in this repository:

- Flag `eval()`, `exec()`, `compile()` with any external input as code injection.
- Flag `pickle.loads/load`, `marshal.loads`, `shelve.open`, `yaml.load` without `SafeLoader` as insecure deserialization.
- Flag `subprocess.call/run/Popen` with `shell=True` as command injection.
- Flag `os.system()`, `os.popen()` as command injection.
- Flag `hashlib.md5()`, `hashlib.sha1()` for security purposes as weak crypto.
- Flag `jinja2.Environment(autoescape=False)` as XSS.
- Flag Django `mark_safe()` on user-controlled input.
- Flag Django `raw()`, `extra()`, `cursor.execute()` with string formatting as SQL injection.
- Flag `requests.get/post()` with user-controlled URLs as SSRF.
- Flag hardcoded passwords, API keys, secrets, tokens in source code.
