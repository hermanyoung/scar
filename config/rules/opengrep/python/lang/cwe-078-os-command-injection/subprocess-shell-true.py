import subprocess
import os

# ruleid: python.lang.security.cwe-078.subprocess-shell-true
subprocess.call(f"ls {user_input}", shell=True)

# ruleid: python.lang.security.cwe-078.subprocess-shell-true
subprocess.run("echo " + user_input, shell=True)

# ruleid: python.lang.security.cwe-078.subprocess-shell-true
subprocess.Popen(cmd, shell=True)

# ruleid: python.lang.security.cwe-078.subprocess-shell-true
os.system(f"rm -rf {path}")

# ruleid: python.lang.security.cwe-078.subprocess-shell-true
os.popen(f"cat {filename}")

# ok: python.lang.security.cwe-078.subprocess-shell-true
subprocess.run(["ls", "-la", directory], shell=False, check=True)

# ok: python.lang.security.cwe-078.subprocess-shell-true
subprocess.run(["echo", "hello"], check=True)
