import os
import pathlib
import shutil

# ruleid: python.lang.security.cwe-022.path-traversal
f = open("/uploads/" + user_input + ".txt", "r")

# ruleid: python.lang.security.cwe-022.path-traversal
f = open(f"/data/{filename}", "r")

# ruleid: python.lang.security.cwe-022.path-traversal
path = os.path.join("/uploads", user_input, "file.txt")
f = open(path, "r")

# ruleid: python.lang.security.cwe-022.path-traversal
p = pathlib.Path(user_input)

# ruleid: python.lang.security.cwe-022.path-traversal
shutil.copy(user_input, "/tmp/dest")

# ok: python.lang.security.cwe-022.path-traversal
safe_path = os.path.realpath(os.path.join(base_dir, sanitized_name))
f = open(safe_path, "r")

# ok: python.lang.security.cwe-022.path-traversal
with open("config/settings.yaml", "r") as f:
    data = f.read()

# ok: python.lang.security.cwe-022.path-traversal
p = pathlib.Path(__file__).parent / "data"
