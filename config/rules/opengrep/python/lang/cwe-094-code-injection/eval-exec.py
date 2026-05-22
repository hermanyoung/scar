import ast

# ruleid: python.lang.security.cwe-094.eval-exec
result = eval(user_input)

# ruleid: python.lang.security.cwe-094.eval-exec
exec(user_code)

# ruleid: python.lang.security.cwe-094.eval-exec
code = compile(user_input, "<string>", "exec")

# ok: python.lang.security.cwe-094.eval-exec
result = ast.literal_eval("[1, 2, 3]")
