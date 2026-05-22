"""CWE-094: Code injection via eval() and exec()."""


def process_expression(user_input: str) -> any:
    # CWE-094: eval with user input
    result = eval(user_input)
    return result


def run_dynamic_code(code: str) -> None:
    # CWE-094: exec with user input
    exec(code)


def compile_and_run(source: str) -> None:
    # CWE-094: compile with user input
    compiled = compile(source, "<user>", "exec")
    exec(compiled)
