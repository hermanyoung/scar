"""CWE-078: Patched versions — no command injection.

These are hard negatives. A correct model should NOT flag these.
Each function mirrors its vulnerable twin but uses safe patterns.
"""
import subprocess
import shlex


def run_with_list_args(user_cmd: str) -> None:
    """SAFE: subprocess with shell=False and list args."""
    args = shlex.split(user_cmd)
    subprocess.call(args, shell=False)


def run_subprocess_safe(filename: str) -> None:
    """SAFE: subprocess.run with list args, no shell."""
    subprocess.run(["cat", filename], shell=False, check=True)


def read_file_safe(path: str) -> str:
    """SAFE: read file directly instead of shelling out."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_subprocess_popen_safe(args: list[str]) -> None:
    """SAFE: Popen with list args, no shell."""
    proc = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE)
    proc.communicate()
