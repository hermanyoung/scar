"""CWE-078: OS command injection via subprocess shell=True and os.system."""
import subprocess
import os


def run_with_shell(user_cmd: str) -> None:
    # CWE-078: subprocess.call with shell=True
    subprocess.call(user_cmd, shell=True)


def run_os_system(filename: str) -> None:
    # CWE-078: os.system with user input
    os.system(f"cat {filename}")


def run_os_popen(path: str) -> str:
    # CWE-078: os.popen with user input
    return os.popen(f"ls {path}").read()


def run_subprocess_popen(cmd: str) -> None:
    # CWE-078: Popen with shell=True
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    proc.communicate()
