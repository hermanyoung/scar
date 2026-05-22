"""A module with unsafe patterns for testing detection."""

import os
import pickle
import subprocess


def run_user_code(code_string):
    return eval(code_string)


def execute_command(cmd):
    os.system(cmd)


def load_data(raw_bytes):
    return pickle.loads(raw_bytes)


def run_shell(command):
    subprocess.call(command, shell=True)
