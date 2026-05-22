"""Secure Python code that should produce zero findings."""
import ast
import hashlib
import json
import os
import subprocess

import yaml


def safe_eval(expression: str) -> any:
    """Uses ast.literal_eval instead of eval."""
    return ast.literal_eval(expression)


def safe_subprocess(args: list[str]) -> None:
    """Subprocess with shell=False and list args."""
    subprocess.run(args, shell=False, check=True)


def safe_sql_query(name: str) -> list:
    """Parameterised SQL query."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()


def safe_yaml_load(content: str) -> any:
    """Uses safe_load."""
    return yaml.safe_load(content)


def safe_json_load(data: str) -> any:
    """json.loads is always safe."""
    return json.loads(data)


def safe_hash(data: bytes) -> str:
    """SHA-256 is not weak."""
    return hashlib.sha256(data).hexdigest()


def safe_secret() -> str:
    """Secret from environment."""
    return os.environ.get("APP_SECRET", "")
