"""CWE-089: SQL injection via raw queries in Django and sqlite3."""
import sqlite3
from django.db import connection


def unsafe_sqlite_query(user_input: str) -> list:
    # CWE-089: string formatting in sqlite3 query
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()


def unsafe_django_raw(name: str):
    # CWE-089: Django raw() with f-string
    from myapp.models import User
    return User.objects.raw(f"SELECT * FROM myapp_user WHERE name = '{name}'")


def unsafe_django_cursor(user_id: str) -> None:
    # CWE-089: Django cursor.execute with string formatting
    cursor = connection.cursor()
    cursor.execute(f"DELETE FROM myapp_user WHERE id = {user_id}")
