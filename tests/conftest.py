"""Shared test fixtures for the security review test suite."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# Fail loudly if any test accidentally makes a real LLM call
try:
    from pydantic_ai import models as pydantic_ai_models
    pydantic_ai_models.ALLOW_MODEL_REQUESTS = False
except ImportError:
    pass


@pytest.fixture
def vulnerable_python_app(tmp_path: Path) -> Path:
    """Write a deliberately vulnerable Python file for scanner testing.

    Contains: eval(), subprocess.call(shell=True), hardcoded password.
    Confirmed true positives for CWE-094, CWE-078, CWE-798.
    """
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '''import subprocess
import os

PASSWORD = "SuperSecret123!"  # CWE-798: hardcoded credential

def process_input(user_input):
    """CWE-094: Code injection via eval()"""
    result = eval(user_input)
    return result

def run_command(cmd):
    """CWE-078: OS command injection via shell=True"""
    subprocess.call(cmd, shell=True)

def get_data(query):
    """CWE-089: SQL injection via string formatting"""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()
''',
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def vulnerable_csharp_app(tmp_path: Path) -> Path:
    """Write a deliberately vulnerable C# controller.

    Contains: SqlCommand string concat, BinaryFormatter, missing [Authorize].
    Confirmed true positives for CWE-089, CWE-502, CWE-862.
    """
    controller = tmp_path / "VulnerableController.cs"
    controller.write_text(
        '''using System;
using System.Data.SqlClient;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    // CWE-862: Missing [Authorize] attribute
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableController : ControllerBase
    {
        [HttpGet("user")]
        public IActionResult GetUser(string name)
        {
            // CWE-089: SQL injection via string concatenation
            var conn = new SqlConnection("Server=.;Database=App;");
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
            conn.Open();
            var reader = cmd.ExecuteReader();
            return Ok(reader);
        }

        [HttpPost("deserialize")]
        public IActionResult Deserialize()
        {
            // CWE-502: Insecure deserialization via BinaryFormatter
            var formatter = new BinaryFormatter();
            var stream = Request.Body;
            var obj = formatter.Deserialize(stream);
            return Ok(obj);
        }
    }
}
''',
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def sample_sarif() -> dict:
    """Minimal valid SARIF 2.1.0 document with 3 findings across 2 tools."""
    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bandit",
                        "version": "1.9.4",
                        "rules": [
                            {
                                "id": "B307",
                                "shortDescription": {"text": "eval() used"},
                                "properties": {"tags": ["security", "CWE-94"]},
                            },
                            {
                                "id": "B602",
                                "shortDescription": {"text": "subprocess with shell=True"},
                                "properties": {"tags": ["security", "CWE-78"]},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "B307",
                        "level": "warning",
                        "message": {"text": "Use of eval() detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 8},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "B602",
                        "level": "error",
                        "message": {"text": "subprocess.call with shell=True"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 13},
                                }
                            }
                        ],
                    },
                ],
            },
            {
                "tool": {
                    "driver": {
                        "name": "gitleaks",
                        "version": "8.30.1",
                        "rules": [
                            {
                                "id": "hardcoded-password",
                                "shortDescription": {"text": "Hardcoded password"},
                                "properties": {"tags": ["security", "CWE-798"]},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "hardcoded-password",
                        "level": "error",
                        "message": {"text": "Hardcoded credential found"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 4},
                                }
                            }
                        ],
                    },
                ],
            },
        ],
    }


@pytest.fixture
def clean_python_app(tmp_path: Path) -> Path:
    """Write a secure Python file that should produce zero findings."""
    app_file = tmp_path / "secure_app.py"
    app_file.write_text(
        '''import subprocess
import sqlite3
import os

def process_input(user_input: str) -> str:
    """Safe input processing - no eval."""
    return user_input.strip()

def run_command(args: list[str]) -> None:
    """Safe subprocess - no shell=True, list args."""
    subprocess.run(args, shell=False, check=True)

def get_data(name: str) -> list:
    """Safe SQL - parameterised query."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()

def get_secret() -> str:
    """Safe secret - from environment."""
    return os.environ.get("APP_SECRET", "")
''',
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def clean_csharp_app(tmp_path: Path) -> Path:
    """Write a secure C# controller with proper security controls."""
    controller = tmp_path / "SecureController.cs"
    controller.write_text(
        '''using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace SecureApp.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        private readonly AppDbContext _context;

        public SecureController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet("user/{id}")]
        public async Task<IActionResult> GetUser(int id)
        {
            // Safe: parameterised EF Core query with ownership check
            var userId = User.FindFirst("sub")?.Value;
            var user = await _context.Users
                .Where(u => u.Id == id && u.OwnerId == userId)
                .FirstOrDefaultAsync();
            return user == null ? NotFound() : Ok(user);
        }
    }
}
''',
        encoding="utf-8",
    )
    return tmp_path
