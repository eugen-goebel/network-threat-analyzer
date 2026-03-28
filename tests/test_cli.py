"""Tests for the CLI entry point (main.py)."""

import os
import subprocess

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_demo_mode(tmp_path):
    result = subprocess.run(
        ["python", "main.py", "--demo", "--output", str(tmp_path)],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        timeout=120,
    )
    assert result.returncode == 0


def test_help_flag():
    result = subprocess.run(
        ["python", "main.py", "--help"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        timeout=30,
    )
    assert result.returncode == 0
    assert "Network Threat Analyzer" in result.stdout or "network" in result.stdout.lower()


def test_missing_file():
    result = subprocess.run(
        ["python", "main.py", "nonexistent.pcap"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        timeout=30,
    )
    assert result.returncode != 0


def test_no_args_shows_help():
    result = subprocess.run(
        ["python", "main.py"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        timeout=30,
    )
    combined = result.stdout + result.stderr
    assert "usage" in combined.lower() or "--help" in combined.lower() or "--demo" in combined
