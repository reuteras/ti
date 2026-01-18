#!/usr/bin/env python3
"""
TOML Configuration Reader for TI Deployment Scripts

Usage:
    python3 scripts/read-toml.py <toml_file> <key_path>
"""

import sys
from pathlib import Path

import tomllib


def get_nested_value(data: dict, key_path: str):
    keys = key_path.split(".")
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None

    return current


def format_value(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python3 read-toml.py <toml_file> <key_path>", file=sys.stderr)
        return 1

    toml_file = Path(sys.argv[1])
    key_path = sys.argv[2]

    if not toml_file.exists():
        print(f"Error: TOML file not found: {toml_file}", file=sys.stderr)
        return 1

    try:
        with toml_file.open("rb") as handle:
            data = tomllib.load(handle)
    except Exception as exc:  # noqa: BLE001 - surface parser issues
        print(f"Error parsing TOML file: {exc}", file=sys.stderr)
        return 1

    value = get_nested_value(data, key_path)
    if value is None:
        print("", end="")
        return 0

    formatted = format_value(value)
    if isinstance(value, list) and formatted:
        print(formatted)
    else:
        print(formatted, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
