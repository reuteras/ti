#!/usr/bin/env python3
import os
import secrets
import sys
from pathlib import Path


def _read_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _parse_example(path: Path) -> list[tuple[str, str]]:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        lines.append((key.strip(), value.strip()))
    return lines


def _prompt(key: str, current: str) -> str:
    if not sys.stdin.isatty():
        return current
    value = input(f"{key} (leave blank to keep current): ").strip()
    return value or current


def _is_placeholder(value: str) -> bool:
    cleaned = value.strip().lower()
    if not cleaned:
        return True
    return cleaned.startswith("changeme") or cleaned == "change_me"


def _should_prompt(key: str, current: str, example_defaults: dict[str, str]) -> bool:
    if not current:
        return True
    example_value = example_defaults.get(key, "")
    return example_value == current and _is_placeholder(example_value)


def _gen_password() -> str:
    return secrets.token_urlsafe(24)


def _gen_uuid() -> str:
    import uuid

    return str(uuid.uuid4())


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    example_path = repo_root / ".env.example"
    env_path = repo_root / ".env"

    if not example_path.exists():
        print(".env.example not found", file=sys.stderr)
        return 1

    existing = _read_env(env_path)
    example_items = _parse_example(example_path)
    example_defaults = {key: value for key, value in example_items}
    generated: dict[str, str] = {}

    if not env_path.exists():
        env_lines: list[str] = []
        for key, value in example_items:
            if key in existing:
                env_lines.append(f"{key}={existing[key]}")
                continue
            if key == "OPENCTI_ADMIN_TOKEN":
                token = existing.get("OPENCTI_APP__ADMIN__TOKEN") or generated.get("OPENCTI_APP__ADMIN__TOKEN")
                if token:
                    value = token
                else:
                    value = _gen_uuid()
            elif key.endswith("_CONNECTOR_ID"):
                value = _gen_uuid()
            elif key.endswith("_PASSWORD"):
                value = _gen_password()
            elif key.endswith("_TOKEN") or key.endswith("_ACCESS_KEY"):
                value = _gen_uuid()
            generated[key] = value
            env_lines.append(f"{key}={value}")
        env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
        existing = _read_env(env_path)

    missing = [item for item in example_items if item[0] not in existing]
    if missing:
        with env_path.open("a", encoding="utf-8") as handle:
            for key, value in missing:
                if key == "OPENCTI_ADMIN_TOKEN":
                    token = existing.get("OPENCTI_APP__ADMIN__TOKEN")
                    if token:
                        value = token
                    else:
                        value = _gen_uuid()
                elif key.endswith("_CONNECTOR_ID"):
                    value = _gen_uuid()
                elif key.endswith("_PASSWORD"):
                    value = _gen_password()
                elif key.endswith("_TOKEN") or key.endswith("_ACCESS_KEY"):
                    value = _gen_uuid()
                handle.write(f"{key}={value}\n")

    env_data = _read_env(env_path)
    if not env_data.get("OPENCTI_ADMIN_TOKEN") and env_data.get("OPENCTI_APP__ADMIN__TOKEN"):
        env_data["OPENCTI_ADMIN_TOKEN"] = env_data["OPENCTI_APP__ADMIN__TOKEN"]
    for key in [
        "OPENCTI_APP__ADMIN__EMAIL",
        "OPENCTI_APP__ADMIN__PASSWORD",
        "OPENCTI_USER_EMAIL",
        "OPENCTI_USER_PASSWORD",
        "OPENCTI_USER_NAME",
        "MINIFLUX_URL",
        "MINIFLUX_TOKEN",
        "READWISE_TOKEN",
        "ALIENVAULT_API_KEY",
        "FIRST_EPSS_API_KEY",
        "MALPEDIA_AUTH_KEY",
        "MALWAREBAZAAR_API_KEY",
        "VIRUSTOTAL_TOKEN",
        "SHODAN_TOKEN",
        "ZOTERO_API_KEY",
        "ZOTERO_LIBRARY_ID",
    ]:
        current = env_data.get(key, "")
        if _should_prompt(key, current, example_defaults):
            env_data[key] = _prompt(key, current)
        else:
            env_data[key] = current

    lines = []
    for key, value in env_data.items():
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(".env updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
