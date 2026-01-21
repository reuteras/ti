import re
from typing import Iterable

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_PATTERN = re.compile(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_PATTERN = re.compile(r"https?://[^\s)\]]+")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")


def extract_cves(text: str) -> list[str]:
    return sorted({match.upper() for match in CVE_PATTERN.findall(text or "")})


def extract_cves_from_labels(labels: Iterable[str]) -> list[str]:
    cves: set[str] = set()
    for label in labels:
        raw = (label or "").strip()
        if not raw:
            continue
        if raw.lower().startswith("cve:"):
            raw = raw.split(":", 1)[1]
        if CVE_PATTERN.fullmatch(raw.strip(), re.IGNORECASE):
            cves.add(raw.strip().upper())
    return sorted(cves)


def extract_label_entities(labels: Iterable[str]) -> dict[str, list[str]]:
    entries = {
        "cves": set(),
        "urls": set(),
        "domains": set(),
        "ipv4": set(),
        "malware": set(),
        "tools": set(),
        "threat_actors": set(),
        "attack_patterns": set(),
    }
    for label in labels:
        raw = (label or "").strip()
        if not raw:
            continue
        lower = raw.lower()
        value = ""
        if lower.startswith("cve:"):
            value = raw.split(":", 1)[1].strip()
            if CVE_PATTERN.fullmatch(value, re.IGNORECASE):
                entries["cves"].add(value.upper())
            continue
        if lower.startswith("ioc:url:"):
            value = raw.split(":", 2)[2].strip()
        elif lower.startswith("url:"):
            value = raw.split(":", 1)[1].strip()
        if value:
            if URL_PATTERN.fullmatch(value):
                entries["urls"].add(value)
            continue
        if lower.startswith("ioc:domain:"):
            value = raw.split(":", 2)[2].strip()
        elif lower.startswith("domain:"):
            value = raw.split(":", 1)[1].strip()
        if value:
            if DOMAIN_PATTERN.fullmatch(value):
                entries["domains"].add(value)
            continue
        if lower.startswith("ioc:ipv4:"):
            value = raw.split(":", 2)[2].strip()
        elif lower.startswith("ipv4:") or lower.startswith("ip:"):
            value = raw.split(":", 1)[1].strip()
        if value:
            if IPV4_PATTERN.fullmatch(value):
                entries["ipv4"].add(value)
            continue
        if lower.startswith("malware:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["malware"].add(value)
            continue
        if lower.startswith("tool:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["tools"].add(value)
            continue
        if lower.startswith("threat-actor:") or lower.startswith("threatactor:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["threat_actors"].add(value)
            continue
        if lower.startswith("attack:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["attack_patterns"].add(value)
            continue
    return {key: sorted(values) for key, values in entries.items()}


def extract_iocs(text: str) -> dict[str, list[str]]:
    text = text or ""
    return {
        "urls": sorted(set(URL_PATTERN.findall(text))),
        "domains": sorted(set(DOMAIN_PATTERN.findall(text))),
        "ipv4": sorted(set(IPV4_PATTERN.findall(text))),
        "sha256": sorted(set(SHA256_PATTERN.findall(text))),
        "md5": sorted(set(MD5_PATTERN.findall(text))),
    }
