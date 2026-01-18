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


def extract_iocs(text: str) -> dict[str, list[str]]:
    text = text or ""
    return {
        "urls": sorted(set(URL_PATTERN.findall(text))),
        "domains": sorted(set(DOMAIN_PATTERN.findall(text))),
        "ipv4": sorted(set(IPV4_PATTERN.findall(text))),
        "sha256": sorted(set(SHA256_PATTERN.findall(text))),
        "md5": sorted(set(MD5_PATTERN.findall(text))),
    }
