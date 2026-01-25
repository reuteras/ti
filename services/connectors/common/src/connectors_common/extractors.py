import re
from typing import Iterable

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_PATTERN = re.compile(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_PATTERN = re.compile(r"https?://[^\s)\]]+")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
ASN_PATTERN = re.compile(r"\bAS\d{1,10}\b", re.IGNORECASE)
ATTACK_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
YARA_RULE_PATTERN = re.compile(r"(?is)\brule\s+[A-Za-z0-9_:-]+\s*\{.*?\}")
SIGMA_BLOCK_SPLIT = re.compile(r"(?m)^\s*---\s*$")
SNORT_RULE_PATTERN = re.compile(r"(?m)^\s*(alert|drop|reject|pass)\s+\S+\s+\S+\s+\S+\s*\(.*\)\s*$")

_COUNTRY_ALIASES = {
    "u.s.": "United States",
    "u.s.a.": "United States",
    "usa": "United States",
    "us": "United States",
    "uk": "United Kingdom",
    "u.k.": "United Kingdom",
    "uae": "United Arab Emirates",
    "russia": "Russia",
    "south korea": "South Korea",
    "north korea": "North Korea",
}

_COUNTRY_NAMES = [
    "Afghanistan",
    "Albania",
    "Algeria",
    "Andorra",
    "Angola",
    "Antigua and Barbuda",
    "Argentina",
    "Armenia",
    "Australia",
    "Austria",
    "Azerbaijan",
    "Bahamas",
    "Bahrain",
    "Bangladesh",
    "Barbados",
    "Belarus",
    "Belgium",
    "Belize",
    "Benin",
    "Bhutan",
    "Bolivia",
    "Bosnia and Herzegovina",
    "Botswana",
    "Brazil",
    "Brunei",
    "Bulgaria",
    "Burkina Faso",
    "Burundi",
    "Cambodia",
    "Cameroon",
    "Canada",
    "Cape Verde",
    "Central African Republic",
    "Chad",
    "Chile",
    "China",
    "Colombia",
    "Comoros",
    "Congo",
    "Costa Rica",
    "Croatia",
    "Cuba",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Djibouti",
    "Dominica",
    "Dominican Republic",
    "Ecuador",
    "Egypt",
    "El Salvador",
    "Equatorial Guinea",
    "Eritrea",
    "Estonia",
    "Eswatini",
    "Ethiopia",
    "Fiji",
    "Finland",
    "France",
    "Gabon",
    "Gambia",
    "Georgia",
    "Germany",
    "Ghana",
    "Greece",
    "Grenada",
    "Guatemala",
    "Guinea",
    "Guinea-Bissau",
    "Guyana",
    "Haiti",
    "Honduras",
    "Hungary",
    "Iceland",
    "India",
    "Indonesia",
    "Iran",
    "Iraq",
    "Ireland",
    "Israel",
    "Italy",
    "Jamaica",
    "Japan",
    "Jordan",
    "Kazakhstan",
    "Kenya",
    "Kiribati",
    "Kuwait",
    "Kyrgyzstan",
    "Laos",
    "Latvia",
    "Lebanon",
    "Lesotho",
    "Liberia",
    "Libya",
    "Liechtenstein",
    "Lithuania",
    "Luxembourg",
    "Madagascar",
    "Malawi",
    "Malaysia",
    "Maldives",
    "Mali",
    "Malta",
    "Marshall Islands",
    "Mauritania",
    "Mauritius",
    "Mexico",
    "Micronesia",
    "Moldova",
    "Monaco",
    "Mongolia",
    "Montenegro",
    "Morocco",
    "Mozambique",
    "Myanmar",
    "Namibia",
    "Nauru",
    "Nepal",
    "Netherlands",
    "New Zealand",
    "Nicaragua",
    "Niger",
    "Nigeria",
    "North Macedonia",
    "Norway",
    "Oman",
    "Pakistan",
    "Palau",
    "Panama",
    "Papua New Guinea",
    "Paraguay",
    "Peru",
    "Philippines",
    "Poland",
    "Portugal",
    "Qatar",
    "Romania",
    "Russia",
    "Rwanda",
    "Saint Kitts and Nevis",
    "Saint Lucia",
    "Saint Vincent and the Grenadines",
    "Samoa",
    "San Marino",
    "Sao Tome and Principe",
    "Saudi Arabia",
    "Senegal",
    "Serbia",
    "Seychelles",
    "Sierra Leone",
    "Singapore",
    "Slovakia",
    "Slovenia",
    "Solomon Islands",
    "Somalia",
    "South Africa",
    "South Korea",
    "South Sudan",
    "Spain",
    "Sri Lanka",
    "Sudan",
    "Suriname",
    "Sweden",
    "Switzerland",
    "Syria",
    "Taiwan",
    "Tajikistan",
    "Tanzania",
    "Thailand",
    "Timor-Leste",
    "Togo",
    "Tonga",
    "Trinidad and Tobago",
    "Tunisia",
    "Turkey",
    "Turkmenistan",
    "Tuvalu",
    "Uganda",
    "Ukraine",
    "United Arab Emirates",
    "United Kingdom",
    "United States",
    "Uruguay",
    "Uzbekistan",
    "Vanuatu",
    "Vatican City",
    "Venezuela",
    "Vietnam",
    "Yemen",
    "Zambia",
    "Zimbabwe",
    "Hong Kong",
]

_COUNTRY_TERMS = sorted({name.lower() for name in _COUNTRY_NAMES} | set(_COUNTRY_ALIASES.keys()), key=len, reverse=True)
COUNTRY_PATTERN = re.compile(r"\b(" + "|".join(re.escape(term) for term in _COUNTRY_TERMS) + r")\b", re.IGNORECASE)

_ORG_SUFFIX_PATTERN = re.compile(
    r"\b([A-Z][A-Za-z0-9&.\-]*(?:\s+[A-Z][A-Za-z0-9&.\-]*)*\s+(?:Limited|Ltd|Inc|Corp|Corporation|Company|LLC|GmbH|AG|BV|AB|PLC|SAS|SA))\b"
)



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


def extract_asns(text: str) -> list[str]:
    return sorted({match.upper() for match in ASN_PATTERN.findall(text or "")})


def extract_countries(text: str) -> list[str]:
    matches: set[str] = set()
    for match in COUNTRY_PATTERN.findall(text or ""):
        key = match.strip().lower()
        canonical = _COUNTRY_ALIASES.get(key, match.strip())
        if canonical:
            matches.add(canonical)
    return sorted(matches)


def extract_organizations(text: str, keywords: Iterable[str] | None = None) -> list[str]:
    matches: set[str] = set()
    text_value = text or ""
    for match in _ORG_SUFFIX_PATTERN.findall(text_value):
        matches.add(match.strip())
    for name in keywords or []:
        if not name:
            continue
        pattern = re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
        if pattern.search(text_value):
            matches.add(name)
    return sorted(matches)


def extract_products(text: str, keywords: Iterable[str] | None = None) -> list[str]:
    matches: set[str] = set()
    text_value = text or ""
    for name in keywords or []:
        if not name:
            continue
        pattern = re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
        if pattern.search(text_value):
            matches.add(name)
    return sorted(matches)


def extract_label_entities(labels: Iterable[str]) -> dict[str, list[str]]:
    entries = {
        "cves": set(),
        "urls": set(),
        "domains": set(),
        "ipv4": set(),
        "asns": set(),
        "countries": set(),
        "organizations": set(),
        "products": set(),
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
        if lower.startswith("asn:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["asns"].add(value.upper())
            continue
        if lower.startswith("country:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["countries"].add(value)
            continue
        if lower.startswith("org:") or lower.startswith("organization:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["organizations"].add(value)
            continue
        if lower.startswith("product:"):
            value = raw.split(":", 1)[1].strip()
            if value:
                entries["products"].add(value)
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


def empty_label_entities() -> dict[str, list[str]]:
    return {
        "cves": [],
        "urls": [],
        "domains": [],
        "ipv4": [],
        "asns": [],
        "countries": [],
        "organizations": [],
        "products": [],
        "malware": [],
        "tools": [],
        "threat_actors": [],
        "attack_patterns": [],
    }


def extract_iocs(text: str) -> dict[str, list[str]]:
    text = text or ""
    hash_source = URL_PATTERN.sub(" ", text)
    return {
        "urls": sorted(set(URL_PATTERN.findall(text))),
        "domains": sorted(set(DOMAIN_PATTERN.findall(text))),
        "ipv4": sorted(set(IPV4_PATTERN.findall(text))),
        "asns": extract_asns(text),
        "countries": extract_countries(text),
        "sha256": sorted(set(SHA256_PATTERN.findall(hash_source))),
        "sha1": sorted(set(SHA1_PATTERN.findall(hash_source))),
        "md5": sorted(set(MD5_PATTERN.findall(hash_source))),
    }


def extract_attack_patterns(text: str) -> list[str]:
    text_value = text or ""
    matches = {match.upper() for match in ATTACK_PATTERN.findall(text_value)}
    return sorted(matches)


def extract_yara_rules(text: str, max_chars: int = 200000, max_rules: int = 10) -> list[str]:
    value = (text or "")[:max_chars]
    rules: list[str] = []
    for match in YARA_RULE_PATTERN.finditer(value):
        rule = match.group(0).strip()
        if rule:
            rules.append(rule)
        if len(rules) >= max_rules:
            break
    return rules


def extract_sigma_rules(text: str, max_chars: int = 200000, max_rules: int = 10) -> list[str]:
    value = (text or "")[:max_chars]
    blocks = SIGMA_BLOCK_SPLIT.split(value)
    results: list[str] = []
    for block in blocks:
        block_text = block.strip()
        if not block_text:
            continue
        lower = block_text.lower()
        if "title:" in lower and "detection:" in lower:
            results.append(block_text)
        if len(results) >= max_rules:
            break
    return results


def extract_snort_rules(text: str, max_chars: int = 200000, max_rules: int = 20) -> list[str]:
    value = (text or "")[:max_chars]
    rules = [match.group(0).strip() for match in SNORT_RULE_PATTERN.finditer(value)]
    return rules[:max_rules]


def empty_iocs() -> dict[str, list[str]]:
    return {
        "urls": [],
        "domains": [],
        "ipv4": [],
        "asns": [],
        "countries": [],
        "sha256": [],
        "sha1": [],
        "md5": [],
    }
