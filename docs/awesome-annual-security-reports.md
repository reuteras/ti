# OpenCTI Connector: Awesome Annual Security Reports

## Purpose

Implement an OpenCTI **external import connector** that ingests reports from the GitHub repository:

[https://github.com/jacobdjwilson/awesome-annual-security-reports](https://github.com/jacobdjwilson/awesome-annual-security-reports)

The connector must **not clone the full repository** (currently ~8.5 GB). Instead, it should:
- Detect new or changed report files in the repo
- Download only the necessary files
- Import them into OpenCTI in a structured and idempotent way

The connector is intended to run continuously (scheduled) and maintain its own state.

---

## High-level behaviour

### First startup
- Discover **all PDF reports** in the repository
- Import every report into OpenCTI

### Subsequent runs
- Detect **new or changed PDF reports**
- Import only those changes
- Previously imported reports must not be duplicated

State must be stored using the OpenCTI connector state mechanism.

---

## Repository layout assumptions

The repository contains (at least) two important directory trees:

1. **PDF reports (authoritative source)**
   - Root: `Annual Security Reports/`
   - Structure is typically year-based
   - Files are `.pdf`
   - These PDFs are the canonical documents and must always be linked in OpenCTI

2. **Markdown conversions (for analysis)**
   - Root: `Markdown Conversions/`
   - Mirrors the PDF directory structure
   - Same filename as PDF but with `.md` extension
   - Markdown is AI-generated and easier to analyze than PDFs

The connector should:
- Treat the **PDF path** as the canonical report identity
- Prefer Markdown for text extraction and analysis
- Always link to the **PDF version** in OpenCTI

---

## GitHub access strategy (important)

❌ Do NOT clone the repository  
❌ Do NOT download the full repo as an archive  

✅ Use the **GitHub REST API**:
- Git Trees API to list files and blob SHAs
- Raw content URLs to download individual files

Key requirements:
- Build an index of files under:
  - `Annual Security Reports/**/*.pdf`
  - `Markdown Conversions/**/*.md`
- Track files by their **blob SHA**
- Handle large repositories where recursive tree calls may be truncated
  (walk subtrees when needed)

---

## Change detection & state

Connector state must record, at minimum:

- PDF file path → last imported blob SHA

On each run:
- If a PDF path is new → import
- If a PDF blob SHA has changed → re-import
- If unchanged → skip

State must only be updated **after successful import**.

---

## Mapping logic

### Canonical identity
- One OpenCTI `Report` per **PDF file**

### Mapping Markdown to PDF
- For a given PDF path:
  - Replace root directory:
    - `Annual Security Reports/` → `Markdown Conversions/`
  - Replace extension:
    - `.pdf` → `.md`
- If Markdown exists, use it for content
- If not, proceed without Markdown (PDF is still imported and linked)

---

## OpenCTI object model

For each report, create:

### 1. Report (SDO)
Required fields:
- `name`: derived from filename (optionally include year)
- `published`: derived from year directory (use `YYYY-01-01T00:00:00Z` if only year is known)
- `description`: short summary (first paragraph of Markdown if available)
- `labels` (minimum):
  - `source:awesome-annual-security-reports`
  - `format:pdf`
  - `year:<YYYY>`

Suggested:
- `report_types`: e.g. `threat-report`
- `confidence`: reasonable static default (e.g. 50)

### 2. External references
Always include:
- GitHub blob URL for the PDF (human readable)
- Raw PDF URL (direct download)

Example:
- [https://github.com/<owner>/<repo>/blob/<ref>/<pdf_path>](https://github.com/<owner>/<repo>/blob/<ref>/<pdf_path>)
- [https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<pdf_path>](https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<pdf_path>)

### 3. Markdown content
If Markdown exists:
- Attach it to the Report as a **Note** (preferred, safest across OpenCTI versions)
- The note should clearly indicate it is an AI-generated Markdown conversion

---

## Non-goals (out of scope)

The connector should NOT:
- Extract IOCs, CVEs, or entities (may be done later by enrichment)
- Modify GitHub content
- Upload PDFs unless explicitly configured
- Perform heavy NLP or LLM analysis

Focus on **structured ingestion and provenance**.

---

## Connector structure expectations

Implement using standard OpenCTI Python connector patterns:

Suggested modules:
- `github_api.py`
  - GitHub API access
  - Tree walking with truncation handling
- `state.py`
  - Connector state management
- `mapper.py`
  - Path mapping (PDF ↔ Markdown)
  - Title and year extraction
- `importer.py`
  - OpenCTI object creation
- `connector.py`
  - Main loop / scheduling

Configuration must be read from environment variables / config.yml.

---

## Configuration parameters

Minimum required:
- GitHub owner
- GitHub repo
- GitHub ref (default: `main`)

Optional:
- GitHub token (strongly recommended to avoid rate limits)
- Maximum file size
- Whether to store Markdown as Note or Report content

---

## Design principles

- Idempotent
- Restart-safe
- No full repo downloads
- Minimal bandwidth usage
- Clear provenance (always link back to GitHub PDF)

The end result should be a clean OpenCTI library of annual security reports,
queryable by year, source, and topic, with Markdown available for downstream analysis.
