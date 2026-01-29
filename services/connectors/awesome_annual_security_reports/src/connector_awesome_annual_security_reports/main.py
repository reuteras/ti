import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from pycti import OpenCTIConnectorHelper

from connectors_common.mapping_store import MappingStore
from connectors_common.opencti_client import OpenCTIClient, ReportInput
from connectors_common.state_store import StateStore
from connectors_common.connector_state import ConnectorState
from connectors_common.work import WorkTracker

logging.basicConfig(
    level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s"
)
logger = logging.getLogger(__name__)

PDF_ROOT = "Annual Security Reports"
MD_ROOT = "Markdown Conversions"

YEAR_PATTERN = re.compile(r"/(19|20)\d{2}/")
FILENAME_YEAR_PATTERN = re.compile(r"(19|20)\d{2}")


@dataclass
class RepoFile:
    path: str
    sha: str
    size: int | None = None


def _first_paragraph(markdown: str) -> str:
    if not markdown:
        return ""
    parts = [part.strip() for part in markdown.split("\n\n") if part.strip()]
    return parts[0] if parts else ""


def _title_from_path(path: str) -> str:
    base = path.split("/")[-1]
    name = base.rsplit(".", 1)[0]
    name = re.sub(r"[_\-]+", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name or "Annual Security Report"


def _extract_year(path: str) -> str | None:
    match = YEAR_PATTERN.search(f"/{path}")
    if match:
        return match.group(0).strip("/")
    base = path.split("/")[-1]
    match = FILENAME_YEAR_PATTERN.search(base)
    return match.group(0) if match else None


def _published_from_year(year: str | None) -> str | None:
    if not year:
        return None
    return datetime(int(year), 1, 1, tzinfo=timezone.utc).isoformat()


def _markdown_path_for_pdf(pdf_path: str) -> str:
    if pdf_path.startswith(f"{PDF_ROOT}/"):
        pdf_path = pdf_path.replace(f"{PDF_ROOT}/", f"{MD_ROOT}/", 1)
    return re.sub(r"\.pdf$", ".md", pdf_path, flags=re.IGNORECASE)


def _github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class AwesomeAnnualConnector:
    def __init__(self) -> None:
        opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
        admin_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv(
            "OPENCTI_ADMIN_TOKEN", ""
        )
        opencti_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv(
            "OPENCTI_ADMIN_TOKEN", ""
        )
        if not opencti_token:
            raise RuntimeError("awesome_annual_missing_token")

        connector_id = os.getenv("CONNECTOR_ID", "").strip()
        if not connector_id:
            raise RuntimeError("awesome_annual_missing_connector_id")
        connector_name = os.getenv("CONNECTOR_NAME", "Awesome Annual Security Reports")
        connector_type = os.getenv("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
        connector_scope = os.getenv(
            "CONNECTOR_SCOPE", "awesome-annual-security-reports"
        )
        connector_log_level = os.getenv("CONNECTOR_LOG_LEVEL", "info")

        def _build_helper(token: str) -> OpenCTIConnectorHelper:
            config = {
                "opencti": {"url": opencti_url, "token": token},
                "connector": {
                    "id": connector_id,
                    "type": connector_type,
                    "name": connector_name,
                    "scope": connector_scope,
                    "log_level": connector_log_level,
                },
            }
            return OpenCTIConnectorHelper(config)

        self.helper = _build_helper(opencti_token)
        self.fallback_token = admin_token
        self.interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "21600"))
        self.owner = os.getenv("AWESOME_ASR_GITHUB_OWNER", "jacobdjwilson")
        self.repo = os.getenv(
            "AWESOME_ASR_GITHUB_REPO", "awesome-annual-security-reports"
        )
        self.ref = os.getenv("AWESOME_ASR_GITHUB_REF", "main")
        self.token = os.getenv("AWESOME_ASR_GITHUB_TOKEN", "")
        self.max_markdown_bytes = int(
            os.getenv("AWESOME_ASR_MAX_MARKDOWN_BYTES", "2000000")
        )
        mapping_path = os.getenv("TI_MAPPING_DB", "/data/mapping/ti-mapping.sqlite")
        self.mapping = MappingStore(mapping_path)
        self.state = StateStore("/data/state.json")
        self.client = OpenCTIClient(
            opencti_url, opencti_token, fallback_token=self.fallback_token
        )

    def _github_get(
        self, client: httpx.Client, url: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        headers = _github_headers(self.token or None)
        response = client.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()

    def _list_repo_files(self) -> tuple[dict[str, RepoFile], dict[str, RepoFile]]:
        pdfs: dict[str, RepoFile] = {}
        mds: dict[str, RepoFile] = {}
        api_base = f"https://api.github.com/repos/{self.owner}/{self.repo}"
        with httpx.Client() as client:
            tree = self._github_get(
                client, f"{api_base}/git/trees/{self.ref}", {"recursive": "1"}
            )
            truncated = tree.get("truncated") is True
            if not truncated:
                for entry in tree.get("tree", []):
                    path = entry.get("path")
                    if entry.get("type") != "blob" or not path:
                        continue
                    size = entry.get("size")
                    sha = entry.get("sha")
                    if path.startswith(f"{PDF_ROOT}/") and path.lower().endswith(
                        ".pdf"
                    ):
                        pdfs[path] = RepoFile(path=path, sha=sha, size=size)
                    elif path.startswith(f"{MD_ROOT}/") and path.lower().endswith(
                        ".md"
                    ):
                        mds[path] = RepoFile(path=path, sha=sha, size=size)
                return pdfs, mds

            root_tree = self._github_get(client, f"{api_base}/git/trees/{self.ref}")
            roots = {
                entry.get("path"): entry.get("sha")
                for entry in root_tree.get("tree", [])
            }
            pdf_root_sha = roots.get(PDF_ROOT)
            md_root_sha = roots.get(MD_ROOT)
            if pdf_root_sha:
                pdfs.update(
                    self._walk_tree(client, api_base, PDF_ROOT, pdf_root_sha, ".pdf")
                )
            if md_root_sha:
                mds.update(
                    self._walk_tree(client, api_base, MD_ROOT, md_root_sha, ".md")
                )
        return pdfs, mds

    def _walk_tree(
        self,
        client: httpx.Client,
        api_base: str,
        prefix: str,
        tree_sha: str,
        suffix: str,
    ) -> dict[str, RepoFile]:
        results: dict[str, RepoFile] = {}
        stack = [(prefix, tree_sha)]
        while stack:
            base_path, sha = stack.pop()
            tree = self._github_get(client, f"{api_base}/git/trees/{sha}")
            for entry in tree.get("tree", []):
                entry_path = entry.get("path")
                entry_type = entry.get("type")
                entry_sha = entry.get("sha")
                if not entry_path or not entry_sha:
                    continue
                full_path = f"{base_path}/{entry_path}" if base_path else entry_path
                if entry_type == "tree":
                    stack.append((full_path, entry_sha))
                    continue
                if entry_type != "blob":
                    continue
                if not full_path.lower().endswith(suffix):
                    continue
                results[full_path] = RepoFile(
                    path=full_path, sha=entry_sha, size=entry.get("size")
                )
        return results

    def _download_markdown(self, path: str, entry: RepoFile | None) -> str:
        if not entry:
            return ""
        if entry.size is not None and entry.size > self.max_markdown_bytes:
            logger.warning(
                "awesome_annual_markdown_too_large path=%s size=%s", path, entry.size
            )
            return ""
        url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.ref}/{path}"
        headers = _github_headers(self.token or None)
        with httpx.Client(timeout=30) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            return response.text

    def _ensure_external_refs(self, report_id: str, pdf_path: str, sha: str) -> None:
        blob_url = (
            f"https://github.com/{self.owner}/{self.repo}/blob/{self.ref}/{pdf_path}"
        )
        raw_url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.ref}/{pdf_path}"
        for url in (blob_url, raw_url):
            if not self.state.remember_hash("external_ref", f"{report_id}:{url}"):
                continue
            self.client.add_external_reference_to_report(
                report_id, "github", url, f"{pdf_path}@{sha}"
            )

    def _process_pdf(
        self,
        pdf_entry: RepoFile,
        md_entry: RepoFile | None,
        state_map: dict[str, str],
    ) -> None:
        pdf_path = pdf_entry.path
        pdf_sha = pdf_entry.sha
        if state_map.get(pdf_path) == pdf_sha:
            return

        report_id = self.mapping.get_by_external_id("awesome_annual_report", pdf_path)
        markdown_text = (
            self._download_markdown(md_entry.path, md_entry) if md_entry else ""
        )
        description = ""
        if markdown_text:
            description = _first_paragraph(markdown_text)
        if not description:
            description = _title_from_path(pdf_path)
        year = _extract_year(pdf_path)
        published = _published_from_year(year)
        labels = ["source:awesome-annual-security-reports", "format:pdf"]
        if year:
            labels.append(f"year:{year}")

        if not report_id:
            report = ReportInput(
                title=_title_from_path(pdf_path),
                description=description,
                published=published,
                source_name="awesome-annual-security-reports",
                source_url=None,
                labels=labels,
                confidence=50,
                external_id=pdf_path,
            )
            report_id = self.client.create_report(report)
            if not report_id:
                logger.warning("awesome_annual_report_create_failed path=%s", pdf_path)
                return
            self.mapping.upsert_external_id(
                "awesome_annual_report", pdf_path, report_id, "Report"
            )
        else:
            if markdown_text:
                self.client.update_report_description(report_id, description)

        self._ensure_external_refs(report_id, pdf_path, pdf_sha)

        if markdown_text and md_entry:
            note_key = f"{pdf_path}:{md_entry.sha}"
            existing_note = self.mapping.get_by_external_id(
                "awesome_annual_md", note_key
            )
            if not existing_note:
                note_text = "Markdown conversion (AI-generated)\n\n" + markdown_text
                note_id = self.client.create_note(
                    note_text,
                    object_refs=[report_id],
                    labels=[
                        "source:awesome-annual-security-reports",
                        "format:markdown",
                    ],
                )
                if note_id:
                    self.mapping.upsert_external_id(
                        "awesome_annual_md", note_key, note_id, "Note"
                    )

        state_map[pdf_path] = pdf_sha

    def _run(self) -> None:
        run_state = ConnectorState(self.helper, "Awesome Annual Security Reports")
        run_state.start()
        metrics = {
            "pdfs_total": 0,
            "markdowns_total": 0,
            "pdfs_processed": 0,
        }
        work = WorkTracker(self.helper, "Awesome Annual Security Reports")
        try:
            pdfs, mds = self._list_repo_files()
        except Exception as exc:
            logger.warning("awesome_annual_list_failed error=%s", exc)
            run_state.failure(str(exc), **metrics)
            return
        metrics["pdfs_total"] = len(pdfs)
        metrics["markdowns_total"] = len(mds)
        work.log(f"pdfs={len(pdfs)} markdowns={len(mds)}")

        raw_state = self.state.get("pdf_sha_map", {})
        state_map = raw_state if isinstance(raw_state, dict) else {}

        updated = 0
        for idx, (pdf_path, pdf_entry) in enumerate(sorted(pdfs.items()), start=1):
            md_path = _markdown_path_for_pdf(pdf_path)
            md_entry = mds.get(md_path)
            self._process_pdf(pdf_entry, md_entry, state_map)
            updated += 1
            if idx % 25 == 0:
                work.progress(
                    int((idx / max(1, len(pdfs))) * 100), f"processed={idx}/{len(pdfs)}"
                )

        self.state.set("pdf_sha_map", state_map)
        self.state.set("last_run", datetime.now(timezone.utc).isoformat())
        logger.info("awesome_annual_run_completed processed=%s", updated)
        work.done(f"processed={updated}")
        metrics["pdfs_processed"] = updated
        run_state.success(**metrics)

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)


def main() -> None:
    try:
        connector = AwesomeAnnualConnector()
    except Exception as exc:
        logger.warning("awesome_annual_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
