import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

import httpx

from connectors_common.state_store import StateStore

logging.basicConfig(level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")
logger = logging.getLogger("connector_cvelist")


def _run_git(args: list[str], repo_path: Path | None = None) -> str:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git", *args],
        cwd=str(repo_path) if repo_path else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "git command failed")
    return result.stdout.strip()


def _ensure_repo(repo_url: str, branch: str, repo_path: Path) -> None:
    if repo_path.exists():
        _run_git(["fetch", "origin", branch], repo_path)
        _run_git(["reset", "--hard", f"origin/{branch}"], repo_path)
        return
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    _run_git(["clone", "--branch", branch, repo_url, str(repo_path)])


def _get_head_commit(repo_path: Path) -> str:
    return _run_git(["rev-parse", "HEAD"], repo_path)


def _changed_files(repo_path: Path, previous: str, current: str) -> list[str]:
    try:
        diff = _run_git(["diff", "--name-only", previous, current, "--", "cves"], repo_path)
    except Exception as exc:
        logger.warning("cvelist_diff_failed error=%s", exc)
        return []
    return [line for line in diff.splitlines() if line.strip()]


def _iter_cve_files(repo_path: Path, changed: list[str] | None) -> Iterable[Path]:
    if changed is None:
        for path in repo_path.joinpath("cves").rglob("*.json"):
            yield path
        return
    for rel in changed:
        if not rel.endswith(".json"):
            continue
        if not rel.startswith("cves/"):
            continue
        yield repo_path / rel


def _extract_cve(payload: dict[str, Any]) -> tuple[str | None, str | None, list[str]]:
    meta = payload.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    description = None
    references: list[str] = []
    containers = payload.get("containers", {})
    for container in containers.values():
        for item in container.get("descriptions", []) if isinstance(container, dict) else []:
            if item.get("lang", "").lower() == "en":
                description = item.get("value")
                break
        for ref in container.get("references", []) if isinstance(container, dict) else []:
            url = ref.get("url")
            if isinstance(url, str) and url.strip():
                references.append(url.strip())
        if description:
            break
    if not description:
        for container in containers.values():
            for item in container.get("descriptions", []) if isinstance(container, dict) else []:
                value = item.get("value")
                if isinstance(value, str) and value.strip():
                    description = value.strip()
                    break
            if description:
                break
    return cve_id, description, sorted(set(references))


class OpenCTIClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.client = httpx.Client(timeout=30)

    def close(self) -> None:
        self.client.close()

    def _post(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        response = self.client.post(f"{self.base_url}/graphql", json={"query": query, "variables": variables}, headers=headers)
        response.raise_for_status()
        payload = response.json()
        if "errors" in payload:
            raise RuntimeError(payload["errors"])
        return payload.get("data", {})

    def find_vulnerability_id(self, name: str) -> str | None:
        query = """
        query VulnerabilityByName($name: String!) {
          vulnerabilities(
            filters: {mode: and, filterGroups: [], filters: [{key: "name", values: [$name]}]}
            first: 1
          ) {
            edges { node { id } }
          }
        }
        """
        data = self._post(query, {"name": name})
        edges = data.get("vulnerabilities", {}).get("edges", [])
        if edges:
            return edges[0].get("node", {}).get("id")
        return None

    def create_vulnerability(self, name: str, description: str | None) -> str | None:
        mutation = """
        mutation VulnerabilityAdd($input: VulnerabilityAddInput!) {
          vulnerabilityAdd(input: $input) { id }
        }
        """
        input_payload: dict[str, Any] = {"name": name}
        if description:
            input_payload["description"] = description
        data = self._post(mutation, {"input": input_payload})
        return data.get("vulnerabilityAdd", {}).get("id")

    def update_description(self, vuln_id: str, description: str) -> None:
        mutation = """
        mutation VulnerabilityEdit($id: ID!, $input: [EditInput]!) {
          stixDomainObjectEdit(id: $id) {
            fieldPatch(input: $input) { id }
          }
        }
        """
        payload = [{"key": "description", "value": [description]}]
        self._post(mutation, {"id": vuln_id, "input": payload})

    def add_external_reference(self, vuln_id: str, source_name: str, url: str) -> None:
        mutation = """
        mutation ExternalReferenceAdd($id: ID!, $input: ExternalReferenceAddInput!) {
          stixDomainObjectEdit(id: $id) {
            externalReferencesAdd(input: $input) { id }
          }
        }
        """
        payload = {"source_name": source_name, "url": url}
        self._post(mutation, {"id": vuln_id, "input": payload})


def _process_cve_file(client: OpenCTIClient, path: Path) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("cvelist_parse_failed file=%s error=%s", path, exc)
        return

    cve_id, description, references = _extract_cve(payload)
    if not cve_id:
        return

    vuln_id = client.find_vulnerability_id(cve_id)
    created = False
    if not vuln_id:
        try:
            vuln_id = client.create_vulnerability(cve_id, description)
            created = True
        except Exception as exc:
            logger.warning("cvelist_create_failed cve_id=%s error=%s", cve_id, exc)
            return

    if vuln_id and description:
        try:
            client.update_description(vuln_id, description)
        except Exception as exc:
            logger.warning("cvelist_update_failed cve_id=%s error=%s", cve_id, exc)

    for url in references:
        try:
            client.add_external_reference(vuln_id, "cvelistv5", url)
        except Exception as exc:
            logger.warning("cvelist_reference_failed cve_id=%s url=%s error=%s", cve_id, url, exc)
            continue

    logger.info("cvelist_processed cve_id=%s created=%s", cve_id, created)


def main() -> None:
    opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
    opencti_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
    repo_url = os.getenv("CVELIST_REPO_URL", "https://github.com/CVEProject/cvelistV5.git")
    branch = os.getenv("CVELIST_BRANCH", "main")
    interval = int(os.getenv("CVELIST_RUN_INTERVAL_SECONDS", "3600"))

    if not opencti_token:
        logger.warning("cvelist_missing_token")
        return

    repo_path = Path("/data/cvelistV5")
    state = StateStore("/data/state.json")
    client = OpenCTIClient(opencti_url, opencti_token)

    try:
        while True:
            try:
                _ensure_repo(repo_url, branch, repo_path)
                head = _get_head_commit(repo_path)
                last_commit = state.get("last_commit")
                if last_commit == head:
                    logger.info("cvelist_no_changes")
                    time.sleep(interval)
                    continue
                changed = None
                if last_commit:
                    changed = _changed_files(repo_path, last_commit, head)
                    if not changed:
                        logger.info("cvelist_no_changed_files")
                        state.set("last_commit", head)
                        time.sleep(interval)
                        continue
                count = 0
                for path in _iter_cve_files(repo_path, changed):
                    _process_cve_file(client, path)
                    count += 1
                logger.info("cvelist_run_complete count=%s", count)
                state.set("last_commit", head)
            except Exception as exc:
                logger.warning("cvelist_run_failed error=%s", exc)
            time.sleep(interval)
    finally:
        client.close()


if __name__ == "__main__":
    main()
