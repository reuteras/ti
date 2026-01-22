import logging
import os

from readwise.api import ReadwiseReader

from .storage import Storage

logger = logging.getLogger(__name__)


def refresh_tags(storage: Storage, max_pages: int = 5) -> int:
    token = os.getenv("READWISE_API_KEY", "")
    if not token:
        logger.warning("readwise_not_configured")
        return 0
    reader = ReadwiseReader(token=token)
    page_cursor = None
    page = 0
    tags: set[str] = set()

    while True:
        params: dict[str, str] = {}
        if page_cursor:
            params["pageCursor"] = page_cursor
        response = reader._make_get_request(params)
        for doc in response.results:
            doc_tags = getattr(doc, "tags", None)
            if isinstance(doc_tags, dict):
                for key, tag in doc_tags.items():
                    name = getattr(tag, "name", None) or key
                    if isinstance(name, str) and name.strip():
                        tags.add(name.strip())
            elif isinstance(doc_tags, list):
                for name in doc_tags:
                    if isinstance(name, str) and name.strip():
                        tags.add(name.strip())
        page_cursor = response.next_page_cursor
        page += 1
        if not page_cursor or page >= max_pages:
            break

    count = 0
    for tag in sorted(tags):
        storage.upsert_readwise_tag(tag, approved=False)
        count += 1
    return count
