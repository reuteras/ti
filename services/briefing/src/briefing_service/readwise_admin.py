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
    tags: set[str] = set()
    max_docs = max_pages * 100 if max_pages > 0 else None
    doc_count = 0

    for doc in reader.iter_documents(retry_on_429=True):
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
        doc_count += 1
        if max_docs is not None and doc_count >= max_docs:
            break

    count = 0
    for tag in sorted(tags):
        storage.upsert_readwise_tag(tag, approved=False)
        count += 1
    return count
