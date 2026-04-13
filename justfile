# TI Stack - justfile
# Requires: just (https://just.systems), uv (https://docs.astral.sh/uv/)

# List all available recipes
default:
    @just --list

# Directories containing Python services
services := "services/briefing services/connectors/common services/connectors/awesome_annual_security_reports services/connectors/cvelist services/connectors/enrich_text services/connectors/miniflux services/connectors/readwise services/connectors/zotero"

# Generate uv.lock files for all services
lock:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in {{ services }}; do
        echo "==> Locking $dir"
        (cd "$dir" && uv lock)
    done

# Upgrade all dependencies and regenerate uv.lock files
update:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in {{ services }}; do
        echo "==> Updating $dir"
        (cd "$dir" && uv lock --upgrade)
    done

# Lock a single service (e.g. just lock-service services/briefing)
lock-service service:
    cd {{ service }} && uv lock

# Upgrade a single service (e.g. just update-service services/briefing)
update-service service:
    cd {{ service }} && uv lock --upgrade

# Show outdated packages for all services
outdated:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in {{ services }}; do
        echo "==> Outdated in $dir"
        (cd "$dir" && uv tree --outdated 2>/dev/null || echo "  (no outdated info available)")
    done

# Sync all service environments (install dependencies from lock files)
sync:
    #!/usr/bin/env bash
    set -euo pipefail
    for dir in {{ services }}; do
        echo "==> Syncing $dir"
        (cd "$dir" && uv sync)
    done
