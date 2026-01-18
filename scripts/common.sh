#!/usr/bin/env bash
# ============================================================
# Common Functions Library for TI Deployment Scripts
# ============================================================

echo_info() {
    echo -e "[*] $1"
}

echo_n_info() {
    echo -e -n "[*] $1"
}

echo_warn() {
    echo -e "[!] $1"
}

echo_error() {
    echo -e "[ERROR] $1"
}

fatal_error() {
    echo_error "$1"
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_dependencies() {
    local missing_deps=()

    for cmd in "$@"; do
        if ! command_exists "$cmd"; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        echo ""
        echo "Please install missing dependencies and try again."
        exit 1
    fi
}

read_toml_value() {
    local toml_file="$1"
    local key_path="$2"
    local script_dir

    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ ! -f "$toml_file" ]; then
        echo_error "TOML file not found: $toml_file"
        return 1
    fi

    python3 "$script_dir/read-toml.py" "$toml_file" "$key_path" 2>/dev/null || echo ""
}

read_toml_default() {
    local toml_file="$1"
    local key_path="$2"
    local default="$3"
    local value

    value=$(read_toml_value "$toml_file" "$key_path")

    if [ -z "$value" ]; then
        echo "$default"
    else
        echo "$value"
    fi
}

read_toml_array() {
    local toml_file="$1"
    local key_path="$2"
    local -n array_ref="$3"

    array_ref=()

    while IFS= read -r line || [ -n "$line" ]; do
        if [ -n "$line" ]; then
            array_ref+=("$line")
        fi
    done < <(read_toml_value "$toml_file" "$key_path")
}

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

ssh_exec() {
    local host="$1"
    local cmd="$2"
    local port="${3:-22}"

    # shellcheck disable=SC2086
    ssh $SSH_OPTS -p "$port" "$host" "$cmd"
}

scp_copy() {
    local source="$1"
    local dest="$2"
    local port="${3:-22}"

    # shellcheck disable=SC2086
    scp $SSH_OPTS -P "$port" "$source" "$dest" > /dev/null 2>&1
}

wait_for_ssh() {
    local host="$1"
    local port="${2:-22}"
    local timeout="${3:-60}"
    local elapsed=0

    echo_n_info "Waiting for SSH to become available"
    # shellcheck disable=SC2086
    while ! ssh $SSH_OPTS -p "$port" -o ConnectTimeout=3 "$host" "exit" 2>/dev/null; do
        printf "."
        sleep 3
        elapsed=$((elapsed + 3))

        if [ $elapsed -ge $timeout ]; then
            echo ""
            fatal_error "SSH connection timeout after ${timeout}s"
        fi
    done
    echo ""
    echo_info "SSH is ready"
}

validate_tailscale_config() {
    local authkey="$1"
    local domain="$2"

    if [ -z "$authkey" ]; then
        fatal_error "tailscale.authkey is required in the config file"
    fi

    if [ -z "$domain" ]; then
        fatal_error "tailscale.tailscale_domain is required in the config file"
    fi
}
