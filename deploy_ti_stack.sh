#!/usr/bin/env bash

# ============================================================
# TI Stack Deployment Script
# ============================================================
# Deploys the OpenCTI-based personal threat intel stack locally
# or on a fresh Hetzner VM via hcloud + SSH.
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/common.sh
# shellcheck disable=SC1091
source "$SCRIPT_DIR/scripts/common.sh"

# ============================================================
# Argument parsing
# ============================================================

CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/master-config.toml}"
INSTALL_DIR="/opt/ti"
REPO_URL="${REPO_URL:-https://github.com/reuteras/ti.git}"
BRANCH="${BRANCH:-main}"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
NO_BUILD="false"
LOCAL_ONLY="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --no-build)
            NO_BUILD="true"
            shift
            ;;
        --local)
            LOCAL_ONLY="true"
            shift
            ;;
        -*)
            fatal_error "Unknown option: $1"
            ;;
        *)
            fatal_error "Unexpected argument: $1"
            ;;
    esac
done

# ============================================================
# Local deployment
# ============================================================

deploy_local() {
    echo_info "Deploying locally in $SCRIPT_DIR"
    check_dependencies "docker" "python3"

    if [ ! -f "$SCRIPT_DIR/.env" ]; then
        echo_info ".env not found; generating with bootstrap script"
        python3 "$SCRIPT_DIR/scripts/bootstrap_env.py"
    fi

    if [ "$NO_BUILD" = "true" ]; then
        docker compose up -d
    else
        docker compose up -d --build
    fi

    echo_info "OpenCTI UI: http://localhost:8080"
    echo_info "Briefing service: http://localhost:8088"
}

# ============================================================
# Hetzner deployment
# ============================================================

deploy_hetzner() {
    if [ ! -f "$CONFIG_FILE" ]; then
        fatal_error "Config file not found: $CONFIG_FILE"
    fi
    if [ ! -f "$ENV_FILE" ]; then
        fatal_error "Env file not found: $ENV_FILE"
    fi

    check_dependencies "hcloud" "jq" "ssh" "scp" "python3" "curl"

    SERVER_NAME=$(read_toml_default "$CONFIG_FILE" "deployment.server_name" "")
    SERVER_TYPE=$(read_toml_default "$CONFIG_FILE" "deployment.server_type" "cx23")
    SERVER_IMAGE=$(read_toml_default "$CONFIG_FILE" "deployment.server_image" "debian-13")
    SERVER_LOCATION=$(read_toml_default "$CONFIG_FILE" "deployment.location" "")
    INSTALL_DIR=$(read_toml_default "$CONFIG_FILE" "deployment.install_dir" "$INSTALL_DIR")
    SSH_USER=$(read_toml_default "$CONFIG_FILE" "deployment.ssh_user" "root")
    SSH_PORT=$(read_toml_default "$CONFIG_FILE" "deployment.ssh_port" "22")
    REPO_URL=$(read_toml_default "$CONFIG_FILE" "repo.url" "$REPO_URL")
    BRANCH=$(read_toml_default "$CONFIG_FILE" "repo.branch" "$BRANCH")

    if [ -z "$SERVER_NAME" ]; then
        fatal_error "deployment.server_name is required in $CONFIG_FILE"
    fi

    read_toml_array "$CONFIG_FILE" "deployment.ssh_keys" SSH_KEYS
    if [ ${#SSH_KEYS[@]} -lt 1 ]; then
        fatal_error "deployment.ssh_keys must include at least one SSH key name"
    fi

    TAILSCALE_AUTHKEY=$(read_toml_default "$CONFIG_FILE" "tailscale.authkey" "")
    TAILSCALE_DOMAIN=$(read_toml_default "$CONFIG_FILE" "tailscale.tailscale_domain" "")
    TAILSCALE_HOSTNAME=$(read_toml_default "$CONFIG_FILE" "tailscale.hostname" "$SERVER_NAME")
    TAILSCALE_USE_SSH=$(read_toml_default "$CONFIG_FILE" "tailscale.use_tailscale_ssh" "false")
    EMAIL_DOMAIN=$(read_toml_default "$CONFIG_FILE" "email.scaleway_domain" "")
    SMTP_HOST=$(read_toml_default "$CONFIG_FILE" "email.smtp_host" "smtp.tem.scw.cloud")
    SMTP_PORT=$(read_toml_default "$CONFIG_FILE" "email.smtp_port" "587")
    SMTP_USER=$(read_toml_default "$CONFIG_FILE" "email.smtp_user" "")
    SMTP_PASSWORD=$(read_toml_default "$CONFIG_FILE" "email.smtp_password" "")
    EMAIL_FROM=$(read_toml_default "$CONFIG_FILE" "email.email_from" "")
    EMAIL_TO=$(read_toml_default "$CONFIG_FILE" "email.email_to" "")

    if [ -n "$TAILSCALE_AUTHKEY" ] && echo "$TAILSCALE_AUTHKEY" | grep -q "^op read"; then
        TAILSCALE_AUTHKEY=$(eval "$TAILSCALE_AUTHKEY" 2>/dev/null || echo "")
    fi
    if [ -n "$SMTP_USER" ] && echo "$SMTP_USER" | grep -q "^op read"; then
        SMTP_USER=$(eval "$SMTP_USER" 2>/dev/null || echo "")
    fi
    if [ -n "$SMTP_PASSWORD" ] && echo "$SMTP_PASSWORD" | grep -q "^op read"; then
        SMTP_PASSWORD=$(eval "$SMTP_PASSWORD" 2>/dev/null || echo "")
    fi
    if [ -n "$EMAIL_DOMAIN" ] && echo "$EMAIL_DOMAIN" | grep -q "^op read"; then
        EMAIL_DOMAIN=$(eval "$EMAIL_DOMAIN" 2>/dev/null || echo "")
    fi

    validate_tailscale_config "$TAILSCALE_AUTHKEY" "$TAILSCALE_DOMAIN"

    echo_info "Creating Hetzner server: $SERVER_NAME"
    HCLOUD_CMD=(hcloud server create --name "$SERVER_NAME" --type "$SERVER_TYPE" --image "$SERVER_IMAGE")
    if [ -n "$SERVER_LOCATION" ]; then
        HCLOUD_CMD+=(--location "$SERVER_LOCATION")
    fi
    for key in "${SSH_KEYS[@]}"; do
        HCLOUD_CMD+=(--ssh-key "$key")
    done
    HCLOUD_CMD+=(--output json)

    SERVER_ID=$("${HCLOUD_CMD[@]}" 2>/dev/null | jq -r '.server.id')
    if [ -z "$SERVER_ID" ] || [ "$SERVER_ID" = "null" ]; then
        fatal_error "Failed to create server via hcloud"
    fi

    cleanup_on_error() {
        echo_warn "Deployment failed; deleting server $SERVER_ID"
        hcloud server delete "$SERVER_ID" 2>/dev/null || true
        exit 1
    }
    trap cleanup_on_error ERR

    echo_info "Waiting for server IP..."
    sleep 5
    SERVER_IP=$(hcloud server describe "$SERVER_ID" --output json | jq -r '.public_net.ipv4.ip')
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "null" ]; then
        fatal_error "Failed to determine server IP"
    fi

    echo_info "Server IP: $SERVER_IP"
    wait_for_ssh "$SSH_USER@$SERVER_IP" "$SSH_PORT" 120

    echo_info "Installing Tailscale..."
    ssh_exec "$SSH_USER@$SERVER_IP" "curl -fsSL https://tailscale.com/install.sh | sh" "$SSH_PORT"
    ssh_exec "$SSH_USER@$SERVER_IP" "tailscale up --authkey=\"$TAILSCALE_AUTHKEY\" --hostname=\"$TAILSCALE_HOSTNAME\" --ssh=$TAILSCALE_USE_SSH" "$SSH_PORT"

    echo_info "Installing Docker and dependencies..."
    ssh_exec "$SSH_USER@$SERVER_IP" "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -qq -y ca-certificates curl git python3 unattended-upgrades apt-listchanges postfix mailutils libsasl2-modules" "$SSH_PORT"
    ssh_exec "$SSH_USER@$SERVER_IP" "curl -fsSL https://get.docker.com | sh" "$SSH_PORT"
    ssh_exec "$SSH_USER@$SERVER_IP" "cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UNATTENDEDEOF'
Unattended-Upgrade::Origins-Pattern {
        \"origin=Debian,codename=\${distro_codename},label=Debian\";
        \"origin=Debian,codename=\${distro_codename},label=Debian-Security\";
        \"origin=Debian,codename=\${distro_codename}-security,label=Debian-Security\";
        \"origin=Debian,codename=\${distro_codename}-updates,label=Debian\";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";
Unattended-Upgrade::Remove-New-Unused-Dependencies \"true\";
Unattended-Upgrade::Remove-Unused-Dependencies \"true\";
Unattended-Upgrade::Automatic-Reboot \"true\";
Unattended-Upgrade::Automatic-Reboot-Time \"03:30\";
UNATTENDEDEOF" "$SSH_PORT"
    ssh_exec "$SSH_USER@$SERVER_IP" "cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOEOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::AutocleanInterval \"7\";
APT::Periodic::Unattended-Upgrade \"1\";
AUTOEOF" "$SSH_PORT"

    if [ -n "$SMTP_USER" ] && [ -n "$SMTP_PASSWORD" ] && [ -n "$EMAIL_DOMAIN" ]; then
        echo_info "Configuring Postfix for Scaleway Transactional Email..."
        ssh_exec "$SSH_USER@$SERVER_IP" "cat > /etc/postfix/main.cf << EOF
# Postfix configuration for Scaleway Transactional Email
myhostname = $SERVER_NAME.$EMAIL_DOMAIN
myorigin = $EMAIL_DOMAIN
mydestination = localhost, $EMAIL_DOMAIN
masquerade_domains = $EMAIL_DOMAIN

mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
inet_interfaces = loopback-only
inet_protocols = all

local_header_rewrite_clients = static:all
append_at_myorigin = yes

relayhost = [$SMTP_HOST]:$SMTP_PORT
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
EOF" "$SSH_PORT"

        ssh_exec "$SSH_USER@$SERVER_IP" "cat > /etc/postfix/sasl_passwd << 'EOF'
[$SMTP_HOST]:$SMTP_PORT $SMTP_USER:$SMTP_PASSWORD
EOF" "$SSH_PORT"
        ssh_exec "$SSH_USER@$SERVER_IP" "chmod 600 /etc/postfix/sasl_passwd && postmap /etc/postfix/sasl_passwd" "$SSH_PORT"
        ssh_exec "$SSH_USER@$SERVER_IP" "systemctl restart postfix && systemctl enable postfix > /dev/null 2>&1" "$SSH_PORT"

        if [ -n "$EMAIL_FROM" ] && [ -n "$EMAIL_TO" ]; then
            echo_info "Sending test email..."
            ssh_exec "$SSH_USER@$SERVER_IP" "SERVER_IP=\\$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print \\$2}' | cut -d/ -f1 || echo \"unavailable\")
echo \"TI stack email configuration test

If you receive this message, your email configuration is working correctly.

Server: \\$(hostname)
IP: \\$SERVER_IP
Time: \\$(date)
\" | mail -s \"[TI] Test Email - Configuration Successful\" -a \"From: $EMAIL_FROM\" \"$EMAIL_TO\"" "$SSH_PORT"
        fi
    else
        echo_warn "Email config missing; skipping Postfix setup"
    fi

    echo_info "Cloning repository..."
    ssh_exec "$SSH_USER@$SERVER_IP" "if [ ! -d \"$INSTALL_DIR/.git\" ]; then rm -rf \"$INSTALL_DIR\"; git clone --branch \"$BRANCH\" \"$REPO_URL\" \"$INSTALL_DIR\"; else cd \"$INSTALL_DIR\"; git fetch --all --prune; git checkout \"$BRANCH\"; git pull --ff-only; fi" "$SSH_PORT"

    echo_info "Copying .env..."
    scp_copy "$ENV_FILE" "$SSH_USER@$SERVER_IP:$INSTALL_DIR/.env" "$SSH_PORT"

    echo_info "Starting docker compose..."
    if [ "$NO_BUILD" = "true" ]; then
        ssh_exec "$SSH_USER@$SERVER_IP" "cd \"$INSTALL_DIR\" && docker compose up -d" "$SSH_PORT"
    else
        ssh_exec "$SSH_USER@$SERVER_IP" "cd \"$INSTALL_DIR\" && docker compose up -d --build" "$SSH_PORT"
    fi

    trap - ERR
    echo_info "Remote stack started. Verify URLs on the host."
}

# ============================================================
# Entrypoint
# ============================================================

if [ "$LOCAL_ONLY" = "true" ]; then
    deploy_local
else
    deploy_hetzner
fi
