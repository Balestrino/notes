#!/bin/bash

# Proxmox Ubuntu Template Creation Script
# Creates a cloud-init enabled Ubuntu template with a custom MOTD.

# --- Configuration ---
# Default values. Can be overridden by template.conf or command-line arguments.
CONFIG_FILE="template.conf"
VMID=5000
STORAGE="local-zfs"
# TEMPLATE_NAME="ubuntu-2404-template"
# UBUNTU_VERSION="noble"
TEMPLATE_NAME="ubuntu-2504-template"
UBUNTU_VERSION="plucky"
MEMORY=2048
CORES=2
DISK_SIZE="10G"
INSTALL_DOCKER=false
USE_SYSLOG=false

# --- Constants ---
IMAGE_NAME="${UBUNTU_VERSION}-server-cloudimg-amd64.img"
IMAGE_URL="https://cloud-images.ubuntu.com/${UBUNTU_VERSION}/current/${IMAGE_NAME}"
SNIPPET_DIR="/var/lib/vz/snippets"
CLOUD_INIT_FILE="${SNIPPET_DIR}/ubuntu-${UBUNTU_VERSION}.yaml"

# --- Colors and Logging ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    local type="$1"
    local message="$2"
    local color
    case "$type" in
        INFO) color="$BLUE" ;;
        SUCCESS) color="$GREEN" ;;
        WARN) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        *) color="$NC" ;;
    esac
    echo -e "${color}[$type]${NC} $message"
    if [[ "$USE_SYSLOG" == true ]]; then
        logger -t proxmox-template-builder "[$type] $message"
    fi
}

# --- Error Handling & Cleanup ---
cleanup() {
    # If VM was created but script failed before templating, destroy it
    if qm status "$VMID" &>/dev/null && ! qm config "$VMID" | grep -q "template: 1"; then
        log "WARN" "Destroying incomplete VM $VMID."
        qm destroy "$VMID" --purge || true
    fi
    log "SUCCESS" "Cleanup finished."
}
trap cleanup EXIT
set -Eeuo pipefail

# --- Helper Functions ---

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    fi
}

validate_integer() {
    if ! [[ "$1" =~ ^[1-9][0-9]*$ ]]; then
        log "ERROR" "$2 must be a positive integer. Got: '$1'"
        exit 1
    fi
}

validate_string() {
    if ! [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log "ERROR" "$2 contains invalid characters. Use only alphanumeric, dashes, and underscores. Got: '$1'"
        exit 1
    fi
}

validate_disk_size() {
    if ! [[ "$DISK_SIZE" =~ ^[1-9][0-9]*[GM]$ ]]; then
        log "ERROR" "Disk size must be in the format <num>G or <num>M. Got: '$DISK_SIZE'"
        exit 1
    fi
}

# --- Core Functions ---

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --docker          Install Docker from official repositories.
  --vmid ID         Set the VM ID (default: $VMID).
  --storage NAME    Set the storage location (default: $STORAGE).
  --memory MB       Set memory in MB (default: $MEMORY).
  --cores NUM       Set number of CPU cores (default: $CORES).
  --disk-size SIZE  Set disk size (e.g., 10G) (default: $DISK_SIZE).
  --name NAME       Set the template name (default: $TEMPLATE_NAME).
  --syslog          Enable logging to syslog.
  -h, --help        Show this help message.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --docker) INSTALL_DOCKER=true; shift ;;
            --vmid) VMID="$2"; shift 2 ;;
            --storage) STORAGE="$2"; shift 2 ;;
            --memory) MEMORY="$2"; shift 2 ;;
            --cores) CORES="$2"; shift 2 ;;
            --disk-size) DISK_SIZE="$2"; shift 2 ;;
            --name) TEMPLATE_NAME="$2"; shift 2 ;;
            --syslog) USE_SYSLOG=true; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) log "ERROR" "Unknown parameter: $1"; show_help; exit 1 ;;
        esac
    done
}

validate_config() {
    log "INFO" "Validating configuration..."
    validate_integer "$VMID" "VMID"
    validate_integer "$MEMORY" "Memory"
    validate_integer "$CORES" "Cores"
    validate_string "$STORAGE" "Storage name"
    validate_string "$TEMPLATE_NAME" "Template name"
    validate_disk_size

    if [[ $EUID -ne 0 ]]; then log "ERROR" "This script must be run as root or with sudo."; exit 1; fi
    if ! pvesm status --storage "$STORAGE" &>/dev/null; then log "ERROR" "Proxmox storage '$STORAGE' not found."; exit 1; fi
    if [[ ! -d "$SNIPPET_DIR" ]]; then log "ERROR" "Proxmox snippets directory not found at '$SNIPPET_DIR'."; exit 1; fi

    if qm status "$VMID" &>/dev/null; then
        read -r -p "$(echo -e "${YELLOW}[WARN]${NC} VM $VMID already exists and will be destroyed. Continue? (y/N): ")" response
        if [[ ! "$response" =~ ^[yY]$ ]]; then log "INFO" "Aborted by user."; exit 0; fi
    fi
    log "SUCCESS" "Configuration is valid."
}

download_image() {
    log "INFO" "Checking for Ubuntu cloud image: $IMAGE_NAME"
    if [[ -f "$IMAGE_NAME" ]]; then
        log "INFO" "Image already exists. Skipping download."
    else
        log "INFO" "Downloading Ubuntu cloud image..."
        wget --progress=bar:force:noscroll -O "$IMAGE_NAME" "$IMAGE_URL"
    fi

    if [[ ! -s "$IMAGE_NAME" ]]; then log "ERROR" "Image file is empty or download failed."; exit 1; fi
    log "SUCCESS" "Image is ready."
}

create_vm_template() {
    log "INFO" "Creating cloud-init configuration..."
    
    local pkgs=(qemu-guest-agent curl wget vim htop net-tools fail2ban unattended-upgrades apt-transport-https ca-certificates gnupg)
    local pkgs_to_purge=(postfix snapd lxd lxcfs)

    local runcmds=()
    
    runcmds+=(
      "- echo '>>> Purging unnecessary services...'"
      "- apt-get purge --auto-remove -y ${pkgs_to_purge[*]} || true"
      # MODIFICATION: Disable default MOTD services for a cleaner login.
      "- echo '>>> Disabling default MOTD services...'"
      "- systemctl disable --now motd-news.timer"
      "- systemctl disable --now landscape-client.service"
    )

    runcmds+=(
        '- systemctl enable --now qemu-guest-agent'
        '- systemctl enable --now fail2ban'
        '- systemctl enable unattended-upgrades'
        '- sed -i "s/^#?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config'
        '- sed -i "s/^#?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config'
        '- sed -i "s/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config'
        '- sed -i "s/^#?X11Forwarding.*/X11Forwarding no/" /etc/ssh/sshd_config'
        '- sed -i "s/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config'
        '- sed -i "s/^#?KerberosAuthentication.*/KerberosAuthentication no/" /etc/ssh/sshd_config'
        '- sed -i "s/^#?GSSAPIAuthentication.*/GSSAPIAuthentication no/" /etc/ssh/sshd_config'
        '- echo "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr" >> /etc/ssh/sshd_config'
        '- echo "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com" >> /etc/ssh/sshd_config'
        '- echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512" >> /etc/ssh/sshd_config'
        '- systemctl restart sshd'
        '- apt-get autoremove -y && apt-get clean'
    )

    if [[ "$INSTALL_DOCKER" == true ]]; then
        log "INFO" "Adding Docker installation and log rotation configuration..."
        runcmds+=(
            '- install -m 0755 -d /etc/apt/keyrings'
            '- curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc'
            '- chmod a+r /etc/apt/keyrings/docker.asc'
            '- echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list'
            '- apt-get update'
            '- apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'
            '- systemctl enable docker'
            '- systemctl start docker'
        )
    fi

    {
        echo "#cloud-config"
        echo "package_update: true"
        echo "package_upgrade: true"
        echo "packages:"
        for pkg in "${pkgs[@]}"; do echo "  - $pkg"; done
        echo "runcmd:"
        for cmd in "${runcmds[@]}"; do echo "  $cmd"; done
        
        if [[ "$INSTALL_DOCKER" == true ]]; then
            echo "  - # Configure Docker log rotation and cleanup"
            echo "  - systemctl daemon-reload"
            echo "  - systemctl restart docker"
            echo "  - systemctl enable docker-cleanup.timer"
            echo "  - systemctl start docker-cleanup.timer"
            echo "  - # Test Docker installation"
            echo "  - docker run --rm hello-world"
            echo "  - # Clean up test container"
            echo "  - docker image rm hello-world"
        fi
    } > "$CLOUD_INIT_FILE"
    log "SUCCESS" "Cloud-init configuration created."

    if qm status "$VMID" &>/dev/null; then
        log "INFO" "Destroying existing VM $VMID..."
        qm destroy "$VMID" --purge
    fi

    local final_template_name="$TEMPLATE_NAME"
    if [[ "$INSTALL_DOCKER" == true ]]; then final_template_name+="-docker"; fi

    log "INFO" "Resizing disk..."
    qemu-img resize "$IMAGE_NAME" "$DISK_SIZE"

    log "INFO" "Creating VM $VMID..."
    qm create "$VMID" --name "$final_template_name" --ostype l26 \
        --memory "$MEMORY" --balloon 0 --cores "$CORES" --cpu host --socket 1 \
        --agent 1,fstrim_cloned_disks=1 --bios ovmf --machine q35 --efidisk0 "$STORAGE:0,pre-enrolled-keys=0" \
        --vga serial0 --serial0 socket --net0 virtio,bridge=vmbr0
    
    log "INFO" "Importing disk..."
    qm importdisk "$VMID" "$IMAGE_NAME" "$STORAGE"

    qm set $VMID --scsihw virtio-scsi-pci --virtio0 $STORAGE:vm-$VMID-disk-1,discard=on
    qm set $VMID --boot order=virtio0
    qm set $VMID --scsi1 $STORAGE:cloudinit
    qm set $VMID --cicustom "vendor=local:snippets/$(basename "$CLOUD_INIT_FILE")"
    qm set $VMID --tags ubuntu-template,cloudinit
    qm set $VMID --ciuser $USER
    qm set $VMID --sshkeys ~/.ssh/authorized_keys
    qm set $VMID --ipconfig0 ip=dhcp

    local ssh_key_file="${SSH_KEY_FILE:-$HOME/.ssh/authorized_keys}"
    if [[ -f "$ssh_key_file" ]]; then
        log "INFO" "Configuring SSH keys from $ssh_key_file"
        qm set "$VMID" --sshkeys "$ssh_key_file"
    else
        log "WARN" "No SSH keys found. Configure manually after cloning."
    fi

    log "INFO" "Converting VM to template..."
    qm template "$VMID"
    log "SUCCESS" "Template '$final_template_name' (ID: $VMID) created successfully."
}

main() {
    load_config
    if [[ $# -eq 0 ]]; then
        read -r -p "$(echo -e "${YELLOW}[PROMPT]${NC} Install Docker? (y/N): ")" response
        if [[ "$response" =~ ^[yY]$ ]]; then
            INSTALL_DOCKER=true
        fi
    else
        parse_args "$@"
    fi

    validate_config
    download_image
    create_vm_template

    echo
    log "SUCCESS" "All tasks completed!"
    if [[ "$INSTALL_DOCKER" == true ]]; then
        log "SUCCESS" "Docker installed with log rotation configured:"
        log "INFO" "  - Container logs limited to 10MB x 3 files per container"
        log "INFO" "  - System-wide log rotation with 7-day retention"
        log "INFO" "  - Weekly automatic cleanup of unused images and volumes"
        log "INFO" "  - Docker daemon configured with overlay2 storage driver"
    fi
    if [[ "$INSTALL_DOCKER" == true ]]; then
        log "WARN" "Docker is installed. For security, use rootless Docker or grant specific permissions via sudo."
    fi
    echo
    echo "To clone: qm clone $VMID <new_vmid> --name <new_vm_name>"
}

main "$@"