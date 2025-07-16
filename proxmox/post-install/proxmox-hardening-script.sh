#!/bin/bash

# Proxmox Security Hardening Script
# This script helps secure and harden a Proxmox server step by step
# Run as root: sudo bash proxmox_hardening.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to ask for confirmation
confirm() {
    while true; do
        read -p "Do you want to proceed? (y/n): " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to backup configuration files
backup_config() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
        print_status "Backed up $file"
    fi
}

# Main script starts here
clear
echo "========================================"
echo "    Proxmox Security Hardening Script"
echo "========================================"
echo ""

check_root

print_warning "This script will make changes to your Proxmox server configuration."
print_warning "Make sure you have console access in case SSH gets locked out."
echo ""

if ! confirm; then
    print_error "Script cancelled by user"
    exit 1
fi

# Step 1: System Updates
print_step "Step 1: System Updates"
echo "This will update all system packages to the latest versions."
if confirm; then
    print_status "Updating package lists..."
    apt update
    print_status "Upgrading packages..."
    apt upgrade -y
    print_status "Installing essential security packages..."
    apt install -y fail2ban unattended-upgrades apt-listchanges

    # Configure automatic updates
    echo "Configuring automatic security updates..."
    backup_config "/etc/apt/apt.conf.d/50unattended-upgrades"
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
    print_status "System updates completed"
fi

# Step 2: SSH Hardening
print_step "Step 2: SSH Hardening"
echo "This will secure SSH access by disabling root login and configuring key-based auth (keeping current port)."
if confirm; then
    backup_config "/etc/ssh/sshd_config"

    # Keep current SSH port
    ssh_port=$(grep "^Port " /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
    print_status "Keeping current SSH port: $ssh_port"

    # Get admin username
    read -p "Enter admin username for SSH access: " admin_user

    # Create admin user if doesn't exist
    if ! id "$admin_user" &>/dev/null; then
        print_status "Creating admin user: $admin_user"
        useradd -m -s /bin/bash "$admin_user"
        usermod -aG sudo "$admin_user"

        # Set password
        print_status "Set password for $admin_user:"
        passwd "$admin_user"

        # Setup SSH key directory
        mkdir -p "/home/$admin_user/.ssh"
        chmod 700 "/home/$admin_user/.ssh"
        chown "$admin_user:$admin_user" "/home/$admin_user/.ssh"

        print_warning "Don't forget to add your SSH public key to /home/$admin_user/.ssh/authorized_keys"
    fi

    # Configure SSH (keeping current port)
    cat > /etc/ssh/sshd_config << EOF
Port $ssh_port
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers $admin_user

# Security settings
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 2

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    print_status "SSH configuration updated (port unchanged)"
    print_warning "SSH will restart with new settings. Make sure you can login with the current port and new user!"

    if confirm; then
        systemctl restart sshd
        print_status "SSH restarted with new configuration"
    fi
fi



# Step 4: Configure Fail2Ban
print_step "Step 4: Configure Fail2Ban"
echo "This will configure fail2ban to protect against brute force attacks."
web_port=8006  # Set default for later use
if confirm; then
    backup_config "/etc/fail2ban/jail.local"

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[proxmox]
enabled = true
port = $web_port
filter = proxmox
logpath = /var/log/daemon.log
maxretry = 3
bantime = 3600
EOF

    # Create Proxmox filter
    cat > /etc/fail2ban/filter.d/proxmox.conf << 'EOF'
[Definition]
failregex = pvedaemon\[.*authentication failure; rhost=<HOST>
ignoreregex =
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    print_status "Fail2ban configured and started"
fi

# Step 6: System Hardening
print_step "Step 6: System Hardening"
echo "This will apply various system hardening measures."
if confirm; then
    # Disable unnecessary services
    services_to_disable="bluetooth cups avahi-daemon"
    for service in $services_to_disable; do
        if systemctl is-enabled $service >/dev/null 2>&1; then
            systemctl disable $service
            systemctl stop $service
            print_status "Disabled $service"
        fi
    done

    # Configure kernel parameters
    backup_config "/etc/sysctl.conf"
    cat >> /etc/sysctl.conf << 'EOF'

# Security hardening
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_syncookies=1
kernel.dmesg_restrict=1
EOF

    sysctl -p
    print_status "Kernel security parameters applied"

    # Set proper file permissions
    chmod 600 /etc/ssh/sshd_config
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow

    print_status "File permissions hardened"
fi

# Step 7: Logging and Monitoring
print_step "Step 7: Logging and Monitoring Setup"
echo "This will configure logging and basic monitoring."
if confirm; then
    # Configure logrotate
    backup_config "/etc/logrotate.conf"

    # Install and configure logwatch
    apt install -y logwatch

    # Configure basic monitoring script
    cat > /usr/local/bin/system-monitor.sh << 'EOF'
#!/bin/bash
# Basic system monitoring script

# Check disk usage
df -h | awk '$5 > 80 {print "WARNING: " $1 " is " $5 " full"}'

# Check memory usage
free -m | awk 'NR==2{printf "Memory usage: %.2f%%\n", $3*100/$2}'

# Check CPU load
uptime | awk '{print "Load average: " $10 $11 $12}'

# Check failed login attempts
grep "Failed password" /var/log/auth.log | tail -5
EOF

    chmod +x /usr/local/bin/system-monitor.sh

    # Add to cron for daily execution
    (crontab -l 2>/dev/null; echo "0 8 * * * /usr/local/bin/system-monitor.sh | mail -s 'Daily System Report' root") | crontab -

    print_status "Logging and monitoring configured"
fi

# Step 8: Backup Configuration
print_step "Step 8: Backup Configuration"
echo "This will help you set up backup strategies."
if confirm; then
    print_status "Creating backup script template..."

    cat > /usr/local/bin/backup-configs.sh << 'EOF'
#!/bin/bash
# Configuration backup script

BACKUP_DIR="/root/config-backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup important configuration files
tar -czf "$BACKUP_DIR/proxmox-config-$DATE.tar.gz" \
    /etc/pve \
    /etc/network/interfaces \
    /etc/ssh/sshd_config \
    /etc/fail2ban \
    /etc/default/pveproxy \
    /etc/apt/sources.list.d/ \
    /etc/cron* \
    2>/dev/null

# Keep only last 7 days of backups
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete

echo "Configuration backup completed: $BACKUP_DIR/proxmox-config-$DATE.tar.gz"
EOF

    chmod +x /usr/local/bin/backup-configs.sh

    # Add to cron for daily execution
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup-configs.sh") | crontab -

    print_status "Backup script created and scheduled"
fi

# Final steps
print_step "Final Steps and Recommendations"
echo ""
print_status "Proxmox hardening completed successfully!"
echo ""
print_warning "IMPORTANT REMINDERS:"
echo "1. Test SSH access with new port ($ssh_port) and user ($admin_user)"
echo "2. Access Proxmox web interface on port $web_port"
echo "3. Add your SSH public key to /home/$admin_user/.ssh/authorized_keys"
echo "4. Configure SSL certificates for the web interface"
echo "5. Set up proper backup storage (external/offsite)"
echo "6. Review and test all configurations"
echo "7. Document your changes and keep configuration backups safe"
echo ""
print_status "Security hardening script completed!"

# Display current status
echo ""
print_step "Current System Status:"
echo "SSH Port: $ssh_port"
echo "Web Interface Port: $web_port"
echo "Admin User: $admin_user"
echo "Firewall Status: Not configured (skipped)"
echo "Fail2ban Status: $(systemctl is-active fail2ban)"
echo ""

print_warning "Remember to reboot the system to ensure all changes take effect!"
echo "Would you like to reboot now?"
if confirm; then
    reboot
fi
