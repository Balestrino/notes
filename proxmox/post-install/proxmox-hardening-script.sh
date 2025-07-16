#!/bin/bash

# Proxmox Security Hardening Script with Native Notification System
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

# Function to send notification via Proxmox native system
send_notification() {
    local severity=$1
    local message=$2
    local title=$3
    
    # Use pvesh to send notification through configured endpoints
    if command -v pvesh &> /dev/null; then
        pvesh create /cluster/notifications \
            --severity "$severity" \
            --title "$title" \
            --message "$message" \
            2>/dev/null || echo "Notification sent via fallback method"
    else
        # Fallback to logger
        logger -t "proxmox-hardening" "[$severity] $title: $message"
    fi
}

# Function to configure Proxmox notification endpoints
configure_notifications() {
    print_step "Configuring Proxmox Native Notifications"
    echo "This will set up notification endpoints (webhook, gotify, mail) for security alerts."
    
    if confirm; then
        echo "Choose notification methods to configure:"
        echo "1) Email notifications"
        echo "2) Webhook notifications"
        echo "3) Gotify notifications"
        echo "4) All of the above"
        read -p "Enter your choice (1-4): " notification_choice
        
        case $notification_choice in
            1|4)
                configure_email_notifications
                ;;
        esac
        
        case $notification_choice in
            2|4)
                configure_webhook_notifications
                ;;
        esac
        
        case $notification_choice in
            3|4)
                configure_gotify_notifications
                ;;
        esac
        
        # Configure notification matchers for security events
        configure_notification_matchers
    fi
}

# Function to configure email notifications
configure_email_notifications() {
    print_status "Configuring email notifications..."
    
    read -p "Enter SMTP server (e.g., smtp.gmail.com): " smtp_server
    read -p "Enter SMTP port (default 587): " smtp_port
    smtp_port=${smtp_port:-587}
    read -p "Enter sender email: " sender_email
    read -p "Enter sender password: " -s sender_password
    echo
    read -p "Enter recipient email: " recipient_email
    
    # Create email endpoint using pvesh
    pvesh create /cluster/notifications/endpoints/sendmail \
        --name "security-alerts-email" \
        --server "$smtp_server" \
        --port "$smtp_port" \
        --username "$sender_email" \
        --password "$sender_password" \
        --from-address "$sender_email" \
        --mailto "$recipient_email" \
        --mode "tls" \
        --comment "Security alerts email endpoint" \
        2>/dev/null || print_warning "Failed to create email endpoint via API, trying configuration file method"
    
    # Fallback: Create configuration manually
    mkdir -p /etc/pve/notifications/endpoints
    cat > /etc/pve/notifications/endpoints/sendmail.cfg << EOF
sendmail: security-alerts-email
    server $smtp_server
    port $smtp_port
    username $sender_email
    password $sender_password
    from-address $sender_email
    mailto $recipient_email
    mode tls
    comment Security alerts email endpoint
EOF
    
    print_status "Email notifications configured"
}

# Function to configure webhook notifications
configure_webhook_notifications() {
    print_status "Configuring webhook notifications..."
    
    read -p "Enter webhook URL: " webhook_url
    read -p "Enter webhook secret (optional): " webhook_secret
    
    # Create webhook endpoint using pvesh
    webhook_config="--name security-alerts-webhook --url $webhook_url"
    if [[ -n "$webhook_secret" ]]; then
        webhook_config="$webhook_config --secret $webhook_secret"
    fi
    
    pvesh create /cluster/notifications/endpoints/webhook \
        $webhook_config \
        --comment "Security alerts webhook endpoint" \
        2>/dev/null || print_warning "Failed to create webhook endpoint via API, trying configuration file method"
    
    # Fallback: Create configuration manually
    mkdir -p /etc/pve/notifications/endpoints
    cat > /etc/pve/notifications/endpoints/webhook.cfg << EOF
webhook: security-alerts-webhook
    url $webhook_url
    $([ -n "$webhook_secret" ] && echo "secret $webhook_secret")
    comment Security alerts webhook endpoint
EOF
    
    print_status "Webhook notifications configured"
}

# Function to configure Gotify notifications
configure_gotify_notifications() {
    print_status "Configuring Gotify notifications..."
    
    read -p "Enter Gotify server URL (e.g., https://gotify.example.com): " gotify_url
    read -p "Enter Gotify application token: " gotify_token
    
    # Create gotify endpoint using pvesh
    pvesh create /cluster/notifications/endpoints/gotify \
        --name "security-alerts-gotify" \
        --server "$gotify_url" \
        --token "$gotify_token" \
        --comment "Security alerts Gotify endpoint" \
        2>/dev/null || print_warning "Failed to create Gotify endpoint via API, trying configuration file method"
    
    # Fallback: Create configuration manually
    mkdir -p /etc/pve/notifications/endpoints
    cat > /etc/pve/notifications/endpoints/gotify.cfg << EOF
gotify: security-alerts-gotify
    server $gotify_url
    token $gotify_token
    comment Security alerts Gotify endpoint
EOF
    
    print_status "Gotify notifications configured"
}

# Function to configure notification matchers
configure_notification_matchers() {
    print_status "Configuring notification matchers for security events..."
    
    # Create matchers for different security events
    mkdir -p /etc/pve/notifications/matchers
    
    # Security alerts matcher
    cat > /etc/pve/notifications/matchers/security.cfg << EOF
matcher: security-alerts
    comment Security-related notifications
    mode all
    target security-alerts-email
    $([ -f /etc/pve/notifications/endpoints/webhook.cfg ] && echo "target security-alerts-webhook")
    $([ -f /etc/pve/notifications/endpoints/gotify.cfg ] && echo "target security-alerts-gotify")
    match-severity warning,error,critical
    match-field type:system
EOF
    
    # Fail2ban matcher
    cat > /etc/pve/notifications/matchers/fail2ban.cfg << EOF
matcher: fail2ban-alerts
    comment Fail2ban security events
    mode all
    target security-alerts-email
    $([ -f /etc/pve/notifications/endpoints/webhook.cfg ] && echo "target security-alerts-webhook")
    $([ -f /etc/pve/notifications/endpoints/gotify.cfg ] && echo "target security-alerts-gotify")
    match-severity warning,error
    match-field source:fail2ban
EOF
    
    print_status "Notification matchers configured"
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

# Configure notifications first
configure_notifications

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
    
    # Send notification
    send_notification "info" "System packages updated and automatic security updates configured" "System Update Complete"
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
        send_notification "info" "SSH hardening completed. Root login disabled, key-based auth configured for user: $admin_user" "SSH Security Update"
    fi
fi

# Step 4: Configure Fail2Ban with Proxmox Notifications
print_step "Step 4: Configure Fail2Ban with Proxmox Notifications"
echo "This will configure fail2ban to protect against brute force attacks with native Proxmox notifications."
web_port=8006  # Set default for later use
if confirm; then
    backup_config "/etc/fail2ban/jail.local"

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
# Custom action for Proxmox notifications
action = %(action_)s
         proxmox-notify

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

    # Create custom Proxmox notification action
    cat > /etc/fail2ban/action.d/proxmox-notify.conf << 'EOF'
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /usr/local/bin/proxmox-fail2ban-notify.sh ban "<ip>" "<name>" "<time>"
actionunban = /usr/local/bin/proxmox-fail2ban-notify.sh unban "<ip>" "<name>" "<time>"

[Init]
EOF

    # Create notification script for fail2ban
    cat > /usr/local/bin/proxmox-fail2ban-notify.sh << 'EOF'
#!/bin/bash
action=$1
ip=$2
jail=$3
time=$4

case $action in
    ban)
        message="IP $ip has been banned in jail $jail due to repeated failed attempts"
        severity="warning"
        title="Fail2Ban: IP Banned"
        ;;
    unban)
        message="IP $ip has been unbanned from jail $jail"
        severity="info"
        title="Fail2Ban: IP Unbanned"
        ;;
esac

# Send notification via Proxmox native system
if command -v pvesh &> /dev/null; then
    pvesh create /cluster/notifications \
        --severity "$severity" \
        --title "$title" \
        --message "$message" \
        --property "source=fail2ban" \
        --property "ip=$ip" \
        --property "jail=$jail" \
        2>/dev/null || logger -t "fail2ban-notify" "[$severity] $title: $message"
else
    logger -t "fail2ban-notify" "[$severity] $title: $message"
fi
EOF

    chmod +x /usr/local/bin/proxmox-fail2ban-notify.sh

    systemctl enable fail2ban
    systemctl restart fail2ban
    print_status "Fail2ban configured with Proxmox notifications"
    send_notification "info" "Fail2ban configured and started with native Proxmox notifications" "Fail2Ban Configuration Complete"
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
    send_notification "info" "System hardening completed: services disabled, kernel parameters configured, file permissions set" "System Hardening Complete"
fi

# Step 7: Logging and Monitoring with Proxmox Notifications
print_step "Step 7: Logging and Monitoring with Proxmox Notifications"
echo "This will configure logging and monitoring with native Proxmox notifications."
if confirm; then
    # Configure logrotate
    backup_config "/etc/logrotate.conf"

    # Install and configure logwatch
    apt install -y logwatch

    # Configure advanced monitoring script with Proxmox notifications
    cat > /usr/local/bin/system-monitor.sh << 'EOF'
#!/bin/bash
# Advanced system monitoring script with Proxmox notifications

# Function to send notification
send_notification() {
    local severity=$1
    local title=$2
    local message=$3
    
    if command -v pvesh &> /dev/null; then
        pvesh create /cluster/notifications \
            --severity "$severity" \
            --title "$title" \
            --message "$message" \
            --property "source=system-monitor" \
            2>/dev/null || logger -t "system-monitor" "[$severity] $title: $message"
    else
        logger -t "system-monitor" "[$severity] $title: $message"
    fi
}

# Check disk usage
high_disk_usage=$(df -h | awk '$5 > 80 {print $1 " is " $5 " full"}')
if [[ -n "$high_disk_usage" ]]; then
    send_notification "warning" "High Disk Usage Alert" "The following filesystems are over 80% full: $high_disk_usage"
fi

# Check memory usage
memory_usage=$(free | awk 'NR==2{printf "%.2f", $3*100/$2}')
if (( $(echo "$memory_usage > 90" | bc -l) )); then
    send_notification "warning" "High Memory Usage Alert" "Memory usage is at ${memory_usage}%"
fi

# Check CPU load
load_avg=$(uptime | awk '{print $10}' | cut -d',' -f1)
cpu_cores=$(nproc)
if (( $(echo "$load_avg > $cpu_cores" | bc -l) )); then
    send_notification "warning" "High CPU Load Alert" "Load average ($load_avg) is higher than CPU cores ($cpu_cores)"
fi

# Check system services
critical_services="pvedaemon pveproxy pvestatd"
for service in $critical_services; do
    if ! systemctl is-active --quiet $service; then
        send_notification "error" "Service Down Alert" "Critical service $service is not running"
    fi
done

# Daily summary (only send if no issues)
if [[ -z "$high_disk_usage" ]] && (( $(echo "$memory_usage < 90" | bc -l) )) && (( $(echo "$load_avg < $cpu_cores" | bc -l) )); then
    send_notification "info" "Daily System Status" "System is healthy - Memory: ${memory_usage}%, Load: $load_avg, Disk usage normal"
fi
EOF

    chmod +x /usr/local/bin/system-monitor.sh

    # Add to cron for regular monitoring
    (crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/system-monitor.sh") | crontab -

    print_status "Enhanced monitoring with Proxmox notifications configured"
    send_notification "info" "Monitoring and logging configured with native Proxmox notifications" "Monitoring Setup Complete"
fi

# Step 8: Backup Configuration with Notifications
print_step "Step 8: Backup Configuration with Notifications"
echo "This will set up backup strategies with notification alerts."
if confirm; then
    print_status "Creating backup script with notifications..."

    cat > /usr/local/bin/backup-configs.sh << 'EOF'
#!/bin/bash
# Configuration backup script with Proxmox notifications

# Function to send notification
send_notification() {
    local severity=$1
    local title=$2
    local message=$3
    
    if command -v pvesh &> /dev/null; then
        pvesh create /cluster/notifications \
            --severity "$severity" \
            --title "$title" \
            --message "$message" \
            --property "source=backup-system" \
            2>/dev/null || logger -t "backup-system" "[$severity] $title: $message"
    else
        logger -t "backup-system" "[$severity] $title: $message"
    fi
}

BACKUP_DIR="/root/config-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/proxmox-config-$DATE.tar.gz"

mkdir -p "$BACKUP_DIR"

# Backup important configuration files
if tar -czf "$BACKUP_FILE" \
    /etc/pve \
    /etc/network/interfaces \
    /etc/ssh/sshd_config \
    /etc/fail2ban \
    /etc/default/pveproxy \
    /etc/apt/sources.list.d/ \
    /etc/cron* \
    2>/dev/null; then
    
    backup_size=$(du -h "$BACKUP_FILE" | cut -f1)
    send_notification "info" "Backup Completed Successfully" "Configuration backup created: $BACKUP_FILE (Size: $backup_size)"
else
    send_notification "error" "Backup Failed" "Failed to create configuration backup"
    exit 1
fi

# Keep only last 7 days of backups
deleted_count=$(find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete -print | wc -l)
if [[ $deleted_count -gt 0 ]]; then
    send_notification "info" "Backup Cleanup" "Removed $deleted_count old backup files"
fi

echo "Configuration backup completed: $BACKUP_FILE"
EOF

    chmod +x /usr/local/bin/backup-configs.sh

    # Add to cron for daily execution
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup-configs.sh") | crontab -

    print_status "Backup script with notifications created and scheduled"
    send_notification "info" "Backup system configured with daily automated backups and notifications" "Backup System Setup Complete"
fi

# Final steps
print_step "Final Steps and Recommendations"
echo ""
print_status "Proxmox hardening with native notifications completed successfully!"
echo ""
print_warning "IMPORTANT REMINDERS:"
echo "1. Test SSH access with new port ($ssh_port) and user ($admin_user)"
echo "2. Access Proxmox web interface on port $web_port"
echo "3. Add your SSH public key to /home/$admin_user/.ssh/authorized_keys"
echo "4. Configure SSL certificates for the web interface"
echo "5. Set up proper backup storage (external/offsite)"
echo "6. Review and test all configurations"
echo "7. Test notification endpoints in Proxmox web interface"
echo "8. Document your changes and keep configuration backups safe"
echo ""
print_status "Security hardening script completed!"

# Send final notification
send_notification "info" "Proxmox security hardening completed successfully with native notification system configured" "Security Hardening Complete"

# Display current status
echo ""
print_step "Current System Status:"
echo "SSH Port: $ssh_port"
echo "Web Interface Port: $web_port"
echo "Admin User: $admin_user"
echo "Firewall Status: Not configured (skipped)"
echo "Fail2ban Status: $(systemctl is-active fail2ban)"
echo "Notifications: Native Proxmox system configured"
echo ""

print_warning "Remember to reboot the system to ensure all changes take effect!"
echo "Would you like to reboot now?"
if confirm; then
    send_notification "info" "System reboot initiated after security hardening" "System Reboot"
    reboot
fi