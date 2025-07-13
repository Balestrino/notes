# Proxmox Ubuntu Template Creator

A robust Bash script for creating cloud-init enabled Ubuntu templates in Proxmox VE with security hardening and optional Docker installation.

## Features

- **Automated Ubuntu Template Creation**: Downloads and configures Ubuntu cloud images for Proxmox
- **Cloud-Init Integration**: Full cloud-init support for easy VM provisioning
- **Security Hardening**: SSH security configurations, fail2ban, and automatic updates
- **Docker Support**: Optional Docker installation with log rotation and cleanup
- **Flexible Configuration**: Command-line arguments and configuration file support
- **Error Handling**: Comprehensive error handling with automatic cleanup
- **Logging**: Colorized output with optional syslog integration

## Prerequisites

- Proxmox VE environment
- Root or sudo access
- Internet connectivity for downloading Ubuntu images
- Available storage pool in Proxmox

## Quick Start

```bash
# Basic usage (interactive mode)
sudo ./create-template.sh

# Create template with Docker
sudo ./create-template.sh --docker

# Custom configuration
sudo ./create-template.sh --vmid 5001 --name my-ubuntu-template --memory 4096 --cores 4
```

## Installation

1. Clone or download the script:
```bash
wget https://raw.githubusercontent.com/yourusername/proxmox-ubuntu-template/main/create-template.sh
chmod +x create-template.sh
```

2. (Optional) Create a configuration file:
```bash
cp template.conf.example template.conf
# Edit template.conf with your preferences
```

## Usage

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--docker` | Install Docker from official repositories | false |
| `--vmid ID` | Set the VM ID | 5000 |
| `--storage NAME` | Set the storage location | local-zfs |
| `--memory MB` | Set memory in MB | 2048 |
| `--cores NUM` | Set number of CPU cores | 2 |
| `--disk-size SIZE` | Set disk size (e.g., 10G, 20G) | 10G |
| `--name NAME` | Set the template name | ubuntu-2504-template |
| `--syslog` | Enable logging to syslog | false |
| `-h, --help` | Show help message | - |

### Configuration File

Create a `template.conf` file in the same directory as the script:

```bash
# template.conf
VMID=5001
STORAGE="local-lvm"
TEMPLATE_NAME="ubuntu-2504-custom"
MEMORY=4096
CORES=4
DISK_SIZE="20G"
INSTALL_DOCKER=true
USE_SYSLOG=true
```

### Examples

#### Create a basic template:
```bash
sudo ./create-template.sh
```

#### Create a template with Docker:
```bash
sudo ./create-template.sh --docker
```

#### Create a high-resource template:
```bash
sudo ./create-template.sh --vmid 5002 --memory 8192 --cores 8 --disk-size 50G --name ubuntu-high-spec
```

#### Use different storage:
```bash
sudo ./create-template.sh --storage local-lvm --name ubuntu-lvm-template
```

## What the Script Does

### 1. **Downloads Ubuntu Cloud Image**
- Fetches the latest Ubuntu 25.04 (Plucky) cloud image
- Verifies download integrity
- Caches image for subsequent runs

### 2. **Creates Cloud-Init Configuration**
- Installs essential packages (qemu-guest-agent, curl, wget, vim, htop, fail2ban, etc.)
- Removes unnecessary services (postfix, snapd, lxd)
- Configures automatic security updates
- Disables default MOTD services for cleaner login

### 3. **Security Hardening**
- Disables root login via SSH
- Enforces key-based authentication
- Configures secure SSH ciphers and algorithms
- Installs and enables fail2ban
- Disables X11 forwarding

### 4. **Docker Installation** (Optional)
- Installs Docker CE from official repositories
- Configures log rotation (10MB × 3 files per container)
- Sets up weekly cleanup of unused images and volumes
- Configures overlay2 storage driver

### 5. **VM Template Creation**
- Creates Proxmox VM with UEFI boot
- Configures virtio drivers for performance
- Sets up cloud-init disk
- Applies SSH keys from authorized_keys
- Converts VM to template

## Post-Installation

### Cloning the Template

```bash
# Clone the template to create a new VM
qm clone 5000 101 --name my-new-vm

# Start the VM
qm start 101

# Get VM IP (after boot)
qm agent 101 network-get-interfaces
```

### Cloud-Init Configuration

When cloning, you can customize the VM through Proxmox UI or CLI:

```bash
# Set hostname and user
qm set 101 --ciuser myuser --cipassword mypassword

# Configure network
qm set 101 --ipconfig0 ip=192.168.1.100/24,gw=192.168.1.1

# Set SSH keys
qm set 101 --sshkeys ~/.ssh/authorized_keys

# Regenerate cloud-init image
qm cloudinit update 101
```

## Security Considerations

- **SSH Keys**: Configure SSH keys before first boot
- **Firewall**: Consider enabling Proxmox firewall
- **Docker Security**: If using Docker, implement rootless Docker or proper sudo permissions
- **Updates**: Template includes automatic security updates
- **Fail2Ban**: Pre-configured for SSH protection

## Troubleshooting

### Common Issues

1. **Storage not found**: Verify storage name with `pvesm status`
2. **Permission denied**: Run script as root or with sudo
3. **VM ID exists**: Script will prompt to destroy existing VM
4. **Download fails**: Check internet connectivity and Ubuntu image URL

### Logs

- Enable syslog with `--syslog` flag
- Check Proxmox logs: `/var/log/pve/`
- VM console available through Proxmox web interface

### Cleanup

If the script fails, it automatically cleans up incomplete VMs. Manual cleanup:

```bash
# Remove incomplete VM
qm destroy 5000 --purge

# Remove cloud-init file
rm /var/lib/vz/snippets/ubuntu-plucky.yaml

# Remove downloaded image
rm noble-server-cloudimg-amd64.img
```

## Supported Ubuntu Versions

- Ubuntu 25.04 (Plucky) - Default
- Ubuntu 24.04 (Noble) - Change `UBUNTU_VERSION` variable

## Requirements

- Proxmox VE 7.0+
- 2GB+ available memory
- 10GB+ available storage
- Internet connection for downloads

## License

This script is provided as-is under the MIT License. See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and questions:
- Create an issue in the GitHub repository
- Check Proxmox documentation
- Review the script's built-in help: `./create-template.sh --help`

---

**Note**: This script creates production-ready templates with security hardening. Always test in a development environment first.