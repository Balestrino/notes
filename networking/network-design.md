# Network Design for Homelab
- This document outlines the network design for a homelab environment, including VLANs, IP ranges, and purposes.
- It is designed to provide a structured and scalable network architecture.
- Version: 1.0
- Date: 2025-07-18

## Hardware Overview
- Router: MikroTik CCR2004-1G-12S+2XS (12xSFP+ 10Gb + 2xSFP+ 25Gb + 1x1GbE management port)
- Core Switch: MikroTik CSS326-24G-2S+RM Managed Gigabit Ethernet (10/100/1000) Power over Ethernet (PoE) 1U
- Servers: Multiple Dell servers using Proxmox for different purposes (load balancing, web, database, applications, etc.)

## Network Design Notes
- The network is segmented into multiple VLANs to isolate traffic and enhance security.
- Each VLAN has a specific purpose and is assigned a unique subnet.
- The untrusted network is isolated to prevent unauthorized access to critical systems.
- The design includes a dedicated management VLAN for infrastructure devices.
- The IP addressing scheme is designed to maximize the use of available addresses while maintaining clear boundaries between different network segments.
- First 10 IPs in each VLAN are reserved for infrastructure devices (routers, switches, servers).
- From the 11th IP to 99th IP, the devices can be assigned dynamically via DHCP.
- Static IPs are assigned from the 100th IP onwards.
- Dell Poweredge servers are connected to the router via 10GbE SFP+ ports for high-speed connectivity.
- Core switch is connected to the router via 10GbE SFP+ ports for high-speed connectivity.
- All the devices in the network are connected to the core switch, which acts as the central point of communication.
- The network is designed as Zero Trust, meaning that no device is trusted by default, and access is granted based on policies.
- Static IP addresses are assigned by the DHCP server for critical infrastructure devices to ensure they remain reachable.

## The network
- Network Overview: 192.168.88.0/21
- Range: 192.168.88.0 - 192.168.95.255
- Usable IPs: 2,046 addresses
- Subnets available: 8 /24 networks
- Description: This supernet is divided into 8x /24 subnets. Each subnet is assigned to a specific VLAN to enable traffic segmentation and inter-VLAN routing, which is enforced by firewall rules on the router.

## VLAN & Subnet Architecture
- Assignment Rule:** For each subnet, IPs `.1-.10` are reserved for network infrastructure, `.11-.99` for DHCP, and `.100-.254` for static assignments via DHCP reservation or manual configuration.

### VLAN 10: Servers
- Subnet: 192.168.88.0/24
- Gateway: 192.168.88.1
- DHCP Range: 192.168.88.11 - 192.168.88.99
- Static Range: 192.168.88.100 - 192.168.88.254
- Purpose: Hosts all server workloads, including Kubernetes nodes, Docker hosts, and other applications.

### VLAN 11: Management
- Subnet: 192.168.89.0/24
- Gateway: 192.168.89.1
- Static Range: 192.168.89.100 - 192.168.89.254
- Purpose: For infrastructure management interfaces (Router, Switch, Server iDRAC/IPMI). Highly restricted access. No general DHCP.

### VLAN 12: Security/Monitoring
- Subnet: 192.168.90.0/24
- Gateway: 192.168.90.1
- Static Range: 192.168.90.100 - 192.168.90.254
- Purpose: For security cameras, monitoring tools (e.g., Prometheus, Zabbix), and log servers.

### VLAN 20: Workstations
- Subnet: 192.168.91.0/24
- Gateway: 192.168.91.1
- DHCP Range: 192.168.91.11 - 192.168.91.254
- Purpose: Trusted client devices (desktops, laptops).

### VLAN 30: Storage
- Subnet: 192.168.92.0/24
- Gateway: 192.168.92.1 (or no gateway if it's a non-routable storage-only network)
- Static Range: 192.168.92.10 - 192.168.92.254
- Purpose: Dedicated high-speed network for NAS, iSCSI, or NFS traffic between servers and storage arrays.

### VLAN 70: Guest/IoT
- Subnet: 192.168.93.0/24
- Gateway: 192.168.93.1
- DHCP Range: 192.168.93.11 - 192.168.93.254
- Purpose: Untrusted guest and IoT devices. Should be firewalled to only allow internet access.

### VLAN 90: Untrusted Lab
- Subnet: 192.168.94.0/24
- Gateway: 192.168.94.1
- DHCP Range: 192.168.94.11 - 192.168.94.254
- Purpose: A sandbox for testing potentially unsafe applications, completely isolated from all other internal VLANs.

### VLAN 80: Reserved/Future
- Subnet: 192.168.95.0/24
- Gateway: 192.168.95.1
- Purpose: Reserved for future use.
