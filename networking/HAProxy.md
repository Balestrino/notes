# HAProxy High Availability Setup with MikroTik CCR2004

This guide provides a complete step-by-step setup for achieving high availability with multiple HAProxy instances behind a MikroTik CCR2004 router using VRRP and health monitoring.

## Architecture Overview

```
Internet → MikroTik CCR2004 → VRRP Virtual IP → HAProxy Instances → Backend Servers
```

- **MikroTik CCR2004**: Routes traffic to HAProxy virtual IP
- **HAProxy Primary**: Active load balancer (VRRP Master)
- **HAProxy Secondary**: Standby load balancer (VRRP Backup)
- **VRRP Virtual IP**: Shared IP address for seamless failover

## Prerequisites

- MikroTik CCR2004 router with RouterOS 7.x
- Two or more Linux servers for HAProxy instances
- Network connectivity between all components
- Administrative access to all devices

## Network Layout

```
Component               IP Address        Role
---------               ----------        ----
MikroTik CCR2004        192.168.1.1       Router/Gateway
HAProxy Primary         192.168.1.10      Master Load Balancer
HAProxy Secondary       192.168.1.11      Backup Load Balancer
VRRP Virtual IP         192.168.1.100     Shared Virtual IP
Backend Server 1        192.168.1.20      Web Server
Backend Server 2        192.168.1.21      Web Server
```

## Step 1: Configure HAProxy Instances

### 1.1 Install HAProxy and Keepalived

On both HAProxy servers:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install haproxy keepalived

# CentOS/RHEL
sudo yum install haproxy keepalived
# or for newer versions
sudo dnf install haproxy keepalived
```

### 1.2 Configure HAProxy

Create `/etc/haproxy/haproxy.cfg` on both servers:

```haproxy
global
    log stdout local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    option dontlognull
    option redispatch
    retries 3
    maxconn 2000

# Statistics page
stats enable
stats uri /haproxy-stats
stats refresh 30s
stats admin if TRUE

# Health check endpoint
listen health_check
    bind *:8080
    mode http
    monitor-uri /health
    option httpchk GET /health

# Frontend configuration
frontend web_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/your-certificate.pem
    redirect scheme https if !{ ssl_fc }
    default_backend web_servers

# Backend configuration
backend web_servers
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200

    server web1 192.168.1.20:80 check inter 5s fall 3 rise 2
    server web2 192.168.1.21:80 check inter 5s fall 3 rise 2
```

### 1.3 Configure Keepalived (VRRP)

#### Primary HAProxy Server (192.168.1.10)

Create `/etc/keepalived/keepalived.conf`:

```bash
global_defs {
    router_id HAPROXY_PRIMARY
    enable_script_security
    script_user root
}

vrrp_script chk_haproxy {
    script "/bin/curl -f http://localhost:8080/health || exit 1"
    interval 3
    weight -2
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 110
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass YourSecurePassword123
    }
    virtual_ipaddress {
        192.168.1.100/24
    }
    track_script {
        chk_haproxy
    }
    notify_master "/etc/keepalived/notify_master.sh"
    notify_backup "/etc/keepalived/notify_backup.sh"
    notify_fault "/etc/keepalived/notify_fault.sh"
}
```

#### Secondary HAProxy Server (192.168.1.11)

Create `/etc/keepalived/keepalived.conf`:

```bash
global_defs {
    router_id HAPROXY_SECONDARY
    enable_script_security
    script_user root
}

vrrp_script chk_haproxy {
    script "/bin/curl -f http://localhost:8080/health || exit 1"
    interval 3
    weight -2
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state BACKUP
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass YourSecurePassword123
    }
    virtual_ipaddress {
        192.168.1.100/24
    }
    track_script {
        chk_haproxy
    }
    notify_master "/etc/keepalived/notify_master.sh"
    notify_backup "/etc/keepalived/notify_backup.sh"
    notify_fault "/etc/keepalived/notify_fault.sh"
}
```

### 1.4 Create Notification Scripts

Create `/etc/keepalived/notify_master.sh`:

```bash
#!/bin/bash
echo "$(date): Transitioned to MASTER state" >> /var/log/keepalived-state.log
logger "HAProxy VRRP: Transitioned to MASTER state"
```

Create `/etc/keepalived/notify_backup.sh`:

```bash
#!/bin/bash
echo "$(date): Transitioned to BACKUP state" >> /var/log/keepalived-state.log
logger "HAProxy VRRP: Transitioned to BACKUP state"
```

Create `/etc/keepalived/notify_fault.sh`:

```bash
#!/bin/bash
echo "$(date): Transitioned to FAULT state" >> /var/log/keepalived-state.log
logger "HAProxy VRRP: Transitioned to FAULT state"
```

Make scripts executable:

```bash
chmod +x /etc/keepalived/notify_*.sh
```

## Step 2: Configure MikroTik CCR2004

### 2.1 Basic Network Configuration

Connect to your MikroTik via Winbox, WebFig, or SSH and configure:

```routeros
# Configure interface
/interface ethernet
set [ find default-name=ether1 ] name=ether1-gateway

# Set IP address
/ip address
add address=192.168.1.1/24 interface=ether1-gateway network=192.168.1.0

# Enable IP forwarding
/ip settings
set ip-forward=yes
```

### 2.2 Configure Default Route to VRRP Virtual IP

```routeros
# Add default route pointing to VRRP virtual IP
/ip route
add dst-address=0.0.0.0/0 gateway=192.168.1.100 distance=1 check-gateway=ping
```

### 2.3 Set Up Netwatch for Health Monitoring

```routeros
# Monitor VRRP virtual IP
/tool netwatch
add host=192.168.1.100 interval=5s timeout=2s up-script="log info \"VRRP VIP is UP\"" down-script="log error \"VRRP VIP is DOWN\""

# Monitor individual HAProxy instances
add host=192.168.1.10 interval=10s timeout=3s up-script="log info \"HAProxy Primary is UP\"" down-script="log error \"HAProxy Primary is DOWN\""
add host=192.168.1.11 interval=10s timeout=3s up-script="log info \"HAProxy Secondary is UP\"" down-script="log error \"HAProxy Secondary is DOWN\""
```

### 2.4 Configure Advanced Health Monitoring (Optional)

For more sophisticated monitoring, create a script that checks HAProxy health endpoints:

```routeros
# Create script to check HAProxy health
/system script
add name="check-haproxy-health" source={
    :local primaryHealth [/tool fetch url="http://192.168.1.10:8080/health" as-value output=none]
    :local secondaryHealth [/tool fetch url="http://192.168.1.11:8080/health" as-value output=none]

    :if (($primaryHealth->"status") = "finished") do={
        :log info "HAProxy Primary health check: OK"
    } else={
        :log error "HAProxy Primary health check: FAILED"
    }

    :if (($secondaryHealth->"status") = "finished") do={
        :log info "HAProxy Secondary health check: OK"
    } else={
        :log error "HAProxy Secondary health check: FAILED"
    }
}

# Schedule the script to run every 30 seconds
/system scheduler
add name="haproxy-health-check" interval=30s on-event="check-haproxy-health"
```

### 2.5 Configure Firewall Rules

```routeros
# Allow VRRP traffic
/ip firewall filter
add chain=input protocol=vrrp action=accept comment="Allow VRRP"

# Allow health monitoring traffic
add chain=input dst-port=8080 protocol=tcp action=accept comment="Allow HAProxy health checks"

# Allow web traffic to HAProxy
add chain=forward dst-address=192.168.1.100 dst-port=80,443 protocol=tcp action=accept comment="Allow web traffic to HAProxy"
```

## Step 3: Start and Enable Services

### 3.1 On Both HAProxy Servers

```bash
# Start and enable HAProxy
sudo systemctl start haproxy
sudo systemctl enable haproxy

# Start and enable Keepalived
sudo systemctl start keepalived
sudo systemctl enable keepalived

# Check service status
sudo systemctl status haproxy
sudo systemctl status keepalived
```

### 3.2 Verify VRRP Status

Check which server is the VRRP master:

```bash
# Check IP addresses
ip addr show

# Check keepalived logs
sudo journalctl -u keepalived -f

# Check VRRP state
sudo tail -f /var/log/keepalived-state.log
```

## Step 4: Testing and Validation

### 4.1 Basic Connectivity Test

```bash
# From MikroTik, ping the virtual IP
/ping 192.168.1.100

# Test web connectivity
/tool fetch url="http://192.168.1.100" keep-result=no
```

### 4.2 Failover Testing

1. **Test Primary HAProxy Failure**:

   ```bash
   # On primary server, stop HAProxy
   sudo systemctl stop haproxy

   # Check if secondary takes over
   ip addr show  # Should show VIP on secondary
   ```

2. **Test Network Interface Failure**:

   ```bash
   # On primary server, disable network interface
   sudo ip link set eth0 down

   # Verify failover occurred
   ```

3. **Test Service Recovery**:

   ```bash
   # Restart services on primary
   sudo systemctl start haproxy
   sudo ip link set eth0 up

   # Check if it becomes master again
   ```

### 4.3 Performance Testing

```bash
# Use tools like Apache Bench or wrk
ab -n 10000 -c 100 http://192.168.1.100/

# Or use wrk
wrk -t12 -c400 -d30s http://192.168.1.100/
```

## Step 5: Monitoring and Maintenance

### 5.1 Log Monitoring

**HAProxy Logs**:

```bash
sudo tail -f /var/log/haproxy.log
```

**Keepalived Logs**:

```bash
sudo journalctl -u keepalived -f
```

**MikroTik Logs**:

```routeros
/log print follow where topics~"system"
```

### 5.2 Health Check Endpoints

- HAProxy Stats: `http://192.168.1.100/haproxy-stats`
- Health Check: `http://192.168.1.100:8080/health`
- Individual HAProxy instances: `http://192.168.1.10:8080/health` and `http://192.168.1.11:8080/health`

### 5.3 Regular Maintenance Tasks

1. **Update HAProxy configurations** on both servers simultaneously
2. **Monitor resource usage** (CPU, memory, connections)
3. **Review logs** for errors or warnings
4. **Test failover scenarios** monthly
5. **Update software packages** during maintenance windows

## Troubleshooting

### Common Issues and Solutions

**VRRP Not Working**:

- Check firewall rules allow VRRP protocol
- Verify network connectivity between servers
- Ensure authentication passwords match
- Check for duplicate VRRP IDs on network

**HAProxy Health Checks Failing**:

- Verify backend servers are responding
- Check HAProxy configuration syntax
- Review backend server health check endpoints
- Monitor network connectivity to backends

**MikroTik Routing Issues**:

- Verify routing table: `/ip route print`
- Check gateway reachability: `/ping 192.168.1.100`
- Review firewall rules: `/ip firewall filter print`

**Split-Brain Scenario**:

- Both servers think they're master
- Check network connectivity between HAProxy servers
- Verify VRRP authentication configuration
- Review keepalived logs for errors

## Security Considerations

1. **Change default VRRP passwords**
2. **Implement proper firewall rules**
3. **Use SSL/TLS certificates for HTTPS**
4. **Regularly update all software components**
5. **Monitor access logs for suspicious activity**
6. **Implement network segmentation**
7. **Use strong authentication for management interfaces**

## Conclusion

This setup provides a robust high availability solution with automatic failover capabilities. The combination of VRRP for IP failover and HAProxy for load balancing ensures minimal downtime and optimal performance. Regular testing and monitoring are essential to maintain the reliability of this configuration.

For additional scalability, consider:

- Adding more HAProxy instances
- Implementing geographical redundancy
- Using advanced load balancing algorithms
- Integrating with monitoring solutions like Prometheus/Grafana
