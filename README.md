# Prometheus Installation Guide

Prometheus is a free and open-source systems monitoring and alerting toolkit originally built at SoundCloud. Now a standalone project and part of the Cloud Native Computing Foundation, it features a multi-dimensional data model with time series data identified by metric name and key/value pairs, PromQL query language, and powerful alerting capabilities. It serves as a FOSS alternative to commercial monitoring solutions like Datadog, New Relic, or Splunk, offering enterprise-grade monitoring and alerting without licensing costs.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended for production)
  - RAM: 2GB minimum (8GB+ recommended for production)
  - Storage: 20GB minimum (100GB+ SSD recommended for metrics retention)
  - Network: Stable connectivity for scraping targets
- **Operating System**: 
  - Linux: Any modern distribution with kernel 2.6.32+
  - macOS: 10.12+ (Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 9090 (Prometheus web UI and API)
  - Port 9093 (Alertmanager)
  - Port 9094 (Alertmanager cluster)
  - Various ports for exporters (9100 for node_exporter, etc.)
- **Dependencies**:
  - No runtime dependencies (Go binary)
  - Optional: Grafana for visualization
  - Optional: Alertmanager for alerting
- **System Access**: root or sudo privileges for installation


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Create prometheus user
sudo useradd --no-create-home --shell /bin/false prometheus

# Create directories
sudo mkdir -p /etc/prometheus /var/lib/prometheus
sudo chown prometheus:prometheus /etc/prometheus /var/lib/prometheus

# Download latest Prometheus
PROMETHEUS_VERSION="2.48.0"
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
tar xzf prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz

# Install binaries
cd prometheus-${PROMETHEUS_VERSION}.linux-amd64
sudo cp prometheus promtool /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool

# Copy configuration files
sudo cp -r consoles console_libraries /etc/prometheus/
sudo chown -R prometheus:prometheus /etc/prometheus/consoles /etc/prometheus/console_libraries

# Create basic configuration
sudo tee /etc/prometheus/prometheus.yml > /dev/null <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF

sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml
```

### Debian/Ubuntu

```bash
# Method 1: From official repository
wget -O prometheus.tar.gz https://github.com/prometheus/prometheus/releases/download/v2.48.0/prometheus-2.48.0.linux-amd64.tar.gz
tar xzf prometheus.tar.gz
cd prometheus-*

# Create user and directories
sudo useradd --no-create-home --shell /bin/false prometheus
sudo mkdir -p /etc/prometheus /var/lib/prometheus
sudo cp prometheus promtool /usr/local/bin/
sudo cp -r consoles console_libraries /etc/prometheus/
sudo chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus /usr/local/bin/prometheus /usr/local/bin/promtool

# Method 2: Using snap (simpler but less flexible)
sudo snap install prometheus

# Method 3: From community packages (older version)
sudo apt update
sudo apt install -y prometheus
```

### Arch Linux

```bash
# Install from official repositories
sudo pacman -S prometheus

# Optional: Install exporters
sudo pacman -S prometheus-node-exporter
sudo pacman -S prometheus-blackbox-exporter

# Enable and start service
sudo systemctl enable --now prometheus

# For latest version from AUR
yay -S prometheus-bin

# Configuration location: /etc/prometheus/prometheus.yml
```

### Alpine Linux

```bash
# Install Prometheus
apk add --no-cache prometheus prometheus-node-exporter

# Create prometheus user if not exists
adduser -D -H -s /sbin/nologin prometheus

# Create directories
mkdir -p /etc/prometheus /var/lib/prometheus
chown prometheus:prometheus /etc/prometheus /var/lib/prometheus

# Enable and start service
rc-update add prometheus default
rc-service prometheus start

# For Alertmanager
apk add --no-cache alertmanager
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y prometheus

# For latest version, build from source
sudo zypper install -y go
go install github.com/prometheus/prometheus/cmd/prometheus@latest
sudo cp ~/go/bin/prometheus /usr/local/bin/

# SLES 15
# May need to add monitoring repository
sudo SUSEConnect -p sle-module-containers/15.5/x86_64
sudo zypper install -y prometheus

# Create service user
sudo useradd --no-create-home --shell /bin/false prometheus

# Enable and start service
sudo systemctl enable --now prometheus
```

### macOS

```bash
# Using Homebrew
brew install prometheus

# Start as service
brew services start prometheus

# Or run manually
prometheus --config.file=/usr/local/etc/prometheus.yml

# Install exporters
brew install prometheus-node-exporter

# Configuration location: /usr/local/etc/prometheus.yml
# Alternative: /opt/homebrew/etc/prometheus.yml (Apple Silicon)
```

### FreeBSD

```bash
# Using pkg
pkg install prometheus
pkg install node_exporter

# Using ports
cd /usr/ports/net-mgmt/prometheus
make install clean

# Enable in rc.conf
echo 'prometheus_enable="YES"' >> /etc/rc.conf
echo 'node_exporter_enable="YES"' >> /etc/rc.conf

# Start services
service prometheus start
service node_exporter start

# Configuration location: /usr/local/etc/prometheus.yml
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install prometheus

# Method 2: Using Scoop
scoop bucket add extras
scoop install prometheus

# Method 3: Manual installation
# Download from https://github.com/prometheus/prometheus/releases
# Extract to C:\prometheus
# Create C:\prometheus\prometheus.yml

# Install as Windows service using NSSM
nssm install prometheus C:\prometheus\prometheus.exe
nssm set prometheus AppParameters "--config.file=C:\prometheus\prometheus.yml --storage.tsdb.path=C:\prometheus\data"
nssm set prometheus AppDirectory C:\prometheus
nssm start prometheus

# Or use Windows Service Wrapper
# Download WinSW from https://github.com/winsw/winsw/releases
```

## Initial Configuration

### First-Run Setup

1. **Create Prometheus user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/lib/prometheus -s /sbin/nologin -c "Prometheus monitoring" prometheus
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/prometheus/prometheus.yml`
- Debian/Ubuntu: `/etc/prometheus/prometheus.yml`
- Arch Linux: `/etc/prometheus/prometheus.yml`
- Alpine Linux: `/etc/prometheus/prometheus.yml`
- openSUSE/SLES: `/etc/prometheus/prometheus.yml`
- macOS: `/usr/local/etc/prometheus.yml`
- FreeBSD: `/usr/local/etc/prometheus.yml`
- Windows: `C:\prometheus\prometheus.yml`

3. **Essential settings to change**:

```yaml
# /etc/prometheus/prometheus.yml
global:
  scrape_interval: 15s       # How often to scrape targets
  evaluation_interval: 15s   # How often to evaluate rules
  external_labels:          # Labels to add to all metrics
    cluster: 'production'
    replica: 'prometheus-1'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - localhost:9093

# Load rules once and periodically evaluate them
rule_files:
  - "rules/*.yml"

# Scrape configurations
scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Node exporter for system metrics
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
```

### Testing Initial Setup

```bash
# Test configuration syntax
promtool check config /etc/prometheus/prometheus.yml

# Start Prometheus (if not using systemd)
prometheus --config.file=/etc/prometheus/prometheus.yml

# Verify Prometheus is running
curl http://localhost:9090/-/healthy

# Check targets
curl http://localhost:9090/api/v1/targets

# Run a test query
curl http://localhost:9090/api/v1/query?query=up
```

**WARNING:** Never expose Prometheus to the public internet without authentication!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Create systemd service file
sudo tee /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
Restart=always
RestartSec=5s
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.libraries=/etc/prometheus/console_libraries \
    --web.console.templates=/etc/prometheus/consoles \
    --web.enable-lifecycle

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start Prometheus
sudo systemctl daemon-reload
sudo systemctl enable prometheus
sudo systemctl start prometheus

# Management commands
sudo systemctl stop prometheus
sudo systemctl restart prometheus
sudo systemctl status prometheus

# View logs
sudo journalctl -u prometheus -f
```

### OpenRC (Alpine Linux)

```bash
# Create init script
sudo tee /etc/init.d/prometheus <<'EOF'
#!/sbin/openrc-run

name="prometheus"
description="Prometheus monitoring system"
command="/usr/bin/prometheus"
command_args="--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus/"
command_user="prometheus:prometheus"
pidfile="/run/${RC_SVCNAME}.pid"
start_stop_daemon_args="--background --make-pidfile"

depend() {
    need net
    after firewall
}
EOF

sudo chmod +x /etc/init.d/prometheus

# Enable and start
rc-update add prometheus default
rc-service prometheus start

# Management commands
rc-service prometheus stop
rc-service prometheus restart
rc-service prometheus status
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'prometheus_enable="YES"' >> /etc/rc.conf
echo 'prometheus_config="/usr/local/etc/prometheus.yml"' >> /etc/rc.conf
echo 'prometheus_data_dir="/var/db/prometheus"' >> /etc/rc.conf

# Start Prometheus
service prometheus start

# Management commands
service prometheus stop
service prometheus restart
service prometheus status
service prometheus reload
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start prometheus
brew services stop prometheus
brew services restart prometheus

# Check status
brew services list | grep prometheus

# Manual launchd management
sudo launchctl load /Library/LaunchDaemons/homebrew.mxcl.prometheus.plist
sudo launchctl unload /Library/LaunchDaemons/homebrew.mxcl.prometheus.plist
```

### Windows Service Manager

```powershell
# Using NSSM
nssm start prometheus
nssm stop prometheus
nssm restart prometheus

# Using native Windows commands
Start-Service prometheus
Stop-Service prometheus
Restart-Service prometheus

# Check status
Get-Service prometheus

# View logs
Get-EventLog -LogName Application -Source prometheus -Newest 50
```

## Advanced Configuration

### Storage Configuration

```yaml
# Advanced storage settings via command-line flags
--storage.tsdb.path=/var/lib/prometheus/
--storage.tsdb.retention.time=30d
--storage.tsdb.retention.size=50GB
--storage.tsdb.wal-compression
--storage.tsdb.max-block-duration=2h
--storage.tsdb.min-block-duration=2h
```

### High Availability Setup

```yaml
# prometheus.yml for HA setup
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    replica: '1'  # Different for each replica

# Remote write for long-term storage
remote_write:
  - url: "http://thanos-receive:19291/api/v1/receive"
    queue_config:
      max_samples_per_send: 10000
      batch_send_deadline: 5s
      max_retries: 3

# Remote read for querying historical data
remote_read:
  - url: "http://thanos-query:9090/api/v1/read"
    read_recent: true
```

### Service Discovery

```yaml
# Kubernetes service discovery
scrape_configs:
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)

# File-based service discovery
  - job_name: 'file-sd'
    file_sd_configs:
      - files:
        - '/etc/prometheus/targets/*.yml'
        refresh_interval: 5m

# DNS service discovery
  - job_name: 'dns-sd'
    dns_sd_configs:
      - names:
        - '_prometheus._tcp.example.com'
        type: 'SRV'
        refresh_interval: 30s
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/prometheus
upstream prometheus {
    server 127.0.0.1:9090;
}

server {
    listen 80;
    server_name prometheus.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name prometheus.example.com;

    ssl_certificate /etc/letsencrypt/live/prometheus.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/prometheus.example.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://prometheus;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Basic authentication
        auth_basic "Prometheus";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```

### Apache Configuration

```apache
# /etc/apache2/sites-available/prometheus.conf
<VirtualHost *:443>
    ServerName prometheus.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/prometheus.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/prometheus.example.com/privkey.pem
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:9090/
    ProxyPassReverse / http://localhost:9090/
    
    <Location />
        AuthType Basic
        AuthName "Prometheus"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Location>
</VirtualHost>
```

### Caddy Configuration

```caddyfile
prometheus.example.com {
    reverse_proxy localhost:9090
    
    basicauth {
        admin $2a$14$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    }
    
    header {
        Strict-Transport-Security "max-age=63072000"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
    }
}
```

### HAProxy Configuration

```haproxy
frontend prometheus_frontend
    bind *:443 ssl crt /etc/haproxy/certs/prometheus.pem
    mode http
    option httplog
    
    # Basic auth
    acl auth_ok http_auth(users)
    http-request auth realm Prometheus if !auth_ok
    
    default_backend prometheus_backend

backend prometheus_backend
    mode http
    balance roundrobin
    option httpchk GET /-/healthy
    server prometheus1 127.0.0.1:9090 check
```

## Security Configuration

### Authentication with Basic Auth

```bash
# Generate password file
htpasswd -c /etc/prometheus/.htpasswd admin

# Configure Prometheus with basic auth
sudo tee /etc/prometheus/web.yml <<EOF
basic_auth_users:
  admin: $2y$10$hashed_password_here
EOF

# Update systemd service to use web config
ExecStart=/usr/local/bin/prometheus \
    --config.file=/etc/prometheus/prometheus.yml \
    --web.config.file=/etc/prometheus/web.yml
```

### TLS Configuration

```yaml
# web.yml for TLS
tls_server_config:
  cert_file: /etc/prometheus/prometheus.crt
  key_file: /etc/prometheus/prometheus.key
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: /etc/prometheus/ca.crt
  min_version: TLS12
  cipher_suites:
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 9090
sudo ufw allow from 192.168.1.0/24 to any port 9093
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=prometheus
sudo firewall-cmd --permanent --zone=prometheus --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=prometheus --add-port=9090/tcp
sudo firewall-cmd --permanent --zone=prometheus --add-port=9093/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 9090 -j ACCEPT
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 9093 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port 9090
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port 9093

# Windows Firewall
New-NetFirewallRule -DisplayName "Prometheus" -Direction Inbound -Protocol TCP -LocalPort 9090 -RemoteAddress 192.168.1.0/24 -Action Allow
```

### Security Best Practices

```bash
# Restrict Prometheus data directory permissions
sudo chmod 700 /var/lib/prometheus
sudo chown -R prometheus:prometheus /var/lib/prometheus

# Disable admin API endpoints in production
# Remove --web.enable-admin-api flag

# Enable CORS restrictions
--web.cors.origin="https://grafana.example.com"

# Set read timeout
--web.read-timeout=5m

# Limit concurrent queries
--query.max-concurrency=20
```

## Database Setup

Prometheus uses its own time-series database (TSDB) and doesn't require external database setup. However, you can configure remote storage:

### Remote Storage Options

```yaml
# PostgreSQL with TimescaleDB
remote_write:
  - url: "http://prometheus-postgresql-adapter:9201/write"
remote_read:
  - url: "http://prometheus-postgresql-adapter:9201/read"

# InfluxDB
remote_write:
  - url: "http://influxdb:8086/api/v1/prom/write?db=prometheus"
remote_read:
  - url: "http://influxdb:8086/api/v1/prom/read?db=prometheus"

# Cortex/Thanos
remote_write:
  - url: "http://cortex:9009/api/prom/push"
    queue_config:
      capacity: 10000
      max_samples_per_send: 3000
```

### Storage Sizing

```bash
# Calculate storage requirements
# Formula: retention_time * ingested_samples_per_second * bytes_per_sample
# Example: 30 days * 100k samples/sec * 2 bytes = ~520GB

# Monitor storage usage
curl http://localhost:9090/api/v1/query?query=prometheus_tsdb_storage_blocks_bytes

# Configure retention
--storage.tsdb.retention.time=30d
--storage.tsdb.retention.size=500GB
```

## Performance Optimization

### System Tuning

```bash
# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf <<EOF
prometheus soft nofile 65535
prometheus hard nofile 65535
EOF

# Kernel parameters for better performance
sudo tee -a /etc/sysctl.conf <<EOF
# Prometheus optimizations
vm.max_map_count = 262144
fs.file-max = 65535
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8192
EOF

sudo sysctl -p
```

### Query Optimization

```yaml
# Recording rules for expensive queries
groups:
  - name: aggregations
    interval: 30s
    rules:
      - record: node:cpu_utilization:avg1m
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)
      
      - record: node:memory_utilization:ratio
        expr: 1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)
```

### Storage Optimization

```bash
# Enable compression
--storage.tsdb.wal-compression

# Optimize block duration for your workload
--storage.tsdb.max-block-duration=2h
--storage.tsdb.min-block-duration=2h

# Increase sample buffer
--storage.tsdb.head-chunks-write-queue-size=1000000
```

## Monitoring

### Built-in Metrics

```bash
# Prometheus self-monitoring queries
# Storage usage
prometheus_tsdb_storage_blocks_bytes

# Ingestion rate
rate(prometheus_tsdb_head_samples_appended_total[5m])

# Query performance
histogram_quantile(0.99, rate(prometheus_engine_query_duration_seconds_bucket[5m]))

# Active time series
prometheus_tsdb_head_series

# Memory usage
process_resident_memory_bytes
```

### Alerting Rules

```yaml
# /etc/prometheus/rules/prometheus.yml
groups:
  - name: prometheus
    rules:
      - alert: PrometheusDown
        expr: up{job="prometheus"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Prometheus is down"
          
      - alert: PrometheusStorageSpace
        expr: prometheus_tsdb_storage_blocks_bytes / 1024 / 1024 / 1024 > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Prometheus storage exceeds 100GB"
          
      - alert: PrometheusHighMemory
        expr: process_resident_memory_bytes / 1024 / 1024 / 1024 > 8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Prometheus memory usage exceeds 8GB"
```

### External Monitoring

```bash
# Blackbox exporter configuration for monitoring Prometheus
modules:
  prometheus_health:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: [200]
      method: GET
      path: /-/healthy
      
  prometheus_ready:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: [200]
      method: GET
      path: /-/ready
```

## 9. Backup and Restore

### Backup Procedures

```bash
#!/bin/bash
# backup-prometheus.sh

BACKUP_DIR="/backup/prometheus/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Option 1: Using snapshots (requires --web.enable-lifecycle)
curl -XPOST http://localhost:9090/api/v1/admin/tsdb/snapshot
SNAPSHOT=$(curl -s http://localhost:9090/api/v1/admin/tsdb/snapshot | jq -r .data.name)
cp -r /var/lib/prometheus/snapshots/$SNAPSHOT "$BACKUP_DIR/data"

# Option 2: Direct file backup (requires stopping Prometheus)
systemctl stop prometheus
tar czf "$BACKUP_DIR/prometheus-data.tar.gz" -C /var/lib/prometheus .
systemctl start prometheus

# Backup configuration
tar czf "$BACKUP_DIR/prometheus-config.tar.gz" -C /etc prometheus

# Backup to remote storage
# aws s3 cp "$BACKUP_DIR" s3://backups/prometheus/ --recursive
# rsync -avz "$BACKUP_DIR" backup-server:/backups/prometheus/

echo "Backup completed: $BACKUP_DIR"
```

### Restore Procedures

```bash
#!/bin/bash
# restore-prometheus.sh

BACKUP_DIR="$1"
if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory>"
    exit 1
fi

# Stop Prometheus
systemctl stop prometheus

# Restore data
rm -rf /var/lib/prometheus/*
tar xzf "$BACKUP_DIR/prometheus-data.tar.gz" -C /var/lib/prometheus
chown -R prometheus:prometheus /var/lib/prometheus

# Restore configuration
tar xzf "$BACKUP_DIR/prometheus-config.tar.gz" -C /etc
chown -R prometheus:prometheus /etc/prometheus

# Start Prometheus
systemctl start prometheus

echo "Restore completed from: $BACKUP_DIR"
```

### Automated Backup

```bash
# Create cron job for daily backups
echo "0 2 * * * /usr/local/bin/backup-prometheus.sh" | sudo tee -a /etc/crontab

# Backup retention script
find /backup/prometheus -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null
```

## 6. Troubleshooting

### Common Issues

1. **High memory usage**:
```bash
# Check cardinality
curl -s http://localhost:9090/api/v1/label/__name__/values | jq -r '.data[]' | wc -l

# Find high cardinality metrics
topk(10, count by (__name__)({__name__=~".+"}))

# Reduce memory usage
--storage.tsdb.retention.time=15d  # Reduce retention
--query.max-samples=50000000       # Limit query samples
```

2. **Slow queries**:
```bash
# Enable query logging
--log.queries-longer-than=10s

# Check slow queries
curl 'http://localhost:9090/api/v1/query?query=up&stats=all' | jq .stats

# Add recording rules for expensive queries
```

3. **Storage issues**:
```bash
# Check disk space
df -h /var/lib/prometheus

# Clean up old blocks
promtool tsdb clean /var/lib/prometheus

# Analyze TSDB
promtool tsdb analyze /var/lib/prometheus
```

4. **Scraping failures**:
```bash
# Check target status
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health != "up")'

# Debug specific target
curl -v http://target-host:9100/metrics

# Check Prometheus logs
journalctl -u prometheus -f | grep "error"
```

### Debug Mode

```bash
# Enable debug logging
--log.level=debug

# Enable query logging
--log.queries-longer-than=0s

# Profile Prometheus
curl http://localhost:9090/debug/pprof/profile?seconds=30 > profile.out
go tool pprof profile.out
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
# Download new version
PROMETHEUS_VERSION="2.49.0"
wget https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz

# Backup current installation
cp /usr/local/bin/prometheus /usr/local/bin/prometheus.backup

# Update binaries
tar xzf prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz
cd prometheus-${PROMETHEUS_VERSION}.linux-amd64
sudo systemctl stop prometheus
sudo cp prometheus promtool /usr/local/bin/
sudo systemctl start prometheus

# Debian/Ubuntu
# Similar process for manual installation
# For snap: sudo snap refresh prometheus

# Arch Linux
sudo pacman -Syu prometheus

# Alpine Linux
apk upgrade prometheus

# openSUSE
sudo zypper update prometheus

# FreeBSD
pkg upgrade prometheus

# macOS
brew upgrade prometheus

# Windows
# Update using package manager or manual download
```

### Health Checks

```bash
#!/bin/bash
# prometheus-health-check.sh

# Check if Prometheus is healthy
if ! curl -f -s http://localhost:9090/-/healthy > /dev/null; then
    echo "CRITICAL: Prometheus is not healthy"
    exit 2
fi

# Check if Prometheus is ready
if ! curl -f -s http://localhost:9090/-/ready > /dev/null; then
    echo "WARNING: Prometheus is not ready"
    exit 1
fi

# Check storage space
USED_PERCENT=$(df /var/lib/prometheus | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$USED_PERCENT" -gt 85 ]; then
    echo "WARNING: Storage usage is ${USED_PERCENT}%"
    exit 1
fi

# Check for failed targets
FAILED_TARGETS=$(curl -s http://localhost:9090/api/v1/targets | jq '[.data.activeTargets[] | select(.health != "up")] | length')
if [ "$FAILED_TARGETS" -gt 0 ]; then
    echo "WARNING: $FAILED_TARGETS targets are down"
    exit 1
fi

echo "OK: Prometheus is healthy"
exit 0
```

### Cleanup Tasks

```bash
# Remove old snapshots
find /var/lib/prometheus/snapshots -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null

# Compact TSDB
promtool tsdb compact /var/lib/prometheus

# Clean WAL
promtool tsdb clean /var/lib/prometheus

# Remove old backups
find /backup/prometheus -type d -mtime +30 -exec rm -rf {} \; 2>/dev/null
```

## Integration Examples

### Grafana Integration

```bash
# Add Prometheus datasource via API
curl -X POST http://admin:admin@localhost:3000/api/datasources \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Prometheus",
    "type": "prometheus",
    "url": "http://localhost:9090",
    "access": "proxy",
    "isDefault": true
  }'
```

### Alertmanager Integration

```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'http://localhost:5001/'
```

### Application Instrumentation

```python
# Python example
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time

# Create metrics
REQUEST_COUNT = Counter('app_requests_total', 'Total requests', ['method', 'endpoint'])
REQUEST_LATENCY = Histogram('app_request_latency_seconds', 'Request latency')
ACTIVE_USERS = Gauge('app_active_users', 'Active users')

# Use in application
@REQUEST_LATENCY.time()
def process_request():
    REQUEST_COUNT.labels(method='GET', endpoint='/api').inc()
    ACTIVE_USERS.set(42)
    time.sleep(0.1)

# Start metrics server
start_http_server(8000)
```

```javascript
// Node.js example
const prometheus = require('prom-client');
const express = require('express');

// Create metrics
const httpRequestDuration = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status']
});

const app = express();

// Middleware to track metrics
app.use((req, res, next) => {
  const end = httpRequestDuration.startTimer();
  res.on('finish', () => {
    end({ method: req.method, route: req.path, status: res.statusCode });
  });
  next();
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.register.contentType);
  res.end(await prometheus.register.metrics());
});
```

```go
// Go example
package main

import (
    "net/http"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    httpRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint"},
    )
)

func init() {
    prometheus.MustRegister(httpRequests)
}

func main() {
    http.Handle("/metrics", promhttp.Handler())
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        httpRequests.WithLabelValues(r.Method, r.URL.Path).Inc()
        w.Write([]byte("Hello World"))
    })
    http.ListenAndServe(":8080", nil)
}
```

## Additional Resources

- [Official Documentation](https://prometheus.io/docs/)
- [GitHub Repository](https://github.com/prometheus/prometheus)
- [PromQL Documentation](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Best Practices](https://prometheus.io/docs/practices/)
- [Awesome Prometheus](https://github.com/roaldnefs/awesome-prometheus)
- [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator)
- [Exporters](https://prometheus.io/docs/instrumenting/exporters/)
- [Community](https://prometheus.io/community/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.