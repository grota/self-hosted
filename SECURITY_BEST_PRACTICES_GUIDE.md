# Security Best Practices Guide
## Docker Compose Infrastructure Security Framework

**Document Version:** 1.0  
**Last Updated:** December 2024  
**Infrastructure:** `/home/daytona/self-hosted/`  
**Scope:** Ongoing security maintenance and best practices  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Secure Container Configuration](#secure-container-configuration)
3. [Secrets Management](#secrets-management)
4. [Network Isolation](#network-isolation)
5. [Access Controls](#access-controls)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Ongoing Security Maintenance](#ongoing-security-maintenance)
8. [Incident Response](#incident-response)
9. [Compliance and Auditing](#compliance-and-auditing)
10. [Security Automation](#security-automation)

---

## Executive Summary

This guide establishes security best practices for maintaining and operating the self-hosted Docker compose infrastructure. It provides practical, implementable security measures that should be followed consistently to maintain a secure environment.

### Security Principles
- **Defense in Depth:** Multiple layers of security controls
- **Least Privilege:** Minimal necessary permissions and access
- **Zero Trust:** Verify everything, trust nothing
- **Continuous Monitoring:** Ongoing security assessment and alerting
- **Incident Preparedness:** Ready response to security events

---

## Secure Container Configuration

### Container Security Template

Every new service should follow this security template:

```yaml
services:
  service-name:
    image: vendor/service:specific-version  # Never use :latest
    container_name: service-name
    restart: unless-stopped
    
    # Security Configuration
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
    
    # User Configuration
    user: "1000:1000"  # Non-root user
    
    # Filesystem Security
    read_only: true  # When possible
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /var/tmp:noexec,nosuid,size=50m
    
    # Capability Management
    cap_drop:
      - ALL
    cap_add:
      - CHOWN  # Only add required capabilities
      - SETGID
      - SETUID
    
    # Resource Limits
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    
    # Health Monitoring
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    
    # Environment Security
    env_file:
      - .env
    environment:
      - SECURE_VAR=${SECURE_VAR}
    
    # Network Security
    networks:
      - service-specific-network
    
    # Logging
    extends:
      file: ../compose-snippets/logging-limits.yaml
      service: logging
    
    # Labels
    labels:
      - diun.enable=true
      - security.scan=enabled
```

### Service-Specific Security Configurations

#### Web Applications (Homepage, Stirling PDF, etc.)
```yaml
services:
  web-app:
    # Base security template +
    environment:
      - ENABLE_SECURITY=true
      - CSRF_PROTECTION=true
      - SESSION_TIMEOUT=3600
      - MAX_LOGIN_ATTEMPTS=5
    
    # Additional security headers
    labels:
      - "traefik.http.middlewares.security-headers.headers.customrequestheaders.X-Forwarded-Proto=https"
      - "traefik.http.middlewares.security-headers.headers.customresponseheaders.X-Frame-Options=SAMEORIGIN"
      - "traefik.http.middlewares.security-headers.headers.customresponseheaders.X-XSS-Protection=1; mode=block"
```

#### Database Services (PostgreSQL, Redis, etc.)
```yaml
services:
  database:
    # Base security template +
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
      - DB_ENCRYPTION=true
      - SSL_MODE=require
    
    # Database-specific security
    volumes:
      - ./data:/var/lib/postgresql/data:Z  # SELinux context
    
    # Network isolation
    networks:
      - database-network
    
    # No external ports
    # ports: []  # Never expose database ports directly
```

#### VPN/Network Services (Gluetun, WireGuard)
```yaml
services:
  vpn-service:
    # Required capabilities only
    cap_add:
      - NET_ADMIN
    cap_drop:
      - ALL
    
    # Security constraints
    security_opt:
      - no-new-privileges:true
    
    # Sysctls (minimal required)
    sysctls:
      - net.ipv4.ip_forward=1
    
    # Device access (minimal)
    devices:
      - /dev/net/tun:/dev/net/tun
```

---

## Secrets Management

### Environment Variable Security

#### Centralized Secrets Management
Create `/home/daytona/self-hosted/.secrets/`:

```bash
# Directory structure
.secrets/
├── master.env          # Master environment template
├── database.env        # Database credentials
├── api-keys.env        # API keys and tokens
├── certificates/       # SSL certificates
└── keys/              # Encryption keys
```

#### Master Environment Template
`/home/daytona/self-hosted/.secrets/master.env`:
```bash
# Global Configuration
TZ=Europe/Madrid
PUID=1000
PGID=1000
DOMAIN=home.lab

# Database Credentials (Generated with: openssl rand -base64 32)
POSTGRES_PASSWORD=
REDIS_PASSWORD=
CLICKHOUSE_PASSWORD=

# API Keys and Tokens
HOMEPAGE_API_KEY=
DIUN_TELEGRAM_TOKEN=
PAPERLESS_SECRET_KEY=

# Encryption Keys (Generated with: openssl rand -hex 32)
LANGFUSE_ENCRYPTION_KEY=
LANGFUSE_SALT=

# Service Credentials
PGADMIN_EMAIL=admin@home.lab
PGADMIN_PASSWORD=
MINIO_ROOT_USER=admin
MINIO_ROOT_PASSWORD=

# Widget Authentication
USERNAME_FOR_WIDGET=
PASSWORD_FOR_WIDGET=
KEY_FOR_WIDGET=
```

#### Secrets Generation Script
Create `/home/daytona/self-hosted/scripts/generate-secrets.sh`:
```bash
#!/bin/bash
set -euo pipefail

SECRETS_DIR="/home/daytona/self-hosted/.secrets"
mkdir -p "$SECRETS_DIR"

# Function to generate secure password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Function to generate encryption key
generate_key() {
    openssl rand -hex 32
}

# Generate secrets
echo "Generating secure secrets..."

cat > "$SECRETS_DIR/generated.env" << EOF
# Generated on $(date)
POSTGRES_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)
PGADMIN_PASSWORD=$(generate_password)
MINIO_ROOT_PASSWORD=$(generate_password)
LANGFUSE_ENCRYPTION_KEY=$(generate_key)
LANGFUSE_SALT=$(generate_key | cut -c1-16)
PAPERLESS_SECRET_KEY=$(generate_key)
EOF

echo "Secrets generated in $SECRETS_DIR/generated.env"
echo "Please review and integrate into your service configurations."
```

#### Service-Specific Environment Files

**PostgreSQL** (`/home/daytona/self-hosted/postgresql/.env`):
```bash
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_USER=postgres
POSTGRES_DB=postgres
POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
```

**Langfuse** (`/home/daytona/self-hosted/langfuse/.env`):
```bash
DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/langfuse
SALT=${LANGFUSE_SALT}
ENCRYPTION_KEY=${LANGFUSE_ENCRYPTION_KEY}
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
REDIS_AUTH=${REDIS_PASSWORD}
```

### Secrets Rotation Policy

#### Monthly Rotation Schedule
```bash
# Create rotation script
#!/bin/bash
# /home/daytona/self-hosted/scripts/rotate-secrets.sh

SERVICES_TO_RESTART=(
    "postgresql"
    "langfuse"
    "redis"
    "minio"
)

echo "Starting secrets rotation..."

# Generate new secrets
./generate-secrets.sh

# Update service configurations
for service in "${SERVICES_TO_RESTART[@]}"; do
    echo "Updating $service..."
    cd "/home/daytona/self-hosted/$service"
    
    # Backup current configuration
    cp .env .env.backup.$(date +%Y%m%d)
    
    # Update with new secrets
    # (Implementation depends on specific service)
    
    # Restart service
    docker compose down
    docker compose up -d
    
    # Verify health
    sleep 30
    docker compose ps
done

echo "Secrets rotation completed."
```

---

## Network Isolation

### Network Segmentation Strategy

#### Network Architecture
```yaml
# /home/daytona/self-hosted/compose-snippets/networks.yaml
networks:
  # Public-facing services
  proxy-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  
  # Database services
  database-network:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.21.0.0/24
  
  # Media services
  media-network:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.22.0.0/24
  
  # Monitoring services
  monitoring-network:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.23.0.0/24
  
  # Management services
  management-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.24.0.0/24
```

#### Service Network Assignment

**Public Services** (proxy-network):
- nginx-proxy-manager
- homepage (read-only dashboard)

**Database Services** (database-network):
- postgresql
- redis
- clickhouse

**Media Services** (media-network):
- sonarr, radarr, prowlarr
- qbittorrent
- gluetun (VPN gateway)

**Monitoring Services** (monitoring-network):
- diun
- dozzle
- prometheus
- grafana

**Management Services** (management-network):
- dockge
- pgadmin

#### Network Security Rules

Create `/home/daytona/self-hosted/scripts/setup-firewall.sh`:
```bash
#!/bin/bash
# Docker network firewall rules

# Block inter-network communication by default
iptables -I DOCKER-USER -i br-+ -o br-+ -j DROP

# Allow specific cross-network communication
# Database access from application networks
iptables -I DOCKER-USER -s 172.20.0.0/24 -d 172.21.0.0/24 -p tcp --dport 5432 -j ACCEPT
iptables -I DOCKER-USER -s 172.22.0.0/24 -d 172.21.0.0/24 -p tcp --dport 5432 -j ACCEPT

# Monitoring access
iptables -I DOCKER-USER -s 172.23.0.0/24 -d 172.20.0.0/24 -j ACCEPT
iptables -I DOCKER-USER -s 172.23.0.0/24 -d 172.21.0.0/24 -j ACCEPT
iptables -I DOCKER-USER -s 172.23.0.0/24 -d 172.22.0.0/24 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

---

## Access Controls

### Authentication and Authorization

#### Multi-Factor Authentication Setup

**Nginx Proxy Manager with OAuth2**:
```yaml
# Add OAuth2 proxy for additional authentication layer
services:
  oauth2-proxy:
    image: quay.io/oauth2-proxy/oauth2-proxy:latest
    container_name: oauth2-proxy
    environment:
      OAUTH2_PROXY_PROVIDER: github
      OAUTH2_PROXY_CLIENT_ID: ${GITHUB_CLIENT_ID}
      OAUTH2_PROXY_CLIENT_SECRET: ${GITHUB_CLIENT_SECRET}
      OAUTH2_PROXY_COOKIE_SECRET: ${OAUTH2_COOKIE_SECRET}
      OAUTH2_PROXY_EMAIL_DOMAINS: "*"
      OAUTH2_PROXY_UPSTREAM: http://homepage:3000
      OAUTH2_PROXY_HTTP_ADDRESS: 0.0.0.0:4180
    networks:
      - proxy-network
```

#### Service-Level Authentication

**Homepage Authentication**:
```yaml
# /home/daytona/self-hosted/homepage/config/settings.yaml
providers:
  longhorn:
    url: https://longhorn.home.lab
    username: ${LONGHORN_USERNAME}
    password: ${LONGHORN_PASSWORD}

# Enable authentication
auth:
  providers:
    oidc:
      issuer: https://auth.home.lab
      clientId: ${OIDC_CLIENT_ID}
      clientSecret: ${OIDC_CLIENT_SECRET}
```

#### Role-Based Access Control

Create `/home/daytona/self-hosted/config/rbac.yaml`:
```yaml
roles:
  admin:
    permissions:
      - "services:*"
      - "containers:*"
      - "networks:*"
      - "volumes:*"
  
  operator:
    permissions:
      - "services:read"
      - "services:restart"
      - "containers:logs"
  
  viewer:
    permissions:
      - "services:read"
      - "containers:read"

users:
  admin@home.lab:
    roles: [admin]
  operator@home.lab:
    roles: [operator]
  viewer@home.lab:
    roles: [viewer]
```

### SSH and System Access

#### SSH Hardening
```bash
# /etc/ssh/sshd_config security settings
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers your-username
```

#### Sudo Configuration
```bash
# /etc/sudoers.d/docker-admin
your-username ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/local/bin/docker-compose
```

---

## Monitoring and Logging

### Centralized Logging

#### Log Aggregation Setup
Create `/home/daytona/self-hosted/logging/compose.yaml`:
```yaml
services:
  loki:
    image: grafana/loki:latest
    container_name: loki
    volumes:
      - ./loki-config.yaml:/etc/loki/local-config.yaml
      - loki-data:/loki
    command: -config.file=/etc/loki/local-config.yaml
    networks:
      - monitoring-network

  promtail:
    image: grafana/promtail:latest
    container_name: promtail
    volumes:
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./promtail-config.yaml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml
    networks:
      - monitoring-network

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - monitoring-network
      - proxy-network

volumes:
  loki-data:
  grafana-data:
```

#### Security Event Monitoring

**Falco Security Monitoring**:
```yaml
services:
  falco:
    image: falcosecurity/falco:latest
    container_name: falco
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - /dev:/host/dev
      - /proc:/host/proc:ro
      - /boot:/host/boot:ro
      - /lib/modules:/host/lib/modules:ro
      - /usr:/host/usr:ro
      - /etc:/host/etc:ro
      - ./falco-rules.yaml:/etc/falco/falco_rules.local.yaml
    environment:
      - FALCO_GRPC_ENABLED=true
    networks:
      - monitoring-network
```

**Custom Falco Rules** (`/home/daytona/self-hosted/logging/falco-rules.yaml`):
```yaml
- rule: Unauthorized Docker Socket Access
  desc: Detect unauthorized access to Docker socket
  condition: >
    open_read and fd.name=/var/run/docker.sock and
    not proc.name in (docker, dockerd, containerd)
  output: >
    Unauthorized Docker socket access (user=%user.name command=%proc.cmdline
    file=%fd.name)
  priority: CRITICAL

- rule: Container Privilege Escalation
  desc: Detect container privilege escalation attempts
  condition: >
    spawned_process and container and
    proc.name in (sudo, su, doas) and
    not user.name=root
  output: >
    Container privilege escalation attempt (user=%user.name command=%proc.cmdline
    container=%container.name)
  priority: HIGH
```

### Performance and Health Monitoring

#### Prometheus Configuration
Create `/home/daytona/self-hosted/monitoring/prometheus.yml`:
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'docker'
    static_configs:
      - targets: ['localhost:9323']
  
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

#### Alert Rules
Create `/home/daytona/self-hosted/monitoring/alert_rules.yml`:
```yaml
groups:
- name: security_alerts
  rules:
  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage detected"
      description: "CPU usage is above 80% for more than 5 minutes"

  - alert: ContainerDown
    expr: up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Container is down"
      description: "Container {{ $labels.instance }} has been down for more than 1 minute"

  - alert: DiskSpaceLow
    expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 10
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Low disk space"
      description: "Disk space is below 10%"
```

---

## Ongoing Security Maintenance

### Regular Security Tasks

#### Daily Tasks
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/daily-security-check.sh

echo "=== Daily Security Check - $(date) ==="

# Check for failed containers
echo "Checking container health..."
docker compose ps --filter "status=exited"

# Check disk space
echo "Checking disk space..."
df -h | grep -E "(8[0-9]|9[0-9])%"

# Check for security updates
echo "Checking for security updates..."
apt list --upgradable | grep -i security

# Check log files for suspicious activity
echo "Checking logs for failed logins..."
grep "Failed password" /var/log/auth.log | tail -10

# Check Docker daemon logs
echo "Checking Docker daemon logs..."
journalctl -u docker --since "24 hours ago" | grep -i error

echo "Daily security check completed."
```

#### Weekly Tasks
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/weekly-security-maintenance.sh

echo "=== Weekly Security Maintenance - $(date) ==="

# Update all containers
echo "Updating container images..."
cd /home/daytona/self-hosted
./exec-all.sh docker compose pull

# Scan for vulnerabilities
echo "Scanning for vulnerabilities..."
for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
    echo "Scanning $image..."
    trivy image --severity HIGH,CRITICAL $image
done

# Clean up unused resources
echo "Cleaning up Docker resources..."
docker system prune -f
docker volume prune -f

# Backup configurations
echo "Backing up configurations..."
tar -czf "/backup/docker-configs-$(date +%Y%m%d).tar.gz" \
    /home/daytona/self-hosted --exclude="*/data" --exclude="*/.git"

echo "Weekly maintenance completed."
```

#### Monthly Tasks
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/monthly-security-audit.sh

echo "=== Monthly Security Audit - $(date) ==="

# Run Docker Bench Security
echo "Running Docker Bench Security..."
cd /opt/docker-bench-security
sudo sh docker-bench-security.sh

# Check for hardcoded secrets
echo "Scanning for hardcoded secrets..."
cd /home/daytona/self-hosted
grep -r "password\|secret\|key" . --include="*.yaml" --include="*.yml" | \
    grep -v "\${" | grep -v "#"

# Review user access
echo "Reviewing user access..."
last | head -20

# Check SSL certificate expiration
echo "Checking SSL certificates..."
for cert in /home/daytona/self-hosted/*/letsencrypt/live/*/cert.pem; do
    if [ -f "$cert" ]; then
        echo "Certificate: $cert"
        openssl x509 -in "$cert" -noout -dates
    fi
done

# Generate security report
echo "Generating security report..."
{
    echo "Security Audit Report - $(date)"
    echo "=================================="
    echo ""
    echo "Container Status:"
    docker compose ps
    echo ""
    echo "Network Configuration:"
    docker network ls
    echo ""
    echo "Volume Usage:"
    docker system df
} > "/var/log/security-audit-$(date +%Y%m).log"

echo "Monthly security audit completed."
```

### Automated Security Updates

#### Update Management Script
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/automated-updates.sh

set -euo pipefail

BACKUP_DIR="/backup/pre-update-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/automated-updates.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Create backup
log "Creating backup..."
mkdir -p "$BACKUP_DIR"
cp -r /home/daytona/self-hosted "$BACKUP_DIR/"

# Update system packages
log "Updating system packages..."
apt update && apt upgrade -y

# Update Docker images
log "Updating Docker images..."
cd /home/daytona/self-hosted

# Update images with specific version tags only
SERVICES_TO_UPDATE=(
    "homepage"
    "nginx-proxy-manager"
    "postgresql"
    "diun"
)

for service in "${SERVICES_TO_UPDATE[@]}"; do
    if [ -d "$service" ]; then
        log "Updating $service..."
        cd "$service"
        
        # Pull new image
        docker compose pull
        
        # Restart service
        docker compose down
        docker compose up -d
        
        # Wait and check health
        sleep 30
        if ! docker compose ps | grep -q "Up"; then
            log "ERROR: $service failed to start, rolling back..."
            docker compose down
            # Restore from backup if needed
            cp "$BACKUP_DIR/self-hosted/$service/compose.yaml" ./
            docker compose up -d
        else
            log "SUCCESS: $service updated successfully"
        fi
        
        cd ..
    fi
done

log "Automated updates completed."
```

---

## Incident Response

### Security Incident Response Plan

#### Incident Classification
- **Critical:** System compromise, data breach, service unavailability
- **High:** Unauthorized access attempts, malware detection
- **Medium:** Configuration drift, policy violations
- **Low:** Informational alerts, minor misconfigurations

#### Response Procedures

**Immediate Response (0-15 minutes)**:
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/incident-response.sh

INCIDENT_TYPE=$1
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"

echo "=== SECURITY INCIDENT RESPONSE ==="
echo "Incident ID: $INCIDENT_ID"
echo "Type: $INCIDENT_TYPE"
echo "Time: $(date)"

case $INCIDENT_TYPE in
    "compromise")
        echo "CRITICAL: System compromise detected"
        # Isolate affected containers
        docker network disconnect bridge suspicious-container || true
        # Stop suspicious services
        docker compose -f suspicious-service/compose.yaml down
        # Preserve evidence
        docker logs suspicious-container > "/var/log/incident-$INCIDENT_ID.log"
        ;;
    
    "unauthorized-access")
        echo "HIGH: Unauthorized access detected"
        # Block suspicious IPs
        iptables -A INPUT -s $SUSPICIOUS_IP -j DROP
        # Force password reset
        # Notify administrators
        ;;
    
    "malware")
        echo "HIGH: Malware detected"
        # Quarantine affected containers
        docker pause affected-container
        # Scan system
        clamscan -r /home/daytona/self-hosted
        ;;
esac

echo "Immediate response completed for $INCIDENT_ID"
```

#### Forensics and Investigation
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/collect-forensics.sh

INCIDENT_ID=$1
FORENSICS_DIR="/var/log/forensics/$INCIDENT_ID"

mkdir -p "$FORENSICS_DIR"

# Collect system information
uname -a > "$FORENSICS_DIR/system-info.txt"
ps aux > "$FORENSICS_DIR/processes.txt"
netstat -tulpn > "$FORENSICS_DIR/network-connections.txt"

# Collect Docker information
docker ps -a > "$FORENSICS_DIR/containers.txt"
docker images > "$FORENSICS_DIR/images.txt"
docker network ls > "$FORENSICS_DIR/networks.txt"

# Collect logs
cp /var/log/auth.log "$FORENSICS_DIR/"
cp /var/log/syslog "$FORENSICS_DIR/"
journalctl -u docker > "$FORENSICS_DIR/docker-daemon.log"

# Collect container logs
for container in $(docker ps -a --format "{{.Names}}"); do
    docker logs "$container" > "$FORENSICS_DIR/container-$container.log" 2>&1
done

# Create forensics archive
tar -czf "/var/log/forensics-$INCIDENT_ID.tar.gz" "$FORENSICS_DIR"

echo "Forensics collection completed: /var/log/forensics-$INCIDENT_ID.tar.gz"
```

---

## Compliance and Auditing

### Compliance Framework

#### Security Controls Mapping
```yaml
# /home/daytona/self-hosted/compliance/controls.yaml
controls:
  access_control:
    AC-2: "Account Management"
    implementation: "User accounts managed via SSH keys and sudo configuration"
    evidence: "/etc/passwd, /etc/sudoers.d/"
    
  audit_accountability:
    AU-2: "Audit Events"
    implementation: "Comprehensive logging via Docker, syslog, and Falco"
    evidence: "/var/log/, container logs"
    
  configuration_management:
    CM-2: "Baseline Configuration"
    implementation: "Infrastructure as Code via Docker Compose"
    evidence: "compose.yaml files, version control"
    
  identification_authentication:
    IA-2: "Identification and Authentication"
    implementation: "Multi-factor authentication via OAuth2 proxy"
    evidence: "OAuth2 configuration, authentication logs"
```

#### Audit Checklist
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/compliance-audit.sh

echo "=== Compliance Audit Checklist ==="

# Check 1: User Access Management
echo "1. Checking user access management..."
echo "   - SSH key authentication: $(grep -c "ssh-" ~/.ssh/authorized_keys)"
echo "   - Root login disabled: $(grep "PermitRootLogin no" /etc/ssh/sshd_config)"

# Check 2: Container Security
echo "2. Checking container security..."
echo "   - Containers running as non-root: $(docker ps --format "table {{.Names}}" | xargs -I {} docker inspect {} | grep -c '"User": "1000:1000"')"
echo "   - Security options enabled: $(docker ps --format "table {{.Names}}" | xargs -I {} docker inspect {} | grep -c "no-new-privileges")"

# Check 3: Network Security
echo "3. Checking network security..."
echo "   - Custom networks in use: $(docker network ls | grep -v "bridge\|host\|none" | wc -l)"
echo "   - Exposed ports: $(docker ps --format "table {{.Names}}\t{{.Ports}}" | grep -c "0.0.0.0")"

# Check 4: Data Protection
echo "4. Checking data protection..."
echo "   - Encrypted volumes: $(docker volume ls | wc -l)"
echo "   - Backup procedures: $(ls -la /backup/ | wc -l)"

# Check 5: Monitoring and Logging
echo "5. Checking monitoring and logging..."
echo "   - Log rotation configured: $(grep -c "max-size" /home/daytona/self-hosted/*/compose.yaml)"
echo "   - Security monitoring active: $(docker ps | grep -c "falco\|prometheus")"

echo "Compliance audit completed."
```

---

## Security Automation

### Automated Security Scanning

#### Vulnerability Scanning Pipeline
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/security-scan-pipeline.sh

SCAN_DATE=$(date +%Y%m%d)
REPORT_DIR="/var/log/security-scans/$SCAN_DATE"
mkdir -p "$REPORT_DIR"

# Container vulnerability scanning
echo "Starting container vulnerability scan..."
for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
    echo "Scanning $image..."
    trivy image --format json --output "$REPORT_DIR/$(echo $image | tr '/' '_' | tr ':' '_').json" "$image"
done

# Configuration scanning
echo "Scanning Docker configurations..."
docker-bench-security > "$REPORT_DIR/docker-bench-security.txt"

# Network scanning
echo "Scanning network configuration..."
nmap -sS -O localhost > "$REPORT_DIR/network-scan.txt"

# Generate summary report
python3 << EOF
import json
import os
import glob

report_dir = "$REPORT_DIR"
vulnerabilities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

for file in glob.glob(f"{report_dir}/*.json"):
    with open(file, 'r') as f:
        data = json.load(f)
        if 'Results' in data:
            for result in data['Results']:
                if 'Vulnerabilities' in result:
                    for vuln in result['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN')
                        if severity in vulnerabilities:
                            vulnerabilities[severity] += 1

with open(f"{report_dir}/summary.txt", 'w') as f:
    f.write(f"Security Scan Summary - {SCAN_DATE}\n")
    f.write("=" * 40 + "\n")
    for severity, count in vulnerabilities.items():
        f.write(f"{severity}: {count}\n")
EOF

echo "Security scan completed. Report available in $REPORT_DIR"
```

#### Continuous Compliance Monitoring
```bash
#!/bin/bash
# /home/daytona/self-hosted/scripts/compliance-monitor.sh

# Run every hour via cron
# 0 * * * * /home/daytona/self-hosted/scripts/compliance-monitor.sh

COMPLIANCE_LOG="/var/log/compliance-monitor.log"

log_compliance() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$COMPLIANCE_LOG"
}

# Check for configuration drift
if git -C /home/daytona/self-hosted status --porcelain | grep -q .; then
    log_compliance "WARNING: Configuration drift detected"
fi

# Check for unauthorized containers
AUTHORIZED_CONTAINERS=$(cat /home/daytona/self-hosted/authorized-containers.txt)
RUNNING_CONTAINERS=$(docker ps --format "{{.Names}}")

for container in $RUNNING_CONTAINERS; do
    if ! echo "$AUTHORIZED_CONTAINERS" | grep -q "$container"; then
        log_compliance "ALERT: Unauthorized container detected: $container"
    fi
done

# Check for security policy violations
if docker ps --format "{{.Names}}" | xargs -I {} docker inspect {} | grep -q '"Privileged": true'; then
    log_compliance "VIOLATION: Privileged container detected"
fi

# Check for exposed sensitive ports
if docker ps --format "{{.Ports}}" | grep -q "0.0.0.0:22\|0.0.0.0:3389\|0.0.0.0:5432"; then
    log_compliance "VIOLATION: Sensitive port exposed"
fi

log_compliance "Compliance check completed"
```

---

## Conclusion

This security best practices guide provides a comprehensive framework for maintaining and operating a secure Docker compose infrastructure. Key implementation priorities:

### Immediate Implementation (Week 1)
1. Apply secure container configuration template to all services
2. Implement centralized secrets management
3. Set up basic network segmentation
4. Deploy security monitoring (Falco)

### Short-term Implementation (Month 1)
1. Complete network micro-segmentation
2. Implement comprehensive logging and monitoring
3. Set up automated security scanning
4. Establish incident response procedures

### Long-term Implementation (Ongoing)
1. Maintain regular security maintenance schedules
2. Conduct monthly compliance audits
3. Continuously improve security automation
4. Stay updated with security best practices

### Success Metrics
- Zero critical vulnerabilities in monthly scans
- 100% of services following security template
- All secrets properly managed and rotated
- Comprehensive monitoring and alerting active
- Regular compliance audit scores > 95%

### Continuous Improvement
This guide should be reviewed and updated quarterly to incorporate:
- New security threats and vulnerabilities
- Updated best practices and standards
- Lessons learned from incidents
- Technology and infrastructure changes

**Remember:** Security is not a destination but a continuous journey. Regular review, testing, and improvement of these practices is essential for maintaining a secure infrastructure.

---

**Document Maintenance:**
- Review quarterly
- Update after security incidents
- Incorporate new threats and best practices
- Test all procedures annually
