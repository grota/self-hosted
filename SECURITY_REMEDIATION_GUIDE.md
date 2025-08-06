# Security Remediation Guide
## Prioritized Action Plan for Docker Compose Infrastructure

**Document Version:** 1.0  
**Last Updated:** December 2024  
**Infrastructure:** `/home/daytona/self-hosted/`  

---

## Executive Summary

This remediation guide provides specific, actionable steps to address the 13 security vulnerabilities identified in the security assessment. Recommendations are prioritized by risk level and include exact configuration changes, file modifications, and implementation timelines.

**Remediation Timeline:**
- **Critical Issues:** Address within 24-48 hours
- **High Priority:** Address within 1-2 weeks  
- **Medium Priority:** Address within 1 month

---

## CRITICAL PRIORITY REMEDIATION (Immediate Action Required)

### 1. Remove Docker Socket Exposure - CRITICAL
**Risk:** Complete system compromise  
**Timeline:** Immediate (within 24 hours)  
**Effort:** Medium  

#### Affected Files:
- `/home/daytona/self-hosted/homepage/compose.yaml`
- `/home/daytona/self-hosted/diun/compose.yaml`

#### Solution: Implement Docker Socket Proxy

**Step 1: Create Docker Socket Proxy Service**
Create `/home/daytona/self-hosted/docker-socket-proxy/compose.yaml`:

```yaml
services:
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy:latest
    container_name: docker-socket-proxy
    restart: unless-stopped
    environment:
      CONTAINERS: 1
      IMAGES: 1
      AUTH: 0
      SECRETS: 0
      POST: 0
      BUILD: 0
      COMMIT: 0
      CONFIGS: 0
      DISTRIBUTION: 0
      EXEC: 0
      GRPC: 0
      INFO: 1
      NETWORKS: 0
      NODES: 0
      PLUGINS: 0
      SERVICES: 0
      SESSION: 0
      SWARM: 0
      SYSTEM: 0
      TASKS: 0
      VERSION: 1
      VOLUMES: 0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - docker-socket-proxy
    ports:
      - "127.0.0.1:2375:2375"

networks:
  docker-socket-proxy:
    driver: bridge
```

**Step 2: Update Homepage Service**
Modify `/home/daytona/self-hosted/homepage/compose.yaml`:

```yaml
# REMOVE this line:
# - /var/run/docker.sock:/var/run/docker.sock

# ADD these configurations:
services:
  homepage:
    # ... existing configuration ...
    environment:
      HOMEPAGE_ALLOWED_HOSTS: home.lab
      DOCKER_HOST: tcp://docker-socket-proxy:2375
    networks:
      - default
      - docker-socket-proxy
    # Remove the docker.sock volume mount

networks:
  docker-socket-proxy:
    external: true
    name: docker-socket-proxy_docker-socket-proxy
```

**Step 3: Update Diun Service**
Modify `/home/daytona/self-hosted/diun/compose.yaml`:

```yaml
# REMOVE this line:
# - "/var/run/docker.sock:/var/run/docker.sock"

# ADD these configurations:
services:
  diun:
    # ... existing configuration ...
    environment:
      # ... existing environment variables ...
      - "DIUN_PROVIDERS_DOCKER_ENDPOINT=tcp://docker-socket-proxy:2375"
    networks:
      - default
      - docker-socket-proxy

networks:
  docker-socket-proxy:
    external: true
    name: docker-socket-proxy_docker-socket-proxy
```

**Step 4: Deploy Socket Proxy**
```bash
cd /home/daytona/self-hosted/docker-socket-proxy
docker compose up -d
```

**Step 5: Restart Affected Services**
```bash
cd /home/daytona/self-hosted/homepage
docker compose down && docker compose up -d

cd /home/daytona/self-hosted/diun
docker compose down && docker compose up -d
```

### 2. Replace Hardcoded Credentials - CRITICAL
**Risk:** Unauthorized access  
**Timeline:** Immediate (within 24 hours)  
**Effort:** High  

#### 2.1 Fix WireGuard Easy Password

**File:** `/home/daytona/self-hosted/wg-easy/compose.yaml`

**Step 1: Generate New Password Hash**
```bash
# Generate a strong password
openssl rand -base64 32

# Create bcrypt hash (use online tool or install bcrypt utility)
# Example result: $2a$12$NEW_SECURE_HASH_HERE
```

**Step 2: Create Environment File**
Create `/home/daytona/self-hosted/wg-easy/.env`:
```bash
WG_HOST=vpn.your-domain.com
WG_DEFAULT_DNS=1.1.1.1
PASSWORD_HASH=$2a$12$YOUR_NEW_SECURE_HASH_HERE
```

**Step 3: Update Compose File**
Modify `/home/daytona/self-hosted/wg-easy/compose.yaml`:
```yaml
services:
  wg-easy:
    environment:
      WG_HOST: ${WG_HOST}
      PASSWORD_HASH: ${PASSWORD_HASH}  # Remove hardcoded hash
      WG_DEFAULT_DNS: ${WG_DEFAULT_DNS}
      WG_DEFAULT_ADDRESS: 10.8.0.x
      WG_DEVICE: eth0
    env_file:
      - .env
```

#### 2.2 Fix Langfuse Hardcoded Secrets

**File:** `/home/daytona/self-hosted/langfuse/compose.yaml`

**Step 1: Generate Secure Secrets**
```bash
# Generate new salt (32 characters)
openssl rand -hex 16

# Generate new encryption key (64 characters)
openssl rand -hex 32

# Generate secure passwords
openssl rand -base64 32  # For MinIO
openssl rand -base64 32  # For Redis
```

**Step 2: Create Environment File**
Create `/home/daytona/self-hosted/langfuse/.env`:
```bash
# Database
DATABASE_URL=postgresql://postgres:SECURE_DB_PASSWORD@postgres:5432/postgres

# Security
SALT=YOUR_NEW_32_CHAR_SALT_HERE
ENCRYPTION_KEY=YOUR_NEW_64_CHAR_ENCRYPTION_KEY_HERE

# MinIO Credentials
MINIO_ROOT_USER=langfuse-admin
MINIO_ROOT_PASSWORD=YOUR_SECURE_MINIO_PASSWORD_HERE
LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID=langfuse-admin
LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY=YOUR_SECURE_MINIO_PASSWORD_HERE
LANGFUSE_S3_MEDIA_UPLOAD_ACCESS_KEY_ID=langfuse-admin
LANGFUSE_S3_MEDIA_UPLOAD_SECRET_ACCESS_KEY=YOUR_SECURE_MINIO_PASSWORD_HERE

# Redis
REDIS_AUTH=YOUR_SECURE_REDIS_PASSWORD_HERE
```

**Step 3: Update Compose File**
Modify `/home/daytona/self-hosted/langfuse/compose.yaml`:
```yaml
services:
  langfuse-worker:
    env_file:
      - .env
    environment: &langfuse-worker-env
      DATABASE_URL: ${DATABASE_URL}
      SALT: ${SALT}  # Remove hardcoded value
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}  # Remove hardcoded value
      # ... other environment variables using ${} syntax
```

### 3. Fix Empty Database Password - CRITICAL
**Risk:** Unauthorized database access  
**Timeline:** Immediate (within 24 hours)  
**Effort:** Low  

**File:** `/home/daytona/self-hosted/postgresql/compose.yaml`

**Step 1: Generate Secure Password**
```bash
openssl rand -base64 32
```

**Step 2: Update Environment File**
Modify `/home/daytona/self-hosted/postgresql/.env-tpl` to `.env`:
```bash
# Postgres
POSTGRES_PASSWORD=YOUR_SECURE_PASSWORD_HERE
POSTGRES_USER=postgres
POSTGRES_DB=postgres
```

**Step 3: Update Compose File**
Ensure `/home/daytona/self-hosted/postgresql/compose.yaml` references the environment file:
```yaml
services:
  postgres:
    env_file:
      - .env
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_USER: ${POSTGRES_USER:-postgres}
      POSTGRES_DB: ${POSTGRES_DB:-postgres}
```

**Step 4: Update Dependent Services**
Update all services that connect to PostgreSQL with the new credentials:
- langfuse
- paperless-ngx
- Any other services using the database

### 4. Enable Security Features - CRITICAL
**Risk:** Reduced application security  
**Timeline:** Immediate (within 24 hours)  
**Effort:** Low  

**File:** `/home/daytona/self-hosted/stirlingpdf/compose.yaml`

**Step 1: Enable Security**
```yaml
services:
  stirling-pdf:
    environment:
      DOCKER_ENABLE_SECURITY: true  # Change from false
      INSTALL_BOOK_AND_ADVANCED_HTML_OPS: false
      LANGS: "en_GB,en_US,es_ES,it_IT"
```

**Step 2: Configure Authentication**
Update `/home/daytona/self-hosted/stirlingpdf/extraConfigs/settings.yml`:
```yaml
security:
  enableLogin: true  # Enable authentication
  csrfDisabled: false  # Enable CSRF protection
  initialLogin:
    username: 'admin'
    password: 'YOUR_SECURE_PASSWORD_HERE'
```

---

## HIGH PRIORITY REMEDIATION (1-2 Weeks)

### 5. Secure Privileged Containers - HIGH
**Risk:** Container escape  
**Timeline:** 1 week  
**Effort:** Medium  

#### 5.1 Secure Gluetun Container

**File:** `/home/daytona/self-hosted/gluetun/compose.yaml`

**Current Configuration:**
```yaml
cap_add:
  - NET_ADMIN
```

**Recommended Secure Configuration:**
```yaml
services:
  gluetun:
    # ... existing configuration ...
    cap_add:
      - NET_ADMIN  # Required for VPN functionality
    cap_drop:
      - ALL  # Drop all other capabilities
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    user: "1000:1000"  # Run as non-root user
```

#### 5.2 Secure WireGuard Easy Container

**File:** `/home/daytona/self-hosted/wg-easy/compose.yaml`

**Add Security Constraints:**
```yaml
services:
  wg-easy:
    # ... existing configuration ...
    cap_add:
      - NET_ADMIN  # Required
      - SYS_MODULE  # Required for WireGuard
    cap_drop:
      - ALL  # Drop all other capabilities
    security_opt:
      - no-new-privileges:true
    # Note: Cannot use read_only due to WireGuard requirements
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
```

### 6. Implement Network Security - HIGH
**Risk:** Direct network access  
**Timeline:** 1 week  
**Effort:** Medium  

#### 6.1 Secure Nginx Proxy Manager

**File:** `/home/daytona/self-hosted/nginx-proxy-manager/compose.yaml`

**Add Security Headers and Rate Limiting:**
```yaml
services:
  nginx-proxy-manager:
    # ... existing configuration ...
    environment:
      # Add security environment variables
      DISABLE_IPV6: 'true'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
      - ./nginx-security.conf:/etc/nginx/conf.d/security.conf:ro
```

**Create Security Configuration File:**
Create `/home/daytona/self-hosted/nginx-proxy-manager/nginx-security.conf`:
```nginx
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

# Rate limiting
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;

# Hide server information
server_tokens off;
```

#### 6.2 Secure VNC Access

**File:** `/home/daytona/self-hosted/restart-router/compose.yaml`

**Restrict VNC Access:**
```yaml
services:
  playwright:
    # ... existing configuration ...
    ports:
      - "127.0.0.1:5900:5900"  # Bind to localhost only
    environment:
      - VNC_PASSWORD=YOUR_SECURE_VNC_PASSWORD
```

### 7. Fix Dockge Host Access - HIGH
**Risk:** Host filesystem access  
**Timeline:** 1 week  
**Effort:** Medium  

**File:** `/home/daytona/self-hosted/dockge/compose.yaml`

**Implement Docker Socket Proxy for Dockge:**
```yaml
services:
  dockge:
    # ... existing configuration ...
    # REMOVE: - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DOCKGE_STACKS_DIR=/home/grota/selfhost
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
    networks:
      - default
      - docker-socket-proxy
    volumes:
      - ./data:/app/data
      - /home/grota/selfhost:/home/grota/selfhost:ro  # Read-only access
```

### 8. Implement Environment Variable Security - HIGH
**Risk:** Service misconfiguration  
**Timeline:** 1-2 weeks  
**Effort:** High  

#### Create Centralized Environment Management

**Step 1: Create Master Environment Template**
Create `/home/daytona/self-hosted/.env.master.template`:
```bash
# Global Configuration
TZ=Europe/Madrid
PUID=1000
PGID=1000

# Domain Configuration
DOMAIN=home.lab
HOMEPAGE_ALLOWED_HOSTS=home.lab

# Database Credentials
POSTGRES_PASSWORD=
POSTGRES_USER=postgres
POSTGRES_DB=postgres

# Widget Credentials
USERNAME_FOR_WIDGET=
PASSWORD_FOR_WIDGET=
KEY_FOR_WIDGET=

# Notification Settings
DIUN_NOTIF_TELEGRAM_TOKEN=
DIUN_NOTIF_TELEGRAM_CHATIDS=

# Service-Specific Tokens
PAPERLESS_NGX_TOKEN=
```

**Step 2: Create Service-Specific Environment Files**
For each service, create or update `.env` files with required variables.

---

## MEDIUM PRIORITY REMEDIATION (1 Month)

### 9. Implement Image Tag Management - MEDIUM
**Risk:** Version drift  
**Timeline:** 1 month  
**Effort:** Low  

#### Create Image Version Management

**Step 1: Pin All Image Versions**
Update all compose files to use specific tags instead of `:latest`:

```yaml
# Before
image: ghcr.io/gethomepage/homepage:latest

# After
image: ghcr.io/gethomepage/homepage:v0.8.10
```

**Step 2: Create Version Management Script**
Create `/home/daytona/self-hosted/update-images.sh`:
```bash
#!/bin/bash
# Image update management script

SERVICES=(
    "homepage:ghcr.io/gethomepage/homepage"
    "prowlarr:lscr.io/linuxserver/prowlarr"
    "radarr:lscr.io/linuxserver/radarr"
    # Add all services
)

for service in "${SERVICES[@]}"; do
    IFS=':' read -r name image <<< "$service"
    echo "Checking updates for $name..."
    # Add update logic here
done
```

### 10. Implement Container Hardening - MEDIUM
**Risk:** Increased attack surface  
**Timeline:** 1 month  
**Effort:** High  

#### Apply Security Hardening to All Services

**Template for Secure Container Configuration:**
```yaml
services:
  service-name:
    # ... existing configuration ...
    
    # Security Options
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
    
    # Read-only filesystem (where possible)
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /var/tmp:noexec,nosuid,size=50m
    
    # User mapping
    user: "1000:1000"
    
    # Resource limits
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    
    # Capability management
    cap_drop:
      - ALL
    cap_add:
      - CHOWN  # Only add required capabilities
      - SETGID
      - SETUID
    
    # Health checks
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### 11. Fix Weak Default Credentials - MEDIUM
**Risk:** Unauthorized access  
**Timeline:** 1 month  
**Effort:** Medium  

#### Update All Default Credentials

**Step 1: pgAdmin Service**
Update `/home/daytona/self-hosted/pgadmin/compose.yaml`:
```yaml
services:
  pgadmin:
    env_file:
      - .env
    environment:
      PGADMIN_DEFAULT_EMAIL: ${PGADMIN_EMAIL}
      PGADMIN_DEFAULT_PASSWORD: ${PGADMIN_PASSWORD}
      PGADMIN_DISABLE_POSTFIX: 1
```

Create `/home/daytona/self-hosted/pgadmin/.env`:
```bash
PGADMIN_EMAIL=admin@home.lab
PGADMIN_PASSWORD=YOUR_SECURE_PASSWORD_HERE
```

### 12. Enhance Network Isolation - MEDIUM
**Risk:** Lateral movement  
**Timeline:** 1 month  
**Effort:** Medium  

#### Implement Micro-segmentation

**Step 1: Create Service-Specific Networks**
```yaml
# Create dedicated networks for service groups
networks:
  media-network:
    driver: bridge
    internal: true
  
  database-network:
    driver: bridge
    internal: true
  
  monitoring-network:
    driver: bridge
    internal: true
```

**Step 2: Assign Services to Appropriate Networks**
- Media services (Sonarr, Radarr, etc.) → media-network
- Database services → database-network  
- Monitoring services → monitoring-network

### 13. Implement Security Monitoring - MEDIUM
**Risk:** Delayed threat detection  
**Timeline:** 1 month  
**Effort:** High  

#### Deploy Security Monitoring Stack

**Step 1: Create Security Monitoring Service**
Create `/home/daytona/self-hosted/security-monitoring/compose.yaml`:
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
    environment:
      - FALCO_GRPC_ENABLED=true
    
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

volumes:
  prometheus_data:
```

---

## Implementation Timeline

### Week 1 (Critical Priority)
- [ ] Deploy Docker Socket Proxy
- [ ] Remove direct Docker socket mounts
- [ ] Replace all hardcoded credentials
- [ ] Fix empty database password
- [ ] Enable security features in Stirling PDF

### Week 2-3 (High Priority)
- [ ] Implement container security hardening
- [ ] Secure network configurations
- [ ] Fix host filesystem access
- [ ] Implement environment variable management

### Week 4+ (Medium Priority)
- [ ] Pin all image versions
- [ ] Apply comprehensive container hardening
- [ ] Fix remaining default credentials
- [ ] Implement network micro-segmentation
- [ ] Deploy security monitoring

---

## Validation and Testing

### Security Validation Checklist

After implementing each remediation:

1. **Docker Socket Exposure**
   ```bash
   # Verify no direct socket mounts
   docker compose config | grep -i "docker.sock"
   # Should return no results
   ```

2. **Credential Security**
   ```bash
   # Verify no hardcoded secrets
   grep -r "password.*=" . --include="*.yaml"
   grep -r "secret.*=" . --include="*.yaml"
   # Should only show environment variable references
   ```

3. **Container Security**
   ```bash
   # Check security options
   docker inspect container_name | jq '.[0].HostConfig.SecurityOpt'
   ```

4. **Network Security**
   ```bash
   # Verify port bindings
   docker compose ps --format "table {{.Name}}\t{{.Ports}}"
   ```

### Automated Security Scanning

**Step 1: Install Security Tools**
```bash
# Install Docker Bench Security
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

**Step 2: Regular Vulnerability Scanning**
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Scan all images
for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
    trivy image $image
done
```

---

## Rollback Procedures

### Emergency Rollback Plan

If any remediation causes service disruption:

1. **Immediate Rollback**
   ```bash
   cd /home/daytona/self-hosted/[service-name]
   git checkout HEAD~1 compose.yaml
   docker compose down && docker compose up -d
   ```

2. **Backup Strategy**
   ```bash
   # Before making changes, create backups
   cp compose.yaml compose.yaml.backup.$(date +%Y%m%d)
   ```

3. **Service Health Monitoring**
   ```bash
   # Monitor service health after changes
   docker compose ps
   docker compose logs [service-name]
   ```

---

## Conclusion

This remediation guide provides a comprehensive, prioritized approach to addressing all identified security vulnerabilities. Implementation should follow the specified timeline, with critical issues addressed immediately and other improvements implemented systematically over the following month.

**Key Success Metrics:**
- Zero critical vulnerabilities remaining
- All services running with least-privilege principles
- Comprehensive secrets management implemented
- Network segmentation and monitoring in place
- Regular security scanning and updates established

**Next Steps:**
1. Begin with critical priority items immediately
2. Schedule high-priority remediation for the following week
3. Plan medium-priority improvements over the next month
4. Implement ongoing security monitoring and maintenance procedures

For questions or assistance with implementation, refer to the Security Best Practices Guide (next document in this series).
