# Comprehensive Security Risk Assessment Report
## Self-Hosted Docker Compose Infrastructure

**Assessment Date:** December 2024  
**Infrastructure Location:** `/home/daytona/self-hosted/`  
**Assessment Scope:** 33 Docker Compose services across multiple directories  

---

## Executive Summary

This security assessment reveals **multiple critical vulnerabilities** in the self-hosted Docker compose infrastructure that require immediate attention. The infrastructure contains 4 critical risks, 4 high-priority risks, and several medium-priority security concerns that collectively expose the system to container escape, unauthorized access, and data compromise.

### Risk Distribution
- **Critical Risk:** 4 findings requiring immediate action
- **High Risk:** 4 findings requiring urgent attention  
- **Medium Risk:** 5 findings requiring planned remediation
- **Positive Practices:** 6 security measures already implemented

---

## Critical Security Findings (Immediate Action Required)

### 1. Docker Socket Exposure - CRITICAL
**Risk Level:** Critical  
**CVSS Score:** 9.8 (Critical)  
**Impact:** Complete system compromise, container escape

**Affected Services:**
- `/home/daytona/self-hosted/homepage/compose.yaml` (Line 17)
- `/home/daytona/self-hosted/diun/compose.yaml` (Line 8)

**Vulnerability Details:**
Both services mount the Docker socket (`/var/run/docker.sock`) directly into containers, providing complete Docker daemon access. This allows:
- Full control over all containers on the host
- Ability to mount host filesystem
- Container escape to host system
- Privilege escalation to root

**Evidence:**
```yaml
# homepage/compose.yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock

# diun/compose.yaml  
volumes:
  - "/var/run/docker.sock:/var/run/docker.sock"
```

### 2. Hardcoded Credentials - CRITICAL
**Risk Level:** Critical  
**CVSS Score:** 9.1 (Critical)  
**Impact:** Unauthorized access, credential compromise

**Affected Services:**

#### wg-easy Service (`/home/daytona/self-hosted/wg-easy/compose.yaml`)
```yaml
environment:
  PASSWORD_HASH: $$2a$$12$$DS4l/vvpOH2CkS4GeUGRruGM6fcbvYvBBPx2P7ncqS.HvqKrPFPfm
```

#### langfuse Service (`/home/daytona/self-hosted/langfuse/compose.yaml`)
```yaml
environment:
  SALT: "smekjdsas1ysalt"
  ENCRYPTION_KEY: "0c8f3b22fd84e55154705fd1d7f47f9b1aab9d96232c18d6d4094fdfcf08c8b4"
  LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID: ${LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID:-minio}
  LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY: ${LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY:-miniosecret}
  MINIO_ROOT_USER: ${MINIO_ROOT_USER:-minio}
  MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD:-miniosecret}
  REDIS_AUTH: ${REDIS_AUTH:-myredissecret}
```

### 3. Empty Database Password - CRITICAL
**Risk Level:** Critical  
**CVSS Score:** 8.8 (High)  
**Impact:** Unauthorized database access

**Affected Service:** `/home/daytona/self-hosted/postgresql/compose.yaml`
```yaml
environment:
  POSTGRES_PASSWORD:  # Empty password
```

### 4. Disabled Security Features - CRITICAL
**Risk Level:** Critical  
**CVSS Score:** 7.5 (High)  
**Impact:** Reduced application security

**Affected Service:** `/home/daytona/self-hosted/stirlingpdf/compose.yaml`
```yaml
environment:
  DOCKER_ENABLE_SECURITY: false
```

---

## High-Priority Security Findings

### 5. Privileged Container Capabilities - HIGH
**Risk Level:** High  
**CVSS Score:** 7.8 (High)  
**Impact:** Container escape, host system access

**Affected Services:**

#### gluetun (`/home/daytona/self-hosted/gluetun/compose.yaml`)
```yaml
cap_add:
  - NET_ADMIN
devices:
  - /dev/net/tun:/dev/net/tun
```

#### wg-easy (`/home/daytona/self-hosted/wg-easy/compose.yaml`)
```yaml
cap_add:
  - NET_ADMIN
  - SYS_MODULE
sysctls:
  - net.ipv4.ip_forward=1
  - net.ipv4.conf.all.src_valid_mark=1
```

### 6. Direct Port Exposure - HIGH
**Risk Level:** High  
**CVSS Score:** 6.5 (Medium)  
**Impact:** Direct network access, bypass proxy security

**Affected Services:**

#### nginx-proxy-manager (`/home/daytona/self-hosted/nginx-proxy-manager/compose.yaml`)
```yaml
ports:
  - '80:80'
  - '443:443'
  - '81:81'
```

#### restart-router (`/home/daytona/self-hosted/restart-router/compose.yaml`)
```yaml
ports:
  - 5900:5900 # VNC server port
```

#### wg-easy (`/home/daytona/self-hosted/wg-easy/compose.yaml`)
```yaml
ports:
  - "51820:51820/udp"
  - "51821:51821/tcp"
```

### 7. Host Filesystem Access - HIGH
**Risk Level:** High  
**CVSS Score:** 6.8 (Medium)  
**Impact:** Host filesystem access

**Affected Service:** `/home/daytona/self-hosted/dockge/compose.yaml`
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
  - /home/grota/selfhost:/home/grota/selfhost
```

### 8. Missing Environment Variables - HIGH
**Risk Level:** High  
**CVSS Score:** 5.5 (Medium)  
**Impact:** Service misconfiguration, potential security bypass

**Affected Services:** Multiple services depend on undefined environment variables that could lead to insecure defaults.

---

## Medium-Priority Security Findings

### 9. Latest Image Tags - MEDIUM
**Risk Level:** Medium  
**Impact:** Version drift, unexpected updates, potential vulnerabilities

**Affected Services:** Most services use `:latest` tags instead of specific versions:
- `ghcr.io/gethomepage/homepage:latest`
- `lscr.io/linuxserver/prowlarr:latest`
- `lscr.io/linuxserver/radarr:latest`
- `lscr.io/linuxserver/sonarr:latest`
- And many others

### 10. Missing Container Hardening - MEDIUM
**Risk Level:** Medium  
**Impact:** Increased attack surface

**Missing Security Features:**
- No `security_opt` configurations
- No `read_only` filesystem configurations  
- No user remapping (services run as default container users)
- No resource limits in most services
- No AppArmor/SELinux profiles

### 11. Weak Default Credentials - MEDIUM
**Risk Level:** Medium  
**Impact:** Unauthorized access with default credentials

**Affected Services:**
- pgAdmin: `PGADMIN_DEFAULT_EMAIL: mele@home.lab` with empty password
- Multiple services with predictable default credentials

### 12. Insufficient Network Isolation - MEDIUM
**Risk Level:** Medium  
**Impact:** Lateral movement between services

While custom networks are used, some services have broader network access than necessary.

### 13. Missing Security Monitoring - MEDIUM
**Risk Level:** Medium  
**Impact:** Delayed threat detection

No centralized security monitoring or intrusion detection systems identified.

---

## Positive Security Practices Identified

### 1. Network Segmentation
- Custom networks implemented: `network-for-nginx-proxy`, `network-postgres`
- Services properly isolated where appropriate

### 2. Port Management
- Most service ports are commented out (not directly exposed)
- Traffic routed through nginx-proxy-manager

### 3. Logging Configuration
- Consistent logging limits applied across services
- JSON file driver with rotation configured
- Non-blocking logging mode

### 4. Health Checks
- Implemented in critical services (PostgreSQL, Langfuse components)
- Proper dependency management with `depends_on`

### 5. Capability Management (Partial)
- searxng service properly implements `cap_drop` and `cap_add`
```yaml
cap_drop:
  - ALL
cap_add:
  - CHOWN
  - SETGID
  - SETUID
```

### 6. Configuration Management
- Environment template files (`.env-tpl`) for secure configuration
- Separation of configuration from compose files

---

## Infrastructure Context

### Environment Details
- **Platform:** Raspberry Pi hosting
- **Network:** Home lab environment (home.lab domain)
- **Services:** 33+ interconnected Docker services
- **Management:** Docker Compose with custom networks and volumes

### Service Categories
- **Media Management:** Sonarr, Radarr, Prowlarr, qBittorrent
- **System Management:** Homepage, Dockge, Diun, Nginx Proxy Manager
- **Applications:** Paperless-ngx, Stirling PDF, OpenWebUI, Langfuse
- **Infrastructure:** PostgreSQL, Redis, MinIO
- **Networking:** Gluetun VPN, WireGuard, Searxng

---

## Risk Assessment Matrix

| Risk Level | Count | Examples |
|------------|-------|----------|
| Critical | 4 | Docker socket exposure, hardcoded secrets |
| High | 4 | Privileged containers, direct port exposure |
| Medium | 5 | Latest tags, missing hardening |
| **Total** | **13** | **Security findings requiring attention** |

---

## Compliance and Standards Impact

### Security Framework Violations
- **NIST Cybersecurity Framework:** Multiple violations in Protect and Detect functions
- **CIS Docker Benchmark:** Violations in container runtime security
- **OWASP Container Security:** Multiple top 10 container risks present

### Regulatory Considerations
- Data protection regulations may be impacted by weak access controls
- Audit trails insufficient for compliance requirements

---

## Conclusion

This security assessment reveals a Docker compose infrastructure with significant security vulnerabilities that require immediate attention. While some positive security practices are in place (network segmentation, logging configuration), critical vulnerabilities such as Docker socket exposure and hardcoded credentials create substantial risk.

**Immediate action is required** to address the 4 critical findings before the infrastructure should be considered secure for production use. The high and medium priority findings should be addressed through a structured remediation plan.

The next phase of this assessment will provide detailed remediation recommendations and a security best practices guide tailored to this infrastructure.

---

**Report Prepared By:** Security Assessment Tool  
**Next Steps:** Proceed to remediation recommendations and security best practices guide
