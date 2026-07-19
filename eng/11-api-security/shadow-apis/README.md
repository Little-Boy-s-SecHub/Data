---
schema_version: 1
id: WEB-A11-SHADOW-APIS
title: "Shadow APIs & Improper Inventory Management"
slug: shadow-apis
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - API9:2023
cwe:
  - CWE-1059
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Shadow APIs & Improper Inventory Management

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Shadow APIs & Improper Inventory Management by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of the Shadow APIs & Improper Inventory Management scenario and how to apply handling input across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Be able to read code/configuration in the language or framework appearing in the example.
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you are the owner of a magnificent ancient castle. To ensure safety, you install a smart lock system, firewalls, and strict surveillance cameras at the main gate (current version API - `/api/v2`). You are convinced that your castle is absolutely secure.  
However, you have no idea that during the construction of the castle in the past, the workers created hidden passageways to transport materials (Debug endpoints `/api/debug/`), or forgot to lock old doors in the basement when building new doors (old version `/api/v1`). These doors and hidden passageways still exist, completely unlocked, without surveillance cameras, and no one bothers to manage them. In the world of cybersecurity, these invisible pathways are called **Shadow APIs (API Shadow)**.

To manage the castle, you need a detailed map that records every nook and cranny, every functioning door. This map is the **API Inventory (API Inventory)**. 
If your inventory map is incomplete, those shadow doors (shadow APIs) will become "invisible" vulnerabilities. They continue to run silently on the actual system but are never patched, not restricted in access, and do not require any security keys.

```yaml
# Example: API inventory document (OpenAPI spec)
# This is what the team KNOWS about — but shadow APIs are NOT listed here
openapi: 3.0.0
info:
  title: User Management API
  version: 2.0.0
paths:
  /api/v2/users:          # Current version — documented ✓
    get:
      summary: List users
      security:
        - BearerAuth: []
  /api/v2/users/{id}:     # Current version — documented ✓
    get:
      summary: Get user by ID

# MISSING from inventory (Shadow APIs still running on production):
# /api/v1/users           ← Deprecated but still active, no auth required!
# /api/internal/metrics   ← Internal endpoint exposed to internet
# /api/debug/user-dump    ← Debug endpoint left from development
# /mobile/api/v1/profile  ← Mobile-only API without proper security
```

```
# Typical shadow API attack surface
                    ┌─────────────────────────────────┐
                    │         Production Server         │
                    │                                   │
 Documented ─────── │  /api/v2/users  ← Auth ✓ WAF ✓  │
                    │  /api/v2/orders ← Auth ✓ WAF ✓  │
                    │                                   │
 Shadow APIs ────── │  /api/v1/users  ← No Auth! ✗     │ ← Attacker targets these
                    │  /api/debug/*   ← No Auth! ✗     │
                    │  /internal/rpc  ← No WAF! ✗      │
                    │  /mobile/api/*  ← Weak Auth ✗    │
                    └─────────────────────────────────┘
```

## 4. Description and Root Cause

The vulnerability **Improper Inventory Management** is essentially the 'losing track' disease of one's own assets. When a business does not clearly know how many API paths it has open to the internet, it will expose extremely dangerous vulnerabilities.

Attackers always like to hunt for these dark doors because they often:
- Require no login at all (lack authentication/authorization) due to using old source code from many years ago.
- Have no rate limiting system, allowing attackers to freely probe for information.
- Use outdated programming libraries, full of publicly disclosed vulnerabilities that no one updates.
- Do not log activities at all (monitoring), enabling attackers to come and go to steal data as if the system were deserted, without anyone knowing.

> **Reference:** the technical claims in the lesson are marked with a source; when applying in practice, cross-check with the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** endpoint/version inventory, authentication/authorization policy, synthetic data and telemetry of API deployed.  
- **Trust boundary:** route from gateway/service mesh cross-checked with OpenAPI, IaC/deployment manifest, and API inventory with an owner.  
- **Actor:** client not logged in/regular user in loopback fixture; analyst only reads APK/config samples provided by the lab.  
- **Prerequisite:** route is still deployed but missing from inventory/monitoring/lifecycle, or legacy version uses weaker auth/schema/patch level than the current route.  
- **Environmental condition:** gateway and API v1/v2/v3 local, hostname `.lab.test`, sample APK synthetic; do not scan public DNS/Internet.

Only detecting the version string or receiving 404/401 is not enough to conclude shadow API; it is necessary to match the running route with the inventory and prove the policy/lifecycle gap. [S1]

## 6. Attack Mechanism

An old route may still be reachable via a direct gateway, different hostname/alias, or client configuration but is no longer subject to current policy/patch/telemetry. Evidence must link artifact discovery with the deployment manifest, gateway route, owner, and request log of the correct version. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** run the gateway with API v1/v2/v3 locally; declare only v2 in the inventory, seed synthetic data, and enable route/auth/audit log.  
2. **Input:** baseline v2 with/without token; then check a finite list of routes/versions taken from the manifest and APK sample.  
3. **Operations:** match each route with inventory/owner, send harmless GET/OPTIONS, and record gateway/backend/policy log.  
4. **Expected result:** the error-prone fixture allows legacy v1 against policy; a fix returns 401/403/410 or no route, while inventory/telemetry matches deployment.  
5. **Cleanup:** delete fake data/tokens, stop gateway/services, and remove hostname/route fixture.  
6. **Safety limits:** do not brute-force public hosts, do not use large wordlists; only test a finite set of routes in the loopback lab.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. API Version Discovery — Find old versions:**

<!-- payload-id: WEB-A11-SHADOW-APIS-001 -->
<!-- context: Python 3.12 with requests 2.32, curl 8.x and Bash 5.2 against the versioned API fixture at 127.0.0.1:18080; case: WEB-A11-SHADOW-APIS-001 -->
<!-- prerequisites: load only the synthetic API manifest, sample APK and loopback endpoints; cap probes to the listed versions and paths; do not resolve public DNS -->
<!-- encoding: UTF-8 Python source; binary/pickle/ROP bytes are constructed explicitly by the snippet and no URL or transport decoding is applied -->
<!-- expected-result: the output matches only endpoints in the synthetic manifest; an unprotected legacy route yields a lab marker and the fixed fixture returns 401, 403 or 410 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Automated version discovery script
import requests

BASE_URL = "http://127.0.0.1:18080"
KNOWN_ENDPOINTS = ["/users", "/orders"]

# Try different version patterns
VERSION_PATTERNS = [
    "/api/v{v}{endpoint}",
    "/api/{endpoint}?version={v}",
    "/v{v}{endpoint}",
    "/{endpoint}/v{v}",
]

def discover_shadow_versions():
    """Probe for deprecated API versions still responding"""
    for endpoint in KNOWN_ENDPOINTS:
        for pattern in VERSION_PATTERNS:
            for version in range(1, 4):  # Keep the local probe bounded to v1-v3
                url = BASE_URL + pattern.format(v=version, endpoint=endpoint)
                try:
                    resp = requests.get(url, timeout=1, allow_redirects=False)
                    if resp.status_code not in [404, 410]:
                        print(f"[ALIVE] {url} → {resp.status_code}")
                        # Check if auth is required
                        if resp.status_code == 200:
                            print(f"  [!!] No authentication required!")
                except requests.exceptions.RequestException:
                    pass

discover_shadow_versions()
```
**2. Exploiting deprecated endpoint without auth:**

<!-- payload-id: WEB-A11-SHADOW-APIS-002 -->
<!-- context: Python 3.12 with requests 2.32, curl 8.x and Bash 5.2 against the versioned API fixture at 127.0.0.1:18080; case: WEB-A11-SHADOW-APIS-002 -->
<!-- prerequisites: load only the synthetic API manifest, sample APK and loopback endpoints; cap probes to the listed versions and paths; do not resolve public DNS -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the output matches only endpoints in the synthetic manifest; an unprotected legacy route yields a lab marker and the fixed fixture returns 401, 403 or 410 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Current API (v2) — requires authentication
GET /api/v2/users/123 HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer eyJhbG...

# HTTP 200 OK — returns user data (with proper auth)

# Deprecated API (v1) — still running, NO AUTH REQUIRED!
GET /api/v1/users/123 HTTP/1.1
Host: api.victim.lab.test
# No Authorization header needed!

# HTTP 200 OK — returns same user data WITHOUT authentication!
# {"id": 123, "name": "Alice", "email": "alice@corp.com", "ssn": "123-45-6789"}
```

**3. Mobile API endpoint discovery — Reverse engineering APK:**

<!-- payload-id: WEB-A11-SHADOW-APIS-003 -->
<!-- context: Python 3.12 with requests 2.32, curl 8.x and Bash 5.2 against the versioned API fixture at 127.0.0.1:18080; case: WEB-A11-SHADOW-APIS-003 -->
<!-- prerequisites: load only the synthetic API manifest, sample APK and loopback endpoints; cap probes to the listed versions and paths; do not resolve public DNS -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the output matches only endpoints in the synthetic manifest; an unprotected legacy route yields a lab marker and the fixed fixture returns 401, 403 or 410 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Extract API endpoints from Android APK
apktool d target-app.apk -o decompiled/

# Search for API URLs in decompiled code
grep -rn "api\|endpoint\|baseurl\|BASE_URL" decompiled/smali/ decompiled/res/
# Output:
# const-string v0, "https://api.victim.lab.test/mobile/v1/"
# const-string v1, "/user/full-profile"        ← Not in public API docs!
# const-string v2, "/admin/user-lookup"         ← Admin endpoint in mobile app!
# const-string v3, "/internal/feature-flags"    ← Internal API exposed!

# Test discovered endpoints
curl https://api.victim.lab.test/mobile/v1/user/full-profile \
  -H "X-Mobile-App: true"
# Returns full user profile including fields not exposed in web API!
```
### Why the API mobile endpoint is particularly dangerous:<!-- payload-id: WEB-A11-SHADOW-APIS-004 -->
<!-- context: Python 3.12 with requests 2.32, curl 8.x and Bash 5.2 against the versioned API fixture at 127.0.0.1:18080; case: WEB-A11-SHADOW-APIS-004 -->
<!-- prerequisites: load only the synthetic API manifest, sample APK and loopback endpoints; cap probes to the listed versions and paths; do not resolve public DNS -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the output matches only endpoints in the synthetic manifest; an unprotected legacy route yields a lab marker and the fixed fixture returns 401, 403 or 410 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Why mobile API endpoints require the same server-side controls
#
# Web client logic is delivered to the browser and can be inspected
# Mobile client logic is packaged in the APK and can also be inspected
#
# An APK may contain:
# - Hardcoded public, internal, or deprecated API endpoint URLs
# - Embedded identifiers or secrets that should not be treated as confidential
# - Client-side validation and business-flow hints
#
# A separately routed mobile API can bypass gateway policy if deployment
# inventory and network routing are inconsistent; this is not inherent to mobile APIs
```
**4. Inventory the debug route using read-only requests:**

<!-- payload-id: WEB-A11-SHADOW-APIS-005 -->
<!-- context: Python 3.12 with requests 2.32, curl 8.x and Bash 5.2 against the versioned API fixture at 127.0.0.1:18080; case: WEB-A11-SHADOW-APIS-005 -->
<!-- prerequisites: load only the synthetic API manifest, sample APK and loopback endpoints; cap probes to the listed versions and paths; do not resolve public DNS -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the output matches only endpoints in the synthetic manifest; an unprotected legacy route yields a lab marker and the fixed fixture returns 401, 403 or 410 -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /api/debug/routes HTTP/1.1
Host: api.victim.lab.test
Accept: application/json
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE: Multiple API versions running without inventory ===
# app_v1.py — deployed 2020, forgotten, still running
@app_v1.route('/api/v1/users/<int:user_id>')
def get_user_v1(user_id):
    # No authentication! No rate limiting! No input validation!
    user = db.users.find_one({"id": user_id})
    return jsonify(user)  # Returns ALL fields including sensitive data

@app_v1.route('/api/v1/debug/sql')
def debug_sql():
    query = request.args.get('q')
    result = db.engine.execute(query)  # RAW SQL EXECUTION — catastrophic!
    return jsonify([dict(row) for row in result])

# === SECURE: Centralized API registry with automatic decommissioning ===
class APIRegistry:
    """Central registry for all API endpoints — nothing runs untracked"""

    def __init__(self):
        self.registered_routes = {}
        self.active_versions = {"v3"}  # Only v3 is active

    def register(self, version, path, handler, auth_required=True):
        """Register an API endpoint — unregistered routes are blocked"""
        if version not in self.active_versions:
            raise ValueError(f"Cannot register route for inactive version {version}")
        key = f"{version}:{path}"
        self.registered_routes[key] = {
            "handler": handler,
            "auth_required": auth_required,
            "registered_at": datetime.utcnow().isoformat(),
        }

    def is_registered(self, version, path):
        """Check if an endpoint is officially registered"""
        return f"{version}:{path}" in self.registered_routes

# Middleware: reject any request to unregistered endpoints
@app.before_request
def enforce_registry():
    version = extract_version(request.path)  # Extract "v3" from path
    if not api_registry.is_registered(version, request.path):
        # Log the attempt for security monitoring
        log_shadow_api_access(request.path, request.remote_addr)
        return jsonify({"error": "Endpoint not found"}), 404
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Shadow APIs & Improper Inventory Management, the policy result and correlation ID; do not log secrets or the entire token.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm that the request reached the sink and whether it had any impact.  
- The scanner or WAF alert is only an investigation signal; it is not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Apply control at the level of objects, attributes, functions, and resource consumption of API. 
- Use inventory with owner attached as the deployment source, default-deny gateway, and the same auth/schema/logging for all versions; legacy routes must be removed or return 410 according to the lifecycle. 
- Use the same policy for all equivalent routes/operations; do not just modify the endpoint appearing in the PoC.

### Defense-in-depth

With Shadow APIs & Improper Inventory Management, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation cannot be used to replace the original controls.

```yaml
# API Gateway configuration — ONLY listed routes are accessible
# All unlisted routes return 404
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway
  annotations:
    nginx.ingress.kubernetes.io/use-regex: "true"
spec:
  rules:
    - host: api.victim.lab.test
      http:
        paths:
          # Only the declared v2 prefix is routed by this Ingress
          - path: /api/v2
            pathType: Prefix
            backend:
              service:
                name: api-v2-service
                port:
                  number: 8080
```
```python
# Deprecation middleware — warn then block old API versions
from datetime import datetime
from flask import request, jsonify
DEPRECATED_VERSIONS = {
    "v1": {"sunset": "2024-06-01", "blocked": True},
    "v2": {"sunset": "2025-12-01", "blocked": False},
}
@app.before_request
def check_api_version():
    """Block deprecated API versions, warn about upcoming deprecation"""
    path = request.path
    for version, config in DEPRECATED_VERSIONS.items():
        if f"/api/{version}/" in path:
            if config["blocked"]:
                # Hard block — version is fully deprecated
                return jsonify({
                    "error": f"API {version} has been deprecated since {config['sunset']}",
                    "migration_guide": f"https://docs.victim.lab.test/migrate-{version}"
                }), 410  # 410 Gone — permanently removed
            else:
                # Soft deprecation — add warning header
                response = None  # Let request proceed
                # After response, add Sunset header
```
```bash
# Use nuclei or custom scripts to detect undocumented endpoints
nuclei -u https://api.victim.lab.test -t exposures/ -t misconfiguration/
```
- **Summary**: Manage API safely by maintaining an automated API catalog (API inventory), decommissioning old versions, and deploying the API gateway as the single access point.
- **Detailed steps**:
  - **Maintain API inventory**: use the API Gateway as a single entry point; for example, the inventory only allows `host=api.victim.lab.test` and `path=/api/v2/.*` in the lab.
  - **Automatically decommission old API versions**: remove routes according to the sunset date or return 410, while updating owner, OpenAPI spec, and telemetry.
  - **Periodic scanning**: cross-check manifest, gateway routes, OpenAPI spec, and access logs to detect running routes without an owner/inventory.
  - **CI/CD pipeline** automatically deletes debug endpoints when deploying to production.
  - **API documentation as code** — OpenAPI spec must match 100% with actual code.

## 12. Retest

- **Positive case:** with Shadow APIs & Improper Inventory Management, the valid flow still works correctly for the actor and allowed data.  
- **Negative case:** with the same input/resources, actors or contexts that are not allowed are denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge limits, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm that policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** save a minimal scenario that reproduces the old bug and demonstrate that the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Shadow APIs & Improper Inventory Management without confirming side effects and logs.
- Use payloads with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.
- Treat UUID, rate limit, WAF, CSP, or general input validation as fixed by another main control.
- Only fix one route while the same sink/policy is used on another route.
- Conclude that a vulnerability exists without recording the source, fixture version, and observable evidence.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Shadow API**: API connections are active on the live system but are not documented, managed, or maintained by the development team.  
- **Zombie APIs**: Common alias for old API or those that have been declared deprecated but are still reachable, lacking an owner or clear lifecycle policy.  
- **API Inventory**: Complete list, detailing the structure, version, and purpose of all API running in the system.  
- **Deprecated**: The status of a feature or old software version that is advised not to be used anymore and will be completely removed in the future.  
- **Endpoint**: The endpoint (specific URL address) of an API that clients can connect to for sending/receiving data.  
- **Expose**: The behavior of accidentally or intentionally making internal information, data, or services available on the internet.  
- **API Gateway**: A gateway that centrally manages all requests sent to API, responsible for authentication, routing, and traffic limiting.  
- **Nuclei**: An automated security vulnerability scanning and detection tool based on available configuration templates.  
- **Decommission**: The process of officially stopping operations, shutting down, and reclaiming resources of an old software service.

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP. https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ — version/status: current version; accessed: 2026-07-18.  
- **[S2]** PortSwigger. https://portswigger.net/web-security/api-testing — version/status: current version; accessed: 2026-07-18.  
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1059.html — version/status: current version; accessed: 2026-07-18.  
- **[S4]** OWASP API Security Top 10 — API9:2023 Improper Inventory Management. https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ — version/date: 2023; accessed: 2026-07-18.  
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.