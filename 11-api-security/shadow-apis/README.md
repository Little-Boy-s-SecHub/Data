# Shadow APIs & Improper Inventory Management

> **OWASP**: API Security (API9:2023) | **CWE**: CWE-1059 | **Nguồn**: OWASP API Security Top 10, Salt Security

## 🧱 Kiến thức Nền tảng

Trong vòng đời phát triển API, các endpoint được tạo ra, cập nhật, và thay thế liên tục. **Shadow APIs** (API bóng) là những endpoint tồn tại trên production nhưng **không được ghi nhận, giám sát, hoặc bảo trì** — thường do:

- **API versioning không quản lý**: `/api/v1/users` bị deprecated nhưng vẫn chạy khi `/api/v2/users` đã thay thế
- **Debug/test endpoints** quên xóa: `/api/debug/dump`, `/api/test/reset-password`
- **Mobile-specific APIs** không được document: endpoints chỉ dùng cho mobile app nhưng vẫn truy cập được qua web
- **Internal APIs** vô tình expose ra internet: admin APIs, microservice-to-microservice endpoints

**API Inventory** (kiểm kê API) là quá trình liệt kê, phân loại, và giám sát tất cả API endpoints đang hoạt động. Khi inventory không đầy đủ, shadow APIs trở thành lỗ hổng "vô hình" — không được patch, không có rate limit, không có authentication.

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

## 🔍 Mô tả lỗ hổng

**API9:2023 — Improper Inventory Management** mô tả tình trạng thiếu visibility về toàn bộ API surface. Các shadow APIs thường có những đặc điểm nguy hiểm:

- **Thiếu authentication/authorization**: version cũ chưa có security middleware
- **Thiếu rate limiting**: không được bảo vệ bởi API gateway
- **Thiếu input validation**: code cũ không có sanitization hiện đại
- **Thiếu monitoring**: không có log, không phát hiện được tấn công
- **Chứa vulnerability đã biết**: dependency cũ không được cập nhật

Kẻ tấn công chủ động tìm shadow APIs vì chúng là "cửa sau" dễ khai thác nhất.

## ⚔️ Cơ chế tấn công

**1. API Version Discovery — Tìm phiên bản cũ:**

```python
# Automated version discovery script
import requests

BASE_URL = "https://api.target.com"
KNOWN_ENDPOINTS = ["/users", "/orders", "/products", "/auth/login"]

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
            for version in range(0, 10):  # Test v0 through v9
                url = BASE_URL + pattern.format(v=version, endpoint=endpoint)
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code not in [404, 410]:
                        print(f"[ALIVE] {url} → {resp.status_code}")
                        # Check if auth is required
                        if resp.status_code == 200:
                            print(f"  [!!] No authentication required!")
                except requests.exceptions.RequestException:
                    pass

discover_shadow_versions()
```

**2. Khai thác deprecated endpoint thiếu auth:**

```http
# Current API (v2) — requires authentication
GET /api/v2/users/123 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbG...

# HTTP 200 OK — returns user data (with proper auth)

# Deprecated API (v1) — still running, NO AUTH REQUIRED!
GET /api/v1/users/123 HTTP/1.1
Host: api.target.com
# No Authorization header needed!

# HTTP 200 OK — returns same user data WITHOUT authentication!
# {"id": 123, "name": "Alice", "email": "alice@corp.com", "ssn": "123-45-6789"}
```

**3. Mobile API endpoint discovery — Reverse engineering APK:**

```bash
# Extract API endpoints from Android APK
apktool d target-app.apk -o decompiled/

# Search for API URLs in decompiled code
grep -rn "api\|endpoint\|baseurl\|BASE_URL" decompiled/smali/ decompiled/res/
# Output:
# const-string v0, "https://api.target.com/mobile/v1/"
# const-string v1, "/user/full-profile"        ← Not in public API docs!
# const-string v2, "/admin/user-lookup"         ← Admin endpoint in mobile app!
# const-string v3, "/internal/feature-flags"    ← Internal API exposed!

# Test discovered endpoints
curl https://api.target.com/mobile/v1/user/full-profile \
  -H "X-Mobile-App: true"
# Returns full user profile including fields not exposed in web API!
```

**4. Debug endpoint exploitation:**

```http
# Common debug endpoints left in production
GET /api/debug/routes HTTP/1.1        # Lists ALL registered routes
GET /api/debug/config HTTP/1.1        # Exposes configuration, secrets
GET /api/debug/health HTTP/1.1        # Internal health check with system info
GET /api/test/create-admin HTTP/1.1   # Test endpoint to create admin user!
POST /api/internal/reset-db HTTP/1.1  # Internal tool left exposed

# Swagger/OpenAPI docs left exposed
GET /swagger.json HTTP/1.1
GET /api-docs HTTP/1.1
GET /openapi.yaml HTTP/1.1
GET /.well-known/openapi.yaml HTTP/1.1
```

## 🛡️ Biện pháp phòng thủ

1. **Maintain API inventory** — sử dụng API Gateway làm single entry point:

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
    - host: api.target.com
      http:
        paths:
          # ONLY v2 endpoints are exposed — v1 is completely blocked
          - path: /api/v2/.*
            pathType: ImplementationSpecific
            backend:
              service:
                name: api-v2-service
                port:
                  number: 8080
          # Everything else → 404 (including /api/v1/*, /debug/*, /internal/*)
```

2. **Tự động decommission API versions cũ:**

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
                    "migration_guide": f"https://docs.example.com/migrate-{version}"
                }), 410  # 410 Gone — permanently removed
            else:
                # Soft deprecation — add warning header
                response = None  # Let request proceed
                # After response, add Sunset header
```

3. **Quét định kỳ** để phát hiện shadow APIs:

```bash
# Use nuclei or custom scripts to detect undocumented endpoints
nuclei -u https://api.target.com -t exposures/ -t misconfiguration/
```

4. **CI/CD pipeline** tự động xóa debug endpoints khi deploy lên production.

5. **API documentation as code** — OpenAPI spec phải khớp 100% với code thực tế.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- OWASP: https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
- PortSwigger: https://portswigger.net/web-security/api-testing
- CWE: https://cwe.mitre.org/data/definitions/1059.html
- Salt Security: https://salt.security/blog/what-are-shadow-apis
