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
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Shadow APIs & Improper Inventory Management bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn là chủ một tòa lâu đài cổ kính nguy nga. Để đảm bảo an toàn, bạn lắp đặt hệ thống cửa khóa thông minh, tường lửa và camera giám sát nghiêm ngặt ở cửa chính (phiên bản API hiện tại - `/api/v2`). Bạn đinh ninh rằng lâu đài của mình tuyệt đối an toàn.
Thế nhưng, bạn không hề biết rằng trong quá trình xây dựng lâu đài trước đây, những người thợ đã tạo ra các lối đi phụ để vận chuyển vật liệu (Debug endpoints `/api/debug/`), hoặc quên khóa các cánh cửa cũ ở tầng hầm khi xây cửa mới (phiên bản cũ `/api/v1`). Những cánh cửa, lối đi phụ này vẫn đang tồn tại, hoàn toàn không được lắp khóa mới, không có camera giám sát và không ai thèm quản lý. Trong thế giới an ninh mạng, những lối đi vô hình này được gọi là **Shadow APIs (API Bóng tối)**.

Để quản lý lâu đài, bạn cần một bản đồ chi tiết ghi nhận mọi ngóc ngách, mọi cánh cửa đang hoạt động. Bản đồ này chính là **Kiểm kê API (API Inventory)**.
Nếu bản đồ kiểm kê của bạn bị thiếu sót, những cánh cửa bóng tối (shadow APIs) kia sẽ trở thành những lỗ hổng "vô hình". Chúng vẫn âm thầm chạy trên hệ thống thực tế nhưng không bao giờ được vá lỗi, không được giới hạn lượt ra vào và không yêu cầu bất kỳ chìa khóa bảo mật nào.

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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Improper Inventory Management (Quản lý kiểm kê không đúng cách)** thực chất là căn bệnh "mất dấu" tài sản của chính mình. Khi doanh nghiệp không biết rõ mình đang có bao nhiêu đường dẫn API đang mở ra internet, họ sẽ để lộ ra những lỗ hổng cực kỳ nguy hiểm.

Kẻ tấn công luôn thích săn tìm những cánh cửa bóng tối này vì chúng thường:
- Hoàn toàn không yêu cầu đăng nhập (thiếu authentication/authorization) do dùng mã nguồn cũ từ nhiều năm trước.
- Không có hệ thống giới hạn lưu lượng (rate limiting), cho phép kẻ tấn công thoải mái dò quét thông tin.
- Sử dụng các thư viện lập trình lỗi thời, chứa đầy các lỗ hổng đã được công bố công khai mà không ai cập nhật.
- Không hề ghi lại nhật ký hoạt động (monitoring), khiến kẻ tấn công có thể ra vào lấy cắp dữ liệu như chốn không người mà hệ thống không hề hay biết.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** endpoint/version inventory, policy xác thực/authorization, dữ liệu giả và telemetry của API đã triển khai.
- **Trust boundary:** route từ gateway/service mesh được đối chiếu với OpenAPI, IaC/deployment manifest và API inventory có chủ sở hữu.
- **Actor:** client chưa đăng nhập/user thường trong loopback fixture; analyst chỉ đọc sample APK/config do lab cung cấp.
- **Điều kiện cần:** route vẫn được deploy nhưng vắng khỏi inventory/monitoring/lifecycle, hoặc legacy version dùng auth/schema/patch level yếu hơn route hiện hành.
- **Điều kiện môi trường:** gateway và API v1/v2/v3 local, hostname `.lab.test`, sample APK synthetic; không quét public DNS/Internet.

Chỉ phát hiện chuỗi version hoặc nhận 404/401 không đủ kết luận shadow API; cần khớp route đang chạy với inventory và chứng minh policy/lifecycle gap. [S1]

## 6. Cơ chế tấn công

Một route cũ có thể còn reachable qua gateway trực tiếp, hostname/alias khác hoặc cấu hình client nhưng không còn được áp policy/patch/telemetry hiện hành. Evidence phải liên kết artifact discovery với deployment manifest, gateway route, owner và request log của đúng version. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy gateway cùng API v1/v2/v3 local; khai báo chỉ v2 trong inventory, seed dữ liệu giả và bật route/auth/audit log.
2. **Input:** baseline v2 với/không token; sau đó kiểm tra danh sách route/version hữu hạn lấy từ manifest và sample APK.
3. **Thao tác:** đối chiếu từng route với inventory/owner, gửi GET/OPTIONS vô hại và ghi gateway/backend/policy log.
4. **Expected result:** fixture dễ lỗi cho phép legacy v1 trái policy; bản sửa trả 401/403/410 hoặc không route, đồng thời inventory/telemetry khớp deployment.
5. **Cleanup:** xóa dữ liệu/token giả, dừng gateway/services và xóa hostname/route fixture.
6. **Giới hạn an toàn:** không brute-force public host, không dùng wordlist lớn; chỉ kiểm tra route hữu hạn trong loopback lab.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**1. API Version Discovery — Tìm phiên bản cũ:**

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

**2. Khai thác deprecated endpoint thiếu auth:**

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

### Tại sao mobile API endpoint đặc biệt nguy hiểm:
<!-- payload-id: WEB-A11-SHADOW-APIS-004 -->
<!-- context: Python 3.12 with requests 2.32, curl 8.x and Bash 5.2 against the versioned API fixture at 127.0.0.1:18080; case: Tại sao mobile API endpoint đặc biệt nguy hiểm: -->
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

**4. Kiểm kê route debug bằng request chỉ đọc:**

<!-- payload-id: WEB-A11-SHADOW-APIS-005 -->
<!-- context: Python 3.12 with requests 2.32, curl 8.x and Bash 5.2 against the versioned API fixture at 127.0.0.1:18080; case: Tại sao mobile API endpoint đặc biệt nguy hiểm: -->
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

## 9. Code dễ bị lỗi và code an toàn

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

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Áp dụng kiểm soát ở cấp đối tượng, thuộc tính, chức năng và mức tiêu thụ tài nguyên của API.
- Dùng inventory gắn owner làm nguồn triển khai, gateway default-deny và cùng auth/schema/logging cho mọi version; legacy route phải được remove hoặc trả 410 theo lifecycle.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

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

- **Tóm tắt**: Quản lý API an toàn bằng cách duy trì danh mục API tự động (API inventory), decommission các phiên bản cũ và triển khai API gateway làm điểm truy cập duy nhất.
- **Các bước chi tiết**:
  - **Maintain API inventory** — sử dụng API Gateway làm single entry point:
  - host: api.victim.lab.test
  - path: /api/v2/.*
  - **Tự động decommission API versions cũ:**
  - **Quét định kỳ** để phát hiện shadow APIs:
  - **CI/CD pipeline** tự động xóa debug endpoints khi deploy lên production.
  - **API documentation as code** — OpenAPI spec phải khớp 100% với code thực tế.

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Shadow API**: Các cổng kết nối API đang hoạt động trên hệ thống thực tế nhưng không được tài liệu hóa, quản lý hay bảo trì bởi đội ngũ phát triển.
- **API Inventory (Kiểm kê API)**: Danh sách đầy đủ, chi tiết mô tả cấu trúc, phiên bản và mục đích của toàn bộ các API đang chạy trong hệ thống.
- **Deprecated (Ngừng hỗ trợ)**: Trạng thái của một tính năng hoặc phiên bản phần mềm cũ bị khuyến cáo không nên sử dụng nữa và sẽ bị loại bỏ hoàn toàn trong tương lai.
- **Endpoint**: Điểm cuối (địa chỉ URL cụ thể) của một API mà client có thể kết nối đến để gửi/nhận dữ liệu.
- **Expose (Lộ lọt)**: Hành vi vô tình hoặc cố ý để lộ thông tin, dữ liệu hoặc dịch vụ nội bộ ra bên ngoài internet.
- **API Gateway**: Cửa ngõ quản lý tập trung toàn bộ các yêu cầu gửi đến API, chịu trách nhiệm xác thực, định tuyến và giới hạn lưu lượng.
- **Nuclei**: Công cụ quét và phát hiện lỗ hổng bảo mật tự động dựa trên các mẫu cấu hình có sẵn (templates).
- **Decommission**: Quá trình chính thức ngừng hoạt động, tắt bỏ và thu hồi tài nguyên của một dịch vụ phần mềm cũ.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP. https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** PortSwigger. https://portswigger.net/web-security/api-testing — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1059.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP API Security Top 10 — API9:2023 Improper Inventory Management. https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ — phiên bản/ngày: 2023; truy cập: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
