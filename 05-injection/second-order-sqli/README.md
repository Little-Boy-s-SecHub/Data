---
schema_version: 1
id: WEB-A05-SECOND-ORDER-SQLI
title: "Second-Order SQL Injection"
slug: second-order-sqli
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-89
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Second-Order SQL Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Second-Order SQL Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Trong các cuộc tấn công SQL Injection truyền thống (first-order), kẻ xấu chèn mã độc vào và nó sẽ phát nổ ngay lập tức trong cùng một yêu cầu gửi lên. Để đối phó, các ứng dụng ngày nay đã bảo vệ cửa ngõ đầu vào rất tốt bằng cách sử dụng các truy vấn tham số hóa (parameterized queries). Tuy nhiên, kẻ tấn công vẫn có một chiêu thức thâm hiểm hơn gọi là SQL Injection bậc hai (Second-Order SQL Injection). Với chiêu này, kẻ xấu sẽ gửi một chuỗi mã độc trông có vẻ vô hại ở bước đầu tiên để ứng dụng lưu trữ an toàn vào cơ sở dữ liệu. Sau đó, ở một bước thứ hai, khi ứng dụng đọc dữ liệu này ra từ cơ sở dữ liệu để thực hiện một truy vấn khác, mã độc mới thực sự phát nổ. Điểm mấu chốt ở đây là nơi nhập mã độc và nơi mã độc thực thi là hoàn toàn khác nhau.

```python
# Step 1: User registration — stores username safely with parameterized query
def register(username, password):
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hash_password(password))
    )
    # Username is stored AS-IS in the database — including special characters

# Step 2: Password change — retrieves username from session
def change_password(session_user, new_password):
    # The username is read from database, assumed "safe"
    cursor.execute(
        "UPDATE users SET password=%s WHERE username=%s",
        (hash_password(new_password), session_user)
    )
```

Quy trình trên an toàn vì **cả hai bước đều dùng parameterized query**. Vấn đề phát sinh khi bước thứ hai sử dụng string concatenation.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Second-Order SQLi xảy ra do lập trình viên mắc phải một sai lầm phổ biến về ranh giới tin cậy: họ cho rằng dữ liệu một khi đã nằm yên vị bên trong cơ sở dữ liệu của mình thì mặc định là an toàn và có thể thoải mái lôi ra sử dụng bằng cách cộng chuỗi trực tiếp. Kẻ tấn công lợi dụng điều này bằng cách đặt một tên đăng nhập độc hại (ví dụ: `admin' --`). Bước đăng ký tài khoản diễn ra suôn sẻ và tên này được lưu vào database. Đến khi nạn nhân thực hiện thao tác đổi mật khẩu, ứng dụng lấy tên này ra và ghép nối trực tiếp vào câu lệnh SQL cập nhật mật khẩu, vô tình biến đổi câu lệnh thành "đổi mật khẩu của người dùng admin". Lỗ hổng này cực kỳ nguy hiểm vì nó ẩn mình rất kỹ, vượt qua các công cụ quét tự động thông thường và có thể âm thầm gây họa sau nhiều ngày lưu trữ.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** giá trị profile đã lưu và SQL report/job ở bước sau.
- **Actor, xác thực và role:** role user lưu profile; job hoặc admin view dùng lại dữ liệu.
- **Điều kiện khai thác:** dữ liệu được lưu ở bước một nhưng bị nối vào SQL ở sink thứ hai.
- **Browser, proxy, framework và phiên bản:** PostgreSQL 16 với Python 3.12/Flask 3.x và log hai bước có correlation ID; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với second order sqli, dữ liệu được lưu ở bước một nhưng bị nối vào SQL ở sink thứ hai. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy PostgreSQL 16 với Python 3.12/Flask 3.x và log hai bước có correlation ID; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case second order sqli; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “dữ liệu được lưu ở bước một nhưng bị nối vào SQL ở sink thứ hai”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của second order sqli; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**Kịch bản kinh điển: Thay đổi mật khẩu admin**

<!-- payload-id: WEB-A05-SECOND-ORDER-SQLI-001 -->
<!-- context: PostgreSQL 16 two-step registration/password-change fixture uses a stored username later -->
<!-- prerequisites: synthetic account and transaction only; two requests with one correlation chain; rollback enabled -->
<!-- encoding: registration form UTF-8 percent-encodes quote once; stored value is passed unchanged to the second query -->
<!-- expected-result: vulnerable second statement selects/updates wrong fixture row; parameterized second use affects only caller -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Step 1: Attacker registers with malicious username
# Registration uses parameterized query — payload stored safely
register_username = "admin'--"
register_password = "anything"
# INSERT INTO users (username, password) VALUES ('admin''--', 'hashed')
# The username admin'-- is now stored in the database

# Step 2: Attacker changes their own password
# But the vulnerable code builds SQL via concatenation
def change_password_vulnerable(session_user, new_password):
    hashed = hash_password(new_password)
    # DANGER: Username from DB used in string concatenation
    query = f"UPDATE users SET password='{hashed}' WHERE username='{session_user}'"
    cursor.execute(query)

# When session_user = "admin'--", the query becomes:
# UPDATE users SET password='new_hash' WHERE username='admin'--'
# The -- comments out the rest — admin's password is changed!
```

**Kịch bản data exfiltration qua profile page**:

<!-- payload-id: WEB-A05-SECOND-ORDER-SQLI-002 -->
<!-- context: PostgreSQL 16 report fixture concatenates a stored company value into a later SELECT -->
<!-- prerequisites: synthetic report rows containing only a public LAB_REPORT_MARKER; one store and one report action; transaction rollback -->
<!-- encoding: company string is UTF-8 form data with quote/spaces encoded once; SQL driver receives stored text unchanged -->
<!-- expected-result: vulnerable report includes only public LAB_REPORT_MARKER from another row; bound query returns caller company rows -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Stored fixture value: ' UNION SELECT 'LAB_REPORT_MARKER'--
company = get_user_company(user_id)
query = f"SELECT display_value FROM reports WHERE company='{company}'"
# The vulnerable report returns only the documented public marker.
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE ===
def change_password_vulnerable(user_id, new_password):
    # Fetch username from database — developer assumes it's safe
    cursor.execute("SELECT username FROM users WHERE id=%s", (user_id,))
    username = cursor.fetchone()[0]

    hashed = hash_password(new_password)
    # DANGER: Username from DB concatenated into SQL
    query = f"UPDATE users SET password='{hashed}' WHERE username='{username}'"
    cursor.execute(query)


# === SECURE CODE ===
def change_password_secure(user_id, new_password):
    hashed = hash_password(new_password)
    # Use parameterized query — even for data retrieved from database
    # Update by user ID instead of username to avoid injection entirely
    cursor.execute(
        "UPDATE users SET password=%s WHERE id=%s",
        (hashed, user_id)
    )
    # No string concatenation, no injection possible
    # Using ID (integer) instead of username further reduces attack surface
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Bind parameter tại mọi lần thực thi, kể cả dữ liệu đọc lại từ storage.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Sử dụng truy vấn tham số hóa ở mọi nơi dữ liệu được sử dụng, không tin cậy dữ liệu được truy xuất từ cơ sở dữ liệu.
- **Các bước chi tiết**:
  - Parameterized queries EVERYWHERE: Không chỉ tại input point mà tại mọi nơi dữ liệu được sử dụng trong SQL — kể cả dữ liệu lấy từ database.
  - Zero trust cho stored data: Coi dữ liệu từ database cũng là untrusted input, áp dụng cùng mức độ sanitization.
  - Input validation tại registration: Validate username chỉ chứa ký tự hợp lệ (alphanumeric, underscore).
  - Code review cross-module: Trace data flow từ input → storage → retrieval → usage để phát hiện second-order vulnerability.
  - ORM framework: Sử dụng ORM (SQLAlchemy, Django ORM) giúp tự động parameterize mọi truy vấn.

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Second-Order SQLi**: Lỗ hổng SQL Injection xảy ra khi mã độc được lưu vào database trước rồi mới thực thi ở một truy vấn sau đó.
- **Trust Boundary**: Ranh giới tin cậy phân biệt giữa dữ liệu đã kiểm duyệt và dữ liệu chưa được kiểm duyệt.
- **Parameterized Query**: Kỹ thuật truyền tham số riêng biệt giúp triệt tiêu hoàn toàn khả năng chèn câu lệnh SQL trái phép.
- **String Concatenation**: Hành động ghép nối các chuỗi chữ lại với nhau, thường gây ra các lỗi injection.
- **First-Order SQLi**: Lỗ hổng SQL Injection truyền thống thực thi ngay lập tức trong yêu cầu gửi lên.

## 16. Bài liên quan và đọc thêm

- [SQL Injection](../sql-injection/) — Lỗ hổng SQL Injection cơ bản sử dụng đầu vào trực tiếp từ người dùng trong cùng một vòng đời yêu cầu.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/sql-injection#second-order-sql-injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/SQL_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/89.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
