---
schema_version: 1
id: WEB-A05-SQL-INJECTION
title: "SQL Injection"
slug: sql-injection
level: beginner
estimated_minutes: 35
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

# SQL Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích SQL Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng cơ sở dữ liệu (Database) giống như một kho lưu trữ thông tin khổng lồ và SQL là ngôn ngữ giao tiếp để bạn yêu cầu người giữ kho lấy dữ liệu ra cho mình. Trong các cuộc đối thoại an toàn, lập trình viên sử dụng các câu lệnh đã được biên dịch sẵn (Prepared Statements) giống như một biểu mẫu điền thông tin có sẵn các ô trống. Khi bạn điền thông tin vào các ô trống này, người giữ kho chỉ coi đó là dữ liệu thuần túy và không bao giờ nhầm lẫn chúng với các mệnh lệnh hành động. Các ký tự như dấu nháy đơn `'` hay dấu chú thích `--` trong SQL thường được dùng để phân định ranh giới chuỗi và viết ghi chú.

```python
import sqlite3

def get_user_by_email(email):
    # Establish connection to the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Normal operation using parameterized query (prepared statement)
    # The database engine compiles the SQL query structure first,
    # then binds the email parameter as a literal value, preventing SQL injection.
    query = "SELECT id, username, email FROM users WHERE email = ?"
    cursor.execute(query, (email,))

    user = cursor.fetchone()
    conn.close()
    return user
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng SQL Injection (SQLi) xuất hiện khi ứng dụng web không dùng các biểu mẫu điền thông tin an toàn mà lại trực tiếp nối chuỗi thông tin của người dùng vào câu lệnh gửi cho người giữ kho. Điều này giống như việc bạn viết thêm một dòng chữ ra lệnh mới vào ngay bên cạnh tên của mình trên tờ giấy yêu cầu. Kẻ tấn công có thể chèn các từ khóa SQL hoặc dấu nháy đơn để bẻ gãy câu lệnh gốc, buộc cơ sở dữ liệu phải thực thi những hành động ngoài ý muốn. Chẳng hạn, thay vì chỉ tìm kiếm một sản phẩm, câu lệnh bị biến thành "hãy hiển thị mật khẩu của toàn bộ người dùng". Lỗ hổng này vô cùng nguy hiểm vì nó có thể dẫn đến việc rò rỉ thông tin nhạy cảm của hàng triệu khách hàng, xóa sạch cơ sở dữ liệu, hoặc thậm chí giúp kẻ tấn công chiếm quyền điều khiển hoàn toàn máy chủ.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** các row fixture và quyền database account.
- **Actor, xác thực và role:** anonymous login/search hoặc role user lọc dữ liệu.
- **Điều kiện khai thác:** input nối vào SQL làm thay đổi predicate, union, error hoặc time semantics.
- **Browser, proxy, framework và phiên bản:** fixture PostgreSQL 16 và MySQL 8 tách biệt với Python 3.12/Flask; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với sql injection, input nối vào SQL làm thay đổi predicate, union, error hoặc time semantics. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy fixture PostgreSQL 16 và MySQL 8 tách biệt với Python 3.12/Flask; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case sql injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input nối vào SQL làm thay đổi predicate, union, error hoặc time semantics”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của sql injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Lesson chỉ giữ một phép thử boolean không đọc dữ liệu. UNION, error-based,
time-based, stacked query và OOB phụ thuộc DBMS/driver/quyền database nên phải
đặt trong fixture riêng và không được suy ra từ kết quả của probe này. [S1]

<!-- payload-id: WEB-A05-SQL-INJECTION-001 -->
<!-- context: PostgreSQL 16 fixture concatenates a string-valued username inside a WHERE predicate -->
<!-- prerequisites: synthetic users only; one baseline and one probe request; response exposes only a public match/no-match marker -->
<!-- encoding: UTF-8 form value percent-encoded once; PostgreSQL receives the decoded quote, spaces and comment marker -->
<!-- expected-result: vulnerable fixture changes from no-match to match; parameterized fixture returns no match and records no SQL syntax error -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```text
' OR '1'='1'--
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE (Python Flask) ===
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user_vulnerable():
    username = request.args.get('username')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # DANGER: Direct string concatenation leads to Union, Error, Blind, or Stacked SQLi
    query = f"SELECT bio FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return str(cursor.fetchall())

# === SECURE CODE (Python Flask) ===
@app.route('/secure-user')
def get_user_secure():
    username = request.args.get('username')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # SECURE: Using placeholder '?' to ensure safe parameter binding
    query = "SELECT bio FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return str(cursor.fetchall())
```

```javascript
// === SECURE CODE (Node.js - pg client) ===
const { Client } = require('pg');

async function getUserSecure(email) {
  const client = new Client();
  await client.connect();
  try {
    // SECURE: Parameterized query using placeholders
    const query = {
      text: 'SELECT name, bio FROM users WHERE email = $1',
      values: [email],
    };
    const res = await client.query(query);
    return res.rows[0];
  } finally {
    await client.end();
  }
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng prepared statement cho value và allowlist identifier không thể bind.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Sử dụng các câu lệnh truy vấn tham số hóa (prepared statements), các framework ORM và kiểm tra nghiêm ngặt kiểu dữ liệu đầu vào.
- **Các bước chi tiết**:
  - Sử dụng truy vấn tham số hóa cho mọi câu lệnh SQL để tách biệt cấu trúc lệnh và dữ liệu.
  - Sử dụng các thư viện ORM (như SQLAlchemy, Hibernate) vì chúng tự động tham số hóa các truy vấn.
  - Xác thực kiểu dữ liệu đầu vào nghiêm ngặt (nhập số thì ép kiểu integer).
  - Giới hạn quyền tối thiểu cho tài khoản cơ sở dữ liệu kết nối từ ứng dụng.

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

- **SQL (Structured Query Language)**: Ngôn ngữ truy vấn có cấu trúc dùng để tương tác với cơ sở dữ liệu.
- **SQL Injection (SQLi)**: Lỗ hổng cho phép kẻ tấn công chèn lệnh SQL tùy ý để thao túng cơ sở dữ liệu.
- **Prepared Statement**: Kỹ thuật biên dịch trước câu lệnh SQL và truyền dữ liệu dạng đối số độc lập để đảm bảo an toàn.
- **RDBMS**: Hệ quản trị cơ sở dữ liệu quan hệ lưu trữ dữ liệu dưới dạng các bảng có liên kết với nhau.
- **Database**: Hệ thống lưu trữ dữ liệu tập trung của ứng dụng.

## 16. Bài liên quan và đọc thêm

- [Second-Order SQL Injection](../second-order-sqli/) — Lỗ hổng SQLi bậc hai xảy ra khi dữ liệu nhập vào được lưu trong DB trước khi được truy vấn không an toàn ở một chức năng khác.
- [NoSQL Injection](../nosql-injection/) — Tương tự SQLi nhưng nhắm vào các hệ quản trị cơ sở dữ liệu phi quan hệ như MongoDB.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/sql-injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/SQL_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/89.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
