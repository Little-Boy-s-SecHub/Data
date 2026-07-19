---
schema_version: 1
id: WEB-A05-XPATH-INJECTION
title: "XPath Injection"
slug: xpath-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-643
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# XPath Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích XPath Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống XPath Injection và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng XML giống như một sơ đồ phả hệ hoặc cấu trúc dạng cây để lưu trữ thông tin (như danh sách người dùng và mật khẩu). Để tìm kiếm và di chuyển giữa các nhánh của cây XML này, lập trình viên sử dụng một ngôn ngữ truy vấn gọi là XPath (tương tự như cách SQL được dùng cho cơ sở dữ liệu quan hệ). XPath sử dụng các biểu thức đường dẫn thông minh như `//user[name='admin']` để nhanh chóng xác định đúng vị trí của nút dữ liệu cần tìm.

```xml
<!-- users.xml — XML-based user database -->
<users>
  <user>
    <name>admin</name>
    <password>s3cur3P@ss</password>
    <role>administrator</role>
  </user>
  <user>
    <name>guest</name>
    <password>guest123</password>
    <role>viewer</role>
  </user>
</users>
```

Ứng dụng xác thực người dùng bằng XPath query:

```python
# Normal authentication using XPath query
import lxml.etree as ET

tree = ET.parse('users.xml')

# Build XPath to find matching user
query = f"//user[name='{username}' and password='{password}']"
result = tree.xpath(query)

if result:
    print("Login successful")
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng XPath Injection xảy ra khi ứng dụng web ghép nối trực tiếp thông tin do người dùng nhập vào câu lệnh truy vấn XPath mà không hề kiểm tra hay làm sạch dữ liệu. Kẻ tấn công có thể chèn các toán tử logic như `or` hoặc `'` để bẻ gãy logic tìm kiếm ban đầu. Khác với cơ sở dữ liệu SQL có các lớp phân quyền phức tạp cho từng bảng, các tài liệu XML thường chỉ là một file đơn lẻ không có cơ chế phân quyền bên trong. Một khi kẻ tấn công chèn được câu lệnh XPath độc hại thành công, họ có thể vượt qua bước xác thực đăng nhập mà không cần mật khẩu, hoặc trích xuất và đọc sạch sẽ mọi thông tin nhạy cảm nằm trong toàn bộ tệp XML đó.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** XML user record và kết quả XPath authentication/search.
- **Actor, xác thực và role:** anonymous gọi login/search.
- **Điều kiện khai thác:** input bị nối vào XPath và thay đổi predicate hoặc node set.
- **Browser, proxy, framework và phiên bản:** Java 17 XPath engine trên XML tổng hợp; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với xpath injection, input bị nối vào XPath và thay đổi predicate hoặc node set. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Java 17 XPath engine trên XML tổng hợp; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case xpath injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input bị nối vào XPath và thay đổi predicate hoặc node set”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của xpath injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**Authentication Bypass** — Classic tautology attack tương tự SQL Injection:

<!-- payload-id: WEB-A05-XPATH-INJECTION-001 -->
<!-- context: Java 17 XPath login fixture concatenates username/password into a string predicate -->
<!-- prerequisites: synthetic XML users; one request; no token or privileged data returned -->
<!-- encoding: quotes/spaces are UTF-8 form data encoded once; XPath engine receives decoded literal input -->
<!-- expected-result: vulnerable expression selects the designated fixture user; variable-bound query returns no match -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Malicious input
username: ' or '1'='1
password: ' or '1'='1

# Resulting XPath query becomes:
//user[name='' or '1'='1' and password='' or '1'='1']
# This always evaluates to TRUE — returns all users
```

**Data Extraction bằng Boolean-based Blind XPath Injection**:

<!-- payload-id: WEB-A05-XPATH-INJECTION-002 -->
<!-- context: Java 17 XPath fixture exposes a boolean response for a public four-character labCode node -->
<!-- prerequisites: synthetic XML only; maximum four positions by 36 characters; bounded harness -->
<!-- encoding: XPath quotes and substring expression are UTF-8 form data percent-encoded once -->
<!-- expected-result: bounded oracle recovers only LAB1; secure variable binding yields no predicate injection -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Test the first character of the public fixture labCode
' or substring(//labCode, 1, 1)='L' or 'a'='b

# The bounded harness tests only four positions against A-Z and 0-9,
# then stops after recovering the documented marker LAB1.
```

**Trích xuất tên node bằng hàm name()**:

<!-- payload-id: WEB-A05-XPATH-INJECTION-003 -->
<!-- context: Java 17 XPath fixture tests one known child-node name in synthetic XML -->
<!-- prerequisites: one fixture user and a three-name allowlist; maximum three requests -->
<!-- encoding: XPath name expression is UTF-8 form input encoded once and inserted only by vulnerable route -->
<!-- expected-result: vulnerable boolean differs for the documented node; fixed expression treats the probe as a literal username -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Discover node names in the XML structure
' or name(//user[1]/child::*[1])='name' or '1'='2

# Attacker can enumerate the entire XML schema
```

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE ===
from lxml import etree

def login_vulnerable(username, password):
    tree = etree.parse('users.xml')
    # DANGER: String concatenation with user input
    query = f"//user[name='{username}' and password='{password}']"
    result = tree.xpath(query)
    return len(result) > 0


# === SECURE CODE ===
from lxml import etree
import re

def login_secure(username, password):
    tree = etree.parse('users.xml')

    # Validate input — allow only alphanumeric characters
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    if not re.match(r'^[a-zA-Z0-9@!#_]+$', password):
        return False

    # Use XPath variables for parameterized queries
    # lxml supports XPath variables via the 'variables' parameter
    query = "//user[name=$uname and password=$pwd]"
    result = tree.xpath(query, uname=username, pwd=password)
    return len(result) > 0
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến XPath Injection, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Bind biến XPath hoặc dùng query cố định; không nối input vào expression.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với XPath Injection, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Sử dụng các truy vấn liên kết biến (variable binding) trong XPath và xác thực danh sách trắng các ký tự đầu vào.
- **Các bước chi tiết**:
  - Parameterized XPath queries: Sử dụng XPath variable binding thay vì nối chuỗi — tương tự prepared statement trong SQL.
  - Input validation: Whitelist ký tự cho phép (alphanumeric), reject ký tự đặc biệt `'`, `"`, `/`, `[`, `]`.
  - Chuyển sang cơ sở dữ liệu: Nếu dữ liệu quan trọng, migrate từ XML file sang database có hệ thống phân quyền.
  - Least privilege: Giới hạn scope XPath query chỉ truy vấn node cần thiết.
  - Error handling: Không expose XPath error message ra cho client.

## 12. Retest

- **Positive case:** với XPath Injection, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của XPath Injection mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **XPath**: Ngôn ngữ truy vấn dùng để định vị và lấy dữ liệu từ tài liệu XML.
- **XPath Injection**: Tiêm mã XPath độc hại nhằm thay đổi truy vấn và trích xuất trái phép dữ liệu XML.
- **XML Node**: Một nút đại diện cho một phần tử, thuộc tính hoặc văn bản trong tài liệu XML.
- **Statement Stacking**: Kỹ thuật xếp chồng nhiều câu lệnh thực thi liên tiếp (không được hỗ trợ trong XPath).
- **Logic Operator**: Các phép toán logic như AND, OR dùng trong câu lệnh truy vấn.

## 16. Bài liên quan và đọc thêm

- [SQL Injection](../sql-injection/) — Lỗ hổng chèn mã truy vấn cấu trúc dữ liệu.

## 17. Tài liệu tham khảo

- **[S1]** OWASP WSTG — Testing for XPath Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection — phiên bản/trạng thái: latest; truy cập: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/XPATH_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/643.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
