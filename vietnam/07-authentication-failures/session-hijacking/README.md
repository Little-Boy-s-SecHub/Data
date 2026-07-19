---
schema_version: 1
id: WEB-A07-SESSION-HIJACKING
title: "Session Hijacking"
slug: session-hijacking
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A07:2025
cwe:
  - CWE-384
  - CWE-613
  - CWE-614
  - CWE-1004
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Session Hijacking

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Session Hijacking bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Session Hijacking và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng giao thức HTTP của mạng Internet giống như một người phục vụ quán ăn bị mất trí nhớ ngắn hạn (**stateless**). Mỗi lần bạn gọi món, người phục vụ này hoàn toàn không nhớ bạn là ai và vừa gọi cái gì ở giây trước. Để giải quyết vấn đề này, sau khi bạn đăng nhập thành công, máy chủ sẽ phát cho bạn một chiếc thẻ bàn có ghi một mã số ngẫu nhiên duy nhất (gọi là **Session ID**). Chiếc thẻ này được trình duyệt của bạn cất giữ trong một ngăn tủ nhỏ gọi là Cookie.

Mỗi khi bạn gửi một yêu cầu tiếp theo (như xem giỏ hàng hay thanh toán), trình duyệt sẽ tự động trình chiếc thẻ bàn (Session ID) này cho người phục vụ xem. Người phục vụ chỉ cần đối chiếu mã số trên thẻ với sổ ghi chép ở quầy để biết bạn là ai và phục vụ đúng món. Chiếc thẻ bàn này chính là "chìa khóa" độc nhất để chứng minh bạn đã đăng nhập. Nếu bất kỳ ai nhặt được hoặc sao chép được chiếc thẻ này của bạn, họ có thể nghiễm nhiên ngồi vào bàn của bạn và gọi món, thanh toán bằng tiền của bạn mà không cần biết mật khẩu.

```python
# Normal session management flow with Flask-Session 0.8.x
from datetime import datetime, timezone
from flask import Flask, redirect, request, session
from flask_session import Session

app = Flask(__name__)
app.config.update(
    SECRET_KEY="load-from-secret-manager",
    SESSION_TYPE="redis",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
Session(app)

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Replace pre-authentication data before rotating the server-side SID
        session.clear()
        session['user_id'] = user.id
        session['login_time'] = datetime.now(timezone.utc).isoformat()
        app.session_interface.regenerate(session)
        return redirect('/dashboard')
    return "Invalid credentials", 401
```

Ví dụ dùng Flask-Session 0.8.x vì built-in Flask session là cookie ký phía client và không có API `session.regenerate()`. Với server-side session, ứng dụng gọi `app.session_interface.regenerate(session)` sau khi tạo state đăng nhập mới. Session ID cần entropy từ CSPRNG và cookie cần `Secure`, `HttpOnly`, `SameSite` phù hợp use case. [S5] [S6]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Cướp quyền điều khiển phiên (Session Hijacking) xảy ra khi kẻ tấn công tìm cách đánh cắp, đoán trước hoặc giả mạo mã Session ID của người dùng hợp lệ để chiếm đoạt phiên làm việc của họ.

Mối nguy hiểm của lỗ hổng này rất lớn vì nó cho phép kẻ tấn công vượt qua toàn bộ các bước bảo mật (kể cả mật khẩu hay xác thực 2FA) để trực tiếp truy cập vào tài khoản của nạn nhân. Kẻ tấn công có thể thực hiện việc này bằng cách chèn mã độc JavaScript (XSS) để đọc trộm cookie, nghe lén lưu lượng mạng không được mã hóa (sniffing) tại các điểm Wi-Fi công cộng, hoặc dự đoán mã Session ID nếu hệ thống tạo ra các mã này theo quy luật quá đơn giản.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5], [S6].

> **Lưu ý mapping:** chủ đề này không có một CWE duy nhất đủ chính xác. Metadata map các cơ chế phổ biến trong bài: session fixation/lifecycle (CWE-384, CWE-613) và cookie flags làm giảm rủi ro đánh cắp/replay (CWE-614, CWE-1004); từng finding thực tế vẫn phải map theo root cause quan sát được. [S3], [S7], [S8], [S9]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** authenticated cookie và server-side session state.
- **Actor, xác thực và role:** actor replay cookie tổng hợp; nạn nhân role user.
- **Điều kiện khai thác:** bearer session bị copy vẫn hợp lệ do transport/cookie/lifecycle control yếu.
- **Browser, proxy, framework và phiên bản:** Flask-Session 0.8 hoặc Express session, Chromium và TLS .lab.test proxy được pin; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với session hijacking, bearer session bị copy vẫn hợp lệ do transport/cookie/lifecycle control yếu. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Flask-Session 0.8 hoặc Express session, Chromium và TLS .lab.test proxy được pin; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case session hijacking; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “bearer session bị copy vẫn hợp lệ do transport/cookie/lifecycle control yếu”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của session hijacking; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**1. XSS-based Session Theft — đánh cắp cookie qua JavaScript:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-001 -->
<!-- context: Chromium pinned by the local browser harness; synthetic non-HttpOnly lab_session cookie -->
<!-- prerequisites: loopback-only fixture; no callback; no real cookie or localStorage content -->
<!-- encoding: UTF-8 inline script; cookie name is ASCII and DOM dataset receives only true/false -->
<!-- expected-result: page records whether the synthetic cookie is script-readable; no value leaves the page -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- The server fixture exposes only a boolean synthetic marker; no cookie value is read. -->
<script>
document.body.dataset.labCookieReadable = window.__LAB_COOKIE_READABLE__ === true
    ? 'true'
    : 'false';
</script>
```

**2. Network Sniffing — nghe lén trên HTTP không mã hóa:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-002 -->
<!-- context: tcpdump captures plain HTTP only inside an isolated network namespace interface lab0 -->
<!-- prerequisites: synthetic client/server and cookie LAB_SESSION_ONLY; maximum 20 packets; no physical interface or sudo -->
<!-- encoding: pcap bytes are decoded only for local ASCII HTTP headers; capture filter is port 8080 on lab0 -->
<!-- expected-result: capture contains the synthetic Cookie header on HTTP; TLS fixture exposes no cookie plaintext -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Capture at most 20 packets on the isolated lab namespace interface.
tcpdump -i lab0 -c 20 -A -s 0 'tcp port 8080 and host victim.lab.test'

# Or using Wireshark filter to capture session cookies:
# http.cookie contains "session"

# Captured fixture value: Cookie: session=LAB_SESSION_ONLY
# A second synthetic client demonstrates replay only inside this namespace.
```

**3. Session Fixation — ép nạn nhân dùng session ID đã biết:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-003 -->
<!-- context: intentionally vulnerable fixture accepts SESSIONID from query and fails to rotate at login -->
<!-- prerequisites: two synthetic browser contexts and attacker_known_id only; one login/replay; loopback -->
<!-- encoding: SESSIONID query is ASCII and percent-encoded once; Set-Cookie framing is generated by fixture -->
<!-- expected-result: old ID accesses victim fixture only on vulnerable route; secure login rotates and invalidates old ID -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
// Step 1: Attacker gets a valid session ID from target site
GET /login HTTP/1.1
Response: Set-Cookie: SESSIONID=attacker_known_id

// Step 2: Attacker sends victim a link with fixed session
https://victim.lab.test/login?SESSIONID=attacker_known_id

// Step 3: Victim logs in using attacker's session ID
// Step 4: Attacker uses the SAME session ID — now authenticated as victim
```

**4. Predictable Session IDs:**

<!-- payload-id: WEB-A07-SESSION-HIJACKING-004 -->
<!-- context: Python 3.12 demonstrates timestamp-plus-username MD5 IDs in a local generator -->
<!-- prerequisites: synthetic username fixture-admin; search window capped at 20 timestamps; no HTTP target -->
<!-- encoding: f-string is UTF-8, timestamp is decimal ASCII and md5 output is lowercase hexadecimal -->
<!-- expected-result: bounded guesses reproduce the fixture ID; secrets.token_urlsafe generator cannot be reproduced by this model -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# VULNERABLE: predictable session ID generation
import time, hashlib

def generate_session_id(username):
    # Session based on timestamp + username — attacker can guess
    raw = f"{username}{int(time.time())}"
    return hashlib.md5(raw.encode()).hexdigest()

# The harness knows fixture username and tests only a 20-second window.
```

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: no cookie flags, predictable session, no regeneration
app.config['SESSION_COOKIE_HTTPONLY'] = False   # JS can read cookie
app.config['SESSION_COOKIE_SECURE'] = False     # Sent over HTTP
app.config['SESSION_COOKIE_SAMESITE'] = None    # No CSRF protection

@app.route('/login', methods=['POST'])
def login_unsafe():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # No session regeneration — fixation possible
        session['user_id'] = user.id
        return redirect('/dashboard')
    return "Failed", 401
```

```python
# SECURE: Flask-Session 0.8.x cookie flags and server-side SID rotation
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
    SESSION_COOKIE_NAME='__Host-sid',
)

@app.route('/login', methods=['POST'])
def login_safe():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Clear pre-authentication state, create authenticated state, then rotate SID
        session.clear()
        session['user_id'] = user.id
        session['created'] = datetime.now(timezone.utc).isoformat()
        app.session_interface.regenerate(session)
        return redirect('/dashboard')
    return "Invalid credentials", 401

@app.route('/logout', methods=['POST'])
def logout():
    # Delete authenticated state and expire the current cookie
    session.clear()
    return redirect('/login')
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Session Hijacking, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Bảo vệ cookie qua TLS và rotate, revoke, monitor toàn bộ session lifecycle.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Session Hijacking, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Ngăn chặn đánh cắp phiên bằng cách sử dụng các cờ bảo mật cookie (HttpOnly, Secure, SameSite), tạo lại session ID khi đăng nhập và bắt buộc HTTPS.
- **Các bước chi tiết**:
  - **Cookie security flags**: Đặt `HttpOnly` để chặn JavaScript đọc cookie, `Secure` để chỉ gửi qua HTTPS và chọn `SameSite=Lax`/`Strict` theo luồng ứng dụng; SameSite là defense-in-depth cho CSRF.
  - **Session regeneration**: Tạo session ID mới sau khi đăng nhập (chống fixation) và sau mỗi thay đổi quyền.
  - **HTTPS everywhere**: Buộc toàn bộ traffic qua HTTPS với HSTS header để chống network sniffing.
  - **Tín hiệu rủi ro phiên**: IP/User-Agent có thể thay đổi hợp lệ hoặc bị giả mạo, nên dùng làm tín hiệu cảnh báo/step-up thay vì khóa cứng phiên trong mọi ứng dụng.
  - **Cryptographic session IDs**: Dùng CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) để tạo session ID 128-bit trở lên.

## 12. Retest

- **Positive case:** với Session Hijacking, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Session Hijacking mà không xác nhận side effect và log.
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

- **Stateless (Không trạng thái)**: HTTP không tự gắn request hiện tại với request trước; ứng dụng vẫn có thể duy trì trạng thái bằng cookie, session server-side hoặc token.
- **Session (Phiên làm việc)**: Cơ chế duy trì trạng thái tương tác giữa người dùng và ứng dụng web trong một khoảng thời gian, lưu giữ thông tin đăng nhập và hoạt động của người dùng ở phía máy chủ.
- **Session ID (Mã định danh phiên)**: Chuỗi ký tự ngẫu nhiên, duy nhất dùng làm khóa để ánh xạ yêu cầu của người dùng với dữ liệu phiên làm việc tương ứng được lưu trên máy chủ.
- **XSS (Cross-Site Scripting)**: Lỗ hổng bảo mật cho phép kẻ tấn công chèn các đoạn mã script độc hại (thường là JavaScript) vào trang web và thực thi trên trình duyệt của người dùng khác.
- **Sniffing (Nghe lén mạng)**: Hành động chặn bắt và theo dõi các gói tin dữ liệu truyền tải trên mạng để thu thập thông tin nhạy cảm (như Session ID truyền qua HTTP không mã hóa).
- **Session Hijacking (Cướp phiên)**: Hành vị tin tặc đánh cắp mã Session ID của người dùng hợp lệ để giả mạo họ và truy cập trái phép vào ứng dụng mà không cần thông tin đăng nhập.

## 16. Bài liên quan và đọc thêm

- [Stored XSS](../../05-injection/xss/stored/) — Kẻ tấn công sử dụng lỗ hổng XSS lưu trữ để chèn mã độc JavaScript nhằm đánh cắp session cookie từ trình duyệt của nạn nhân.

## 17. Tài liệu tham khảo

- **[S1]** OWASP WSTG — Testing for Session Hijacking. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking — phiên bản/trạng thái: latest; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Session_hijacking_attack — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/384.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** OWASP Session Management Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S6]** Flask-Session 0.8.0 API. https://flask-session.readthedocs.io/en/latest/api.html — phiên bản/ngày: 0.8.0; truy cập: 2026-07-18.
- **[S7]** CWE-613 — Insufficient Session Expiration. https://cwe.mitre.org/data/definitions/613.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S8]** CWE-614 — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute. https://cwe.mitre.org/data/definitions/614.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S9]** CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag. https://cwe.mitre.org/data/definitions/1004.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
