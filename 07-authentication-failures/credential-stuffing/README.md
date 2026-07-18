---
schema_version: 1
id: WEB-A07-CREDENTIAL-STUFFING
title: "Credential Stuffing & Brute Force"
slug: credential-stuffing
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A07:2025
cwe:
  - CWE-307
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Credential Stuffing & Brute Force

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Credential Stuffing & Brute Force bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng một tên trộm đang cố gắng đột nhập vào một ngôi nhà.
- Nếu hắn đứng trước cửa, cầm một bộ dụng cụ vạn năng và kiên nhẫn thử hàng nghìn chiếc chìa khóa khác nhau để mở ổ khóa, đó là tấn công dò mật khẩu thủ công (**Brute Force**).
- Nhưng nếu tên trộm đó lùng sục trên "chợ đen", mua lại một chiếc hộp chứa hàng triệu chiếc chìa khóa thật của những ngôi nhà khác đã từng bị mất trộm, rồi mang chiếc hộp đó đi thử khắp các ngôi nhà trong khu phố với hy vọng chủ nhà lười biếng dùng chung một ổ khóa, đó chính là tấn công chèn thông tin rò rỉ (**Credential Stuffing**).

Sở dĩ cuộc tấn công này thành công là vì thói quen của con người: khoảng 65% chúng ta sử dụng cùng một tổ hợp tài khoản/mật khẩu cho nhiều trang web khác nhau (như Facebook, Gmail, tài khoản mua sắm). Khi một trang web nhỏ, bảo mật kém bị tin tặc hack và làm lộ cơ sở dữ liệu mật khẩu, tin tặc sẽ lập tức dùng danh sách đó để đi "gõ cửa" các dịch vụ lớn hơn như ngân hàng, ví điện tử hay mạng xã hội.

```python
# Normal login endpoint (simplified)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return redirect('/dashboard')

    # Generic error message (good practice)
    return render_template('login.html', error='Invalid credentials')
```

Endpoint trên hoạt động đúng cho từng request, nhưng nếu không có cơ chế giới hạn tốc độ (rate limiting), attacker có thể gửi hàng nghìn request mỗi phút để thử tổ hợp credentials.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng này xảy ra khi hệ thống xác thực của trang web quá hiền lành, cho phép bất kỳ ai gửi hàng ngàn yêu cầu đăng nhập liên tục mà không có biện pháp ngăn chặn hay giới hạn tốc độ.

Mối nguy hiểm của lỗ hổng này rất rõ ràng: kẻ tấn công sử dụng các công cụ tự động hóa (scripts) để chạy thử hàng triệu tài khoản bị rò rỉ hoặc thử đoán mật khẩu trong thời gian cực ngắn. Nếu không bị chặn, chúng chắc chắn sẽ tìm ra được những tài khoản sử dụng mật khẩu yếu hoặc tái sử dụng mật khẩu cũ, từ đó chiếm đoạt thông tin cá nhân và tài sản của khách hàng mà không gặp bất kỳ rào cản nào.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** account tổng hợp và kiểm soát đăng nhập tự động.
- **Actor, xác thực và role:** anonymous thử tối đa ba credential fixture; chưa có role.
- **Điều kiện khai thác:** credential tái sử dụng được thử khi thiếu normalization, aggregate throttling hoặc detection.
- **Browser, proxy, framework và phiên bản:** Python 3.12 requests tới login proxy/app loopback với DB snapshot; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với credential stuffing, credential tái sử dụng được thử khi thiếu normalization, aggregate throttling hoặc detection. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Python 3.12 requests tới login proxy/app loopback với DB snapshot; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case credential stuffing; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “credential tái sử dụng được thử khi thiếu normalization, aggregate throttling hoặc detection”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của credential stuffing; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**1. Mô phỏng Credential Stuffing bằng dữ liệu tổng hợp:**

<!-- payload-id: WEB-A07-CREDENTIAL-STUFFING-001 -->
<!-- context: Python 3.12 requests client against a login fixture bound to 127.0.0.1:9002 -->
<!-- prerequisites: exactly three synthetic credentials owned by the fixture; database snapshot; no breach data; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded generated by requests from Unicode strings -->
<!-- expected-result: exactly three attempts are logged; one designated fixture account succeeds and no real credential is printed -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
import requests

LAB_CREDENTIALS = [
    ("fixture-a@victim.lab.test", "Wrong-Lab-Password-1"),
    ("fixture-b@victim.lab.test", "Fixture-Match-2"),
    ("fixture-c@victim.lab.test", "Wrong-Lab-Password-3"),
]

def try_login(cred):
    email, password = cred
    resp = requests.post('http://127.0.0.1:9002/login', data={
        'username': email, 'password': password
    }, allow_redirects=False, timeout=2)

    # Check for successful login indicators
    if resp.status_code == 302 and '/dashboard' in resp.headers.get('Location', ''):
        print(f"[LAB MATCH] {email}")
        return email
    return None

# Keep the fixture test sequential and bounded
results = [try_login(cred) for cred in LAB_CREDENTIALS]
```

**2. Kiểm tra chuẩn hóa danh tính và nguồn tại lớp rate limit:**

<!-- payload-id: WEB-A07-CREDENTIAL-STUFFING-002 -->
<!-- context: HTTP/1.1 login requests pass through a loopback reverse proxy and authentication fixture -->
<!-- prerequisites: synthetic account only; trusted-proxy configuration documented; maximum three requests per normalization case; database snapshot; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded usernames; percent-decoding and case normalization are logged before policy evaluation -->
<!-- expected-result: untrusted forwarding headers do not change client identity, equivalent usernames share one counter, and malformed usernames are rejected consistently -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
// Case 1: untrusted forwarding headers must not replace the proxy identity
X-Forwarded-For: 192.0.2.10
X-Real-IP: 192.0.2.11
X-Originating-IP: 192.0.2.12

// Case 2: equivalent username forms must share the same policy identity
POST /login  → username=Admin@victim.lab.test
POST /login  → username=admin@victim.lab.test
POST /login  → username=ADMIN@victim.lab.test

// Case 3: malformed or padded usernames must be rejected consistently
POST /login  → username=admin%00@victim.lab.test
POST /login  → username= admin@victim.lab.test
```

**3. Password Spraying — thử 1 mật khẩu cho nhiều user:**

<!-- payload-id: WEB-A07-CREDENTIAL-STUFFING-003 -->
<!-- context: Python 3.12 reuses try_login against the loopback login fixture -->
<!-- prerequisites: exactly two synthetic users and one synthetic password; fixture lockout threshold is documented; database snapshot; no outbound network -->
<!-- encoding: application/x-www-form-urlencoded generated by requests -->
<!-- expected-result: exactly two failed attempts are logged and the fixture's per-account plus aggregate controls are observable without reaching lockout -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Bounded spray simulation with fixture-owned accounts only
lab_password = 'Synthetic-Wrong-Password'
usernames = ['fixture-a', 'fixture-b']

for username in usernames:
    try_login((username, lab_password))
```

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: no rate limiting, no lockout
@app.route('/login', methods=['POST'])
def login_unsafe():
    user = User.query.filter_by(username=request.form['username']).first()
    if user and check_password(user, request.form['password']):
        return login_user(user)
    # Attacker can try unlimited times
    return "Invalid credentials", 401
```

```python
# SECURE: rate limiting + progressive lockout + breach detection
from flask_limiter import Limiter
import hashlib, requests as req

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # IP-based rate limit
def login_safe():
    username = request.form['username']
    password = request.form['password']

    # Check if account is temporarily locked
    lockout = get_lockout_status(username)
    if lockout and lockout.locked_until > datetime.utcnow():
        remaining = (lockout.locked_until - datetime.utcnow()).seconds
        return jsonify({"error": f"Account locked. Retry in {remaining}s"}), 429

    user = User.query.filter_by(username=username.lower().strip()).first()
    if user and check_password(user, password):
        clear_failed_attempts(username)
        return login_user(user)

    # Progressive lockout: 3→1min, 6→5min, 10→30min
    failures = increment_failed_attempts(username)
    if failures >= 10:
        lock_account(username, minutes=30)
    elif failures >= 6:
        lock_account(username, minutes=5)
    elif failures >= 3:
        lock_account(username, minutes=1)

    return jsonify({"error": "Invalid credentials"}), 401
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Kết hợp MFA, breached-password prevention, normalized account/aggregate controls và detection.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Chống Credential Stuffing bằng cách triển khai rate limiting, cơ chế khóa tài khoản tạm thời (progressive lockout), CAPTCHA và phát hiện mật khẩu bị rò rỉ.
- **Các bước chi tiết**:
  - **Rate limiting**: Giới hạn 5-10 lần thử mỗi IP mỗi phút, sử dụng token bucket hoặc sliding window algorithm.
  - **Account lockout**: Khóa tạm thời tài khoản sau N lần thất bại (progressive delay: 1 phút → 5 phút → 30 phút).
  - **CAPTCHA**: Yêu cầu CAPTCHA sau 3 lần thất bại liên tiếp.
  - **Breach password detection**: Kiểm tra mật khẩu mới đối chiếu với database breach đã biết (HaveIBeenPwned API).
  - **MFA enforcement**: Bật 2FA giúp credential stuffing trở nên vô hiệu ngay cả khi mật khẩu đúng.

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

- **Brute Force (Tấn công vét cạn)**: Phương pháp thử tất cả các chuỗi mật khẩu có thể có cho đến khi tìm được mật khẩu đúng, thường được thực hiện tự động bằng phần mềm.
- **Credential Stuffing (Nhồi thông tin đăng nhập)**: Kiểu tấn công tự động sử dụng danh sách các cặp tài khoản và mật khẩu bị rò rỉ từ một trang web khác để thử đăng nhập vào trang web mục tiêu.
- **Password Spraying (Rải mật khẩu)**: Kỹ thuật thử nghiệm một số ít mật khẩu rất phổ biến (như `123456`, `Password123`) trên một danh sách dài các tài khoản người dùng khác nhau để tránh bị khóa tài khoản.
- **Rate Limiting (Giới hạn lưu lượng)**: Cơ chế kiểm soát và giới hạn số lượng yêu cầu (requests) mà một địa chỉ IP hoặc tài khoản được phép gửi tới máy chủ trong một khoảng thời gian nhất định.
- **Account Lockout (Khóa tài khoản)**: Cơ chế bảo mật tự động khóa tạm thời hoặc vĩnh viễn tài khoản người dùng sau khi phát hiện một số lần cố gắng đăng nhập sai liên tiếp.
- **Data Breach (Rò rỉ dữ liệu)**: Sự cố an ninh mạng mà trong đó thông tin nhạy cảm, bí mật hoặc được bảo vệ bị truy cập, xem hoặc sao chép bởi một cá nhân hoặc tổ chức không có thẩm quyền.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/authentication/password-based — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Credential_stuffing — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/307.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
