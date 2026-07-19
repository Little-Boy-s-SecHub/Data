---
schema_version: 1
id: WEB-A07-OAUTH-VULNERABILITIES
title: "OAuth 2.0 Vulnerabilities"
slug: oauth-vulnerabilities
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
  - A07:2025
cwe:
  - CWE-601
  - CWE-287
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# OAuth 2.0 Vulnerabilities

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích OAuth 2.0 Vulnerabilities bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống OAuth 2.0 Vulnerabilities và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đến ở tại một khách sạn sang trọng. Thay vì giao cho bạn chìa khóa vạn năng của cả tòa nhà, khách sạn cấp cho bạn một chiếc thẻ từ phòng (Access Token). Chiếc thẻ này chỉ cho phép bạn mở cửa phòng của mình và phòng tập gym trong thời gian bạn lưu trú. Bạn không cần biết mật khẩu mở cửa của ban quản lý khách sạn để vào phòng. Giao thức cấp quyền này tương tự như cách hoạt động của **OAuth 2.0**.

OAuth 2.0 là một khung ủy quyền tiêu chuẩn, cho phép các ứng dụng bên thứ ba (như một trang web chơi game) truy cập vào một số thông tin giới hạn của bạn (như danh sách bạn bè hoặc địa chỉ email) trên một ứng dụng khác (như Google hay Facebook) mà bạn không cần phải tiết lộ mật khẩu đăng nhập Google/Facebook cho trang web chơi game đó.

Các thành phần tham gia bao gồm:
- **Resource Owner**: Chính là bạn, chủ sở hữu tài khoản.
- **Client**: Ứng dụng muốn xin quyền truy cập (như trang web chơi game).
- **Authorization Server**: Máy chủ cấp quyền (như Google, Facebook), nơi xác thực bạn và cấp thẻ từ.
- **Resource Server**: Máy chủ chứa dữ liệu thực tế (như API chứa email, ảnh của bạn).

Quy trình lấy mã ủy quyền thông thường:

```
1. User clicks "Login with Google"
2. Browser redirects to: https://oauth.provider.lab.test/authorize?
     response_type=code&
     client_id=APP_ID&
     redirect_uri=https://myapp.lab.test/callback&
     scope=profile email&
     state=random_csrf_token

3. User approves → Google redirects to:
     https://myapp.lab.test/callback?code=AUTH_CODE&state=random_csrf_token

4. Server exchanges code for access_token (server-to-server)
5. Server uses access_token to fetch user profile
```

```python
# Normal OAuth callback handler
@app.route('/callback')
def oauth_callback():
    # Verify state parameter to prevent CSRF
    if request.args.get('state') != session.get('oauth_state'):
        return "CSRF detected", 403

    code = request.args.get('code')

    # Exchange authorization code for access token (server-side)
    token_response = requests.post('https://oauth.provider.lab.test/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    })

    access_token = token_response.json()['access_token']
    user_info = fetch_user_profile(access_token)
    return login_user(user_info)
```

OAuth hoạt động đúng khi mọi tham số được validate chặt chẽ, nhưng cấu hình sai bất kỳ thành phần nào cũng tạo ra lỗ hổng nghiêm trọng.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng OAuth 2.0 (OAuth 2.0 Vulnerabilities) xảy ra khi quá trình thiết lập và trao đổi các tham số xác thực giữa các bên bị cấu hình sai hoặc lỏng lẻo.

Mối nguy hiểm của lỗ hổng này là cực kỳ nghiêm trọng: kẻ tấn công có thể lén lút sửa đổi địa chỉ nhận thẻ từ (redirect URI) để lừa máy chủ gửi mã xác thực (authorization code) về máy của chúng. Chúng cũng có thể lợi dụng việc thiếu tham số chống giả mạo (`state`) để ép tài khoản của bạn liên kết với tài khoản mạng xã hội của chúng, hoặc đánh cắp token của bạn thông qua các lỗi chuyển hướng trang web (Open Redirect). Một khi sở hữu được Access Token hay Refresh Token của bạn, kẻ tấn công có thể truy cập trái phép dữ liệu cá nhân của bạn vô thời hạn mà không cần biết mật khẩu.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** authorization code/token và account-link state.
- **Actor, xác thực và role:** client/origin untrusted khởi tạo flow; nạn nhân user xác thực tại mock provider.
- **Điều kiện khai thác:** redirect, state, PKCE hoặc code lifecycle không bind exact client session.
- **Browser, proxy, framework và phiên bản:** provider/client được pin trên .lab.test với Chromium, callback loopback và PKCE S256; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với oauth vulnerabilities, redirect, state, PKCE hoặc code lifecycle không bind exact client session. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy provider/client được pin trên .lab.test với Chromium, callback loopback và PKCE S256; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case oauth vulnerabilities; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “redirect, state, PKCE hoặc code lifecycle không bind exact client session”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của oauth vulnerabilities; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**1. Redirect URI Manipulation — đánh cắp authorization code:**
Nếu Authorization Server cho phép so khớp tương đối hoặc wildcard đối với `redirect_uri`, attacker có thể trỏ redirect về server của chúng để lấy trộm mã code.

<!-- payload-id: WEB-A07-OAUTH-VULNERABILITIES-001 -->
<!-- context: OAuth authorization request sent only to the mock provider at oauth.provider.lab.test -->
<!-- prerequisites: provider and redirect origins resolve to local fixtures; synthetic client APP_ID; one request; no outbound network -->
<!-- encoding: redirect_uri is shown decoded for readability and must be percent-encoded once by the test client -->
<!-- expected-result: intentionally vulnerable provider accepts the unregistered redirect; fixed provider rejects it before issuing a code -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
https://oauth.provider.lab.test/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://untrusted.lab.test/oauth-callback&scope=profile
```

**2. Missing State Parameter — CSRF to link attacker's account:**
Nếu không sử dụng tham số `state` để chống CSRF, attacker có thể lừa nạn nhân nhấn vào liên kết OAuth chứa mã code của attacker, liên kết tài khoản nạn nhân với thông tin mạng xã hội của attacker.

**3. Implicit Flow Token Leakage:**
Implicit flow trả access token trong URL fragment. Fragment không được gửi trong HTTP request hoặc `Referer`; rủi ro chính là token bị code chạy trong trang redirect, extension, log phía client hoặc cơ chế lưu/history của user agent truy cập. Với ứng dụng mới, ưu tiên Authorization Code + PKCE và tránh token trong front-channel. [S3]

**4. Token Theft via Open Redirect Chain:**
Ngay cả khi server cấu hình `redirect_uri` chính xác cho fixture (ví dụ: `https://myapp.lab.test/callback`), một open redirect sau callback có thể chuyển trình duyệt sang origin không tin cậy. Việc authorization code hoặc token có thực sự bị lộ còn phụ thuộc response mode, vị trí dữ liệu, Referrer-Policy và code phía callback; phải quan sát trong browser harness, không suy từ redirect đơn lẻ.
<!-- payload-id: WEB-A07-OAUTH-VULNERABILITIES-002 -->
<!-- context: OAuth authorization-code flow using local .lab.test provider, client callback and untrusted redirect fixtures -->
<!-- prerequisites: synthetic client and one-time code; all .lab.test names map to loopback; outbound network disabled; one authorization attempt -->
<!-- encoding: nested redirect_uri and next values must each be percent-encoded by their owning request layer -->
<!-- expected-result: vulnerable client redirects to untrusted.lab.test after callback; fixed client rejects next; logs confirm whether any code-bearing request reached the untrusted fixture -->
<!-- risk: oob -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
https://oauth.provider.lab.test/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://myapp.lab.test/callback?next=https://untrusted.lab.test/collect
```

**5. Scope Escalation (Leo thang phạm vi):**
Attacker chặn yêu cầu authorization và thay đổi tham số `scope` (ví dụ từ `scope=read` thành `scope=read+write+admin`). Nếu Authorization Server không hiển thị rõ ràng những quyền nâng cao này cho người dùng duyệt, hoặc Client Application mặc nhiên tin tưởng scope của token mà không xác thực lại, attacker sẽ có quyền truy cập trái phép.

**6. Authorization Code Replay:**
Mã Authorization Code chỉ được phép sử dụng một lần để đổi lấy Access Token. Nếu Authorization Server bị lỗi logic không thu hồi code sau khi sử dụng, attacker có thể chặn và dùng lại code đó để sinh ra Access Token mới.

**7. Refresh Token Abuse:**
Refresh Token thường có thời gian sống rất dài. Nếu hệ thống không áp dụng cơ chế quay vòng (Refresh Token Rotation - RTR) và attacker đánh cắp được Refresh Token, chúng có thể tạo mới các Access Token vô thời hạn để chiếm quyền kiểm soát tài khoản mà không cần tương tác với user.

### PKCE Bypass (OAuth 2.1)
PKCE (Proof Key for Code Exchange) yêu cầu client gửi `code_challenge` (SHA-256 hash của `code_verifier`) cùng request. Một số implementation lỗi:
- Chấp nhận `code_challenge_method=plain` thay vì `S256` (attacker có thể intercept verifier)
- Không kiểm tra `code_challenge` nếu không có trong request (optional mismatch)
- `state` parameter bị bypass khi server chấp nhận bất kỳ giá trị nào

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE ===
# 1. Vulnerable to Open Redirect Chain
@app.route('/callback')
def oauth_callback_unsafe():
    code = request.args.get('code')
    # Unvalidated 'next' parameter causes an open redirect; whether data leaks
    # must be established from the browser/network trace, not assumed.
    next_url = request.args.get('next', '/dashboard')

    token = exchange_code(code)
    session['token'] = token
    return redirect(next_url)

# 2. Vulnerable to Scope Escalation (trusts token scopes blindly without server-side check)
@app.route('/api/admin/settings')
def admin_settings_unsafe():
    # Dangerous: client application trusts the scope claim inside the JWT without validating
    # with the Resource Server's access control policy
    token = request.headers.get('Authorization').split(" ")[1]
    payload = jwt.decode(token, verify=False)
    if 'admin' in payload.get('scope', ''):
        return get_admin_settings()
    return "Unauthorized", 403
```

```python
# === SECURE CODE ===
# 1. Secure Redirect and Single-use Code Verification
@app.route('/callback')
def oauth_callback_safe():
    # Verify state to prevent CSRF
    if request.args.get('state') != session.pop('oauth_state', None):
        return "CSRF detected", 403

    code = request.args.get('code')

    # Exchange code (Authorization Server enforces single-use and exact redirect_uri match)
    token_response = requests.post('https://oauth.provider.lab.test/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': FIXED_REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    })

    if token_response.status_code != 200:
        return "Failed to exchange code", 400

    # Safe redirect to a hardcoded dashboard or validated local path only
    return redirect('/dashboard')

# 2. Refresh Token Rotation (RTR) logic
def rotate_refresh_token(user_id, client_refresh_token):
    stored_token = db.get_refresh_token(user_id)

    # If the presented refresh token has already been used, trigger compromise detection
    if stored_token.is_used and stored_token.token_value == client_refresh_token:
        db.revoke_all_sessions(user_id) # Revoke all active tokens for the user
        raise SecurityException("Replay of refresh token detected! Revoking all sessions.")

    # Generate new access token and new refresh token (Rotation)
    new_access_token = generate_access_token(user_id)
    new_refresh_token = generate_new_refresh_token(user_id)

    # Mark old token as used and store new one
    db.mark_token_used(client_refresh_token)
    db.save_refresh_token(user_id, new_refresh_token)

    return new_access_token, new_refresh_token
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến OAuth 2.0 Vulnerabilities, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Exact redirect matching, state gắn session, PKCE S256, code single-use và token rotation.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với OAuth 2.0 Vulnerabilities, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Bảo mật quy trình OAuth bằng cách kiểm tra trùng khớp tuyệt đối redirect URI, bắt buộc sử dụng tham số state ngẫu nhiên, và áp dụng luồng Authorization Code + PKCE.
- **Các bước chi tiết**:
  - **Strict redirect URI validation**: So sánh exact match (không dùng wildcard hay partial match) cho `redirect_uri`.
  - **Always use `state` parameter**: Tạo giá trị ngẫu nhiên, lưu trong session, và xác minh khi nhận callback.
  - **Use Authorization Code + PKCE**: Thay thế implicit flow bằng Authorization Code flow kết hợp PKCE cho mọi loại client.
  - **Fix Open Redirects**: Đảm bảo các endpoint callback không chuyển hướng tự do dựa trên input từ client.
  - **Scope Whitelisting & Validation**: Máy chủ tài nguyên phải luôn kiểm tra scope gắn liền với access token cho mỗi yêu cầu API.
  - **Single-use Authorization Code**: Đảm bảo mã code tự động bị hủy ngay sau khi trao đổi lần đầu tiên.
  - **Refresh Token Rotation (RTR)**: Mỗi khi sử dụng Refresh Token để lấy Access Token mới, Refresh Token cũ phải bị vô hiệu hóa và trả về một Refresh Token mới. Nếu Refresh Token cũ được sử dụng lại, vô hiệu hóa toàn bộ phiên làm việc của user đó ngay lập tức.

## 12. Retest

- **Positive case:** với OAuth 2.0 Vulnerabilities, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của OAuth 2.0 Vulnerabilities mà không xác nhận side effect và log.
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

- **OAuth 2.0**: Giao thức ủy quyền tiêu chuẩn giúp các ứng dụng chia sẻ tài nguyên với nhau một cách an toàn mà không cần chia sẻ thông tin đăng nhập trực tiếp (như mật khẩu).
- **Access Token**: Chuỗi mã ngắn hạn đại diện cho quyền truy cập được cấp cho ứng dụng để gọi API và lấy dữ liệu của người dùng.
- **Refresh Token**: Chuỗi mã dài hạn dùng để yêu cầu máy chủ cấp một Access Token mới sau khi Access Token cũ đã hết hạn mà không bắt người dùng đăng nhập lại từ đầu.
- **Redirect URI**: Địa chỉ URL mà máy chủ ủy quyền sẽ gửi trình duyệt của người dùng quay trở lại kèm theo mã code xác thực sau khi người dùng đồng ý cấp quyền.
- **PKCE (Proof Key for Code Exchange)**: Bản mở rộng bảo mật cho OAuth 2.0, sử dụng một chuỗi mật mã ngẫu nhiên để xác minh rằng ứng dụng yêu cầu token chính là ứng dụng đã yêu cầu mã code ban đầu.
- **Open Redirect (Chuyển hướng mở)**: Lỗ hổng bảo mật xảy ra khi trang web tự động chuyển hướng người dùng đến một địa chỉ URL khác do người dùng tự nhập mà không thực hiện kiểm tra độ an toàn của địa chỉ đó.

## 16. Bài liên quan và đọc thêm

- [Session Fixation](../session-fixation/README.md)

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/oauth — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/601.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** CWE-287. https://cwe.mitre.org/data/definitions/287.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
