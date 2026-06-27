# OAuth 2.0 Vulnerabilities

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-601 | **Nguồn**: PortSwigger, OWASP, RFC 6749

## 🧱 Kiến thức Nền tảng

OAuth 2.0 là giao thức ủy quyền (authorization framework) cho phép ứng dụng bên thứ ba truy cập tài nguyên của user mà không cần biết mật khẩu. Các bên tham gia: **Resource Owner** (user), **Client** (ứng dụng), **Authorization Server** (Google, Facebook), và **Resource Server** (API chứa dữ liệu).

Luồng Authorization Code Grant (phổ biến nhất):

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

## 🔍 Mô tả lỗ hổng

Các lỗ hổng OAuth phổ biến: redirect URI không được validate chặt cho phép attacker đánh cắp authorization code, thiếu `state` parameter dẫn đến CSRF, implicit flow để lộ token trong URL fragment, và bypass PKCE trong mobile app cho phép code interception.

## ⚔️ Cơ chế tấn công

**1. Redirect URI Manipulation — đánh cắp authorization code:**

```
// If server allows partial redirect_uri matching:
// Legitimate: https://myapp.com/callback
// Attacker crafts:
https://oauth.provider.com/authorize?
  response_type=code&
  client_id=APP_ID&
  redirect_uri=https://myapp.com.evil.com/steal&
  scope=profile email

// Or using open redirect on legitimate domain:
  redirect_uri=https://myapp.com/redirect?url=https://evil.com/steal

// Authorization code is sent to attacker's server
```

**2. Missing State Parameter — CSRF to link attacker's account:**

```python
# Attacker generates an OAuth link with THEIR authorization code
# and tricks victim into clicking it
malicious_link = (
    "https://myapp.com/callback"
    "?code=ATTACKER_AUTH_CODE"
    # No state parameter — server can't detect CSRF
)
# Victim's account is now linked to attacker's social profile
# Attacker can now "Login with Google" into victim's account
```

**3. Implicit Flow Token Leakage:**

```
// Implicit flow returns token in URL fragment
https://myapp.com/callback#access_token=eyJhbG...&token_type=bearer

// Token is exposed in browser history, Referer headers, and
// can be stolen by malicious JavaScript on the page
```

## 🛡️ Biện pháp phòng thủ

1. **Strict redirect URI validation**: So sánh exact match (không dùng wildcard hay partial match) cho `redirect_uri`.
2. **Always use `state` parameter**: Tạo giá trị ngẫu nhiên, lưu trong session, và xác minh khi nhận callback.
3. **Use Authorization Code + PKCE**: Thay thế implicit flow bằng Authorization Code flow kết hợp PKCE cho mọi loại client.
4. **Short-lived authorization codes**: Code chỉ sử dụng được một lần và hết hạn trong 60 giây.

## 💻 Code Example

```python
# VULNERABLE: loose redirect_uri validation, no state check
@app.route('/callback')
def oauth_callback_unsafe():
    code = request.args.get('code')
    # No state verification — CSRF possible
    # No redirect_uri validation on provider side
    token = exchange_code(code, redirect_uri=request.args.get('redirect_uri'))
    return login_user(token)
```

```python
# SECURE: strict validation with PKCE support
import secrets, hashlib, base64

@app.route('/login/oauth')
def oauth_start():
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    
    session['oauth_state'] = state
    session['code_verifier'] = code_verifier
    
    # Fixed redirect_uri, state for CSRF, PKCE for code protection
    return redirect(
        f"https://oauth.provider.com/authorize?"
        f"response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri={FIXED_REDIRECT_URI}"
        f"&state={state}&code_challenge={code_challenge}"
        f"&code_challenge_method=S256&scope=profile email"
    )

@app.route('/callback')
def oauth_callback_safe():
    if request.args.get('state') != session.pop('oauth_state', None):
        return "CSRF detected", 403
    
    code = request.args.get('code')
    code_verifier = session.pop('code_verifier')
    token = exchange_code(code, FIXED_REDIRECT_URI, code_verifier)
    return login_user(token)
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/oauth
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses
- CWE: https://cwe.mitre.org/data/definitions/601.html
