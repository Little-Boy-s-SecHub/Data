# 2FA/MFA Bypass

> **CWE**: CWE-308, CWE-287 | **Phân loại**: Authentication

## Kiến thức Nền tảng
Hãy tưởng tượng việc bảo vệ tài khoản của bạn giống như việc đi qua một cánh cửa an ninh bảo mật cao. Thay vì chỉ sử dụng một chiếc khóa thông thường (mật khẩu) mà kẻ xấu có thể nhìn trộm được, bạn lắp đặt thêm một hệ thống xác thực hai lớp (2FA) hoặc nhiều lớp (MFA). Cửa an ninh này yêu cầu bạn phải cung cấp đủ ba nhóm bằng chứng khác nhau để chứng minh danh tính:
1. **Thứ bạn biết (Something you know)**: Mật khẩu, mã PIN cá nhân.
2. **Thứ bạn sở hữu (Something you have)**: Điện thoại nhận tin nhắn, khóa bảo mật vật lý (YubiKey), ứng dụng tạo mã OTP.
3. **Thứ đại diện cho chính bạn (Something you are)**: Dấu vân tay, quét võng mạc hoặc nhận diện khuôn mặt.

Quy trình 2FA phổ biến nhất hiện nay là sử dụng mã OTP dùng một lần được gửi qua SMS/Email hoặc tự động sinh ra sau mỗi 30 giây bằng ứng dụng Authenticator (gọi là **TOTP**). Dù trên lý thuyết, lớp bảo vệ thứ hai này cực kỳ vững chắc, nhưng trong thực tế, nếu người thiết kế hệ thống cẩu thả, kẻ tấn công vẫn có thể dễ dàng đi đường vòng để bypass hoàn toàn bước xác thực này.

Quy trình 2FA thông thường:

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

## Mô tả lỗ hổng
Lỗ hổng Bỏ qua xác thực hai yếu tố (2FA/MFA Bypass) xuất hiện khi ứng dụng không thực thi việc kiểm tra lớp xác thực thứ hai một cách nghiêm ngặt trên toàn bộ hệ thống. 

Mối nguy hiểm của lỗ hổng này nằm ở chỗ, kẻ tấn công sau khi biết được mật khẩu của nạn nhân có thể dễ dàng lách qua bước nhập mã OTP bằng nhiều cách: truy cập trực tiếp các đường dẫn bên trong ứng dụng mà không cần đi qua trang nhập mã, sửa đổi phản hồi của máy chủ từ "sai OTP" thành "đúng OTP" trên trình duyệt, thử đi thử lại hàng ngàn mã OTP cho đến khi đúng do hệ thống thiếu giới hạn tần suất nhập (rate limiting), hoặc lừa đảo người dùng qua các trang web giả mạo theo thời gian thực để cướp cookie phiên đăng nhập đã được xác thực sẵn.

## Cơ chế tấn công
**1. Direct Endpoint Access — bỏ qua trang nhập OTP:**
Nếu server chỉ kiểm tra xem người dùng đã nhập đúng mật khẩu chưa mà không kiểm tra cờ `2fa_verified`, attacker chỉ cần đăng nhập bằng pass và truy cập thẳng `/dashboard` qua proxy/HTTP client.

**2. Response Manipulation — sửa response trong proxy:**
Attacker nhập OTP sai, server trả về `401 Unauthorized` hoặc `{"success": false}`. Attacker chặn response bằng Burp Suite và sửa thành `200 OK` hoặc `{"success": true}` để lừa phía client-side chuyển hướng.

**3. OTP Brute Force — thử tất cả tổ hợp:**
Nếu hệ thống không giới hạn số lần nhập mã OTP (rate limit), attacker có thể brute force toàn bộ 1,000,000 tổ hợp của mã 6 chữ số trong vài phút.

**4. Backup Code Abuse:**
Attacker đoán hoặc brute force mã khôi phục tĩnh (backup codes) được tạo sẵn khi thiết lập 2FA, đặc biệt nếu các mã này không bị giới hạn tần suất thử hoặc không bị hủy sau khi dùng.

**5. SIM Swapping & SS7 Interception:**
- **SIM Swapping**: Attacker sử dụng kỹ thuật lừa đảo (social engineering) nhắm vào nhân viên nhà mạng di động để thuyết phục họ chuyển số điện thoại của nạn nhân sang một thẻ SIM mới thuộc quyền kiểm soát của attacker, từ đó nhận toàn bộ tin nhắn SMS chứa mã OTP.
- **SS7 Interception**: Khai thác các lỗ hổng thiết kế trong mạng báo hiệu SS7 của các nhà mạng viễn thông để nghe lén và định tuyến lại tin nhắn SMS chứa mã OTP trên đường truyền mà không cần tương tác vật lý.

**6. Real-time Phishing (Evilginx Proxy Flow):**
Attacker thiết lập một máy chủ reverse proxy trung gian (như Evilginx). Nạn nhân truy cập vào link phishing trông giống thật, nhập mật khẩu và mã OTP. Proxy sẽ chuyển tiếp các thông tin này theo thời gian thực tới máy chủ gốc và nhận lại Session Cookie đã xác thực hoàn toàn của nạn nhân, cho phép attacker vượt qua 2FA bằng session cướp được.

**7. TOTP Time Window Abuse:**
- **Lệch cửa sổ thời gian**: Server chấp nhận các mã OTP được tạo từ quá khứ rất xa hoặc tương lai (ví dụ ± 10 phút thay vì ± 30 giây mặc định) để tránh lỗi lệch giờ thiết bị. Attacker có thể sử dụng lại một mã OTP vừa hết hạn.
- **Không vô hiệu hóa mã đã dùng (No One-Time Enforcement)**: Server chấp nhận mã OTP nhiều lần trong cùng một chu kỳ thời gian (30 giây). Attacker có thể replay mã OTP đã chặn được trước khi chu kỳ 30 giây kết thúc.

**8. Authentication Downgrade (Hạ cấp xác thực):**
Attacker cố tình yêu cầu hạ cấp phương thức xác thực xuống loại yếu nhất. Ví dụ, thay vì dùng Hardware Key (FIDO2) bảo mật cao, attacker yêu cầu reset 2FA bằng câu hỏi bảo mật yếu hoặc gửi OTP qua email/SMS đã bị thỏa hiệp bằng cách lợi dụng các API cũ hoặc API dành riêng cho mobile.

## Biện pháp phòng thủ
- **Tóm tắt**: Bảo mật xác thực hai yếu tố bằng cách bắt buộc kiểm tra trạng thái 2FA trên mọi API endpoint, giới hạn số lần nhập mã (rate limit) và chống tấn công replay.
- **Các bước chi tiết**:
  - **Server-side 2FA enforcement**: Kiểm tra `2fa_verified` flag ở **mọi** protected endpoint, không chỉ ở trang OTP.
  - **Rate limiting**: Giới hạn 3-5 lần thử OTP, sau đó lock tài khoản hoặc yêu cầu đợi 15 phút.
  - **One-Time Use Enforcement**: Lưu lịch sử các mã OTP đã được sử dụng thành công trong chu kỳ hiện tại (ví dụ: dùng Redis cache) và từ chối nếu mã đó được gửi lại.
  - **Tighten TOTP Time Window**: Chỉ chấp nhận lệch tối đa 1 chu kỳ (± 30 giây) và đồng bộ hóa NTP server.
  - **Secure Authentication Flow**: Không cho phép hạ cấp xác thực xuống phương thức kém an toàn hơn mà không qua xác minh nghiêm ngặt.
  - **Move away from SMS**: Khuyến khích user sử dụng Authenticator app hoặc WebAuthn/FIDO2 để loại bỏ nguy cơ SIM Swapping và SS7 Interception.

## Code Example
```python
# === VULNERABLE CODE ===
import time
import pyotp

# 1. Vulnerable to TOTP Time Window Abuse & Replay Attack
def verify_totp_unsafe(user_totp_secret, submitted_code):
    totp = pyotp.TOTP(user_totp_secret)
    # DANGER: Validating with a huge time window of 5 minutes (valid_window=10 means +/- 10 intervals of 30s)
    # DANGER: Does not check if the code was already used within this window
    is_valid = totp.verify(submitted_code, valid_window=10)
    return is_valid

# 2. Vulnerable to Authentication Downgrade
@app.route('/api/mfa/challenge', methods=['POST'])
def mfa_challenge_unsafe():
    user = get_user(request.json['user_id'])
    # DANGER: Allows the client to request a weaker fallback channel (like SMS) 
    # even if they have a hardware key (FIDO2) configured.
    requested_channel = request.json.get('fallback_channel', 'FIDO2')
    
    if requested_channel == 'SMS':
        send_sms_otp(user.phone)
        return {"status": "sms_sent"}
    return {"status": "awaiting_fido2"}
```

```python
# === SECURE CODE ===
import pyotp
from redis import Redis

redis_client = Redis(host='localhost', port=6379, db=0)

# 1. Secure TOTP Verification with Replay Prevention and Strict Window
def verify_totp_secure(user_id, user_totp_secret, submitted_code):
    totp = pyotp.TOTP(user_totp_secret)
    
    # SECURE: Only allow +/- 30 seconds drift (valid_window=1 means current and immediate adjacent)
    # verify_result returns the timestamp index if valid, else None
    verified_time = totp.verify(submitted_code, valid_window=1, for_time=time.time())
    
    if verified_time is None:
        return False
        
    # SECURE: Prevent replay attacks by checking if the code has already been used
    replay_key = f"totp_used:{user_id}:{submitted_code}"
    # Set expiration equal to double the window size (60s)
    if not redis_client.set(replay_key, "1", ex=60, nx=True):
        return False # Code was already used within the valid window
        
    return True

# 2. Prevent Authentication Downgrade
def initiate_mfa_secure(user):
    # SECURE: Enforce MFA based on user's strongest configured method
    if user.has_fido2_configured:
        return {"required_method": "FIDO2", "details": get_fido2_challenge(user)}
    elif user.has_totp_configured:
        return {"required_method": "TOTP"}
    else:
        # Fall back to SMS only if no stronger method is configured
        send_sms_otp(user.phone)
        return {"required_method": "SMS"}
```

## Xem thêm
- [User Enumeration](../user-enumeration/README.md)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/multi-factor
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication
- CWE: https://cwe.mitre.org/data/definitions/308.html

## Giải thích thuật ngữ
- **2FA / MFA (Two-Factor / Multi-Factor Authentication)**: Cơ chế xác thực yêu cầu người dùng cung cấp từ hai yếu tố xác minh độc lập trở lên trước khi cấp quyền truy cập tài khoản.
- **TOTP (Time-based One-Time Password)**: Thuật toán tạo mật khẩu dùng một lần thay đổi liên tục theo thời gian (thường là mỗi 30 giây), đồng bộ giữa thiết bị người dùng và máy chủ.
- **Brute-Force (Tấn công vét cạn)**: Kỹ thuật dò tìm mật khẩu hoặc mã OTP bằng cách tự động thử lần lượt tất cả các tổ hợp ký tự hoặc số có thể xảy ra cho đến khi tìm được kết quả đúng.
- **SIM Swapping**: Hình thức lừa đảo mà tin tặc thuyết phục nhà mạng viễn thông chuyển số điện thoại của nạn nhân sang thẻ SIM mới do chúng kiểm soát, nhằm đánh cắp các mã OTP gửi qua SMS.
- **SS7 Interception**: Kỹ thuật khai thác các lỗ hổng trong mạng báo hiệu viễn thông SS7 để chặn bắt và đọc trộm tin nhắn SMS chứa mã OTP đang được truyền trên đường truyền.
- **Reverse Proxy**: Máy chủ trung gian nhận các yêu cầu từ máy khách và chuyển tiếp chúng đến một hoặc nhiều máy chủ phía sau, thường bị tin tặc dùng làm trung gian để đánh cắp session cookie thời gian thực.
