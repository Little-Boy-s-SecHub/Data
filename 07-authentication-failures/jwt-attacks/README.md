# JWT Attacks

> **CWE**: CWE-345, CWE-347, CWE-20 | **Phân loại**: Authentication

## Kiến thức Nền tảng
Hãy tưởng tượng JWT (JSON Web Token) giống như một tấm thẻ căn cước công dân kỹ thuật số được ép nhựa cứng. Tấm thẻ này gồm ba phần riêng biệt ghép lại:
1. **Header (Ảnh chân dung và quốc huy)**: Nơi ghi rõ tấm thẻ này sử dụng công nghệ bảo mật nào để ký xác nhận (thuật toán mã hóa).
2. **Payload (Thông tin cá nhân)**: Nơi ghi họ tên, chức vụ, ngày cấp và ngày hết hạn của bạn (dữ liệu truyền tải).
3. **Signature (Con dấu đỏ của cơ quan công an)**: Chữ ký số mã hóa để đảm bảo thông tin trên thẻ không bị cạo sửa.

Để tạo ra con dấu đỏ này, cơ quan cấp thẻ có hai cách chọn công nghệ ký:
- **Ký đối xứng (HS256)**: Dùng chung một chiếc con dấu bí mật (Secret Key) để vừa đóng dấu lúc cấp thẻ, vừa dùng chính chiếc dấu đó để đối chiếu lúc kiểm tra.
- **Ký bất đối xứng (RS256)**: Dùng một chiếc chìa khóa riêng mật (Private Key) được cất kỹ ở trụ sở để đóng dấu, và phát hành rộng rãi một chiếc kính lúp công khai (Public Key) cho tất cả các chốt an ninh tự đối chiếu chữ ký.

Hệ thống sẽ hoàn toàn tin tưởng bạn là Admin nếu bạn xuất trình một tấm thẻ có ghi chữ "Role: Admin" và đi kèm một con dấu đỏ hợp lệ. Sự nguy hiểm bắt đầu khi chốt an ninh kiểm tra thẻ bị lơ là, hoặc người làm thẻ cẩu thả, tạo điều kiện cho kẻ xấu tự đóng dấu giả hoặc cạo sửa thông tin trên thẻ.

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

## Mô tả lỗ hổng
Lỗ hổng Tấn công JWT (JWT Attacks) xảy ra khi quá trình xác minh chữ ký số của token trên máy chủ bị cấu hình sai hoặc thiếu chặt chẽ. 

Mối nguy hiểm của lỗ hổng này rất lớn: kẻ tấn công có thể tự tạo ra một tấm thẻ căn cước giả bằng cách đổi thuật toán ký thành `none` (yêu cầu máy chủ không cần kiểm tra con dấu), tự dùng khóa công khai để ký giả mạo thẻ (lợi dụng sự nhầm lẫn thuật toán HS256/RS256), hoặc lừa máy chủ đi lấy con dấu xác thực từ một địa chỉ web độc hại do chúng kiểm soát (JWK/JKU injection). Khi máy chủ tin tưởng tấm thẻ giả mạo này, kẻ tấn công có thể giả danh bất kỳ người dùng nào hoặc tự nâng quyền của mình lên Admin để kiểm soát hệ thống.

## Cơ chế tấn công
**1. Algorithm "none" Attack — bỏ hoàn toàn chữ ký:**
Attacker thay đổi trường `alg` trong header thành `none` và xóa bỏ chữ ký để qua mặt cơ chế kiểm tra.

```python
# Craft a JWT with algorithm set to "none"
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({"sub": "1", "username": "admin", "role": "admin"}).encode()).decode().rstrip('=')
forged_token = f"{header}.{payload}."
# If server accepts alg:none, attacker is now admin
```

**2. HS256/RS256 Confusion — dùng public key làm HMAC secret:**
Attacker ký token bằng public key RSA (vốn công khai) bằng thuật toán đối xứng HS256, lừa server coi public key này là secret key HMAC.

```python
import jwt
public_key = open('public_key.pem').read()
# Sign with public key using HS256 (instead of RS256)
forged = jwt.encode({"sub": "1", "role": "admin"}, public_key, algorithm="HS256")
```

**3. Weak Secret Brute Force:**
Sử dụng công cụ để dò tìm khóa bí mật HS256 nếu nó quá ngắn hoặc dễ đoán.

```bash
hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
```

**4. JWK Header Injection:**
Attacker nhúng trực tiếp public key của mình vào tham số `jwk` trong JWT header và ký token bằng private key tương ứng. Nếu máy chủ tin cậy key này mà không đối chiếu với danh sách đáng tin cậy, nó sẽ dùng chính public key do attacker gửi để xác minh chữ ký.

**5. JKU Header Injection:**
Attacker tạo một file JWKS chứa public key của mình, tải lên một server độc lập và chèn đường dẫn URL đó vào tham số `jku` trong JWT header. Server mục tiêu sẽ gửi request lấy JWK từ URL của attacker để verify chữ ký.

**6. kid Parameter Injection:**
Tham số `kid` (Key ID) dùng để chỉ định khóa nào cần sử dụng.
- **Path Traversal**: Nếu server tìm khóa từ file trên disk (`/keys/key_id`), attacker inject `kid: "../../../dev/null"` để ép server dùng tệp trống (key = rỗng) để ký hoặc verify.
- **SQL Injection**: Nếu server truy vấn khóa từ database bằng `kid` nối chuỗi trực tiếp, attacker chèn payload SQL để ép database trả về một khóa tự định nghĩa (ví dụ: `' UNION SELECT 'my_secret'--`).

**7. Token Replay:**
Kẻ tấn công đánh cắp token hợp lệ và gửi lại (replay) nhiều lần để truy cập tài nguyên trái phép do token thiếu cơ chế khóa một lần (như `jti` - JWT ID) hoặc thời gian sống quá dài.

## Biện pháp phòng thủ
- **Tóm tắt**: Bảo vệ JWT bằng cách chỉ định thuật toán verify cố định, cấm thuật toán "none", sử dụng khóa bí mật mạnh, validate tham số kid và jti chống replay.
- **Các bước chi tiết**:
  - **Whitelist algorithms**: Luôn chỉ định danh sách thuật toán được chấp nhận khi verify, **không bao giờ** để server tự chọn từ header.
  - **Strong secrets**: Sử dụng secret key tối thiểu 256-bit ngẫu nhiên cho HS256, hoặc RSA key ≥ 2048-bit cho RS256.
  - **Reject "none" algorithm**: Đảm bảo library JWT không chấp nhận `alg: none`.
  - **JWK/JKU Validation**: Chỉ cho phép nạp JWK từ các domain được whitelist nghiêm ngặt, hoặc cấm hoàn toàn việc nạp key từ client-side.
  - **Sanitize `kid`**: Validate `kid` không chứa ký tự lạ (như `/`, `\`, `'`, `"`) hoặc dùng SQL parameterized queries.
  - **Token Replay Defense**: Sử dụng claim `jti` duy nhất và lưu trạng thái token đã sử dụng trong cache (Redis), đồng thời set thời gian sống của token ngắn.

## Code Example
```javascript
// === VULNERABLE CODE ===
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// 1. Vulnerable to JWK/JKU Header Injection
function verifyJkuUnsafe(token) {
    const decoded = jwt.decode(token, { complete: true });
    // DANGER: Fetching key from external JKU URL provided by user
    if (decoded.header.jku) {
        const jwks = fetchExternalKey(decoded.header.jku); // Simulated external fetch
        const key = jwks.find(k => k.kid === decoded.header.kid);
        return jwt.verify(token, key);
    }
    return null;
}

// 2. Vulnerable to Path Traversal via kid
function verifyKidPathUnsafe(token) {
    const decoded = jwt.decode(token, { complete: true });
    // DANGER: Direct file path construction using unsanitized kid
    const keyPath = path.join(__dirname, 'keys', decoded.header.kid);
    const key = fs.readFileSync(keyPath); 
    return jwt.verify(token, key);
}
```

```javascript
// === SECURE CODE ===
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
    // SECURE: Hardcoded trusted JWKS URI
    jwksUri: 'https://trusted-identity-provider.com/.well-known/jwks.json'
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, function(err, key) {
        if (err) return callback(err);
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

function verifyTokenSafe(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKey, {
            // SECURE: Whitelist only RS256, reject none/HS256
            algorithms: ['RS256'],
            issuer: 'https://trusted-identity-provider.com',
            audience: 'my-secure-app'
        }, (err, decoded) => {
            if (err) return reject(err);
            
            // SECURE: Check jti against Redis to prevent Replay Attack
            const isReplayed = checkTokenIdInRedis(decoded.jti); 
            if (isReplayed) return reject(new Error('Token replayed'));
            
            resolve(decoded);
        });
    });
}
```

## Xem thêm
- [Weak Session IDs](../weak-session-ids/README.md)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/jwt
- Auth0: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- CWE: https://cwe.mitre.org/data/definitions/345.html

## Giải thích thuật ngữ
- **JWT (JSON Web Token)**: Định dạng mã nguồn mở giúp truyền tải thông tin an toàn giữa các bên dưới dạng một đối tượng JSON, thường dùng để xác thực và phân quyền người dùng trong ứng dụng web.
- **HS256 (HMAC with SHA-256)**: Thuật toán ký số đối xứng, sử dụng duy nhất một khóa bí mật chung cho cả việc tạo chữ ký và xác minh tính toàn vẹn của token.
- **RS256 (RSA Signature with SHA-256)**: Thuật toán ký số bất đối xứng, sử dụng khóa bí mật (Private Key) để ký số và khóa công khai (Public Key) để kiểm tra chữ ký.
- **JWK (JSON Web Key)**: Cấu trúc dữ liệu JSON dùng để biểu diễn các khóa mật mã công khai được sử dụng trong hệ thống JWT.
- **JKU (JSON Web Key Set URL)**: Tham số trong header của JWT chứa liên kết URL trỏ tới danh sách các khóa công khai hợp lệ để máy chủ tải về phục vụ việc xác minh chữ ký.
- **kid (Key ID)**: Tham số định danh khóa, giúp máy chủ biết chính xác khóa nào trong cơ sở dữ liệu cần dùng để kiểm tra chữ ký của token này.
- **Token Replay (Tấn công gửi lại)**: Hình thức tấn công mà kẻ xấu chặn bắt được một token hợp lệ của nạn nhân rồi gửi lại yêu cầu đó lên máy chủ để giả mạo phiên làm việc của nạn nhân.
