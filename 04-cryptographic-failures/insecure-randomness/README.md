# Insecure Randomness

> **CWE**: CWE-330 | **Phân loại**: Cryptographic Failures

## Kiến thức Nền tảng
Trong thế giới bảo mật số, tính ngẫu nhiên (randomness) đóng vai trò như chiếc chìa khóa vạn năng. Nó được dùng để tạo ra mã OTP gửi về điện thoại của bạn, mã khôi phục mật khẩu, mã phiên đăng nhập (session ID), hay các khóa mã hóa bảo vệ ví điện tử. Nếu những chiếc chìa khóa này được làm từ một chiếc khuôn dễ đoán, kẻ xấu hoàn toàn có thể tự đúc cho mình chiếc chìa khóa giống hệt để đột nhập vào tài khoản của bạn.

Để tạo ra các số ngẫu nhiên, các máy tính sử dụng hai loại "máy gieo số" chính:
- **PRNG (Bộ sinh số giả ngẫu nhiên)**: Hoạt động như một cỗ máy toán học có quy luật. Nếu bạn biết công thức (thuật toán) và điểm bắt đầu (seed - hạt giống), bạn sẽ luôn nhận được một dãy số hoàn toàn giống nhau. Các hàm phổ biến như `Math.random()` trong JavaScript hay `random()` trong Python là những cỗ máy loại này. Chúng cực kỳ nhanh và phù hợp để làm game hoặc hoạt hình, nhưng đối với bảo mật, chúng là một thảm họa vì kẻ tấn công chỉ cần quan sát vài kết quả đầu ra là có thể tính ngược lại quy luật của cỗ máy.
- **CSPRNG (Bộ sinh số giả ngẫu nhiên an toàn về mặt mật mã)**: Trái ngược với cỗ máy toán học trên, CSPRNG giống như việc bạn tung đồng xu trong một cơn bão dữ dội. Nó thu thập các yếu tố nhiễu loạn ngẫu nhiên thực tế từ môi trường xung quanh (như nhiệt độ CPU, chuyển động chuột, thời điểm ổ cứng ghi dữ liệu) để tạo ra các số hoàn toàn không thể dự đoán được. Các hàm như `crypto.randomBytes()` trong Node.js hay thư viện `secrets` trong Python chính là những chiếc khiên vững chắc này.

```javascript
// Normal operation: generating a random number in JavaScript
// Math.random() uses xorshift128+ algorithm internally
const value = Math.random();  // Returns float between 0 and 1
console.log(value);           // e.g., 0.7281943042158021

// The internal state can be reconstructed from ~5 outputs
// This is FINE for non-security purposes (games, UI animations)
```

Điểm mấu chốt ở đây là: các thuật toán PRNG thông thường hoạt động trên một trạng thái (state) hữu hạn. Khi kẻ tấn công thu thập đủ số lượng mẫu đầu ra, họ có thể dùng toán học để khôi phục trạng thái này và đọc trước được tương lai.

## Mô tả lỗ hổng
Lỗ hổng "Tính ngẫu nhiên không an toàn" (Insecure Randomness) xuất hiện khi lập trình viên vô tình sử dụng các bộ sinh số ngẫu nhiên thông thường (PRNG) cho các mục đích bảo mật. 

Hãy tưởng tượng bạn yêu cầu đặt lại mật khẩu và hệ thống gửi cho bạn một liên kết chứa mã khôi phục ngẫu nhiên được sinh ra từ `Math.random()`. Kẻ tấn công, bằng cách tự yêu cầu khôi phục mật khẩu cho tài khoản của chính chúng vài lần, sẽ thu thập được các mã ngẫu nhiên liên tiếp. Từ đó, chúng tính toán được mã khôi phục mật khẩu tiếp theo dành cho tài khoản của bạn và chiếm quyền điều khiển tài khoản trước khi bạn kịp nhận ra. 

Hay nguy hiểm hơn, các mã OTP chỉ có 6 chữ số nếu được sinh ra một cách dễ đoán sẽ nhanh chóng bị bẻ gãy, khiến lớp bảo mật hai yếu tố (2FA) trở nên vô dụng. Tương tự, session ID hay các khóa mã hóa được sinh một cách hời hợt cũng là chiếc vé thông hành miễn phí mời gọi tin tặc vào nhà.

## Cơ chế tấn công
### 1. Dự đoán Math.random() trong V8 (Chrome/Node.js)

V8 engine sử dụng thuật toán **xorshift128+** cho `Math.random()`. Chỉ cần biết **3-5 output liên tiếp**, attacker có thể khôi phục internal state bằng Z3 SMT solver:

```python
# Using z3-solver to crack xorshift128+ state
from z3 import *

# Attacker collects sequential Math.random() outputs from the target
observed = [0.7281943042, 0.1538294017, 0.9824571036, 0.4019283746, 0.6293847102]

# Convert float outputs back to 64-bit state values
def float_to_state(f):
    return int(f * (2**52)) | 0x3FF0000000000000

# Set up Z3 constraints to solve for internal state
state0, state1 = BitVecs('state0 state1', 64)
solver = Solver()

# Add constraints based on xorshift128+ algorithm
# Once solved, attacker can predict ALL future outputs
```

### 2. Predictable Seed Attack

```java
// Attacker knows the server restarted at a specific time
// java.util.Random seeded with System.currentTimeMillis()
long estimatedSeed = 1719489337000L;  // Approximate restart timestamp

// Try seeds within a small window (±5 seconds)
for (long seed = estimatedSeed - 5000; seed <= estimatedSeed + 5000; seed++) {
    Random rng = new Random(seed);
    String token = generateToken(rng);  // Reproduce the token generation
    if (tryPasswordReset(token)) {
        System.out.println("Account hijacked with seed: " + seed);
        break;
    }
}
```

### 3. Sequential/Time-based Token Prediction

```python
# Vulnerable app generates tokens based on timestamp
import time
import hashlib

# Attacker observes their own reset token and timestamp
my_token = "a3f2b8c1..."
my_timestamp = 1719489337

# Predict victim's token generated seconds later
for offset in range(0, 60):
    predicted = hashlib.md5(str(my_timestamp + offset).encode()).hexdigest()
    if try_reset(victim_email, predicted):
        print(f"Success! Token predicted with offset={offset}")
        break
```

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống lỗi sử dụng giá trị ngẫu nhiên không an toàn bằng cách sử dụng bộ tạo số ngẫu nhiên an toàn về mặt mật mã (CSPRNG), tránh sử dụng seed dựa trên thời gian, đảm bảo đủ entropy và giới hạn tần suất yêu cầu.
- **Các bước chi tiết**:
  - **Luôn sử dụng CSPRNG**: sử dụng CSPRNG cho mọi giá trị liên quan đến bảo mật như token, session ID, khóa, vector khởi tạo (IV), và salt.
  - **Không sử dụng seed dựa trên thời gian (No time-based seeds)**: tránh sử dụng các giá trị thời gian hệ thống như `System.currentTimeMillis()`, `Date.now()` làm seed.
  - **Đảm bảo đủ entropy (Provide sufficient entropy)**: token phải đảm bảo có ít nhất 128 bits entropy (ví dụ: 32 ký tự hex hoặc 24 ký tự base64).
  - **Sử dụng các framework tiêu chuẩn**: ưu tiên sử dụng cơ chế quản lý phiên của các framework hiện đại đã được tích hợp sẵn CSPRNG.
  - **Giới hạn tần suất (Rate limiting)**: giới hạn số lần thử/nhập token để giảm thiểu khả năng bị tấn công vét cạn (brute-force).

## Code Example
```javascript
// ❌ VULNERABLE: Using Math.random() for security-sensitive values
function generateResetToken() {
    // Math.random() is NOT cryptographically secure
    const token = Math.random().toString(36).substring(2, 15);
    return token;  // e.g., "k5x8f2m9q1w" - predictable!
}

function generateSessionId() {
    // Timestamp-based ID - trivially guessable
    return "sess_" + Date.now().toString(36);
}

function generateOTP() {
    // Only 27,000 possible values with Math.random()
    return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
}
```

```javascript
// ✅ SECURE: Using crypto module for security-sensitive values
const crypto = require('crypto');

function generateResetToken() {
    // 32 bytes = 256 bits of entropy from OS CSPRNG
    return crypto.randomBytes(32).toString('hex');
    // e.g., "a1b2c3d4e5f6...64 hex chars" - unpredictable
}

function generateSessionId() {
    // Use crypto.randomUUID() for unique session identifiers
    return crypto.randomUUID();
    // e.g., "550e8400-e29b-41d4-a716-446655440000"
}

function generateOTP() {
    // Uniform distribution from CSPRNG, no modulo bias
    const buffer = crypto.randomBytes(4);
    const value = buffer.readUInt32BE(0) % 1000000;
    return value.toString().padStart(6, '0');
}
```

```python
# ✅ SECURE: Python equivalent using secrets module
import secrets

# Generate URL-safe token (default 32 bytes = 256 bits)
reset_token = secrets.token_urlsafe(32)

# Generate random integer for OTP
otp = secrets.randbelow(1000000)

# Compare tokens in constant time to prevent timing attacks
is_valid = secrets.compare_digest(user_token, stored_token)
```


## Xem thêm
- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/other-mechanisms
- OWASP – Insecure Randomness: https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
- V8 Math.random() Predictor: https://github.com/psmolak/v8-randomness-predictor

## Giải thích thuật ngữ
- **Entropy**: Khái niệm đo lường mức độ hỗn loạn hoặc tính không thể dự đoán trước của dữ liệu. Entropy càng cao thì giá trị được tạo ra càng ngẫu nhiên và khó đoán.
- **Seed (Hạt giống)**: Giá trị ban đầu được truyền vào bộ sinh số ngẫu nhiên để khởi tạo chuỗi số. Nếu sử dụng cùng một hạt giống với cùng một thuật toán PRNG, kết quả thu được sẽ luôn trùng khớp hoàn toàn.
- **Deterministic (Tính xác định)**: Đặc tính của một hệ thống hoặc thuật toán mà ở đó đầu ra hoàn toàn bị quyết định bởi đầu vào và trạng thái hiện tại, không có yếu tố ngẫu nhiên thực sự nào.
- **PRNG (Pseudo-Random Number Generator)**: Bộ sinh số giả ngẫu nhiên, sử dụng các công thức toán học để tạo ra chuỗi số trông có vẻ ngẫu nhiên. Nó có tính xác định và không an toàn cho mục đích bảo mật.
- **CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)**: Bộ sinh số giả ngẫu nhiên an toàn về mặt mật mã, kết hợp nguồn entropy vật lý để sinh ra các số ngẫu nhiên không thể dự đoán trước, ngay cả khi kẻ tấn công biết tất cả các số đã sinh ra trước đó.
- **Session ID**: Một chuỗi ký tự duy nhất được máy chủ cấp cho người dùng sau khi đăng nhập thành công, đại diện cho phiên làm việc hiện tại của người dùng đó.
- **OTP (One-Time Password)**: Mật khẩu dùng một lần, thường có hiệu lực trong thời gian rất ngắn (vài chục giây đến vài phút) để xác thực người dùng trong các giao dịch quan trọng.
