# Insecure Randomness

> **OWASP Top 10:2025**: A04 – Cryptographic Failures | **CWE**: CWE-330 | **Nguồn**: OWASP, CWE, PortSwigger

## 🧱 Kiến thức Nền tảng

Tính ngẫu nhiên (randomness) là nền tảng của nhiều cơ chế bảo mật: session ID, token xác thực, CSRF token, mã OTP, khóa mã hóa, salt cho password hashing. Nếu giá trị "ngẫu nhiên" có thể đoán được, toàn bộ hệ thống bảo mật sụp đổ.

Có hai loại Random Number Generator (RNG):

- **PRNG (Pseudo-Random Number Generator)**: Tạo chuỗi số có vẻ ngẫu nhiên nhưng thực chất là **deterministic** — cùng seed sẽ cho cùng kết quả. Ví dụ: `Math.random()` (JS), `random.random()` (Python), `java.util.Random`. Phù hợp cho game, simulation, nhưng **KHÔNG an toàn cho bảo mật**.

- **CSPRNG (Cryptographically Secure PRNG)**: Sử dụng entropy từ hệ điều hành (hardware interrupts, mouse movements, disk timing). Không thể dự đoán output ngay cả khi biết các output trước đó. Ví dụ: `crypto.randomBytes()` (Node.js), `secrets.token_hex()` (Python), `java.security.SecureRandom`.

```javascript
// Normal operation: generating a random number in JavaScript
// Math.random() uses xorshift128+ algorithm internally
const value = Math.random();  // Returns float between 0 and 1
console.log(value);           // e.g., 0.7281943042158021

// The internal state can be reconstructed from ~5 outputs
// This is FINE for non-security purposes (games, UI animations)
```

Điểm mấu chốt: PRNG sử dụng thuật toán toán học với state nội bộ cố định. Nếu attacker biết thuật toán và đủ output samples, họ có thể **reverse-engineer state** và dự đoán mọi giá trị tương lai.

## 🔍 Mô tả lỗ hổng

Lỗ hổng Insecure Randomness xảy ra khi ứng dụng sử dụng PRNG không an toàn về mặt mật mã cho các mục đích bảo mật. Các tình huống phổ biến:

- **Password reset token** tạo bằng `Math.random()` → attacker có thể dự đoán token và chiếm tài khoản.
- **Session ID** dựa trên timestamp hoặc sequential counter → session hijacking.
- **OTP/2FA code** sinh từ weak PRNG → bypass xác thực hai yếu tố.
- **Encryption key/IV** tạo bằng `java.util.Random` → giải mã dữ liệu.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Luôn dùng CSPRNG** cho mọi giá trị liên quan đến bảo mật: tokens, session IDs, keys, IVs, salts.
2. **Không dùng time-based seeds**: Tránh `System.currentTimeMillis()`, `Date.now()` làm seed.
3. **Đủ entropy**: Token phải có ít nhất **128 bits** entropy (32 hex chars hoặc 24 base64 chars).
4. **Sử dụng framework có sẵn**: Hầu hết framework hiện đại đã dùng CSPRNG cho session management.
5. **Rate limiting**: Giới hạn số lần thử token để giảm khả năng brute-force.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/authentication/other-mechanisms
- OWASP – Insecure Randomness: https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
- V8 Math.random() Predictor: https://github.com/psmolak/v8-randomness-predictor
