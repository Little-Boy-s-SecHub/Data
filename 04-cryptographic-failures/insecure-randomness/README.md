---
schema_version: 1
id: WEB-A04-INSECURE-RANDOMNESS
title: "Insecure Randomness"
slug: insecure-randomness
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A04:2025
cwe:
  - CWE-330
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Insecure Randomness

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Insecure Randomness bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Seed, state và khác biệt PRNG/CSPRNG.

- Python `random`, `secrets` và Node `crypto`.

- Entropy budget, encoding và token lifecycle.

## 3. Kiến thức nền tảng

Trong thế giới bảo mật số, tính ngẫu nhiên (randomness) đóng vai trò như chiếc chìa khóa vạn năng. Nó được dùng để tạo ra mã OTP gửi về điện thoại của bạn, mã khôi phục mật khẩu, mã phiên đăng nhập (session ID), hay các khóa mã hóa bảo vệ ví điện tử. Nếu những chiếc chìa khóa này được làm từ một chiếc khuôn dễ đoán, kẻ xấu hoàn toàn có thể tự đúc cho mình chiếc chìa khóa giống hệt để đột nhập vào tài khoản của bạn. [S6]

Để tạo ra các số ngẫu nhiên, các máy tính sử dụng hai loại "máy gieo số" chính:
- **PRNG (Bộ sinh số giả ngẫu nhiên)**: là thuật toán xác định có trạng thái. Cùng thuật toán, seed và chuỗi lời gọi sẽ cho cùng đầu ra. `Math.random()` và module `random` của Python không cam kết tính khó dự đoán về mật mã, nên không dùng cho token, session ID, OTP hoặc khóa. Khả năng khôi phục trạng thái phụ thuộc thuật toán, cách biểu diễn đầu ra và số mẫu quan sát được; không có ngưỡng “vài mẫu” áp dụng cho mọi runtime. [S6]
- **CSPRNG (Bộ sinh số giả ngẫu nhiên an toàn về mặt mật mã)**: cũng có thể là thuật toán xác định, nhưng được thiết kế để đầu ra khó dự đoán khi không biết trạng thái nội bộ và được khởi tạo/reseed từ nguồn entropy của hệ điều hành. Trong Node.js và Python, ưu tiên API `node:crypto` và `secrets` thay vì tự thiết kế bộ sinh. [S6], [S7]

```javascript
// Normal operation: generating a random number in JavaScript
const value = Math.random();  // Returns float between 0 and 1
console.log(value);           // e.g., 0.7281943042158021

// This API is suitable for non-security uses, not secrets or tokens
```

Điểm mấu chốt ở đây là: các thuật toán PRNG thông thường hoạt động trên một trạng thái (state) hữu hạn. Khi kẻ tấn công thu thập đủ số lượng mẫu đầu ra, họ có thể dùng toán học để khôi phục trạng thái này và đọc trước được tương lai. [S6]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng "Tính ngẫu nhiên không an toàn" (Insecure Randomness) xuất hiện khi lập trình viên vô tình sử dụng các bộ sinh số ngẫu nhiên thông thường (PRNG) cho các mục đích bảo mật. [S6]

Ví dụ, token đặt lại mật khẩu được tạo bằng PRNG seed theo thời gian có thể bị thu hẹp không gian tìm kiếm nếu actor biết gần đúng thời điểm và thuật toán. Việc quan sát token của chính actor không tự động chứng minh có thể dự đoán token của người khác; phải xác nhận cùng bộ sinh, thứ tự lời gọi và không có entropy bí mật bổ sung. [S6]

Hay nguy hiểm hơn, các mã OTP chỉ có 6 chữ số nếu được sinh ra một cách dễ đoán sẽ nhanh chóng bị bẻ gãy, khiến lớp bảo mật hai yếu tố (2FA) trở nên vô dụng. Tương tự, session ID hay các khóa mã hóa được sinh một cách hời hợt cũng là chiếc vé thông hành miễn phí mời gọi tin tặc vào nhà. [S6]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** reset token, session ID và OTP synthetic.

- **Actor:** observer biết public seed hoặc nhiều đầu ra; không có trạng thái CSPRNG nội bộ.

- **Trust boundary:** API random của Node.js/Python tạo giá trị dùng làm secret.

- **Điều kiện cần:** ứng dụng dùng PRNG dự đoán được, seed yếu hoặc không đủ không gian/giới hạn thử.

- **Môi trường:** Python 3.12 random.Random và Node.js crypto pin version, process local, no network.

Tính duy nhất như UUID không đồng nghĩa bí mật; session token phải opaque, đủ entropy và sinh từ OS CSPRNG. [S6], [S7]

## 6. Cơ chế tấn công

Ứng dụng biến đầu ra PRNG dự đoán được thành token/OTP. Khi actor biết seed/state hoặc không gian nhỏ, chuỗi tương lai có thể tái tạo; OS CSPRNG với lifecycle đúng loại bỏ giả định đó. [S6], [S7]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy process Python/Node local với seed fixture công khai và không external input.
2. **Baseline:** hai CSPRNG outputs khác nhau; format/length đáp ứng contract.
3. **Thao tác:** tạo hai random.Random cùng seed để chứng minh chuỗi trùng; không brute-force token.
4. **Expected result:** PRNG fixture tái tạo được; code sửa dùng randomBytes/secrets và regression không dựa vào giá trị cố định.
5. **Boundary:** kiểm tra lỗi entropy source, fork/reseed, token expiration và rate cap riêng.
6. **Cleanup:** xóa token/log fixture và terminate process.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Ví dụ cốt lõi chỉ minh họa tính lặp lại của PRNG khi seed bị lộ. Nó không dùng token, tài khoản hoặc endpoint thật.

<!-- payload-id: WEB-A04-INSECURE-RANDOMNESS-001 -->
<!-- context: Python 3.12 standard-library random.Random; local process; deterministic-generator behavior [S6] -->
<!-- prerequisites: no external input or network access -->
<!-- encoding: UTF-8 Python source; decimal seed is parsed as an integer; no transport or secondary decoding -->
<!-- expected-result: both sequences are equal because both generators use the same public seed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
```python
import random

public_seed = 20260717
first = random.Random(public_seed)
second = random.Random(public_seed)

sequence_a = [first.randrange(1_000_000) for _ in range(4)]
sequence_b = [second.randrange(1_000_000) for _ in range(4)]
assert sequence_a == sequence_b
```

## 9. Code dễ bị lỗi và code an toàn

```javascript
// ❌ VULNERABLE: Using Math.random() for security-sensitive values
function generateResetToken() {
    // Math.random() is NOT cryptographically secure
    const token = Math.random().toString(36).substring(2, 15);
    return token;  // The runtime does not guarantee cryptographic unpredictability
}

function generateSessionId() {
    // Timestamp-based ID - trivially guessable
    return "sess_" + Date.now().toString(36);
}

function generateOTP() {
    // The space has 1,000,000 values, but Math.random() is not a CSPRNG
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
    // Generate an opaque 256-bit session identifier from the OS CSPRNG
    return crypto.randomBytes(32).toString('base64url');
}

function generateOTP() {
    // randomInt uses the CSPRNG and avoids modulo bias
    const value = crypto.randomInt(0, 1_000_000);
    return value.toString().padStart(6, '0');
}
```

```python
# ✅ SECURE: Python equivalent using secrets module
import secrets

# Explicitly request 32 random bytes, then encode them for URLs
reset_token = secrets.token_urlsafe(32)

# A six-digit OTP has a small output space even with a CSPRNG; enforce
# short expiry, one-time use and attempt limits in the verification flow.
otp = secrets.randbelow(1000000)

# Compare tokens in constant time to prevent timing attacks
is_valid = secrets.compare_digest(user_token, stored_token)
```

## 10. Phát hiện

- Tái tạo chuỗi từ seed công khai trong fixture và phân biệt với OS-backed CSPRNG. [S6], [S7]

- Review API sinh token/OTP/key, cách seed và nơi token bị truncate/encode. [S6], [S7]

- Không ghi token thật; chỉ log length, source API và collision test synthetic.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Sinh secret bằng API CSPRNG của platform và số byte phù hợp với threat model. [S6], [S7]

- Quản lý token lifecycle: scope, expiry, single-use và invalidation theo use case. [S6]

### Defense-in-depth

- Rate limit giúp giảm online guessing cho OTP không gian nhỏ.

- Encoding/UUID chỉ biểu diễn dữ liệu, không tự thêm entropy.

## 12. Retest

- **Positive:** token đúng độ dài và luồng consume/invalidate hoạt động.

- **Negative:** seed cố định hoặc API non-crypto bị gate/code review chặn.

- **Boundary:** fork/process restart, truncation, concurrency và entropy failure.

- **Telemetry:** ghi API/version và lifecycle event, không ghi secret.

## 13. Sai lầm thường gặp

- Dùng `random`/`Math.random()` cho token bảo mật.

- Seed bằng timestamp rồi coi output là bí mật.

- Đếm ký tự encoded như số bit entropy.

- Gọi mọi PRNG là không an toàn; CSPRNG cũng thường là bộ sinh tất định có thiết kế riêng.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Entropy:** độ bất định của nguồn dùng để seed/reseed bộ sinh. [S6]

- **PRNG:** bộ sinh tất định mở rộng seed thành chuỗi đầu ra. [S6]

- **CSPRNG:** bộ sinh được thiết kế để đầu ra khó dự đoán khi state bí mật và lifecycle đúng. [S6], [S7]

## 16. Bài liên quan và đọc thêm

- [DNS Poisoning](../dns-poisoning/) — Xem thêm bài học về DNS Poisoning.

## 17. Tài liệu tham khảo

- **[S6]** Python 3.12 documentation — `random` and `secrets`. https://docs.python.org/3.12/library/random.html — phiên bản: Python 3.12; truy cập: 2026-07-17.
- **[S7]** Node.js documentation — `crypto.randomBytes()` and `crypto.randomInt()`. https://nodejs.org/api/crypto.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
