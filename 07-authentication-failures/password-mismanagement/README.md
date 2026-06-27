# Password Mismanagement

> **OWASP Top 10:2025**: A07:2025 – Authentication Failures | **CWE**: CWE-916 (Use of Password Hash with Insufficient Computational Effort) | **Phân loại**: Authentication

## 🧱 Kiến thức Nền tảng
Trong quản lý mật khẩu, việc lưu trữ thông tin xác thực an toàn đòi hỏi sự hiểu biết sâu sắc về các khái niệm mật mã cơ bản. Đầu tiên, cần phân biệt rõ **Cryptographic Hashing (băm mật mã)** và **Encryption (mã hóa)**. Băm là hàm số một chiều (one-way function) biến đổi đầu vào thành một chuỗi có độ dài cố định, không thể đảo ngược để tìm lại bản rõ ban đầu. Ngược lại, mã hóa là quá trình hai chiều (two-way function) cho phép chuyển đổi dữ liệu thành bản mã và có thể giải mã ngược lại bằng một khóa bí mật thích hợp. Do đó, mật khẩu tuyệt đối không được mã hóa mà bắt buộc phải băm.

Để tăng cường độ an toàn của chuỗi băm, cơ chế **Salt (muối)** được sử dụng. Salt là một chuỗi dữ liệu ngẫu nhiên được sinh ra cho mỗi người dùng và được ghép vào mật khẩu trước khi băm. Salt giúp ngăn chặn các cuộc tấn công sử dụng bảng băm tính sẵn (Rainbow Table) và đảm bảo rằng hai người dùng có cùng mật khẩu vẫn có chuỗi băm hoàn toàn khác nhau trong cơ sở dữ liệu.

Bên cạnh đó, các thuật toán băm hiện đại như **Argon2** và **bcrypt** tích hợp tham số **Work Factor (hệ số công việc)**. Đây là một cấu hình điều chỉnh độ phức tạp tính toán (chi phí CPU, bộ nhớ hoặc số vòng lặp). Bằng cách tăng Work Factor, nhà phát triển làm chậm tốc độ tính toán của thuật toán một cách có chủ đích, từ đó vô hiệu hóa hoặc làm tăng đáng kể chi phí kinh tế của kẻ tấn công khi chúng cố gắng thực hiện tấn công vét cạn (brute-force) bằng phần cứng chuyên dụng như GPU hay chip ASIC.

```python
import bcrypt
import hashlib
import base64

def hash_password_securely(password: str) -> bytes:
    # Pre-hash password with SHA-256 to overcome bcrypt's 72-byte limit
    sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
    b64_hash = base64.b64encode(sha256_hash)
    
    # Generate salt with a work factor of 12 (2^12 rounds)
    salt = bcrypt.gensalt(rounds=12)
    
    # Hash the pre-hashed password using bcrypt
    hashed = bcrypt.hashpw(b64_hash, salt)
    return hashed

def verify_password_securely(password: str, hashed: bytes) -> bool:
    # Re-calculate SHA-256 pre-hash of the input password
    sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
    b64_hash = base64.b64encode(sha256_hash)
    
    # Verify using bcrypt's secure timing-safe compare
    return bcrypt.checkpw(b64_hash, hashed)
```

## 🔍 Mô tả lỗ hổng
Quản lý mật khẩu yếu kém (Password Mismanagement) bao gồm các sai sót trong việc lưu trữ và xác thực mật khẩu của người dùng. Các lỗi phổ biến bao gồm lưu mật khẩu dưới dạng bản rõ, sử dụng các thuật toán băm yếu (như MD5, SHA1), hoặc triển khai salt/pepper sai quy cách. Điều này khiến mật khẩu dễ dàng bị bẻ khóa thông qua tấn công vét cạn hoặc bảng tra cứu (rainbow table) nếu cơ sở dữ liệu bị rò rỉ.

## ⚔️ Cơ chế tấn công
Bước 1: Nhà phát triển lưu trữ mật khẩu bằng cách ghép trực tiếp mật khẩu với một chuỗi pepper cố định rồi băm trực tiếp qua thư viện bcrypt: `bcrypt.hashpw(pepper + password, salt)`.
Bước 2: Do thư viện bcrypt có giới hạn xử lý độ dài chuỗi đầu vào tối đa là 72 byte, bất kỳ ký tự nào vượt quá giới hạn này sẽ bị bỏ qua khi tính toán mã băm.
Bước 3: Kẻ tấn công phát hiện ra lỗi này và nhận thấy nếu mật khẩu của nạn nhân là `A` dài 80 ký tự, chúng chỉ cần đoán đúng 72 ký tự đầu là có thể đăng nhập thành công mà không cần 8 ký tự cuối, làm giảm entropy và độ an toàn của mật khẩu.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Password mismanagement covers insecure storage, weak hashing, and lack of complexity policies. Mitigation involves using strong, modern cryptographic hashing algorithms (like Argon2id or bcrypt) with random salts, enforcing password complexity, and using secure communication channels.
- **Các bước chi tiết**:
  - Hash passwords using strong, adaptive, salted hashing algorithms such as Argon2id or bcrypt with appropriate work factors.
  - Never store passwords in plaintext or using outdated, fast hash algorithms (like MD5, SHA-1, or plain SHA-256).
  - Enforce strong password complexity guidelines, including minimum length and checking against lists of known breached passwords.
  - Secure all password entry, reset, and recovery flows with HTTPS, and protect authentication endpoints from brute-force attacks via rate limiting.

## 💻 Code Example
```python
from argon2 import PasswordHasher

ph = PasswordHasher()

# Hashing a password
hash_value = ph.hash("user_secure_password")

# Verifying a password
try:
    ph.verify(hash_value, "user_secure_password")
    print("Password verified successfully")
except Exception:
    print("Invalid password")
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này đã được chỉnh sửa (FIXED). Sửa đổi lỗi nghiêm trọng khi ghép trực tiếp chuỗi pepper vào mật khẩu trước khi đưa vào bcrypt (combined = pepper + password). Vì bcrypt giới hạn độ dài đầu vào 72 byte, mật khẩu dài sẽ bị cắt cụt làm giảm entropy. Sửa đổi bằng cách thực hiện băm mật khẩu + pepper qua SHA-256 trước, tạo chuỗi băm 32-byte cố định, sau đó mới thực hiện băm qua bcrypt.
- **Nguồn tham khảo**: OWASP A02:2021, CWE-916, NIST SP 800-63B
