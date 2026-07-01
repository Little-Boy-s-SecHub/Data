# Password Mismanagement

> **CWE**: CWE-916 (Use of Password Hash with Insufficient Computational Effort) | **Phân loại**: Authentication

## Kiến thức Nền tảng
Hãy tưởng tượng bạn điều hành một câu lạc bộ và cần lưu trữ danh sách mật khẩu của các thành viên.
- Nếu bạn chọn cách **mã hóa (Encryption)**, giống như việc bạn cất danh sách mật khẩu vào một chiếc hộp sắt và khóa lại bằng một chiếc chìa khóa. Khi cần xác thực, bạn mở hộp ra để xem mật khẩu gốc. Cách này có một điểm yếu chí tử: nếu kẻ trộm ăn cắp được chiếc chìa khóa hộp sắt, chúng sẽ đọc được toàn bộ mật khẩu của tất cả mọi người.
- Vì vậy, bạn nên chọn cách **băm mật mã (Cryptographic Hashing)**. Băm giống như một cỗ máy hủy tài liệu một chiều: bạn đút mật khẩu vào, cỗ máy sẽ nghiền nát và nhào trộn nó thành một đống bột giấy có hình thù cố định. Bạn không thể ghép đống bột giấy đó trở lại thành tờ giấy ban đầu. Khi thành viên đăng nhập, bạn chỉ cần bỏ mật khẩu họ nhập vào máy hủy xem đống bột giấy tạo ra có giống hệt đống bột giấy bạn đang lưu giữ hay không.

Để đống bột giấy này an toàn hơn nữa, bạn trộn thêm vào giấy một nhúm **muối (Salt)** — là các ký tự ngẫu nhiên duy nhất cho mỗi người dùng trước khi băm. Việc này giúp ngăn kẻ trộm dùng các bảng tính sẵn mật khẩu phổ biến (**Rainbow Table**) để dò ngược lại mật khẩu gốc.

Tuy nhiên, các máy tính hiện đại ngày nay có tốc độ tính toán cực kỳ nhanh. Chúng có thể chạy thử hàng tỷ phép băm MD5 hay SHA256 mỗi giây để tìm ra mật khẩu gốc. Do đó, các thuật toán băm hiện đại như **Argon2** hay **bcrypt** giới thiệu thêm khái niệm **Work Factor (Hệ số công việc)**. Đây là nút vặn điều chỉnh độ phức tạp: bạn tăng Work Factor lên thì cỗ máy băm sẽ hoạt động chậm đi một chút (ví dụ mất 0.1 giây thay vì 0.000001 giây). Đối với người dùng bình thường, 0.1 giây là không đáng kể, nhưng đối với tin tặc muốn thử hàng triệu mật khẩu bằng siêu máy tính, việc này sẽ làm chậm tốc độ của chúng đến mức không thể thực hiện được.

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

## Mô tả lỗ hổng
Lỗ hổng Quản lý mật khẩu yếu kém (Password Mismanagement) xảy ra khi ứng dụng lưu trữ mật khẩu của người dùng ở dạng văn bản thô (cleartext), sử dụng thuật toán băm cũ và chạy quá nhanh (như MD5, SHA1), hoặc tự chế ra các công thức băm/ghép muối sai quy chuẩn bảo mật.

Mối nguy hiểm lớn nhất của lỗ hổng này xuất hiện khi cơ sở dữ liệu của ứng dụng bị rò rỉ hoặc bị hack. Kẻ tấn công có thể dễ dàng đọc trực tiếp mật khẩu của người dùng (nếu lưu bản rõ), hoặc sử dụng các công cụ bẻ khóa tự động bằng card đồ họa (GPU) để giải mã ngược hàng triệu mật khẩu được băm bằng thuật toán yếu chỉ trong vài giờ, từ đó chiếm đoạt tài khoản của người dùng trên hệ thống của bạn và trên cả các hệ thống khác mà họ tái sử dụng mật khẩu.

## Cơ chế tấn công
Bước 1: Nhà phát triển lưu trữ mật khẩu bằng cách ghép trực tiếp mật khẩu với một chuỗi pepper cố định rồi băm trực tiếp qua thư viện bcrypt: `bcrypt.hashpw(pepper + password, salt)`.
Bước 2: Do thư viện bcrypt có giới hạn xử lý độ dài chuỗi đầu vào tối đa là 72 byte, bất kỳ ký tự nào vượt quá giới hạn này sẽ bị bỏ qua khi tính toán mã băm.
Bước 3: Kẻ tấn công phát hiện ra lỗi này và nhận thấy nếu mật khẩu của nạn nhân là `A` dài 80 ký tự, chúng chỉ cần đoán đúng 72 ký tự đầu là có thể đăng nhập thành công mà không cần 8 ký tự cuối, làm giảm entropy và độ an toàn của mật khẩu.

## Biện pháp phòng thủ
- **Tóm tắt**: Password mismanagement covers insecure storage, weak hashing, and lack of complexity policies. Mitigation involves using strong, modern cryptographic hashing algorithms (like Argon2id or bcrypt) with random salts, enforcing password complexity, and using secure communication channels.
- **Các bước chi tiết**:
  - Hash passwords using strong, adaptive, salted hashing algorithms such as Argon2id or bcrypt with appropriate work factors.
  - Never store passwords in plaintext or using outdated, fast hash algorithms (like MD5, SHA-1, or plain SHA-256).
  - Enforce strong password complexity guidelines, including minimum length and checking against lists of known breached passwords.
  - Bảo vệ toàn bộ luồng nhập, đặt lại và khôi phục mật khẩu bằng HTTPS, đồng thời áp dụng rate limiting cho endpoint xác thực.

### Argon2id vs Argon2i vs Argon2d
Theo RFC 9106, Argon2 có 3 biến thể:
- **Argon2id** (khuyến nghị): Kết hợp cả hai, chống side-channel và GPU attack. Dùng cho password hashing.
- **Argon2i**: Chống side-channel attack (cache timing), nhưng yếu hơn trước GPU attack. Dùng cho key derivation.
- **Argon2d**: Mạnh trước GPU attack nhưng dễ bị side-channel. Không dùng cho môi trường có side-channel risk.

Tham số khuyến nghị (OWASP): memory=64MB, iterations=3, parallelism=4.

## Code Example
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

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A02:2021, CWE-916, NIST SP 800-63B

## Giải thích thuật ngữ
- **Cryptographic Hashing (Băm mật mã)**: Thuật toán chuyển đổi một lượng dữ liệu bất kỳ thành một chuỗi ký tự có độ dài cố định. Đây là quá trình một chiều, không thể đảo ngược từ chuỗi băm để tìm lại dữ liệu gốc.
- **Encryption (Mã hóa)**: Quá trình chuyển đổi thông tin từ dạng đọc được (bản rõ) sang dạng không đọc được (bản mã) bằng một thuật toán và khóa. Đây là quá trình hai chiều, có thể giải mã ngược lại nếu có khóa chính xác.
- **Salt (Muối)**: Chuỗi ký tự ngẫu nhiên được thêm vào mật khẩu trước khi băm, đảm bảo rằng ngay cả hai mật khẩu giống nhau cũng sẽ tạo ra hai mã băm khác nhau trong cơ sở dữ liệu, chống lại việc tra cứu bằng bảng băm tính sẵn.
- **Work Factor (Hệ số công việc / Chi phí)**: Tham số cấu hình xác định số lượng tài nguyên (CPU, bộ nhớ, thời gian) mà máy chủ phải bỏ ra để thực hiện một phép băm, giúp làm chậm quá trình bẻ khóa mật khẩu của kẻ tấn công.
- **Rainbow Table (Bảng cầu vồng)**: Cơ sở dữ liệu chứa danh sách các mật khẩu phổ biến được tính toán sẵn mã băm tương ứng, dùng để tra cứu nhanh nhằm bẻ khóa mật khẩu đã bị băm.
- **Argon2id**: Thuật toán băm mật khẩu hiện đại, an toàn nhất hiện nay, được thiết kế để chống lại các cuộc tấn công bẻ khóa bằng phần cứng chuyên dụng (như GPU/ASIC) và các cuộc tấn công kênh kề (side-channel).
