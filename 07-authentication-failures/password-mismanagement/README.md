---
schema_version: 1
id: WEB-A07-PASSWORD-MISMANAGEMENT
title: "Password Mismanagement"
slug: password-mismanagement
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A04:2025
cwe:
  - CWE-916
content_status: technical-review
payload_status: none
last_verified: null
---

# Password Mismanagement

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Password Mismanagement bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn điều hành một câu lạc bộ và cần lưu trữ danh sách mật khẩu của các thành viên.
- Nếu bạn chọn cách **mã hóa (Encryption)**, giống như việc bạn cất danh sách mật khẩu vào một chiếc hộp sắt và khóa lại bằng một chiếc chìa khóa. Khi cần xác thực, bạn mở hộp ra để xem mật khẩu gốc. Cách này có một điểm yếu chí tử: nếu kẻ trộm ăn cắp được chiếc chìa khóa hộp sắt, chúng sẽ đọc được toàn bộ mật khẩu của tất cả mọi người.
- Vì vậy, mật khẩu nên được lưu bằng hàm băm mật khẩu chậm, có salt như Argon2id, scrypt hoặc bcrypt theo use case. “Một chiều” không có nghĩa mật khẩu yếu không thể bị tìm lại: đối thủ có database hash vẫn có thể thử từng candidate ngoại tuyến và so sánh kết quả. [S3] [S4]

Để đống bột giấy này an toàn hơn nữa, bạn trộn thêm vào giấy một nhúm **muối (Salt)** — là các ký tự ngẫu nhiên duy nhất cho mỗi người dùng trước khi băm. Việc này giúp ngăn kẻ trộm dùng các bảng tính sẵn mật khẩu phổ biến (**Rainbow Table**) để dò ngược lại mật khẩu gốc.

Các hash tổng quát nhanh như MD5, SHA-1 hoặc SHA-256 không phù hợp để lưu mật khẩu vì đối thủ có thể thử candidate ngoại tuyến với throughput cao. Hàm băm mật khẩu có cost điều chỉnh làm mỗi lần thử tốn thêm CPU và, với thuật toán memory-hard, bộ nhớ. Điều này tăng chi phí tấn công nhưng không làm việc đoán mật khẩu yếu trở thành “không thể”; tham số phải được benchmark và nâng dần theo năng lực hệ thống. [S3] [S4]

```python
import bcrypt
import hashlib
import base64

def hash_password_securely(password: str) -> bytes:
    # Pre-hash password with SHA-256 to overcome bcrypt's 72-byte limit
    sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
    b64_hash = base64.b64encode(sha256_hash)

    # Generate a salt with bcrypt cost 12; benchmark this cost for the deployment.
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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Quản lý mật khẩu yếu kém (Password Mismanagement) xảy ra khi ứng dụng lưu trữ mật khẩu của người dùng ở dạng văn bản thô (cleartext), sử dụng thuật toán băm cũ và chạy quá nhanh (như MD5, SHA1), hoặc tự chế ra các công thức băm/ghép muối sai quy chuẩn bảo mật.

Mối nguy hiểm lớn nhất của lỗ hổng này xuất hiện khi cơ sở dữ liệu của ứng dụng bị rò rỉ hoặc bị hack. Kẻ tấn công có thể dễ dàng đọc trực tiếp mật khẩu của người dùng (nếu lưu bản rõ), hoặc sử dụng các công cụ bẻ khóa tự động bằng card đồ họa (GPU) để giải mã ngược hàng triệu mật khẩu được băm bằng thuật toán yếu chỉ trong vài giờ, từ đó chiếm đoạt tài khoản của người dùng trên hệ thống của bạn và trên cả các hệ thống khác mà họ tái sử dụng mật khẩu.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** password verifier, reset secret và password policy.
- **Actor, xác thực và role:** user đăng ký/đổi/reset; anonymous có thể thử credential.
- **Điều kiện khai thác:** storage yếu, thiếu breached-password blocklist hoặc reset-token lifecycle sai.
- **Browser, proxy, framework và phiên bản:** fixture Argon2id/bcrypt được pin với account tổng hợp; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với password mismanagement, storage yếu, thiếu breached-password blocklist hoặc reset-token lifecycle sai. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy fixture Argon2id/bcrypt được pin với account tổng hợp; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case password mismanagement; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “storage yếu, thiếu breached-password blocklist hoặc reset-token lifecycle sai”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của password mismanagement; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Nhà phát triển lưu trữ mật khẩu bằng cách ghép trực tiếp mật khẩu với một chuỗi pepper cố định rồi băm trực tiếp qua thư viện bcrypt: `bcrypt.hashpw(pepper + password, salt)`.
Bước 2: Do thư viện bcrypt có giới hạn xử lý độ dài chuỗi đầu vào tối đa là 72 byte, bất kỳ ký tự nào vượt quá giới hạn này sẽ bị bỏ qua khi tính toán mã băm.
Bước 3: Kẻ tấn công phát hiện ra lỗi này và nhận thấy nếu mật khẩu của nạn nhân là `A` dài 80 ký tự, chúng chỉ cần đoán đúng 72 ký tự đầu là có thể đăng nhập thành công mà không cần 8 ký tự cuối, làm giảm entropy và độ an toàn của mật khẩu.

## 9. Code dễ bị lỗi và code an toàn

Hai hàm sau dùng Python 3.12 cho cùng use case lưu và xác minh mật khẩu. Hash nhanh không salt cho phép so sánh hàng loạt hiệu quả; `argon2-cffi` 23.1.x tạo salt và lưu tham số trong encoded hash để xác minh. Tham số production phải được benchmark trên hệ thống đích theo ngân sách tài nguyên. [S3] [S5]

### Không an toàn (vulnerable): hash nhanh, không salt

```python
import hashlib
import hmac

def store_password_vulnerable(password):
    # Vulnerable: fast unsalted hashes make offline guessing inexpensive
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password_vulnerable(stored_hash, candidate):
    candidate_hash = hashlib.sha256(candidate.encode('utf-8')).hexdigest()
    return hmac.compare_digest(stored_hash, candidate_hash)
```

### An toàn (secure): password hashing chuyên dụng

```python
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

ph = PasswordHasher()

def store_password_secure(password):
    # Secure: Argon2id stores salt and parameters in the encoded hash
    return ph.hash(password)

def verify_password_secure(stored_hash, candidate):
    try:
        return ph.verify(stored_hash, candidate)
    except (VerificationError, InvalidHashError):
        return False
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng adaptive salted hashing hiện hành, breached-password blocklist và reset token single-use.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

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

OWASP cung cấp nhiều cấu hình tối thiểu cân bằng memory/iteration; đây không phải một bộ tham số cố định cho mọi hệ thống. Chọn profile được tài liệu hiện hành hỗ trợ, benchmark trên production-like hardware, đặt giới hạn tài nguyên để tránh DoS và lưu phiên bản/cost trong chuỗi hash để có thể rehash khi đăng nhập. [S3]

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

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

- **Cryptographic Hashing (Băm mật mã)**: Phép biến đổi không có thao tác giải mã bằng khóa; tuy nhiên đối thủ vẫn có thể thử candidate và so sánh hash, nên mật khẩu phải dùng hàm băm chuyên dụng có salt và cost.
- **Encryption (Mã hóa)**: Quá trình chuyển đổi thông tin từ dạng đọc được (bản rõ) sang dạng không đọc được (bản mã) bằng một thuật toán và khóa. Đây là quá trình hai chiều, có thể giải mã ngược lại nếu có khóa chính xác.
- **Salt (Muối)**: Chuỗi ký tự ngẫu nhiên được thêm vào mật khẩu trước khi băm, đảm bảo rằng ngay cả hai mật khẩu giống nhau cũng sẽ tạo ra hai mã băm khác nhau trong cơ sở dữ liệu, chống lại việc tra cứu bằng bảng băm tính sẵn.
- **Work Factor (Hệ số công việc / Chi phí)**: Tham số cấu hình xác định số lượng tài nguyên (CPU, bộ nhớ, thời gian) mà máy chủ phải bỏ ra để thực hiện một phép băm, giúp làm chậm quá trình bẻ khóa mật khẩu của kẻ tấn công.
- **Rainbow Table (Bảng cầu vồng)**: Cơ sở dữ liệu chứa danh sách các mật khẩu phổ biến được tính toán sẵn mã băm tương ứng, dùng để tra cứu nhanh nhằm bẻ khóa mật khẩu đã bị băm.
- **Argon2id**: Biến thể Argon2 cân bằng khả năng kháng side-channel và tấn công dùng phần cứng song song; độ an toàn phụ thuộc tham số, thư viện và vận hành, không nên gọi tuyệt đối là “an toàn nhất”.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-916. https://cwe.mitre.org/data/definitions/916.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** OWASP Password Storage Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** NIST SP 800-63B-4 — Authentication and Authenticator Management. https://pages.nist.gov/800-63-4/sp800-63b.html — phiên bản/trạng thái: SP 800-63B-4; truy cập: 2026-07-18.
- **[S5]** argon2-cffi API Reference. https://argon2-cffi.readthedocs.io/en/23.1.0/api.html — phiên bản/trạng thái: 23.1.0; truy cập: 2026-07-18.
