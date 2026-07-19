---
schema_version: 1
id: WEB-A01-DIRECTORY-TRAVERSAL
title: "Directory Traversal"
slug: directory-traversal
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-22
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Directory Traversal

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Directory Traversal bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Filesystem path resolution, canonical path và symbolic link.

- URL decoding và vị trí decode trong web stack.

- Quyền filesystem của process chạy fixture.

## 3. Kiến thức nền tảng

Hãy tưởng tượng hệ thống tệp tin trên máy chủ web giống như một thư viện lưu trữ tài liệu khổng lồ. Trong đó, mỗi phòng ban có một tủ hồ sơ riêng và nhân viên chỉ được phép xem các tài liệu trong tủ hồ sơ của phòng mình. Để giữ an toàn, người quản lý thư viện đã đặt quy định: "Bạn chỉ được phép tìm kiếm hồ sơ trong phạm vi ngăn tủ công cộng được chỉ định". [S4]

Trong cấu trúc đường dẫn, một phân đoạn tham chiếu thư mục cha làm bộ phân giải lùi lên một cấp. Nếu ứng dụng nối nhiều phân đoạn như vậy từ input vào thư mục gốc mà không chuẩn hóa và kiểm tra containment, đường dẫn cuối cùng có thể thoát khỏi cây tài nguyên được phép. Cơ chế và chuỗi kiểm thử cụ thể được cô lập ở mục 8; phần nền tảng chỉ cần ghi nhớ rằng kiểm tra chuỗi trước khi phân giải không chứng minh được tệp cuối cùng vẫn nằm trong thư mục cho phép. [S2] [S4]

Ngoài ra, cấu trúc URL (URL structure) của ứng dụng thường chứa các tham số truy vấn chỉ định tài nguyên tải xuống (ví dụ: `https://victim.lab.test/download?file=report.pdf`). Trình duyệt gửi URL này dưới dạng HTTP request, và máy chủ sẽ phân tích giá trị của tham số `file` để định vị tệp trên đĩa cứng. Nếu lập trình viên không xác thực tham số này mà xử lý tệp trực tiếp, kẻ tấn công sẽ thao túng cấu trúc URL để thực hiện cuộc tấn công duyệt thư mục. Để phòng thủ hiệu quả, máy chủ bắt buộc phải phân giải đường dẫn đầu vào thành một đường dẫn tuyệt đối chuẩn hóa (canonical path) và xác thực rõ ràng xem đường dẫn đã được giải quyết có thực sự nằm bên dưới thư mục gốc được phép truy cập hay không. [S4]

```python
# Safe path resolution check to prevent directory traversal
from pathlib import Path

def get_safe_filepath(user_filename, base_dir="/var/www/safe_uploads"):
    """
    Resolves the target file path and ensures it does not escape the base directory.
    """
    # The lab directory is not writable by the requesting user. Canonicalize
    # only paths that already exist so missing components cannot hide behavior.
    base_path = Path(base_dir).resolve(strict=True)

    # Resolve parent segments and existing symlinks at validation time.
    target_path = Path(base_path, user_filename).resolve(strict=True)

    # Verify that the resolved target path is still located within the base path
    if not target_path.is_relative_to(base_path):
        # Deny access if a path traversal attempt is detected
        raise PermissionError("Access Denied: Requested file escapes the base directory.")

    # If an attacker can mutate this directory, use a descriptor-relative open
    # with no-follow semantics instead of returning a path after this check.
    return target_path
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Duyệt thư mục** (Directory Traversal hoặc Path Traversal) xuất hiện khi ứng dụng tin tưởng mù quáng vào đường dẫn hoặc tên tệp tin do người dùng nhập vào. [S4]

Nguyên nhân gốc là ứng dụng để input quyết định đường dẫn tệp rồi mở kết quả mà không ánh xạ qua định danh phía máy chủ hoặc không xác nhận đường dẫn canonical nằm trong thư mục cho phép. Hậu quả phụ thuộc quyền của tiến trình: ứng dụng có thể đọc nhầm dữ liệu ngoài phạm vi hoặc ghi vào vị trí không được thiết kế cho chức năng đó. [S2] [S4]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** các file ngoài thư mục menu được phép; lab chỉ có marker /srv/lab/lab-secret.txt.

- **Actor:** client chưa đăng nhập hoặc đã đăng nhập nếu endpoint download yêu cầu session.

- **Trust boundary:** tham số file đi vào phép nối/resolve đường dẫn của Python 3.12.

- **Điều kiện cần:** actor kiểm soát tên file và handler không ánh xạ allowlist hoặc không kiểm tra đường dẫn đã resolve.

- **Môi trường:** filesystem container disposable; query được decode đúng một lần; không symlink ra host.

Chỉ kết luận khi log open() và nội dung LAB_ONLY_SECRET chứng minh file ngoài base directory đã được đọc. [S1]

## 6. Cơ chế tấn công

Handler nối tên file do client cung cấp vào base path. Các segment cha hoặc cách decode tương đương làm đường dẫn đã resolve thoát khỏi base directory nếu không có allowlist/containment check. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** tạo /srv/lab/public/menus cùng file menu hợp lệ và file marker synthetic bên ngoài; bật file-access log.
2. **Baseline:** tải breakfast.txt hoặc opaque menu ID hợp lệ.
3. **Thao tác:** gửi đúng payload đã annotation ở mục 8; sau đó thử biến thể percent-encoded như một boundary case riêng.
4. **Expected result:** bản lỗi trả LAB_ONLY_SECRET; bản sửa chỉ chấp nhận allowlist và trả 404 mà không mở file ngoài base.
5. **Boundary:** kiểm tra đường dẫn tuyệt đối, separator khác, double decoding và symlink chỉ trong container.
6. **Cleanup:** xóa container và xác nhận không có file hệ thống/host nào được truy cập.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Một ứng dụng lab tải thực đơn thông qua tham số `file=menu1.txt`. Nếu máy chủ nối trực tiếp input vào thư mục gốc, chuỗi `../` có thể thoát khỏi thư mục được phép và đọc `lab-secret.txt` trong fixture. Không dùng tệp hệ thống hoặc dữ liệu thật để minh họa. [S4]

### Các biến thể encoding để bypass filter:
| Payload | Ý nghĩa |
|---|---|
| `../` | Cơ bản |
| `%2e%2e%2f` | URL encode toàn phần |
| `..%2f` | Chỉ encode `/` |
| `%2e%2e/` | Chỉ encode `.` |
| `....//` | Chỉ có thể vượt bộ lọc xóa `../` một lần; không phải biến thể phổ quát |
| `..\` | Windows path separator |
| `%252e%252e%252f` | Double URL encode |
| `..%c0%af` | Legacy: chỉ liên quan decoder UTF-8 cũ chấp nhận overlong sequence; decoder hiện hành phải từ chối [S3] |

### Ví dụ HTTP request minh họa Directory Traversal:
<!-- payload-id: WEB-A01-DIRECTORY-TRAVERSAL-001 -->
<!-- context: HTTP/1.1; fixture root /srv/lab/public/menus; synthetic file /srv/lab/lab-secret.txt; path-containment model [S4] -->
<!-- prerequisites: local fixture normalizes the query once and joins it to the configured menu directory -->
<!-- encoding: ASCII request-target with literal ../ segments; raw harness emits CRLF; request has no body or Content-Length -->
<!-- expected-result: vulnerable fixture returns the marker LAB_ONLY_SECRET; fixed fixture returns 404 without opening a file outside the allowlist -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# Each ../ segment moves up one parent directory
GET /download?file=../../lab-secret.txt HTTP/1.1
Host: files.lab.test
# The vulnerable fixture returns the synthetic marker LAB_ONLY_SECRET
```

## 9. Code dễ bị lỗi và code an toàn

```python
from pathlib import Path

BASE_DIRECTORY = Path("/srv/lab/public/menus")
ALLOWED_MENUS = {
    "breakfast": "breakfast.txt",
    "dinner": "dinner.txt",
}

def read_menu_vulnerable(user_filename):
    # BAD: user input is appended directly to the trusted base directory
    return (BASE_DIRECTORY / user_filename).read_text(encoding="utf-8")

def read_menu_secure(menu_id):
    # GOOD: the client selects an opaque ID whose filename is server-controlled
    filename = ALLOWED_MENUS.get(menu_id)
    if filename is None:
        raise FileNotFoundError("Unknown menu")
    return (BASE_DIRECTORY / filename).read_text(encoding="utf-8")
```

## 10. Phát hiện

- Gửi tên file hợp lệ và đường dẫn thoát base; xác nhận file nào thực sự được mở trong syscall/log. [S4]

- Review phép nối path, số lần decode và containment check sau canonicalization. [S4]

- Log file ID, resolved path tương đối, quyết định allow/deny; không log nội dung file.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Ưu tiên ánh xạ file ID phía server; nếu nhận tên file, resolve rồi xác nhận đích nằm trong base directory. [S4]

- Từ chối absolute path, path thoát base và symlink vượt boundary theo policy rõ ràng. [S4]

### Defense-in-depth

- Chạy process với quyền filesystem tối thiểu.

- Cô lập fixture/container để giảm blast radius.

## 12. Retest

- **Positive:** file allowlisted trong base directory vẫn được đọc.

- **Negative:** path thoát base và absolute path bị từ chối trước open.

- **Boundary:** kiểm tra encoded separator, nhiều lần decode và symlink.

- **Telemetry:** xác nhận resolved path và syscall không chạm file ngoài fixture.

## 13. Sai lầm thường gặp

- Chỉ xóa chuỗi `../` trước khi decode.

- So sánh path dạng chuỗi trước canonicalization.

- Dùng prefix string không có separator boundary.

- Test bằng file hệ thống thật thay vì marker synthetic.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Canonical path:** path sau khi runtime phân giải thành phần tương đối và liên kết theo filesystem. [S4]

- **Containment check:** xác nhận object đã resolve vẫn nằm dưới base directory được phép. [S4]

- **Traversal:** input làm path đích thoát khỏi cây tài nguyên dự kiến. [S4]

## 16. Bài liên quan và đọc thêm

- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** CWE-22. https://cwe.mitre.org/data/definitions/22.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** RFC 3629 — UTF-8, a transformation format of ISO 10646. https://www.rfc-editor.org/rfc/rfc3629.html — phiên bản/ngày: November 2003; truy cập: 2026-07-17.
- **[S4]** OWASP Path Traversal. https://owasp.org/www-community/attacks/Path_Traversal — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
