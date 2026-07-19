---
schema_version: 1
id: WEB-A06-FILE-UPLOAD
title: "File Upload Vulnerabilities"
slug: file-upload
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
  - A06:2025
cwe:
  - CWE-434
  - CWE-22
  - CWE-918
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# File Upload Vulnerabilities

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích File Upload Vulnerabilities bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống File Upload Vulnerabilities và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng hệ thống tải tệp tin (File Upload) của một trang web giống như quầy tiếp nhận bưu phẩm tại một tòa nhà văn phòng. Khách hàng có thể gửi các thùng hàng (các tệp tin) đến cho nhân viên tòa nhà. Nếu người bảo vệ chỉ nhìn lướt qua nhãn dán bên ngoài hộp (như phần mở rộng tệp tin `.jpg`, `.png` hay thuộc tính `Content-Type` do người gửi tự khai báo) để quyết định xem bên trong chứa cái gì, họ sẽ dễ dàng bị lừa. Một kẻ xấu có thể dán nhãn "ảnh gia đình" bên ngoài một chiếc hộp thực chất chứa một quả bom (mã độc).

Magic bytes là chữ ký byte ở đầu tệp giúp loại bỏ một số trường hợp giả mạo phần mở rộng. Đây chỉ là một tín hiệu: ứng dụng vẫn phải dùng parser phù hợp, giới hạn kích thước/độ phức tạp và xử lý tệp theo đúng use case thay vì coi magic bytes là bằng chứng đầy đủ về tính an toàn. [S6]

Bên cạnh đó, việc cất giữ chiếc hộp ở đâu cũng cực kỳ quan trọng. Nếu người bảo vệ cất chiếc hộp ngay tại phòng làm việc chính của ban quản lý (thư mục gốc web - **Web Root**) và cho phép người gửi kích hoạt chiếc hộp từ xa thông qua một đường link URL, tòa nhà sẽ gặp nguy hiểm lớn. Nếu kẻ xấu tải lên một tệp mã nguồn độc hại (như PHP Web Shell) và gọi đến nó, máy chủ web sẽ ngoan ngoãn thực thi các lệnh phá hoại đó. Vì thế, các bưu phẩm tải lên phải luôn được lưu trữ ở một kho biệt lập bên ngoài tòa nhà (ngoài thư mục gốc web hoặc trên các dịch vụ lưu trữ đám mây riêng biệt) và bị tước bỏ hoàn toàn quyền "chạy" (thực thi).

#### Minh họa hoạt động bình thường (Normal Operation)
```python
# Secure file upload validation and storage outside the web root
import os
import uuid
import magic  # Used for checking magic bytes/MIME type accurately

# Define upload directory located outside the web root folder
UPLOAD_DIR = "/var/secure_storage/uploads/"
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "application/pdf"}

def process_uploaded_file(file_stream, client_filename):
    # Read the first 2048 bytes to analyze the magic bytes of the file
    header_data = file_stream.read(2048)
    file_stream.seek(0)  # Reset file pointer after reading header

    # Detect the actual MIME type based on the file content (magic bytes)
    detected_mime = magic.from_buffer(header_data, mime=True)

    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError("Security violation: Unsupported file format detected via magic bytes")

    # Map the detected type to a server-controlled extension.
    extension_by_mime = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "application/pdf": ".pdf",
    }

    # A random name avoids trusting the client filename; storage and execution
    # policy remain the controls that prevent traversal and code execution.
    secure_filename = f"{uuid.uuid4().hex}{extension_by_mime[detected_mime]}"

    # Save the file in the non-executable directory outside web root
    save_path = os.path.join(UPLOAD_DIR, secure_filename)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    with open(save_path, 'wb') as dest_file:
        dest_file.write(file_stream.read())

    return secure_filename
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Tải tệp tin (File Upload Vulnerabilities) xuất hiện khi hệ thống mở cửa cho người dùng tải tệp lên nhưng lại thiếu sự kiểm soát chặt chẽ, giống như việc nhận bưu phẩm mà không qua kiểm tra an ninh.

Điều này cho phép kẻ tấn công tải lên các tệp mã độc (web shell) để điều khiển máy chủ từ xa, hoặc gửi các tệp nén độc hại để ghi đè vào các file hệ thống quan trọng. Chúng thậm chí có thể lợi dụng ứng dụng để thực hiện các cuộc tấn công gián tiếp như SSRF (lừa máy chủ kết nối tới các dịch vụ nội bộ nhạy cảm) hay chèn mã độc JavaScript vào các tệp ảnh (như SVG) để tấn công những người dùng khác khi họ xem ảnh. Mối nguy hiểm của lỗ hổng này rất lớn, thường dẫn tới việc máy chủ bị kiểm soát hoàn toàn (RCE) hoặc rò rỉ dữ liệu nghiêm trọng.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** storage, archive/image processor và origin phục vụ upload.
- **Actor, xác thực và role:** role user upload/import; user khác xem asset tổng hợp.
- **Điều kiện khai thác:** server tin extension, MIME, archive path, remote URL hoặc active-content origin.
- **Browser, proxy, framework và phiên bản:** Python 3.12, ZIP/ImageMagick fixture và Chromium được pin; object storage loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với file upload, server tin extension, MIME, archive path, remote URL hoặc active-content origin. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Python 3.12, ZIP/ImageMagick fixture và Chromium được pin; object storage loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case file upload; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “server tin extension, MIME, archive path, remote URL hoặc active-content origin”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của file upload; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**1. Tấn công Web Shell cơ bản:**
Kẻ tấn công tắt kiểm tra phía client và tải lên tệp PHP (`hack.php`) chứa hàm thực thi lệnh. Do máy chủ không đổi tên file và lưu trực tiếp trong thư mục web, kẻ tấn công có thể gọi lệnh trực tiếp qua URL.

**2. ImageTragick (CVE-2016-3714):**
Kẻ tấn công khai thác lỗ hổng trong thư viện xử lý ảnh phổ biến (như ImageMagick). Attacker tải lên tệp tin có đuôi là `.png` hoặc `.jpg` nhưng thực chất chứa mã nguồn định dạng MVG (Magick Vector Graphics) độc hại nhằm kích hoạt thực thi lệnh hệ thống (RCE) khi thư viện tiến hành chuyển đổi/render ảnh.
*Ví dụ payload MVG:*
<!-- payload-id: WEB-A06-FILE-UPLOAD-001 -->
<!-- context: ImageMagick 6.9.3-9/7.0.1-0 vulnerable fixture; MVG delegate processing -->
<!-- prerequisites: disposable container; no outbound network; vulnerable delegate configuration reproduced locally -->
<!-- encoding: UTF-8 MVG; double quotes are balanced and the delegate argument is confined to the disposable fixture -->
<!-- expected-result: fixture creates only /tmp/imagemagick-lab-marker; no shell is downloaded or opened -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
```mvg
push graphic-context
viewbox 0 0 640 480
fill 'url(http://127.0.0.1:9001/image.png";printf IMAGEMAGICK_LAB >/tmp/imagemagick-lab-marker")'
pop graphic-context
```

**3. Zip Slip (Path Traversal qua giải nén):**
Khi ứng dụng giải nén archive mà không kiểm tra đường dẫn đích canonical, một entry chứa thành phần đi lên thư mục có thể thoát khỏi extraction root. Lesson không phát hành archive traversal cụ thể; fixture chỉ dùng entry marker tổng hợp và xác nhận bản sửa từ chối trước khi ghi file.

**4. Polyglot Files (GIF + PHP):**
Một file có thể thỏa kiểm tra signature nông nhưng vẫn chứa nội dung khác sau header. Lesson chỉ dùng byte marker vô hại để chứng minh kiểm tra magic-byte riêng lẻ không đủ; upload volume phải non-executable và file phải được decode/re-encode bằng thư viện phù hợp.

**5. SSRF via Upload URL (Tải tệp qua liên kết):**
Khi ứng dụng hỗ trợ "Import from URL", một URL tùy ý có thể khiến server truy cập dịch vụ mà người dùng không thể gọi trực tiếp. Trong lab, chỉ dùng mock read-only `http://127.0.0.1:9002/fixtures/metadata` trả dữ liệu giả; không gọi metadata cloud thật hoặc endpoint thay đổi trạng thái.

**6. SVG XSS (Stored XSS qua SVG):**
Ảnh định dạng SVG (Scalable Vector Graphics) thực chất là một tài liệu XML. Kẻ tấn công có thể chèn một thẻ `<script>` chứa mã độc JavaScript vào trong tệp SVG.
*Ví dụ payload SVG:*
<!-- payload-id: WEB-A06-FILE-UPLOAD-002 -->
<!-- context: SVG served by the upload fixture and opened as a top-level document in pinned Chromium -->
<!-- prerequisites: synthetic origin only; no session cookie or sensitive data; outbound network disabled -->
<!-- encoding: UTF-8 XML/SVG with inline JavaScript -->
<!-- expected-result: direct top-level rendering on the vulnerable fixture shows one alert; attachment or isolated-origin delivery does not execute in the application origin -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```
Việc script có thực thi và có cùng origin với ứng dụng hay không phụ thuộc cách phân phối, `Content-Type`, `Content-Disposition`, `nosniff`, sandbox và browser. Chỉ kết luận stored XSS khi browser harness chứng minh SVG được render trong origin mang phiên ứng dụng; tải xuống dạng attachment hoặc phục vụ từ origin cô lập làm thay đổi kết quả.

## 9. Code dễ bị lỗi và code an toàn

```python
# === VULNERABLE CODE ===
import zipfile
import os
import requests

# 1. Vulnerable to Zip Slip (No validation on path traversal inside zip entries)
def extract_zip_unsafe(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # DANGER: Directly joining target path without checking directory escape (../)
            target_path = os.path.join(extract_dir, member.filename)
            zip_ref.extract(member, extract_dir)

# 2. Vulnerable to SSRF via Upload URL (No check for private IP ranges)
def upload_from_url_unsafe(url):
    # DANGER: Allows user to specify internal URLs like http://127.0.0.1 or metadata servers
    response = requests.get(url, timeout=5)
    file_content = response.content
    save_file(file_content)
```

```python
# === SECURE CODE ===
import zipfile
import os
import requests

# 1. Secure Zip Extraction (Zip Slip Prevention)
def extract_zip_secure(zip_path, extract_dir):
    # Get absolute canonical path of the target directory
    extract_dir = os.path.abspath(extract_dir)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # SECURE: Resolve target path and verify it stays inside target directory
            target_path = os.path.abspath(os.path.join(extract_dir, member.filename))

            # Check if resolved path starts with the extract directory path
            if not target_path.startswith(extract_dir + os.sep):
                raise ValueError("Security violation: Directory traversal attempt detected in ZIP!")

            zip_ref.extract(member, extract_dir)

# 2. Secure remote import: users select an application-owned source ID,
# not an arbitrary URL. The egress proxy independently enforces the same
# origin/IP allowlist after DNS resolution and on every connection.
TRUSTED_IMPORT_URLS = {
    "avatar-template": "http://127.0.0.1:9003/avatar.png",
}
MAX_IMPORT_BYTES = 2 * 1024 * 1024

def upload_from_trusted_source(source_id):
    url = TRUSTED_IMPORT_URLS.get(source_id)
    if url is None:
        raise ValueError("Unknown import source")

    with requests.get(
        url,
        timeout=(2, 5),
        allow_redirects=False,
        stream=True,
    ) as response:
        # Never revalidate only the first hop and then follow a redirect.
        if 300 <= response.status_code < 400:
            raise ValueError("Redirects are not allowed")
        response.raise_for_status()

        content = bytearray()
        for chunk in response.iter_content(64 * 1024):
            content.extend(chunk)
            if len(content) > MAX_IMPORT_BYTES:
                raise ValueError("Remote file is too large")
        save_file(bytes(content))
```

Chỉ kiểm tra IP một lần rồi gọi lại hostname bằng `requests.get()` vẫn để lại khoảng trống DNS rebinding; tự động theo redirect cũng có thể chuyển sang địa chỉ nội bộ. Mẫu an toàn loại URL tùy ý khỏi input, tắt redirect và yêu cầu egress proxy kiểm tra destination trên kết nối thực tế. [S5]

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến File Upload Vulnerabilities, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Xác minh content allowlist, lưu ngoài webroot thực thi, canonicalize extraction và cô lập origin.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với File Upload Vulnerabilities, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Secure file uploads by validating file extensions and MIME-types, renaming uploads randomly, and storing them outside the web root on non-executable folders.
- **Các bước chi tiết**:
  - Validate file types using strict lists of allowed extensions and verify file headers/magic bytes to confirm the true file format.
  - Bỏ tên tệp do client cung cấp khỏi đường dẫn lưu; sinh tên phía server và ánh xạ phần mở rộng từ loại tệp đã xác minh. UUID chỉ hỗ trợ tránh va chạm/đoán tên, không thay thế canonical-path check hoặc chính sách không thực thi.
  - Store uploaded files in a separate directory or third-party storage (like AWS S3) entirely outside the web application root.
  - Disable execution permissions (PHP, ASP, CGI, script engines) on the directories hosting user uploads.
  - Enforce strict file size limits to prevent Denial of Service through disk space exhaustion.
  - **Zip Slip Defense**: Khi giải nén, luôn chuẩn hóa đường dẫn giải nén (canonical path) và kiểm tra xem nó có bắt đầu bằng thư mục đích (destination directory) được cấu hình trước hay không.
  - **SVG XSS Defense**: Cấm SVG nếu use case không cần; nếu cần, dùng bộ xử lý XML được duy trì để áp dụng allowlist phần tử/thuộc tính và phục vụ từ origin cách ly. Không coi lọc một tên phần tử hoặc một event attribute là đủ. [S6]
  - Phục vụ tệp không tin cậy từ origin không mang cookie ứng dụng; với tệp chỉ để tải xuống, đặt `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` và `Content-Type` đã xác minh. Các header này hỗ trợ phân phối an toàn nhưng không thay thế kiểm tra định dạng, lưu ngoài web root và chính sách không thực thi.
  - **SSRF Defense**: Chỉ cho phép tải từ URL thuộc danh sách domain đáng tin cậy (whitelist), chặn tất cả các địa chỉ IP nội bộ (private/loopback ranges).

## 12. Retest

- **Positive case:** với File Upload Vulnerabilities, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của File Upload Vulnerabilities mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

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

- **Magic Bytes**: Chữ ký byte thường nằm ở đầu tệp, hữu ích để nhận diện sơ bộ định dạng nhưng không chứng minh toàn bộ tệp hợp lệ hoặc an toàn để parser xử lý.
- **MIME Type (Multipurpose Internet Mail Extensions)**: Chuỗi ký tự định nghĩa loại dữ liệu của tệp (ví dụ: `image/jpeg`), được truyền trong header HTTP để trình duyệt biết cách xử lý tệp.
- **Web Root Folder**: Thư mục trên máy chủ chứa toàn bộ mã nguồn và tài nguyên công khai của trang web, nơi người dùng ngoài Internet có thể truy cập trực tiếp bằng URL.
- **Web Shell**: Một tệp mã độc (viết bằng PHP, ASPX, v.v.) được tải lên máy chủ web, cho phép kẻ tấn công thực thi lệnh hệ thống và kiểm soát máy chủ từ xa thông qua giao diện web.
- **RCE (Remote Code Execution)**: Lỗ hổng cho phép kẻ tấn công thực thi các câu lệnh hoặc mã nguồn tùy ý trên máy chủ mục tiêu từ xa.
- **SSRF (Server-Side Request Forgery)**: Lỗ hổng xảy ra khi kẻ tấn công có thể ép máy chủ web gửi các yêu cầu mạng được tạo ra bởi máy chủ đó tới các hệ thống nội bộ hoặc bên ngoài.
- **Stored XSS (Stored Cross-Site Scripting)**: Lỗ hổng xảy ra khi mã độc JavaScript được lưu trữ trực tiếp trên cơ sở dữ liệu của máy chủ, sau đó tự động thực thi trên trình duyệt của bất kỳ người dùng nào truy cập vào trang web chứa mã độc đó.

## 16. Bài liên quan và đọc thêm

- [LFI/RFI](../../05-injection/lfi-rfi/) — Cho phép kẻ tấn công thực thi mã độc hoặc đọc tệp tin cục bộ sau khi đã tải thành công tệp tin lên hệ thống.
- [Command Execution](../../05-injection/command-execution/) — Sử dụng các tệp tin tải lên (ví dụ: web shell) làm bàn đạp để thực thi lệnh hệ thống trực tiếp trên máy chủ.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-434. https://cwe.mitre.org/data/definitions/434.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-22. https://cwe.mitre.org/data/definitions/22.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** CWE-918. https://cwe.mitre.org/data/definitions/918.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** OWASP Server-Side Request Forgery Prevention Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S6]** OWASP File Upload Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
