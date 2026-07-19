---
schema_version: 1
id: WEB-A06-INFORMATION-LEAKAGE
title: "Information Leakage"
slug: information-leakage
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
cwe:
  - CWE-200
  - CWE-538
  - CWE-527
content_status: technical-review
payload_status: none
last_verified: null
---

# Information Leakage

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Information Leakage bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Information Leakage và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang xây dựng một pháo đài để bảo vệ kho báu. Bạn thiết kế các bức tường dày, các cổng sắt kiên cố và trang bị vũ khí tối tân. Thế nhưng, người gác cổng của bạn lại vô tình làm rơi một tấm bản đồ thiết kế chi tiết của pháo đài ngay trước cổng, hoặc vui vẻ trả lời bất kỳ ai hỏi về vị trí của các lối đi bí mật, sơ đồ bố trí quân lính và loại khóa đang dùng. Tình huống này tương tự như lỗi **Rò rỉ thông tin (Information Leakage)** trong phần mềm.

Khi ứng dụng gặp sự cố kỹ thuật, nó sẽ phản hồi bằng một mã trạng thái HTTP (HTTP status codes). Nếu không được cấu hình cẩn thận, hệ thống có thể tạo ra các vết ngăn xếp (**stack trace**) — một danh sách dài các dòng mã nguồn nội bộ mô tả lỗi chi tiết từ đầu đến cuối.

Lỗi này thường xảy ra khi lập trình viên quên tắt **chế độ gỡ lỗi (debug mode)** khi đưa ứng dụng lên môi trường thực tế (production). Chế độ gỡ lỗi giống như việc mở toang cửa kính pháo đài để nhìn rõ mọi hoạt động bên trong trong lúc xây dựng. Nhưng khi pháo đài đã đi vào hoạt động, việc để lộ các thông số kỹ thuật, biến môi trường nhạy cảm hay sơ đồ mã nguồn sẽ biến những nỗ lực bảo mật trước đó thành công cốc.

#### Minh họa hoạt động bình thường (Normal Operation)
```python
# Secure error handling demonstrating production mode with generic responses
import logging
from flask import Flask, jsonify

app = Flask(__name__)

# Configure internal logger for server-side debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In production, debug mode must be disabled
app.config['DEBUG'] = False

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    # Log the detailed stack trace internally for developers
    logger.exception("An unhandled exception occurred: %s", str(error))

    # Return a generic HTTP response status code (500) and safe message to client
    # This prevents stack trace leaking to external users
    response = jsonify({
        "error": "Internal Server Error",
        "message": "A generic error occurred. Please try again later."
    })
    return response, 500
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Rò rỉ thông tin (Information Leakage) xảy ra khi ứng dụng vô tình phơi bày các bí mật công nghệ hoặc dữ liệu nhạy cảm của hệ thống cho những người dùng không có quyền biết.

Các thông tin rò rỉ này có thể là mã lỗi chi tiết, thông tin phiên bản phần mềm, cấu trúc bảng cơ sở dữ liệu, các tệp cấu hình ẩn (như `.git`), hoặc những tệp sao lưu tạm thời mà lập trình viên vô tình bỏ quên trên máy chủ (như `.bak`, `.old`).

Mặc dù bản thân việc rò rỉ thông tin không lập tức làm sập hệ thống hoặc cho phép chiếm quyền điều khiển ngay, nhưng nó lại cung cấp một lượng lớn "tình báo" quý giá. Kẻ tấn công có thể sử dụng thông tin này để vẽ nên bức tranh toàn cảnh về công nghệ của bạn, từ đó tìm kiếm các lỗ hổng đã biết của phiên bản đó để thực hiện các cuộc tấn công phá hoại chính xác và nhanh chóng hơn.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** secret tổng hợp, config, version và debug artifact.
- **Actor, xác thực và role:** anonymous hoặc role user truy cập public/error/static route.
- **Điều kiện khai thác:** debug header, stack trace, source map hoặc artifact lộ dữ liệu nội bộ không cần thiết.
- **Browser, proxy, framework và phiên bản:** Nginx được pin trước Flask/Express production fixture; HTTP loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với information leakage, debug header, stack trace, source map hoặc artifact lộ dữ liệu nội bộ không cần thiết. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Nginx được pin trước Flask/Express production fixture; HTTP loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case information leakage; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một kịch bản/biến đầu vào mô tả ở mục 8; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “debug header, stack trace, source map hoặc artifact lộ dữ liệu nội bộ không cần thiết”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của information leakage; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**1. Khai thác Stack Trace qua thông báo lỗi:**
Kẻ tấn công cố tình nhập các dữ liệu đầu vào không hợp lệ (như truyền ký tự đặc biệt vào tham số ID) để kích hoạt lỗi hệ thống. Trang lỗi chi tiết chứa stack trace của framework (như Django, Express) sẽ phơi bày các thư viện hệ thống đang dùng, phiên bản cụ thể, cấu trúc bảng dữ liệu, và đường dẫn file vật lý trên server.

**2. Lộ lọt thư mục `.git` (Git Directory Exposure):**
Nếu máy chủ web được cấu hình sai và cho phép truy cập trực tiếp vào các tệp ẩn, kẻ tấn công có thể truy cập đường dẫn `https://victim.lab.test/.git/`. Bằng cách tải xuống các tệp tin trong thư mục này (như `.git/index`, `.git/refs/heads/master`, `.git/objects/`), kẻ tấn công có thể khôi phục lại toàn bộ mã nguồn lịch sử commit và tìm thấy các API key hoặc mật khẩu cấu hình từng được commit trước đó.

**3. Rò rỉ tệp sao lưu (Backup File Disclosure):**
Lập trình viên khi chỉnh sửa trực tiếp mã nguồn trên máy chủ thường để lại các tệp sao lưu tự động của editor hoặc tệp đổi tên thủ công (ví dụ: `index.php.bak`, `config.php.old`, `.app.py.swp`, `settings.py~`). Kẻ tấn công sử dụng công cụ fuzzer để quét và tải các file này về, đọc được các bí mật cấu hình và mã nguồn kiểm tra logic.

**4. Rò rỉ qua robots.txt/sitemap:**
File `robots.txt` và `sitemap.xml` được dùng để điều hướng bot tìm kiếm. Tuy nhiên, lập trình viên thường điền các đường dẫn nhạy cảm vào mục `Disallow` (ví dụ: `Disallow: /admin-secret-login/`, `Disallow: /backups/`, `Disallow: /dev/`). Kẻ tấn công đọc tệp này để xác định chính xác các thư mục nhạy cảm cần nhắm tới.

**5. Rò rỉ mã nguồn do lỗi cấu hình máy chủ web:**
Cấu hình sai trên Nginx hoặc Apache có thể khiến máy chủ không chuyển tiếp các yêu cầu tệp script (như `.php`, `.jsp`) đến trình thông dịch xử lý (như PHP-FPM, Tomcat) mà trả về trực tiếp dưới dạng văn bản thuần túy. Kẻ tấn công truy cập trang web và trình duyệt sẽ hiển thị toàn bộ mã nguồn thô của ứng dụng.

## 9. Code dễ bị lỗi và code an toàn

```nginx
# === VULNERABLE CONFIGURATION ===
# Vulnerable Nginx configuration leaking hidden directories and backup files
server {
    listen 80;
    server_name victim.lab.test;
    root /var/www/html;

    # DANGER: No restriction on hidden files or folders
    # Anyone can download http://victim.lab.test/.git/config
    # Anyone can access http://victim.lab.test/config.php.bak
    location / {
        try_files $uri $uri/ =404;
    }

    # DANGER: Misconfigured PHP handler that falls back to plaintext if PHP-FPM is down or misconfigured
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

```nginx
# === SECURE CONFIGURATION ===
# Secure Nginx configuration blocking sensitive files and hiding signatures
server {
    listen 80;
server_name secure-app.lab.test;
    root /var/www/html;

    # SECURE: Hide Nginx version signature from error pages and headers
    server_tokens off;

    location / {
        try_files $uri $uri/ =404;
    }

    # SECURE: Block access to all hidden files and directories (starting with a dot)
    location ~ /\.(?!well-known) {
        deny all;
        access_log off;
        log_not_found off;
    }

    # SECURE: Block access to backup, swap, and temporary development files
    location ~* \.(bak|old|save|swp|orig|temp|tmp|~)$ {
        deny all;
        access_log off;
        log_not_found off;
    }

    # SECURE: Properly configured PHP handler with strict error trapping
    location ~ \.php$ {
        try_files $uri =404; # Prevent execution of non-existent PHP files (mitigates RCE)
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Information Leakage, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Giảm dữ liệu response/artifact và tắt debug/source/config exposure trong production build.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Information Leakage, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Mitigate information disclosure by removing debugging interfaces, disabling stack trace output in production, and scrubbing headers and response metadata.
- **Các bước chi tiết**:
  - Disable developer debug modes, diagnostic pages, and stack trace dumps in production environments.
  - Implement global error handling to display generic, non-informative error messages to public users.
  - Remove unnecessary server signatures and software version information from outgoing HTTP response headers.
  - Scrub metadata (e.g. GPS tags, author info) from file attachments, images, and documents before serving them.
  - Ensure system log configuration does not write sensitive information like credentials, passwords, session tokens, or PII.
  - **Block Access to Hidden Files**: Cấu hình Nginx/Apache để chặn hoàn toàn quyền truy cập vào tất cả các tệp và thư mục ẩn bắt đầu bằng dấu chấm (ví dụ: `.git`, `.env`) và các phần mở rộng tệp sao lưu (`.bak`, `.old`, `.swp`, `~`).
  - **Clean Deployments**: Sử dụng quy trình CI/CD chuyên nghiệp để triển khai ứng dụng, đảm bảo không sao chép thư mục `.git` hoặc các tệp sao lưu tạm thời lên môi trường production.

## 12. Retest

- **Positive case:** với Information Leakage, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Information Leakage mà không xác nhận side effect và log.
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

- **Information Leakage (Rò rỉ thông tin)**: Lỗi xảy ra khi hệ thống tiết lộ các thông tin kỹ thuật nhạy cảm (như stack trace, cấu hình hệ thống, phiên bản phần mềm) cho người dùng không có quyền truy cập, gián tiếp giúp tin tặc dễ dàng tấn công hơn.
- **HTTP Response Status Codes**: Mã số tiêu chuẩn do máy chủ web trả về để thông báo kết quả của một yêu cầu HTTP (ví dụ: `200 OK`, `404 Not Found`, `500 Internal Server Error`).
- **Stack Trace (Vết ngăn xếp)**: Bản ghi chi tiết về đường đi của các lệnh gọi hàm dẫn đến lỗi, hiển thị tên tệp và số dòng code trong chương trình.
- **Debug Mode (Chế độ gỡ lỗi)**: Chế độ chạy ứng dụng cung cấp nhiều thông tin kỹ thuật chi tiết để lập trình viên tìm và sửa lỗi. Chế độ này bắt buộc phải tắt trên môi trường sản xuất (production).
- **Git Directory (`.git`)**: Thư mục ẩn chứa toàn bộ lịch sử quản lý mã nguồn, các nhánh, các cam kết (commit) và có thể chứa cả thông tin cấu hình nhạy cảm nếu không được bảo vệ.
- **Fuzzer**: Công cụ tự động hóa quá trình gửi số lượng lớn các yêu cầu dữ liệu ngẫu nhiên hoặc được chuẩn bị trước đến ứng dụng để phát hiện các tệp tin ẩn, đường dẫn chưa được bảo vệ hoặc các lỗi phần mềm.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-200. https://cwe.mitre.org/data/definitions/200.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE-538. https://cwe.mitre.org/data/definitions/538.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** CWE-527. https://cwe.mitre.org/data/definitions/527.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
