# Command Execution

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-78 | **Phân loại**: Injection

## 🧱 Kiến thức Nền tảng
Môi trường Shell của hệ điều hành (OS Shell) là một giao diện dòng lệnh cho phép người dùng hoặc ứng dụng tương tác trực tiếp với nhân hệ điều hành thông qua các lệnh. Khi một ứng dụng thực thi một lệnh thông qua shell, shell đó sẽ diễn giải và xử lý các ký tự đặc biệt gọi là shell metacharacters (như `;`, `&`, `|`, `$()`, `` ` ``). Các ký tự này có chức năng điều khiển luồng, nối lệnh, chuyển hướng đầu vào/đầu ra hoặc nội suy biến môi trường. Ví dụ, dấu `;` ngăn cách các câu lệnh độc lập để thực hiện tuần tự, còn `|` chuyển hướng đầu ra của lệnh trước làm đầu vào cho lệnh sau.

Lỗ hổng Command Execution phát sinh khi ứng dụng nối chuỗi dữ liệu không tin cậy của người dùng trực tiếp vào lệnh hệ thống được thực thi qua shell. Kẻ tấn công có thể chèn các metacharacters để kết thúc lệnh hiện tại và bắt đầu một lệnh mới tùy ý dưới đặc quyền của ứng dụng. Để phòng ngừa lỗ hổng này, lập trình viên cần tránh sử dụng shell để thông dịch lệnh. Thay vào đó, ta sử dụng cơ chế subprocess spawning (khởi tạo tiến trình con) trực tiếp thông qua API của hệ thống (ví dụ: `execve` trong Unix, `CreateProcess` trong Windows). Với cơ chế này, ứng dụng khởi chạy trực tiếp tệp thực thi của chương trình mong muốn mà không thông qua trình thông dịch shell (`shell=False`). Các tham số đầu vào được truyền dưới dạng một danh sách riêng biệt. Hệ điều hành sẽ ánh xạ trực tiếp các tham số này vào mảng đối số của tiến trình mới, khiến shell metacharacters mất tác dụng và chỉ được coi là các đối số văn bản thông thường.

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

## 🔍 Mô tả lỗ hổng
Các lỗ hổng thực thi lệnh (command execution) phát sinh khi một ứng dụng nối đầu vào không đáng tin cậy của người dùng trực tiếp vào các lệnh hệ thống được thực thi bởi một shell của hệ điều hành. Điều này cho phép kẻ tấn công thêm vào các ký tự siêu (metacharacters) của shell và chạy các lệnh tùy ý với đặc quyền của tiến trình ứng dụng web.

## ⚔️ Cơ chế tấn công
Một ứng dụng web thực hiện tra cứu tên miền bằng cách truyền một tham số yêu cầu GET trực tiếp vào system("nslookup {$domain}"). Kẻ tấn công thêm một dấu chấm phẩy và một lệnh shell (ví dụ: domain=google.com; cat /etc/passwd) để lừa máy chủ thực hiện việc tra cứu trước, sau đó đọc và trả về tệp mật khẩu của máy chủ.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Tránh gọi trực tiếp shell của hệ điều hành. Sử dụng các thư viện dựa trên API, hạn chế định dạng đối số, và truyền các đầu vào dưới dạng phần tử của mảng.
- **Các bước chi tiết**:
  - Tránh các cuộc gọi shell hệ thống; sử dụng các hàm API gốc tương đương (như subprocess.run của Python với shell=False) trong đó các đối số được truyền dưới dạng một danh sách (mảng).
  - Triển khai danh sách trắng (whitelist) nghiêm ngặt để xác thực rằng các đầu vào chỉ chứa các ký tự mong đợi (ví dụ: chỉ chứa chữ và số).
  - Nếu việc thực thi shell là không thể tránh khỏi, hãy thoát (escape) các đầu vào của người dùng bằng cách sử dụng các hàm thoát gốc (như escapeshellarg trong PHP).
  - Chạy tiến trình máy chủ web dưới một tài khoản người dùng có đặc quyền thấp để hạn chế tác động của việc thực thi lệnh.

## 💻 Code Example
```python
# Python subprocess API call passing parameters securely as list (shell=False)
import subprocess
import re

def run_safe_ping(user_input_ip):
    # Validate IP address format first
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', user_input_ip):
        raise ValueError("Invalid IP address format")
        
    # Safe: Passing arguments as a list. Python runs /bin/ping directly without invoking a shell.
    result = subprocess.run(["ping", "-c", "1", user_input_ip], 
                            capture_output=True, 
                            text=True, 
                            shell=False) # shell=False is default but explicitly shown here for security
    return result.stdout
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lỗi một mẫu thực thi lệnh PHP chứa các dòng đầu ra trùng lặp (echo($lookup) ngay sau system()). Đã chuyển đổi tệp mục tiêu không thực tế từ /etc/shadow (thường chỉ dành cho root) thành /etc/passwd để phản ánh một kịch bản khai thác thực tế.
- **Nguồn tham khảo**: OWASP A03:2021-Injection, CWE-78 (OS Command Injection)
