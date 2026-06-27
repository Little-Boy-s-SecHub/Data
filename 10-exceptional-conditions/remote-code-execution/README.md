# Remote Code Execution

> **OWASP Top 10:2025**: A10:2025 – Mishandling of Exceptional Conditions | **CWE**: CWE-94 (Improper Control of Generation of Code) | **Phân loại**: System

## 🧱 Kiến thức Nền tảng
Tấn công Thực thi Mã từ xa (Remote Code Execution - RCE) là một trong những lỗ hổng nguy hại nhất, cho phép kẻ tấn công thực thi các lệnh hệ thống hoặc chạy mã nguồn tùy ý trên máy chủ. Lỗ hổng này thường phát sinh từ thói quen lập trình thiếu an toàn khi sử dụng các tính năng thực thi động. Để phòng chống, lập trình viên cần hiểu rõ cơ chế vận hành của:

1. **Code evaluation (Đánh giá mã nguồn)**: Đây là tính năng cho phép chương trình biên dịch và chạy một chuỗi ký tự (string) trực tiếp như thể nó là mã nguồn thực tế tại thời điểm thực thi. Các hàm này thường nhận đầu vào, chuyển đổi thành cây cú pháp trừu tượng (AST), rồi chạy mã đó trong ngữ cảnh hiện hành của ứng dụng. Nếu dữ liệu đầu vào chứa các hàm hoặc thư viện nguy hiểm (như các hàm gọi hệ thống, đọc ghi file), máy chủ sẽ thực thi chúng dưới quyền của tiến trình hiện tại.
2. **Dynamic execution (Thực thi động qua `eval`/`exec`)**: Các hàm như `eval()` và `exec()` trong Python hoặc JavaScript là ví dụ điển hình của thực thi động. Khác biệt cơ bản là `eval()` thường đánh giá một biểu thức đơn lẻ và trả về kết quả (ví dụ: tính toán biểu thức toán học `"2 + 3"`), trong khi `exec()` thực thi một khối mã nguồn lớn hơn, chứa các câu lệnh khai báo lớp, hàm, vòng lặp và không trả về kết quả trực tiếp. Việc lạm dụng hai hàm này với dữ liệu từ người dùng sẽ mở toang cánh cửa cho RCE. Để thay thế, lập trình viên nên sử dụng các bộ parser cấu trúc an toàn (như thư viện JSON, AST của Python) để phân tích cú pháp thay vì thực thi trực tiếp mã thô.

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Normal operation: Safe evaluation of arithmetic string expressions using AST (no eval/exec)
import ast
import operator

# Map AST operators to standard operators safely
SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg
}

def safe_math_eval(expression_str):
    # Parse the string into an Abstract Syntax Tree safely without executing it
    parsed_tree = ast.parse(expression_str, mode='eval')
    
    def _evaluate(node):
        # Allow only pure mathematical values and operations
        if isinstance(node, ast.Expression):
            return _evaluate(node.body)
        elif isinstance(node, ast.BinOp):
            operator_type = type(node.op)
            if operator_type in SAFE_OPERATORS:
                return SAFE_OPERATORS[operator_type](_evaluate(node.left), _evaluate(node.right))
        elif isinstance(node, ast.UnaryOp):
            operator_type = type(node.op)
            if operator_type in SAFE_OPERATORS:
                return SAFE_OPERATORS[operator_type](_evaluate(node.operand))
        elif isinstance(node, ast.Constant): # Python 3.8+ constant nodes (numbers)
            if isinstance(node.value, (int, float)):
                return node.value
        
        # Reject any other node type (e.g. Call, Attribute, Name) to block code execution
        raise ValueError(f"Unsupported syntax tree element detected: {type(node).__name__}")

    return _evaluate(parsed_tree)

# Normal application run: Safely compute user math input
user_input = "20 * 5 + (4 - 2)"
try:
    result = safe_math_eval(user_input)
    print(f"Calculated result safely: {result}")
except ValueError as e:
    print(f"Rejected expression: {e}")
```

## 🔍 Mô tả lỗ hổng
Thực thi mã từ xa (Remote Code Execution - RCE) là một trong những lỗ hổng nguy hiểm nhất, cho phép kẻ tấn công thực thi trực tiếp các lệnh hệ thống hoặc mã nguồn bất kỳ trên máy chủ. Lỗ hổng thường phát sinh do ứng dụng truyền trực tiếp dữ liệu chưa được làm sạch từ người dùng vào các hàm thực thi động (như eval, exec) hoặc các lệnh hệ điều hành. Kẻ tấn công có thể tận dụng RCE để đọc, xóa file, cài đặt backdoor hoặc chiếm quyền kiểm soát hoàn toàn hệ thống máy chủ.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công phát hiện ứng dụng có chức năng ping địa chỉ IP do người dùng nhập vào, sử dụng lệnh shell hệ điều hành được nối chuỗi động: `os.system("ping -c 1 " + user_input)`.
Bước 2: Kẻ tấn công nhập vào địa chỉ IP kèm theo các ký tự đặc biệt điều khiển shell (như `;`, `&&`, hoặc `|`): `8.8.8.8 ; cat /etc/passwd`.
Bước 3: Máy chủ thực thi chuỗi lệnh nối: `ping -c 1 8.8.8.8 ; cat /etc/passwd`.
Bước 4: Sau khi lệnh ping kết thúc, shell tiếp tục thực thi lệnh thứ hai `cat /etc/passwd` dưới quyền của tiến trình web server và trả kết quả hiển thị file chứa danh sách tài khoản hệ thống cho kẻ tấn công.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Remote Code Execution (RCE) allows attackers to execute arbitrary system commands or code on the hosting server. Mitigation relies on avoiding unsafe dynamic execution functions (e.g., eval, exec), sanitizing and white-listing parameters, using parameterized system APIs, and running applications in sandboxed or containerized environments.
- **Các bước chi tiết**:
  - Never pass raw user inputs to dynamic code execution functions like eval(), exec(), execScript(), or database commands.
  - When spawning system processes, use APIs that pass arguments in an array rather than a single string shell command, to prevent shell expansion.
  - Validate all inputs against a strict allow-list before using them in file paths, commands, or serialization libraries.
  - Isolate processes using sandboxing, containerization (Docker, gVisor), and low-privilege service accounts.

## 💻 Code Example
```python
import subprocess
import ipaddress

def ping_host(user_ip):
    try:
        ipaddress.ip_address(user_ip)
    except ValueError:
        raise ValueError("Invalid IP address")

    result = subprocess.run(["ping", "-c", "1", user_ip], capture_output=True, text=True, shell=False)
    return result.stdout
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Mã nguồn ví dụ sử dụng thư viện ipaddress của Python để kiểm tra nghiêm ngặt dữ liệu đầu vào trước khi truyền vào subprocess, đồng thời khuyến cáo không dùng các hàm eval(), exec() với dữ liệu chưa được làm sạch.
- **Nguồn tham khảo**: OWASP A03:2021, CWE-94
