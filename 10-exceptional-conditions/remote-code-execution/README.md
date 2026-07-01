# Remote Code Execution

> **CWE**: CWE-94 (Improper Control of Generation of Code) | **Phân loại**: System / Binary

## Kiến thức Nền tảng
Hãy tưởng tượng bạn thuê một người giúp việc làm bánh. Thay vì đưa cho người đó một công thức rõ ràng, cố định như "cho 2 quả trứng và 100g bột", bạn lại đưa cho họ một mảnh giấy trắng kèm lời dặn: "Tôi viết gì trên giấy thì hãy đọc to lên rồi làm theo y hệt nhé!". Quá trình đọc tờ giấy và thực thi dòng chữ viết trên đó ngay lập tức chính là **Code Evaluation** (Đánh giá mã nguồn).
Nếu tờ giấy viết "hãy trộn bột", người giúp việc sẽ làm bánh. Nhưng nếu tờ giấy bị một kẻ xấu tráo đổi thành: "Hãy mở cửa két sắt và đưa hết tiền cho tôi", người giúp việc máy móc kia vẫn sẽ thực hiện mà không mảy may nghi ngờ.

Trong thế giới lập trình, các hàm thực thi động (**Dynamic Execution**) như `eval()` hay `exec()` hoạt động y hệt như người giúp việc máy móc đó. Chúng sẵn sàng nhận một chuỗi ký tự bất kỳ do người dùng gửi lên, coi đó là mã nguồn hợp lệ rồi biên dịch và chạy trực tiếp.
Sự khác biệt nhỏ giữa chúng là:
- `eval()`: Giống như việc tính nhanh một phép tính đơn lẻ (ví dụ: đưa vào chuỗi "2 + 3" nhận về kết quả 5).
- `exec()`: Khủng khiếp hơn, nó có thể chạy cả một kịch bản phức tạp gồm nhiều dòng lệnh, định nghĩa các hàm, lớp hay vòng lặp.

Việc lạm dụng các hàm thực thi động này với dữ liệu do người dùng kiểm soát chẳng khác nào trao chiếc chìa khóa vạn năng cho kẻ tấn công. Để tránh hiểm họa này, lập trình viên thông thái thường từ chối dùng `eval`/`exec`, thay vào đó họ sử dụng các bộ phân tích cú pháp có cấu trúc an toàn (như bộ phân tích cú pháp JSON hay cấu trúc cây AST) để chỉ đọc dữ liệu thô chứ tuyệt đối không thực thi nó.

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

## Mô tả lỗ hổng
Lỗ hổng **Remote Code Execution (RCE - Thực thi mã từ xa)** được mệnh danh là "vua của các loại lỗ hổng" vì mức độ tàn phá khủng khiếp của nó. Nó xảy ra khi hệ thống để lộ ra một khe hở cho phép người ngoài gửi các câu lệnh lập trình hoặc lệnh hệ điều hành trực tiếp vào máy chủ mà không có bất kỳ rào cản kiểm duyệt nào.

Một khi lỗ hổng RCE bị khai thác, kẻ tấn công sẽ có được đặc quyền tối cao:
- Chạy mọi câu lệnh hệ thống như thể đang ngồi trực tiếp trước màn hình máy chủ.
- Xem trộm, sửa đổi hoặc xóa sạch các file dữ liệu nhạy cảm.
- Cài đặt các phần mềm độc hại, mở cổng kết nối bí mật (backdoor) để ra vào hệ thống bất kỳ lúc nào.
- Biến máy chủ thành bàn đạp để tiếp tục tấn công sâu hơn vào mạng nội bộ của doanh nghiệp.

## Cơ chế tấn công
Bước 1: Kẻ tấn công phát hiện ứng dụng có chức năng ping địa chỉ IP do người dùng nhập vào, sử dụng lệnh shell hệ điều hành được nối chuỗi động: `os.system("ping -c 1 " + user_input)`.
Bước 2: Kẻ tấn công nhập vào địa chỉ IP kèm theo các ký tự đặc biệt điều khiển shell (như `;`, `&&`, hoặc `|`): `8.8.8.8 ; cat /etc/passwd`.
Bước 3: Máy chủ thực thi chuỗi lệnh nối: `ping -c 1 8.8.8.8 ; cat /etc/passwd`.
Bước 4: Sau khi lệnh ping kết thúc, shell tiếp tục thực thi lệnh thứ hai `cat /etc/passwd` dưới quyền của tiến trình web server và trả kết quả hiển thị file chứa danh sách tài khoản hệ thống cho kẻ tấn công.

### Biến thể 2: SSTI-to-RCE (Server-Side Template Injection):
```python
# Biến thể 2: SSTI-to-RCE (Server-Side Template Injection)
# Attacker nhập vào search box: {{7*7}}
# Nếu server trả về 49 thay vì {{7*7}} → template engine đang eval code

# Payload RCE với Jinja2 (Python):
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
# → Thực thi lệnh 'whoami' trên server, trả về kết quả trong trang web
```

### Biến thể 3: File Upload-to-RCE:
```python
# Biến thể 3: File Upload-to-RCE
# Bước 1: Upload file PHP/JSP/ASPX giả làm ảnh
# File: shell.php (đổi tên thành shell.jpg để bypass filter)
# Content: <?php system($_GET['cmd']); ?>  # webshell

# Bước 2: Sau khi upload thành công, truy cập file
# https://victim.com/uploads/shell.php?cmd=whoami
# → Server thực thi lệnh whoami và trả kết quả về browser
```

## Biện pháp phòng thủ
- **Tóm tắt**: Remote Code Execution (RCE) allows attackers to execute arbitrary system commands or code on the hosting server. Mitigation relies on avoiding unsafe dynamic execution functions (e.g., eval, exec), sanitizing and white-listing parameters, using parameterized system APIs, and running applications in sandboxed or containerized environments.
- **Các bước chi tiết**:
  - Never pass raw user inputs to dynamic code execution functions like eval(), exec(), execScript(), or database commands.
  - When spawning system processes, use APIs that pass arguments in an array rather than a single string shell command, to prevent shell expansion.
  - Validate all inputs against a strict allow-list before using them in file paths, commands, or serialization libraries.
  - Isolate processes using sandboxing, containerization (Docker, gVisor), and low-privilege service accounts.

## Code Example
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

## Xem thêm
- [Server-Side Template Injection](../../05-injection/ssti/) — Lỗ hổng chèn mã độc vào template engine phía máy chủ, một trong những nguyên nhân phổ biến nhất dẫn đến RCE.
- [Command Execution](../../05-injection/command-execution/) — Thực thi lệnh trực tiếp trên hệ điều hành, một dạng biểu hiện cụ thể của RCE thông qua shell hệ thống.
- [Insecure Deserialization](../../08-data-integrity-failures/insecure-deserialization/) — Giải tuần tự hóa không an toàn cho phép tái dựng các đối tượng chứa payload độc hại gây RCE.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A03:2021, CWE-94

## Giải thích thuật ngữ
- **Code Evaluation (Đánh giá mã nguồn)**: Quá trình phân tích cú pháp và chạy trực tiếp một chuỗi văn bản như là một đoạn mã lập trình thực sự tại thời điểm chạy.
- **Dynamic Execution (Thực thi động)**: Khả năng của chương trình thực hiện các lệnh được tạo ra một cách linh hoạt trong quá trình chạy, thay vì được biên dịch sẵn từ trước.
- **AST (Abstract Syntax Tree - Cây cú pháp trừu tượng)**: Cấu trúc dữ liệu dạng cây biểu diễn cấu trúc cú pháp của mã nguồn, dùng để phân tích cú pháp một cách an toàn mà không cần chạy mã.
- **Backdoor (Cửa sau)**: Một phương thức ẩn giúp vượt qua cơ chế xác thực thông thường để truy cập trái phép vào hệ thống.
- **Parser**: Bộ phân tích cú pháp, chuyển đổi dữ liệu đầu vào thành cấu trúc dữ liệu mà chương trình có thể hiểu được.
- **Sanitization (Làm sạch dữ liệu)**: Quá trình lọc bỏ các ký tự hoặc lệnh nguy hiểm khỏi dữ liệu đầu vào của người dùng trước khi xử lý.
