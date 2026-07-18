---
schema_version: 1
id: WEB-A05-CODE-INJECTION
title: "Code Injection"
slug: code-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-94
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Code Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Code Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Đọc được biểu thức, callable và namespace trong Python 3.12, JavaScript hoặc PHP.
- Phân biệt parser cú pháp với evaluator thực thi code và nhận diện dữ liệu đi qua trust boundary.
- Biết các node cơ bản của Python AST và cách viết test cho một ngữ pháp phép tính allowlist.
- Có calculator fixture trên loopback, không mount secret và đã tắt outbound network.

## 3. Kiến thức nền tảng

Các API đánh giá động như Python `eval()`, JavaScript `eval()` và PHP `eval()` phân tích chuỗi như mã của ngôn ngữ tương ứng. Nếu chuỗi chịu ảnh hưởng của input không tin cậy, code đó chạy với quyền và phạm vi mà runtime cung cấp cho lời gọi. Đây là code injection; OS command injection là trường hợp khác, nơi input làm thay đổi lệnh được chuyển tới hệ điều hành hoặc shell. [S1] [S2] [S3]

```python
# Simple calculator — legitimate use of eval (still risky)
expression = "2 + 3 * 4"
result = eval(expression)  # Returns 14
print(f"Result: {result}")
```

## 4. Mô tả và nguyên nhân gốc

Root cause là dữ liệu không tin cậy vượt trust boundary và được runtime diễn giải như code thay vì dữ liệu. Tác động phụ thuộc các object, module, file, network và quyền hệ điều hành mà tiến trình thực sự có; không được suy ra RCE hoặc đọc secret chỉ từ việc một biểu thức số được đánh giá. [S2] [S3]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** tiến trình runtime, secret và dữ liệu ứng dụng mà tiến trình truy cập được.

- **Actor:** người dùng public hoặc role user gửi biểu thức; họ không có tài khoản hệ điều hành.

- **Điều kiện khai thác:** biểu thức không tin cậy đi vào evaluator và được diễn giải như code. [S1] [S5] [S6]

- **Runtime:** fixture pin Python 3.12, Node.js 20 và PHP 8.3 trên loopback; bài không suy rộng kết quả giữa các evaluator.

- **Evidence:** lưu input, sink đã gọi và marker trả về; phép tính `2+2` không chứng minh code injection.

## 6. Cơ chế tấn công

Đối với code injection, biểu thức không tin cậy đi vào `eval()` hoặc API tương đương và được diễn giải như code. Positive case phải chứng minh input đến đúng sink và tạo marker không thuộc ngữ pháp phép tính; negative case phải bị parser allowlist từ chối. Kết luận chỉ áp dụng cho runtime được pin ở mục 5. [S1] [S5] [S6]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy fixture Python 3.12/Flask 3.x và Node.js 20/Express 4.x trên loopback; không cần browser; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case code injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “biểu thức không tin cậy đi vào eval/Function và được diễn giải như code”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của code injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block chưa có runtime evidence; chỉ chạy trong đúng context đã annotation.

**Python eval() exploitation**:

<!-- claim-source: [S1] -->
<!-- payload-id: WEB-A05-CODE-INJECTION-001 -->
<!-- context: Python 3.12 expression passed to eval() in an isolated calculator fixture -->
<!-- prerequisites: loopback-only fixture; no filesystem or network access required -->
<!-- encoding: query component is percent-encoded once as UTF-8; Python source uses literal ASCII quotes and underscores -->
<!-- expected-result: response contains CODE_INJECTION_LAB, proving non-arithmetic code evaluation -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S5 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable calculator endpoint
user_input = request.args.get('expr')
result = eval(user_input)

# Harmless lab input that invokes a non-arithmetic callable:
# expr=__import__('builtins').str('CODE_INJECTION_LAB')
```

**JavaScript eval() exploitation**:

<!-- claim-source: [S5] -->
<!-- payload-id: WEB-A05-CODE-INJECTION-002 -->
<!-- context: Node.js 20.x Express calculator fixture using direct eval() -->
<!-- prerequisites: loopback-only fixture; no filesystem or network access required -->
<!-- encoding: URLSearchParams percent-encodes String('CODE_INJECTION_LAB') once in UTF-8 -->
<!-- expected-result: response contains CODE_INJECTION_LAB instead of an arithmetic result -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// Vulnerable template processing
app.get('/calc', (req, res) => {
    let expr = req.query.expr;
    let result = eval(expr);  // DANGER: Direct eval of user input
    res.send(`Result: ${result}`);
});

// Harmless lab input that is valid JavaScript but not arithmetic:
// /calc?expr=String('CODE_INJECTION_LAB')
```

**PHP eval() exploitation**:

<!-- claim-source: [S6] -->
<!-- payload-id: WEB-A05-CODE-INJECTION-003 -->
<!-- context: PHP 8.3 calculator fixture using eval() -->
<!-- prerequisites: loopback-only fixture; no filesystem or network access required -->
<!-- encoding: code query value is UTF-8 and percent-encoded once, including parentheses and quotes -->
<!-- expected-result: response prints CODE_INJECTION_LAB, proving arbitrary PHP statements are evaluated -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```php
<?php
// Vulnerable dynamic code execution
$code = $_GET['code'];
eval($code);  // DANGER: Arbitrary PHP execution

// Harmless lab input:
// ?code=print('CODE_INJECTION_LAB');
?>
```

## 9. Code dễ bị lỗi và code an toàn

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

## 10. Phát hiện

- Tìm `eval`, `exec`, `Function` và API biên dịch động; truy ngược dữ liệu từ request, queue hoặc datastore.

- Ghi loại AST được chấp nhận hoặc từ chối, nhưng không ghi nguyên biểu thức có thể chứa dữ liệu nhạy cảm.

- Cảnh báo khi calculator nhận identifier, attribute, call hoặc node ngoài số và toán tử được phép.

- Marker phải cho thấy evaluator đã gọi code ngoài ngữ pháp phép tính; lỗi HTTP 500 không đủ để kết luận.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Loại bỏ thực thi động; dùng parser hoặc AST allowlist chỉ hỗ trợ ngữ pháp phép tính cần thiết.

- Từ chối mọi node ngoài allowlist, gồm call, attribute, subscript, name và comprehension. [S2] [S3]

### Defense-in-depth

- Chạy calculator không đặc quyền, không mount secret và không cho outbound network để giảm tác động nếu parser lỗi. [S3]

- Đặt giới hạn chiều dài, độ sâu AST, CPU và thời gian để một biểu thức hợp lệ không chiếm tài nguyên quá mức.

- Nếu nghiệp vụ thật sự cần chạy code do người dùng cung cấp, dùng ranh giới cô lập được thiết kế cho hostile code và vẫn coi đó là bề mặt rủi ro; container đơn lẻ không thay thế việc loại bỏ sink nguy hiểm. [S3]

## 12. Retest

- **Positive case:** `2 + 3 * 4` vẫn trả `14` qua chính parser allowlist dùng trong bản sửa.
- **Negative case:** `__import__('builtins').str('CODE_INJECTION_LAB')` bị từ chối trước khi bất kỳ callable nào được gọi.
- **Boundary case:** thử số âm, phép chia cho 0, biểu thức rỗng, số rất lớn, AST lồng sâu và node `Name`/`Attribute`/`Call`.
- **Telemetry:** log chỉ ra node bị từ chối và route tương ứng; không có file, process hoặc network side effect trong fixture.
- **Regression:** chạy cùng bộ test trực tiếp với `safe_eval()` và qua endpoint để tránh trường hợp route khác vẫn gọi `eval()`.

## 13. Sai lầm thường gặp

- Dùng regex để “lọc ký tự nguy hiểm” rồi vẫn chuyển chuỗi còn lại vào evaluator.

- Cho phép toàn bộ `ast.Name` hoặc `ast.Attribute` vì tưởng rằng parse AST đồng nghĩa với an toàn.

- Xóa `eval()` ở endpoint chính nhưng bỏ sót worker, rule engine hoặc template helper dùng cùng dữ liệu.

- Kết luận RCE chỉ vì biểu thức số được tính đúng; phép thử phải vượt ngoài ngữ pháp nghiệp vụ bằng marker vô hại.

- Coi giảm quyền hoặc chạy trong container là bản sửa cho việc diễn giải input không tin cậy như code.

## 14. Tóm tắt và checklist

- [ ] Đã xác định chính xác input nào tới `eval` hoặc evaluator tương đương.
- [ ] Probe chỉ gọi callable vô hại và không truy cập file, process hay network.
- [ ] Parser sửa lỗi chỉ cho phép literal số và các toán tử nghiệp vụ đã liệt kê.
- [ ] Test từ chối `Name`, `Attribute`, `Call`, `Subscript` và AST vượt giới hạn.
- [ ] Calculator hợp lệ vẫn cho kết quả đúng sau khi loại bỏ dynamic evaluation.
- [ ] Runtime, source và trạng thái static của từng payload được ghi đúng thực tế.

## 15. Giải thích thuật ngữ

- **Code Injection**: Lỗ hổng cho phép kẻ tấn công chèn và thực thi mã độc trong ngữ cảnh của ngôn ngữ lập trình.
- **Dynamic Code Evaluation**: Khả năng thực thi các chuỗi ký tự như mã nguồn tại thời điểm chạy (runtime).
- **RCE (Remote Code Execution)**: Khả năng thực thi code từ xa; đây có thể là tác động của code injection nhưng không tự động được chứng minh bởi mọi sink đánh giá biểu thức.
- **Runtime Environment**: Môi trường thực thi của ứng dụng tại thời điểm chạy.
- **AST (Abstract Syntax Tree)**: Cấu trúc cây biểu diễn cú pháp; chỉ an toàn khi ứng dụng từ chối mọi node và toán tử ngoài ngữ pháp nghiệp vụ đã cho phép. [S3]

## 16. Bài liên quan và đọc thêm

- [Command Execution](../command-execution/) — Thực thi lệnh trực tiếp trên hệ điều hành của máy chủ đích.
- [Insecure Deserialization](../../08-data-integrity-failures/insecure-deserialization/) — Giải tuần tự hóa không an toàn có thể dẫn đến việc khởi tạo đối tượng độc hại gây chèn mã hoặc thực thi mã từ xa.

## 17. Tài liệu tham khảo

- **[S1]** Python 3.12 Documentation — Built-in `eval`. https://docs.python.org/3.12/library/functions.html#eval — phiên bản/trạng thái: Python 3.12; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Code_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/94.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** MDN — JavaScript `eval()`. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S6]** PHP Manual — `eval`. https://www.php.net/manual/en/function.eval.php — phiên bản/trạng thái: PHP 8.x; truy cập: 2026-07-18.
