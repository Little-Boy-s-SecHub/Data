---
schema_version: 1
id: WEB-A10-REMOTE-CODE-EXECUTION
title: "Remote Code Execution"
slug: remote-code-execution
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp: []
cwe: []
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Remote Code Execution

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Remote Code Execution bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

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

## 4. Mô tả và nguyên nhân gốc

**Remote Code Execution (RCE - Thực thi mã từ xa)** là một tác động, không phải một nguyên nhân gốc duy nhất. Tác động này có thể xuất phát từ code injection, command injection, template injection, deserialization hoặc việc máy chủ thực thi tệp upload. Vì vậy bài này không ánh xạ toàn bộ RCE vào một CWE duy nhất; CWE-94 chỉ phù hợp với nhánh code injection. [S2]

Một khi lỗ hổng RCE bị khai thác, kẻ tấn công sẽ có được đặc quyền tối cao:
- Chạy mọi câu lệnh hệ thống như thể đang ngồi trực tiếp trước màn hình máy chủ.
- Xem trộm, sửa đổi hoặc xóa sạch các file dữ liệu nhạy cảm.
- Cài đặt các phần mềm độc hại, mở cổng kết nối bí mật (backdoor) để ra vào hệ thống bất kỳ lúc nào.
- Biến máy chủ thành bàn đạp để tiếp tục tấn công sâu hơn vào mạng nội bộ của doanh nghiệp.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** quyền thực thi của process ứng dụng, biến môi trường và filesystem mà service account có thể truy cập.
- **Trust boundary:** input đi vào template engine, lệnh hệ điều hành, upload handler hoặc deserializer trước execution sink.
- **Actor:** client local với role đúng của endpoint fixture; chỉ tạo marker vô hại, không tạo reverse shell hay callback Internet.
- **Điều kiện cần:** một root cause cụ thể như injection, unsafe deserialization hoặc upload-to-execution phải đưa input tới execution API; “RCE” là tác động, không thay tên root cause.
- **Điều kiện môi trường:** Python 3.12, Flask/Jinja2 3.1 trong container non-root, filesystem giả và outbound network bị tắt.

Chỉ kết luận execution khi marker do process tạo khớp request/correlation ID; lỗi template, status 500 hoặc file upload thành công chưa đủ chứng minh RCE. [S1]

## 6. Cơ chế tấn công

Unsafe template evaluation hoặc truyền chuỗi vào shell có thể chuyển dữ liệu thành lệnh; upload chỉ dẫn tới execution nếu file nằm trên executable path và runtime thực sự xử lý nó. Fixture dùng phép tính template/ghi marker local để chứng minh sink mà không mở shell hay kết nối ra ngoài. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy Flask/Jinja2 fixture non-root, mount thư mục upload `noexec`, chỉ cho phép ghi marker trong `/tmp/sechub-lab` và chặn outbound.
2. **Input:** baseline render text literal/upload file inert; sau đó dùng phép tính template hoặc hành động ghi marker cục bộ đã định trước.
3. **Thao tác:** gửi từng vector riêng, ghi raw request, application log, PID/UID và sự tồn tại/nội dung marker.
4. **Expected result:** bản dễ lỗi đánh giá input hoặc tạo marker; bản sửa render literal, không gọi shell và upload không thể được runtime thực thi.
5. **Cleanup:** xóa marker/upload, dừng container và xác nhận không có process con còn chạy.
6. **Giới hạn an toàn:** cấm reverse shell, downloader, credential access và callback Internet; process có timeout/CPU/memory cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Bước kiểm thử phải chứng minh đúng sink. Ví dụ, command injection cần xác nhận shell diễn giải một marker vô hại; SSTI cần xác nhận template engine cụ thể; file upload chỉ dẫn tới thực thi khi upload directory được ánh xạ tới runtime handler. Không dùng một payload của nhánh này để kết luận nhánh khác. [S3], [S4], [S5]

### Probe SSTI không thực thi lệnh hệ điều hành
<!-- payload-id: WEB-A10-REMOTE-CODE-EXECUTION-001 -->
<!-- context: Jinja2 expression context; fixture phải pin phiên bản Jinja2 và render input như template -->
<!-- prerequisites: chỉ dùng fixture local; outbound network bị chặn; không dùng gadget truy cập os/subprocess -->
<!-- encoding: UTF-8, không URL encode khi nhập trực tiếp vào template fixture -->
<!-- expected-result: fixture dễ lỗi render 49; fixture an toàn hiển thị nguyên văn hoặc từ chối input; kết quả 49 chỉ chứng minh SSTI, chưa chứng minh RCE -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```jinja2
{{ 7 * 7 }}
```

### Probe thực thi tệp upload bằng marker vô hại
<!-- payload-id: WEB-A10-REMOTE-CODE-EXECUTION-002 -->
<!-- context: PHP 8.x file executed by a disposable local web fixture; upload directory and handler mapping must be documented -->
<!-- prerequisites: fixture filesystem is disposable; uploaded file cannot invoke a shell and outbound network is disabled -->
<!-- encoding: UTF-8 PHP source; upload request framing is generated by the lab client -->
<!-- expected-result: requesting the uploaded file returns SECHUB_UPLOAD_EXECUTION_PROBE only when the server executes PHP in the upload directory -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```php
<?php
// Harmless execution marker for a disposable PHP fixture
echo "SECHUB_UPLOAD_EXECUTION_PROBE";
?>
```

## 9. Code dễ bị lỗi và code an toàn

### Python 3.12: cùng use case `ping`, khác cách tạo tiến trình

```python
import subprocess
import ipaddress

def ping_host_vulnerable(user_ip):
    # Vulnerable: the shell interprets metacharacters from user_ip
    result = subprocess.run(
        f"ping -c 1 {user_ip}",
        capture_output=True,
        text=True,
        shell=True,
        timeout=3,
    )
    return result.stdout

def ping_host_secure(user_ip):
    try:
        ipaddress.ip_address(user_ip)
    except ValueError:
        raise ValueError("Invalid IP address")

    # Safe for this use case: no shell, fixed executable and fixed argument positions
    result = subprocess.run(
        ["ping", "-c", "1", user_ip],
        capture_output=True,
        text=True,
        shell=False,
        timeout=3,
        check=False,
    )
    return result.stdout
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Giới hạn tài nguyên, fail safely và xử lý mọi trạng thái ngoại lệ có thể đạt tới.
- Loại bỏ dynamic evaluation/shell, dùng API có tham số, tách upload khỏi executable path và chạy service non-root; sửa đúng root cause thay vì dựa vào WAF.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Sửa nguyên nhân gốc dẫn tới RCE: loại bỏ việc diễn giải input như code/command, không thực thi file upload và không deserialize kiểu đối tượng tùy ý. Cô lập tiến trình chỉ giảm blast radius.
- **Các bước chi tiết**:
  - Không truyền input không tin cậy vào `eval`, `exec`, template source, shell hoặc API deserialize có thể dựng kiểu tùy ý.
  - Khi cần tạo tiến trình, dùng executable cố định và danh sách đối số; không ghép chuỗi và không bật shell.
  - Lưu file upload ngoài web root, đổi tên phía server và không ánh xạ upload directory tới runtime handler.
  - Chạy tiến trình bằng tài khoản ít quyền, filesystem hạn chế và outbound network mặc định bị chặn như defense-in-depth.

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Code Evaluation (Đánh giá mã nguồn)**: Quá trình phân tích cú pháp và chạy trực tiếp một chuỗi văn bản như là một đoạn mã lập trình thực sự tại thời điểm chạy.
- **Dynamic Execution (Thực thi động)**: Khả năng của chương trình thực hiện các lệnh được tạo ra một cách linh hoạt trong quá trình chạy, thay vì được biên dịch sẵn từ trước.
- **AST (Abstract Syntax Tree - Cây cú pháp trừu tượng)**: Cấu trúc dữ liệu dạng cây biểu diễn cấu trúc cú pháp của mã nguồn, dùng để phân tích cú pháp một cách an toàn mà không cần chạy mã.
- **Backdoor (Cửa sau)**: Một phương thức ẩn giúp vượt qua cơ chế xác thực thông thường để truy cập trái phép vào hệ thống.
- **Parser**: Bộ phân tích cú pháp, chuyển đổi dữ liệu đầu vào thành cấu trúc dữ liệu mà chương trình có thể hiểu được.
- **Sanitization (Làm sạch dữ liệu)**: Quá trình lọc bỏ các ký tự hoặc lệnh nguy hiểm khỏi dữ liệu đầu vào của người dùng trước khi xử lý.

## 16. Bài liên quan và đọc thêm

- [Server-Side Template Injection](../../05-injection/ssti/) — Lỗ hổng chèn mã độc vào template engine phía máy chủ, một trong những nguyên nhân phổ biến nhất dẫn đến RCE.
- [Command Execution](../../05-injection/command-execution/) — Thực thi lệnh trực tiếp trên hệ điều hành, một dạng biểu hiện cụ thể của RCE thông qua shell hệ thống.
- [Insecure Deserialization](../../08-data-integrity-failures/insecure-deserialization/) — Giải tuần tự hóa không an toàn cho phép tái dựng các đối tượng chứa payload độc hại gây RCE.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-94. https://cwe.mitre.org/data/definitions/94.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** OWASP WSTG: Testing for Command Injection. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP File Upload Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** PortSwigger Web Security Academy — Server-side template injection. https://portswigger.net/web-security/server-side-template-injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
