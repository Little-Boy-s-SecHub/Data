---
schema_version: 1
id: WEB-A05-CRLF-INJECTION
title: "CRLF Injection"
slug: crlf-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-93
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# CRLF Injection

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích CRLF Injection bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Đọc được HTTP/1.1 start-line, field-line, header-section boundary và `Content-Length` ở dạng raw byte.
- Hiểu URL percent-decoding và biết xác định chính xác thành phần nào decode một hay nhiều lần.
- Phân biệt HTTP header serialization với newline dùng làm ranh giới record của log text.
- Có raw-socket fixture và reverse proxy local, không kết nối target hay cache dùng chung.

## 3. Kiến thức nền tảng

Trong HTTP/1.1, start-line và từng field-line kết thúc bằng CRLF; một dòng trống kết thúc header section. Vì vậy CR/LF không phải dữ liệu hợp lệ tùy ý bên trong field value. Log text có thể cũng dùng newline làm ranh giới record, nhưng đó là format riêng và phải được kiểm tra tách biệt với HTTP framing. [S5]

```http
# Normal HTTP response structure
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
Set-Cookie: session=abc123\r\n
\r\n
<html>...</html>
```

Trong web application, redirect thường lấy URL từ user input:

```python
# Normal redirect implementation in Flask
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/redirect')
def do_redirect():
    # User-supplied destination used in Location header
    dest = request.args.get('url', '/')
    return redirect(dest)
```

## 4. Mô tả và nguyên nhân gốc

Root cause là dữ liệu đã decode được ghi vào field-line hoặc raw protocol stream mà không bị API lõi từ chối CR/LF. Tác động có thể dừng ở một header phụ hoặc, trong một chuỗi framing/caching cụ thể, tạo response splitting; không được mặc định suy ra XSS, cache poisoning hay session fixation chỉ từ hai byte CRLF. [S1] [S5]

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** framing HTTP response, header và trạng thái cache/browser phía sau.

- **Actor, xác thực và role:** người dùng chưa đăng nhập điều khiển tham số redirect/header.

- **Điều kiện khai thác:** CR/LF sau decode đi vào header và tạo header hoặc response boundary ngoài ý định.

- **Runtime:** fixture Python 3.12 tự serialize HTTP/1.1; raw socket thu byte và Chromium chỉ test rendering.

- **Evidence:** lưu raw response hai phía proxy; phải thấy CRLF tạo field-line độc lập. [S1] [S5]

## 6. Cơ chế tấn công

Fixture dễ lỗi decode tham số một lần rồi ghép thẳng vào field `Location`; CRLF vì thế kết thúc field hiện tại và mở field mới. Bản sửa chỉ nhận redirect path từ bảng ánh xạ cố định và từ chối CR/LF trước khi serialize. Phải phân tích raw octet vì client hoặc proxy có thể chuẩn hóa phản hồi sai framing. [S1] [S5]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy fixture Python 3.12 tự serialize HTTP/1.1 sau reverse proxy local được pin; dùng raw socket để thu response và chỉ mở Chromium trong test rendering riêng.
2. **Baseline:** gửi một input hợp lệ của use case crlf injection; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “CR/LF sau decode đi vào header và tạo header hoặc response boundary ngoài ý định”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của crlf injection; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các probe dưới đây vẫn ở `static-verified`; raw response phải được so sánh theo byte và đúng một lần URL-decode. [S1] [S5]

**HTTP Response Splitting** — Attacker chèn CRLF vào tham số redirect để inject header mới:

<!-- claim-source: [S1] [S5] -->
<!-- payload-id: WEB-A05-CRLF-INJECTION-001 -->
<!-- context: HTTP/1.1 redirect fixture reflects decoded url into Location -->
<!-- prerequisites: raw response capture on loopback; synthetic cookie name lab_admin; one request; no browser session -->
<!-- encoding: %0d%0a is decoded once to CRLF; spaces use %20; harness generates request framing -->
<!-- expected-result: vulnerable raw response has a separate Set-Cookie lab_admin header; fixed route rejects CR/LF -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S5 -->
<!-- last-verified: 2026-07-17 -->
```
# Attack URL — injecting Set-Cookie header via CRLF
https://victim.lab.test/redirect?url=%0d%0aSet-Cookie:%20lab_admin=true

# The server generates this malformed response:
HTTP/1.1 302 Found\r\n
Location: \r\n
Set-Cookie: lab_admin=true\r\n    <-- Injected header
\r\n
```

**Log Injection** — Attacker chèn newline để tạo log entry giả:

<!-- claim-source: [S3] -->
<!-- payload-id: WEB-A05-CRLF-INJECTION-002 -->
<!-- context: UTF-8 username written as one structured log field by the authentication fixture -->
<!-- prerequisites: synthetic admin username; isolated log file; one failed login; no SIEM or production log -->
<!-- encoding: newline is the single LF byte 0x0a inside the decoded field; structured logger must JSON-escape it -->
<!-- expected-result: vulnerable text log spans two physical entries; structured log remains one event with escaped newline -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```
# Malicious username input for log injection
username = "admin\nINFO: Login successful for user admin from 10.0.0.1"

# Log file now shows fake entry:
# WARN: Failed login for user admin
# INFO: Login successful for user admin from 10.0.0.1
```

## 9. Code dễ bị lỗi và code an toàn

```python
# Python 3.12 raw HTTP/1.1 teaching fixture

# === VULNERABLE CODE ===
def build_redirect_vulnerable(destination: str) -> bytes:
    # DANGER: decoded input changes the serialized header section
    response = (
        "HTTP/1.1 302 Found\r\n"
        f"Location: {destination}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    )
    return response.encode("ascii")


# === SECURE CODE ===
REDIRECTS = {
    "home": "/",
    "profile": "/profile",
}

def build_redirect_secure(destination_id: str) -> bytes:
    # Map an opaque identifier to a server-owned path
    try:
        destination = REDIRECTS[destination_id]
    except KeyError as exc:
        raise ValueError("Unknown redirect destination") from exc

    response = (
        "HTTP/1.1 302 Found\r\n"
        f"Location: {destination}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    )
    return response.encode("ascii")
```

## 10. Phát hiện

- Tìm phép ghép chuỗi vào raw response, header API tự viết và đường decode input nhiều lần.

- Thu raw response ở hai phía proxy; đếm field-line, header boundary và `Content-Length`.

- Với log injection, LF trong username phải vẫn nằm trong một event có cấu trúc đã escape.

- Phân biệt application từ chối, proxy từ chối và client nhận field mới; chỉ trường hợp cuối xác nhận injection.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Không tự serialize header từ dữ liệu người dùng; dùng API header của framework/runtime có kiểm tra CR/LF.

- Với redirect, ánh xạ destination ID sang path cố định và từ chối CR/LF thay vì strip. [S1] [S2]

### Defense-in-depth

- Cấu hình proxy từ chối response framing không hợp lệ và không cache phản hồi lỗi từ fixture.

- Ghi log có cấu trúc để newline trong trường dữ liệu được escape; giới hạn độ dài header và trường log.

- Theo dõi các lần runtime từ chối header chứa control character. WAF có thể bổ sung tín hiệu nhưng không thay thế API serialize an toàn. [S1] [S3]

## 12. Retest

- **Positive case:** destination ID `profile` tạo đúng một field `Location: /profile` và một header-section boundary.
- **Negative case:** input chứa `%0d%0aSet-Cookie` sau một lần decode bị từ chối; raw response không có field `Set-Cookie` ngoài baseline.
- **Boundary case:** thử CR đơn, LF đơn, CRLF literal, percent-encoding chữ hoa/thường, double-encoding và input đi qua một hoặc hai proxy.
- **Telemetry:** so sánh byte application/proxy/client và xác nhận log newline vẫn nằm trong một event có cấu trúc.
- **Regression:** kiểm tra mọi helper tạo `Location`, `Set-Cookie`, filename tải xuống và log text, vì các sink này có quy tắc output khác nhau.

## 13. Sai lầm thường gặp

- Chỉ tìm chuỗi `%0d%0a` trước URL decoding nên bỏ sót biểu diễn khác, hoặc decode hai lần ngoài contract.

- Xóa CR/LF khỏi destination rồi tiếp tục redirect, vô tình biến input sai thành một URL khác thay vì fail closed.

- Dùng browser devtools làm bằng chứng duy nhất; browser và proxy có thể bỏ hoặc chuẩn hóa response không hợp lệ.

- Trộn log injection với HTTP response splitting dù hai sink dùng ranh giới record và bộ serialize khác nhau.

- Suy ra XSS hoặc cache poisoning khi chưa chứng minh field/body chèn được downstream chấp nhận. [S1] [S5]

## 14. Tóm tắt và checklist

- [ ] Đã lưu raw octet trước và sau proxy, không chỉ ảnh chụp browser.
- [ ] Số lần percent-decoding và vị trí field value được ghi rõ trong payload context.
- [ ] Bản sửa dùng destination ID do server ánh xạ và từ chối control character.
- [ ] CR, LF, CRLF, double-encoding và proxy boundary đều được retest riêng.
- [ ] Log injection được kiểm bằng event có cấu trúc, tách khỏi response splitting.
- [ ] Không suy ra XSS, cache poisoning hay session fixation khi chưa có evidence downstream.

## 15. Giải thích thuật ngữ

- **CRLF**: Cặp ký tự xuống dòng (Carriage Return + Line Feed), ký hiệu là `\r\n`.
- **HTTP Response Splitting**: Cuộc tấn công chia tách phản hồi HTTP bằng cách chèn CRLF để tạo ra phản hồi giả.
- **Session Fixation**: Tấn công cố định phiên, kẻ xấu ép nạn nhân sử dụng session ID định sẵn để chiếm đoạt tài khoản sau đó.
- **Cache Poisoning**: Đầu độc bộ nhớ đệm của proxy hoặc trình duyệt để phân phối nội dung giả mạo.
- **Log Injection**: Dữ liệu không tin cậy làm thay đổi ranh giới hoặc cấu trúc record log; đây là sink khác với HTTP response splitting. [S3] [S5]

## 16. Bài liên quan và đọc thêm

- [Web Cache Poisoning](../../08-data-integrity-failures/web-cache-poisoning/) — Lỗ hổng đầu độc bộ nhớ đệm web, thường tận dụng kỹ thuật chèn header thông qua CRLF Injection để đầu độc cache response.

## 17. Tài liệu tham khảo

- **[S1]** OWASP WSTG — Testing for HTTP Response Splitting. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Response_Splitting — phiên bản/trạng thái: latest; truy cập: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-community/vulnerabilities/CRLF_Injection — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/93.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** RFC 9112 — HTTP/1.1, Sections 2 and 11.1. https://www.rfc-editor.org/rfc/rfc9112.html — phiên bản/trạng thái: RFC 9112; truy cập: 2026-07-18.
