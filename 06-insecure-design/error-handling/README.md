---
schema_version: 1
id: WEB-A06-ERROR-HANDLING
title: "Error Handling & Exception Mismanagement"
slug: error-handling
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A10:2025
cwe:
  - CWE-755
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Error Handling & Exception Mismanagement

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Error Handling & Exception Mismanagement bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang lái một chiếc xe hơi hiện đại. Khi động cơ gặp sự cố, hệ thống điều khiển thông minh trên xe sẽ sáng đèn báo lỗi "Check Engine" màu vàng trên táp-lô để bạn biết đường mang xe đi sửa. Chiếc xe hoàn toàn ẩn đi các thông số kỹ thuật phức tạp như áp suất buồng đốt hay lỗi dòng điện cụ thể để tránh làm bạn bối rối. Cơ chế xử lý sự cố này tương tự như **xử lý lỗi (error handling)** trong lập trình. Khi ứng dụng gặp tình huống bất ngờ (như cơ sở dữ liệu bị ngắt kết nối, người dùng nhập chữ vào ô nhập số), nó cần phải phản hồi một cách khéo léo để hệ thống không bị sập hoàn toàn.

Trong bảo mật phần mềm, khi xảy ra lỗi, hệ thống phải tuân theo hai triết lý thiết kế đối nghịch:
- **Fail-Close (Thất bại thì Đóng/Bảo mật)**: Giống như một chiếc két sắt thông minh, khi hệ thống quét vân tay bị mất điện hoặc gặp lỗi, két sắt sẽ tự động khóa chặt lại để bảo vệ tài sản bên trong. Đây là cách xử lý an toàn và đúng đắn nhất.
- **Fail-Open (Thất bại thì Mở)**: Ngược lại, nếu khóa cửa từ của một tòa nhà bị lỗi mất điện mà lại tự động mở toang cửa cho bất kỳ ai đi vào mà không cần quẹt thẻ, đó chính là Fail-Open. Thiết kế này cực kỳ nguy hiểm trong bảo mật vì nó tạo ra sơ hở cho kẻ xấu lợi dụng.

```python
# Normal error handling in a web application
from flask import Flask, jsonify
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(error):
    # Log full details server-side for debugging
    logger.error(f"Unhandled exception: {error}", exc_info=True)

    # Return generic message to client (no internal details)
    return jsonify({
        "error": "An unexpected error occurred",
        "reference": "ERR-2025-06-27-001"
    }), 500
```

Đoạn code trên minh họa cách xử lý đúng: log chi tiết ở server, trả về thông báo chung cho client kèm mã tham chiếu để đội support có thể tra cứu.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng xử lý lỗi (Improper Error Handling) xảy ra khi ứng dụng trở nên lúng túng khi gặp sự cố và vô tình "nói quá nhiều" hoặc "mở toang cửa".

Cụ thể, khi có lỗi xảy ra, thay vì hiển thị một lời xin lỗi chung chung, ứng dụng lại ném ra toàn bộ nhật ký lỗi kỹ thuật chi tiết (stack trace), bao gồm đường dẫn thư mục, tên bảng trong cơ sở dữ liệu, phiên bản thư viện đang dùng, hay thậm chí là hệ điều hành của máy chủ.

Tệ hơn nữa, nếu hệ thống được thiết kế theo kiểu "Fail-Open", khi quá trình kiểm tra đăng nhập gặp lỗi kỹ thuật, nó lại mặc định cho phép người dùng đi qua.

Mối nguy hiểm của lỗ hổng này là nó cung cấp cho kẻ tấn công một "bản đồ kho báu" chi tiết về cấu trúc bên trong của hệ thống để chúng lên kế hoạch tấn công chính xác, hoặc giúp chúng dễ dàng vượt qua các bước xác thực bằng cách cố tình tạo ra các lỗi hệ thống.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** chi tiết stack/config nội bộ và hành vi khi service lỗi.
- **Actor, xác thực và role:** anonymous hoặc role user kích hoạt input lỗi có kiểm soát.
- **Điều kiện khai thác:** exception detail tới client hoặc error path fail-open.
- **Browser, proxy, framework và phiên bản:** Flask 3.x và Express 4.x ở production mode sau proxy loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với error handling, exception detail tới client hoặc error path fail-open. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Flask 3.x và Express 4.x ở production mode sau proxy loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case error handling; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “exception detail tới client hoặc error path fail-open”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của error handling; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**1. Stack Trace Information Disclosure — kích hoạt lỗi để thu thập thông tin:**

<!-- payload-id: WEB-A06-ERROR-HANDLING-001 -->
<!-- context: HTTP/1.1 request triggers a controlled conversion error in a Django 4.2.1 fixture -->
<!-- prerequisites: loopback production-mode clone with synthetic paths/versions only; one invalid user ID -->
<!-- encoding: ASCII request target and headers with harness-generated CRLF; response JSON escapes newline characters -->
<!-- expected-result: vulnerable response exposes only fixture stack/host markers; secure response is generic with correlation ID -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
GET /api/users/abc HTTP/1.1
Host: victim.lab.test

// Response with verbose error (DANGEROUS):
HTTP/1.1 500 Internal Server Error
{
    "error": "Traceback (most recent call last):\n  File \"/app/views/user.py\", line 42\n    user = User.objects.get(id=int(user_id))\nValueError: invalid literal for int() with base 10: 'abc'\n\nDjango Version: 4.2.1\nDatabase: PostgreSQL 15.3 at db-prod.internal:5432\nOS: Ubuntu 22.04"
}
// Attacker now knows: framework, DB type, internal hostname, OS version
```

**2. Fail-Open Authentication Bypass — lợi dụng lỗi để vượt qua xác thực:**

<!-- payload-id: WEB-A06-ERROR-HANDLING-002 -->
<!-- context: Python authentication fixture catches a deliberately malformed synthetic JWT -->
<!-- prerequisites: one invalid token; no real account; application/audit logs enabled -->
<!-- encoding: token is ASCII Authorization data; no decoding beyond the JWT parser; code block itself is UTF-8 Python -->
<!-- expected-result: vulnerable function returns authenticated=True; fail-closed implementation returns an authentication error -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# VULNERABLE: fail-open design
def check_authentication(token):
    try:
        user = verify_jwt(token)
        return user
    except Exception:
        # On ANY error (expired, invalid, malformed), grant access anyway!
        return {"role": "guest", "authenticated": True}  # DANGEROUS
```

Attacker có thể gửi token sai định dạng cố ý để trigger exception và được cấp quyền truy cập.

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: exposes internal details and fails open
@app.route('/api/admin/dashboard')
def admin_dashboard():
    try:
        token = request.headers.get('Authorization')
        user = verify_admin_token(token)
        return get_admin_data(user)
    except Exception as e:
        # Leaks full error details to attacker
        return jsonify({
            "error": str(e),
            "stack": traceback.format_exc(),
            "db_host": app.config['DB_HOST']
        }), 500
```

```python
# SECURE: fail-close with generic error response
@app.route('/api/admin/dashboard')
def admin_dashboard():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Authentication required"}), 401

        user = verify_admin_token(token)
        if not user or user.get('role') != 'admin':
            return jsonify({"error": "Forbidden"}), 403

        return get_admin_data(user)

    except jwt.ExpiredSignatureError:
        # Specific exception: deny access (fail-close)
        return jsonify({"error": "Session expired, please re-login"}), 401

    except Exception:
        # Generic exception: deny access and log internally
        logger.exception("Admin dashboard error")
        return jsonify({
            "error": "Internal server error",
            "ref": generate_error_reference()
        }), 500
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Fail closed tại boundary, tách lỗi client tối thiểu khỏi internal log có correlation ID.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Xử lý lỗi an toàn bằng cách ẩn stack trace chi tiết trên môi trường production, thiết kế theo nguyên lý Fail-Close, và ghi log cấu trúc phía máy chủ.
- **Các bước chi tiết**:
  - **Custom error pages**: Cấu hình error page riêng cho production, ẩn toàn bộ stack trace và thông tin debug.
  - **Fail-close by default**: Khi xảy ra lỗi, luôn từ chối truy cập và yêu cầu xác thực lại.
  - **Structured logging**: Ghi log chi tiết ở server (ELK Stack, Splunk) nhưng chỉ trả về error code/reference cho client.
  - **Disable debug mode**: Tắt `DEBUG=True` (Django), `app.debug` (Flask), `SHOW_ERRORS` (Laravel) trong production.

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

- **Stack Trace (Vết ngăn xếp)**: Danh sách chi tiết các hàm đang chạy tại thời điểm xảy ra lỗi, chỉ ra chính xác tệp tin và số dòng code gặp sự cố. Đây là thông tin cực kỳ hữu ích cho lập trình viên nhưng rất nguy hiểm nếu để lộ ra ngoài.
- **Fail-Close (Thất bại - Đóng)**: Nguyên tắc thiết kế bảo mật mà khi một chức năng hoặc hệ thống gặp lỗi, nó sẽ mặc định chuyển sang trạng thái an toàn nhất bằng cách từ chối mọi yêu cầu truy cập.
- **Fail-Open (Thất bại - Mở)**: Thiết kế lỗi mà khi hệ thống gặp sự cố, nó lại tự động bỏ qua các bước kiểm tra bảo mật và cho phép người dùng truy cập vào tài nguyên.
- **Exception (Ngoại lệ)**: Một sự kiện đặc biệt xảy ra trong quá trình thực thi chương trình làm gián đoạn luồng hướng dẫn bình thường (như lỗi chia cho 0, lỗi mất kết nối mạng).
- **Graceful Error Handling (Xử lý lỗi khéo léo)**: Việc bắt và xử lý các lỗi phát sinh sao cho ứng dụng không bị sập đột ngột, đồng thời chỉ hiển thị những thông báo thân thiện và an toàn cho người dùng cuối.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/information-disclosure — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-community/Improper_Error_Handling — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/755.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
