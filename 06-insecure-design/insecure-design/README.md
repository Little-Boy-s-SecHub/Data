---
schema_version: 1
id: WEB-A06-INSECURE-DESIGN
title: "Insecure Design"
slug: insecure-design
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
  - A06:2025
cwe:
  - CWE-602
  - CWE-862
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Insecure Design

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Insecure Design bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn muốn xây dựng một ngôi nhà. Bản thiết kế ban đầu của kiến trúc sư hoàn toàn quên vẽ cửa sổ phòng tắm, hoặc đặt két sắt ngay cạnh cửa sổ tầng trệt mà không có song sắt bảo vệ. Dù sau đó thợ xây có sử dụng loại gạch tốt nhất, xi măng đắt nhất và xây dựng cực kỳ tỉ mỉ (code chuẩn không lỗi cú pháp), ngôi nhà vẫn rất dễ bị đột nhập. Lỗi thiết kế gốc này tương tự như **Thiết kế không an toàn (Insecure Design)**.

Để tránh những sai lầm chết người ngay từ đầu, quy trình phát triển phần mềm cần áp dụng mô hình **Secure SDLC** — tức là đưa các tiêu chuẩn bảo mật vào từng bước, ngay từ khâu lên ý tưởng.

Một công cụ quan trọng trong Secure SDLC là **Threat Modeling (Mô hình hóa mối đe dọa)**, giúp lập trình viên vẽ ra bản đồ các mối nguy để chủ động phòng tránh trước khi đặt những viên gạch code đầu tiên.
Trong bản đồ này, việc vẽ ra các **Trust Boundaries (Ranh giới tin cậy)** là tối quan trọng. Hãy tưởng tượng ranh giới tin cậy giống như lớp cửa kính an ninh tại sân bay: khu vực sảnh ngoài là nơi bất kỳ ai cũng có thể vào (vùng không tin cậy - trình duyệt người dùng), còn khu vực phòng chờ lên máy bay là nơi cực kỳ bảo mật (vùng tin cậy - máy chủ dịch vụ). Một thiết kế an toàn bắt buộc phải kiểm tra kỹ càng mọi hành lý, giấy tờ của hành khách ngay tại cửa an ninh. Nếu bạn chỉ tin tưởng vào các tấm biển báo "cấm vào" ở sảnh ngoài mà không có nhân viên soát vé thật sự ở cửa an ninh, kẻ xấu sẽ dễ dàng lẻn vào khu vực cấm.

#### Minh họa hoạt động bình thường (Normal Operation)
```python
# Decorator to enforce trust boundary checks at the backend API layer
from functools import wraps
from flask import session, abort, request

def enforce_trust_boundary(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check if the user is authenticated and has the correct role
            # This validation occurs right at the entry point of the trusted zone
            user_role = session.get('user_role')
            if not user_role or user_role != required_role:
                # Reject unauthorized traffic from untrusted client zone
                abort(403, "Access Denied: Insufficient privileges at trust boundary")
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Thiết kế không an toàn (Insecure Design) là những sai lầm nghiêm trọng nằm ngay ở kiến trúc và tư duy logic của hệ thống trước khi mã nguồn được viết ra.

Nó nguy hiểm ở chỗ, bạn không thể vá lỗ hổng này bằng cách sửa một vài dòng code đơn lẻ. Lỗi nằm ở cách thức vận hành của quy trình.

Ví dụ điển hình là việc bạn thiết kế hệ thống chỉ ẩn nút "Xóa người dùng" trên giao diện web của người dùng thường, nhưng lại quên cấu hình kiểm tra quyền hạn thực sự ở máy chủ backend. Kẻ tấn công chỉ cần tìm ra đường dẫn API ẩn và gửi yêu cầu trực tiếp là có thể xóa bất kỳ ai. Dù code của tính năng xóa được viết hoàn hảo, không có lỗi kỹ thuật nào, hệ thống của bạn vẫn bị sụp đổ từ bên trong do lỗi thiết kế quy trình lỏng lẻo.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** authorization và workflow invariant của operation admin.
- **Actor, xác thực và role:** role user đã xác thực tìm thấy operation admin nhưng không có admin role.
- **Điều kiện khai thác:** thiết kế dựa vào UI ẩn hoặc thứ tự client thay vì server policy có thẩm quyền.
- **Browser, proxy, framework và phiên bản:** Flask 3.x/PostgreSQL 16 với role matrix rõ ràng; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với insecure design, thiết kế dựa vào UI ẩn hoặc thứ tự client thay vì server policy có thẩm quyền. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Flask 3.x/PostgreSQL 16 với role matrix rõ ràng; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case insecure design; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “thiết kế dựa vào UI ẩn hoặc thứ tự client thay vì server policy có thẩm quyền”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của insecure design; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Trong giai đoạn thiết kế, các nhà phát triển không thực hiện mô hình hóa mối đe dọa (threat modeling) và không xác định đúng ranh giới tin cậy (trust boundaries).
Bước 2: Ứng dụng phụ thuộc hoàn toàn vào việc ẩn các chức năng hành động (như nút 'Xóa người dùng') ở giao diện HTML phía client đối với người dùng không có quyền quản trị.
Bước 3: Kẻ tấn công là người dùng thông thường phân tích mã nguồn HTML/JS, tìm ra URL API của chức năng xóa (`/admin/delete-user`), và gửi trực tiếp HTTP POST request đến API đó.
Bước 4: Do backend không thực hiện kiểm tra quyền hạn của phiên làm việc hiện tại mà chỉ dựa vào việc ẩn nút bấm ở frontend, hành động xóa được thực thi thành công.

### Ví dụ HTTP request bypass frontend validation:
<!-- payload-id: WEB-A06-INSECURE-DESIGN-001 -->
<!-- context: HTTP/1.1 JSON purchase request reaches a synthetic ledger without authoritative checks -->
<!-- prerequisites: authenticated normal fixture user; item 999 and zero price exist only in disposable DB; one request -->
<!-- encoding: UTF-8 application/json with Content-Length generated from exact bytes -->
<!-- expected-result: vulnerable ledger creates a zero-price order; secure service recalculates price/balance and rejects with no row -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
POST /api/purchase HTTP/1.1
Host: victim.lab.test
Content-Type: application/json
Content-Length: 40

{"item_id":999,"quantity":100,"price":0}
```

Trong fixture dễ lỗi, server tin `price` từ client và tạo order giá 0. Fixture an toàn bỏ qua trường giá do client gửi, tải giá authoritative theo `item_id` và kiểm tra invariant trước transaction.

## 9. Code dễ bị lỗi và code an toàn

Hai route sau dùng Flask 3.x cho cùng hành động quản trị. Ẩn nút trên giao diện không tạo authorization ở server; mọi request tới route nhạy cảm vẫn phải được policy phía server quyết định trước side effect. [S2] [S3]

### Không an toàn (vulnerable): chỉ dựa vào giao diện

```python
from flask import request

@app.post('/admin/delete-user')
def delete_user_vulnerable():
    # Vulnerable: the UI hides this action, but the backend has no authorization check
    user_id = request.form['user_id']
    user_store.delete(user_id)
    return ('', 204)
```

### An toàn (secure): kiểm tra quyền tại backend

```python
from functools import wraps
from flask import abort, request, session

# Secure design enforces access controls on the backend API,
# not just hiding buttons or links on the frontend templates.
def require_privilege(needed_privilege):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_permissions = session.get('permissions', [])
            if needed_privilege not in user_permissions:
                # Terminate with unauthorized error status
                abort(403, "Access Forbidden: Insufficient Permissions")
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.post('/admin/delete-user')
@require_privilege('admin_manage')
def delete_user_secure():
    # Secure: authorization runs before the state-changing operation
    user_id = request.form['user_id']
    user_store.delete(user_id)
    return ('', 204)
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Định nghĩa và enforce authorization/invariant server-side cho mọi operation, độc lập UI.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Tránh thiết kế không an toàn bằng cách nhúng mô hình hóa mối đe dọa, các mẫu thiết kế bảo mật và kiểm tra kiểm soát truy cập nghiêm ngặt xuyên suốt vòng đời phát triển phần mềm (SDLC).
- **Các bước chi tiết**:
  - Tích hợp phân tích bảo mật — như mô hình hóa mối đe dọa (ví dụ: STRIDE) — vào giai đoạn thiết kế ban đầu của mọi dự án.
  - Áp dụng nguyên tắc đặc quyền tối thiểu, đảm bảo cấu hình mặc định hạn chế quyền truy cập cho đến khi được cấp phép rõ ràng.
  - Xác minh kiểm tra phân quyền tại tất cả các lớp logic backend, thay vì chỉ dựa vào cài đặt hiển thị giao diện phía client (frontend UI).
  - Sử dụng các thư viện và mẫu bảo mật đã được kiểm chứng thay vì tự xây dựng các cơ chế bảo mật tùy chỉnh chưa được kiểm tra.
  - Rà soát và thực thi quy trình logic nghiệp vụ để đảm bảo người dùng không thể bỏ qua các bước xác thực quan trọng.

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

- **Insecure Design (Thiết kế không an toàn)**: Nhóm lỗ hổng phát sinh do sai sót hoặc thiếu sót trong quá trình lập kế hoạch và thiết kế kiến trúc hệ thống, khiến hệ thống không có các cơ chế kiểm soát bảo mật cần thiết ngay từ đầu.
- **Secure SDLC (Vòng đời phát triển phần mềm bảo mật)**: Quy trình phát triển phần mềm tích hợp các hoạt động kiểm tra và thực hành bảo mật vào mọi giai đoạn từ yêu cầu, thiết kế, triển khai cho đến kiểm thử và bảo trì.
- **Threat Modeling (Mô hình hóa mối đe dọa)**: Phương pháp phân tích hệ thống để xác định các nguy cơ bảo mật tiềm ẩn, các tác nhân đe dọa và đề xuất các biện pháp giảm thiểu tương ứng trong giai đoạn thiết kế.
- **Trust Boundaries (Ranh giới tin cậy)**: Điểm phân cách trong kiến trúc hệ thống nơi dữ liệu chuyển tiếp từ vùng có mức độ tin cậy thấp (ví dụ: dữ liệu do người dùng gửi lên) sang vùng có mức độ tin cậy cao (ví dụ: cơ sở dữ liệu nội bộ).
- **STRIDE**: Khung phân loại mối đe dọa do Microsoft phát triển, đại diện cho: Giả mạo (Spoofing), Can thiệp (Tampering), Chối bỏ (Repudiation), Tiết lộ thông tin (Information Disclosure), Từ chối dịch vụ (Denial of Service), và Leo thang đặc quyền (Elevation of Privilege).
- **Least Privilege (Đặc quyền tối thiểu)**: Nguyên tắc bảo mật yêu cầu chỉ cấp cho người dùng hoặc tiến trình các quyền hạn tối thiểu cần thiết để hoàn thành công việc của họ, nhằm hạn chế thiệt hại nếu tài khoản bị xâm nhập.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-602 — Client-Side Enforcement of Server-Side Security. https://cwe.mitre.org/data/definitions/602.html — phiên bản/trạng thái: CWE 4.20; truy cập: 2026-07-18.
- **[S3]** CWE-862 — Missing Authorization. https://cwe.mitre.org/data/definitions/862.html — phiên bản/trạng thái: CWE 4.20; truy cập: 2026-07-18.
