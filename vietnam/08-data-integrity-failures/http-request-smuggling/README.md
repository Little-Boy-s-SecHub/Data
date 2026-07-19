---
schema_version: 1
id: WEB-A08-HTTP-REQUEST-SMUGGLING
title: "HTTP Request Smuggling"
slug: http-request-smuggling
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A06:2025
cwe:
  - CWE-444
content_status: technical-review
payload_status: lab-verified
last_verified: null
---

# HTTP Request Smuggling

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích HTTP Request Smuggling bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống HTTP Request Smuggling và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng hệ thống web hiện đại giống như một chuỗi nhà hàng thức ăn nhanh hoạt động hết công suất. Khi bạn gửi yêu cầu (request), yêu cầu đó không đi thẳng tới người đầu bếp (Back-end Server) ngay lập tức. Thay vào đó, nó phải đi qua một người thu ngân ở quầy (Front-end Proxy/Load Balancer/CDN). Để tiết kiệm thời gian và tăng tốc phục vụ, người thu ngân thường gom nhiều yêu cầu từ các khách hàng khác nhau lại và gửi chung qua một đường truyền duy nhất (kỹ thuật gọi là tái sử dụng kết nối - connection reuse).

Để đầu bếp và thu ngân có thể hiểu nhau, họ phải dùng chung một giao thức (HTTP/1.1) với hai cách để đo lường độ dài của một đơn hàng:
- **Content-Length (CL)**: Giống như dán nhãn ghi rõ "Gói hàng này nặng đúng 13 gram (byte)".
- **Transfer-Encoding (TE)**: Giống như chia nhỏ món ăn ra gửi đi từng phần (chunked), và báo hiệu hết hàng bằng một phần có kích thước bằng 0.

Theo RFC 9112, message có cả `Transfer-Encoding` và `Content-Length` là trường hợp nguy hiểm: server có thể từ chối hoặc xử lý theo `Transfer-Encoding`, nhưng phải đóng kết nối sau response; proxy không được forward framing mơ hồ mà không chuẩn hóa. Request smuggling xuất hiện khi các recipient phân tích ranh giới message khác nhau, không phải vì chuẩn cho phép tùy ý chọn CL hay TE. [S6]

```
# Normal HTTP/1.1 request flow through proxy chain
Client ──→ [Front-end Proxy] ──TCP connection──→ [Back-end Server]
           │                                      │
           │  Request 1: POST /api                 │  Parses request boundaries
           │  Request 2: GET /home                 │  using CL or TE headers
           │  (multiplexed on same connection)     │
```

```http
# Normal request with Content-Length
POST /api/submit HTTP/1.1
Host: victim.lab.test
Content-Length: 13

{"key":"val"}
```

```http
# Normal request with Transfer-Encoding: chunked
POST /api/submit HTTP/1.1
Host: victim.lab.test
Transfer-Encoding: chunked

d\r\n
{"key":"val"}\r\n
0\r\n
\r\n
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **HTTP Request Smuggling (Buôn lậu yêu cầu HTTP)** xuất hiện chính từ sự thiếu đồng bộ kể trên. Hãy hình dung kẻ tấn công như một vị khách tinh quái. Hắn chuẩn bị một đơn hàng "siêu đặc biệt" kết hợp cả hai nhãn CL và TE để lừa hệ thống. Người thu ngân phía trước đọc nhãn CL, thấy độ dài hợp lý nên cho đi qua. Nhưng khi đến tay đầu bếp ở phía sau, do ưu tiên đọc nhãn TE, ông ấy dừng lại giữa chừng vì tưởng đơn hàng đã hết. Phần đuôi còn thừa của đơn hàng đó vẫn nằm vất vưởng trên băng chuyền.

Khi bạn – một người dùng vô tội tiếp theo – đến quầy gửi yêu cầu của mình, phần đuôi "bị buôn lậu" trước đó của kẻ tấn công sẽ tự động dán chặt vào đầu yêu cầu của bạn. Kết quả là hệ thống xử lý yêu cầu của bạn nhưng lại thực hiện hành động mà kẻ tấn công đã cài cắm từ trước.

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó có thể giúp kẻ tấn công:
- Vượt qua các hệ thống kiểm soát an ninh (WAF).
- Chiếm đoạt phiên làm việc (session) hoặc thông tin cá nhân của người dùng khác khi họ vô tình truy cập ngay sau đó.
- Làm nhiễm độc bộ nhớ đệm (cache poisoning), khiến mọi người dùng khác đều nhận được nội dung độc hại.
- Lẻn vào các giao diện quản trị nội bộ mà bình thường họ không thể tiếp cận.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4], [S5], [S6].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** request boundary giữa frontend/backend và queue/cache state.
- **Actor, xác thực và role:** anonymous raw client chỉ tới proxy namespace disposable.
- **Điều kiện khai thác:** hai hop ưu tiên CL/TE hoặc parse chunk khác nhau gây boundary mismatch.
- **Browser, proxy, framework và phiên bản:** frontend/backend pair được pin, raw HTTP/1.1 socket và network namespace cô lập; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với http request smuggling, hai hop ưu tiên CL/TE hoặc parse chunk khác nhau gây boundary mismatch. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy frontend/backend pair được pin, raw HTTP/1.1 socket và network namespace cô lập; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case http request smuggling; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “hai hop ưu tiên CL/TE hoặc parse chunk khác nhau gây boundary mismatch”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của http request smuggling; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

**1. Các Biến thể HTTP/1.1 Desync Cơ bản:**

- **Fixture framing CL/TE không mở socket**:
<!-- payload-id: WEB-A08-HTTP-REQUEST-SMUGGLING-001 -->
<!-- context: Python 3.12; mô hình byte HTTP/1.1 theo RFC 9112; không network I/O -->
<!-- prerequisites: chạy fixture byte-only local; không mở socket hoặc gửi request ra network -->
<!-- encoding: ASCII bytes với CRLF tường minh; Content-Length tính trên body bytes -->
<!-- expected-result: body dài đúng 6 byte và fixture policy trả REJECT_AMBIGUOUS_FRAMING -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
  ```python
  # Safe framing fixture: construct bytes only; never send them to a socket
  BODY = b"0\r\n\r\nG"
  AMBIGUOUS_REQUEST = (
      b"POST /fixture HTTP/1.1\r\n"
      b"Host: lab.example.test\r\n"
      b"Content-Length: 6\r\n"
      b"Transfer-Encoding: chunked\r\n"
      b"\r\n" + BODY
  )

  assert len(BODY) == 6
  assert b"Content-Length: 6\r\n" in AMBIGUOUS_REQUEST
  assert b"Transfer-Encoding: chunked\r\n" in AMBIGUOUS_REQUEST
  ```
  *Giải thích*: regression test chỉ xác nhận byte length/CRLF và policy phải từ chối framing mơ hồ. Nó không gửi request và không chứng minh một proxy thật bị desync. [S6]

- **TE.CL Attack (Front-end dùng TE, back-end dùng CL)**: chỉ giữ mô tả khái niệm. Payload cũ có chunk size/byte length không tự nhất quán nên đã loại khỏi lesson; chỉ được đưa lại sau khi có proxy pair pin version và regression evidence.

- **TE.TE/header obfuscation**: hành vi phụ thuộc parser và version cụ thể. Không có payload canonical chung; fixture phải ghi chính xác chuỗi header và cách từng hop parse trước khi kết luận.

**2. Request capture:** biến thể state-changing có thể ảnh hưởng request của phiên khác. Lesson không phát hành payload này; chỉ mô phỏng bằng hai synthetic clients trên disposable proxy fixture, không dùng cookie/token thật.

**3. HTTP/2 Downgrade Smuggling (H2.CL và H2.TE):**
  - **Cơ chế**: Nhiều proxy front-end nhận request HTTP/2 từ client nhưng chuyển đổi hạ cấp (downgrade) thành HTTP/1.1 trước khi chuyển tiếp cho back-end. Do HTTP/2 là giao thức nhị phân và xác định độ dài request bằng các frame dữ liệu nên nó không cần đến các header xác định ranh giới. Tuy nhiên, kẻ tấn công có thể chèn thủ công các header `content-length` hoặc `transfer-encoding` vào HTTP/2 request. Front-end proxy thường bỏ qua các header này vì đã có frame nhị phân, nhưng khi downgrade sang HTTP/1.1, proxy lại đính kèm các header này vào request gửi tới back-end, gây ra sự bất đồng bộ (desync) ở back-end.
  - **H2.CL Attack**: Kẻ tấn công gửi request HTTP/2 chứa header `content-length` giả mạo. Sau khi downgrade, back-end HTTP/1.1 xử lý request dựa trên `content-length` này, dẫn đến bỏ sót một phần request body trong buffer để ghép vào request sau.
  - **H2.TE Attack**: Kẻ tấn công gửi request HTTP/2 chứa header `transfer-encoding: chunked`. Khi chuyển sang HTTP/1.1, back-end server ưu tiên xử lý dạng chunked, gây desync với luồng dữ liệu mà front-end đã gửi.

**4. CL.0 Attacks (Content-Length 0):**
  - **Cơ chế**: Xảy ra khi front-end proxy chuyển tiếp request body và sử dụng header `Content-Length` bình thường, nhưng back-end server lại cấu hình để bỏ qua body của một số request (ví dụ như các API GET hoặc POST cụ thể) và mặc định coi độ dài body bằng `0`.
  - **Tấn công**: Kẻ tấn công gửi một POST request chứa dữ liệu bổ sung trong body và chỉ định `Content-Length` chính xác. Front-end forward toàn bộ request này. Back-end nhận request, nhưng vì nó coi độ dài body bằng `0` nên xử lý ngay lập tức và coi phần body thực tế của request đó là sự khởi đầu của request tiếp theo được gửi trên cùng kết nối TCP.

**5. Request Tunneling (Đào hầm yêu cầu qua Proxy):**
  - **Cơ chế**: Kẻ tấn công lợi dụng sự desync giữa proxy và back-end để đóng gói một request hoàn chỉnh khác bên trong phần thân của request đầu tiên (smuggled request).
  - Request này được "tunnel" qua proxy mà hoàn toàn không bị kiểm tra bởi các chính sách bảo mật, bộ lọc IP, xác thực hay WAF được cài đặt trên proxy front-end. Back-end server khi đọc luồng dữ liệu từ socket sẽ phân tách yêu cầu bị chèn này và thực thi nó dưới tư cách là một yêu cầu nội bộ hợp lệ, cho phép kẻ tấn công truy cập trái phép các endpoint nhạy cảm (như `/admin`, `/internal-api`) hoặc giả mạo người dùng nội bộ.

## 9. Code dễ bị lỗi và code an toàn

Ví dụ dưới đây chỉ phân loại metadata framing đã được parser fixture tách sẵn; nó không mở socket và không dùng timeout làm bằng chứng lỗ hổng.

```python
def framing_policy_vulnerable(headers):
    """Vulnerable: silently prefers Transfer-Encoding when CL and TE coexist."""
    content_length = headers.get("content-length", [])
    transfer_encoding = headers.get("transfer-encoding", [])
    if transfer_encoding:
        return "chunked"
    if content_length:
        return "content-length"
    return "no-body"


def framing_policy_secure(headers):
    """Reject ambiguous HTTP/1.1 framing before forwarding a request."""
    content_length = headers.get("content-length", [])
    transfer_encoding = headers.get("transfer-encoding", [])

    if content_length and transfer_encoding:
        raise ValueError("ambiguous Content-Length/Transfer-Encoding")
    if len(set(content_length)) > 1:
        raise ValueError("conflicting Content-Length values")
    if transfer_encoding and transfer_encoding != ["chunked"]:
        raise ValueError("unsupported Transfer-Encoding chain")
    return "chunked" if transfer_encoding else "content-length" if content_length else "no-body"


fixture_headers = {
    "content-length": ["6"],
    "transfer-encoding": ["chunked"],
}
assert framing_policy_vulnerable(fixture_headers) == "chunked"
try:
    framing_policy_secure(fixture_headers)
except ValueError as exc:
    assert str(exc) == "ambiguous Content-Length/Transfer-Encoding"
else:
    raise AssertionError("ambiguous framing was not rejected")
```

Đây là minh họa policy ở một hop, không phải parser HTTP hoàn chỉnh. Retest thực tế vẫn phải dùng frontend/backend pair đã pin, so sánh cách cả hai hop xác định message boundary và không suy từ một timeout đơn lẻ. [S1], [S6]

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến HTTP Request Smuggling, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Áp dụng một framing policy và từ chối mọi request CL/TE mơ hồ tại edge.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với HTTP Request Smuggling, các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

```nginx
# Nginx — reject ambiguous requests
if ($http_transfer_encoding ~* "chunked" ) {
    # If both CL and TE are present, return 400
    set $ambiguous "TE";
}
if ($content_length != "") {
    set $ambiguous "${ambiguous}CL";
}
if ($ambiguous = "TECL") {
    return 400;  # Reject ambiguous requests
}
```

- **Tóm tắt**: Phòng chống HTTP Request Smuggling bằng cách sử dụng HTTP/2 end-to-end, cấu hình proxy từ chối request không rõ ràng, và chuẩn hóa các HTTP header.
- **Các bước chi tiết**:
  - **Sử dụng HTTP/2 end-to-end** — HTTP/2 dùng binary framing, loại bỏ hoàn toàn ambiguity về ranh giới request. Đảm bảo không downgrade sang HTTP/1.1 ở back-end.
  - **Cấu hình proxy từ chối request ambiguous** — reject request có cả `Content-Length` và `Transfer-Encoding`:
  - **Normalize header** trước khi forward — strip duplicate `Transfer-Encoding`, loại bỏ obfuscation.
  - **Mỗi request một TCP connection** — tắt connection reuse giữa front-end và back-end (giảm hiệu suất nhưng an toàn).
  - **Sử dụng công cụ kiểm tra** — Burp Suite's HTTP Request Smuggler extension để phát hiện vulnerability.

## 12. Retest

- **Positive case:** với HTTP Request Smuggling, luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của HTTP Request Smuggling mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **CDN (Content Delivery Network)**: Mạng lưới phân phối nội dung giúp tăng tốc độ tải trang bằng cách lưu trữ bản sao ở nhiều nơi trên thế giới gần với người dùng hơn.
- **Load Balancer**: Bộ cân bằng tải, phân chia lưu lượng truy cập đều cho các máy chủ phía sau để tránh quá tải.
- **Reverse Proxy**: Máy chủ trung gian đứng trước các máy chủ ứng dụng để tiếp nhận, xử lý hoặc lọc yêu cầu từ client trước khi gửi vào hệ thống nội bộ.
- **Application Server**: Máy chủ ứng dụng xử lý logic nghiệp vụ chính của website (như xử lý database, đăng nhập, mua hàng...).
- **Connection Reuse**: Kỹ thuật tái sử dụng một kết nối mạng (TCP) để gửi nhiều yêu cầu liên tiếp nhằm tiết kiệm thời gian thiết lập kết nối mới.
- **TCP Connection**: Kết nối mạng tin cậy giúp truyền dữ liệu ổn định và chính xác giữa hai máy tính.
- **RFC**: Bộ tài liệu tiêu chuẩn kỹ thuật quy định các quy tắc hoạt động của các giao thức trên Internet.
- **Desync (Mất đồng bộ)**: Sự không thống nhất về cách hiểu hoặc trạng thái dữ liệu giữa hai hay nhiều hệ thống khác nhau.
- **WAF (Web Application Firewall)**: Tường lửa bảo vệ ứng dụng web khỏi các cuộc tấn công bằng cách lọc và giám sát lưu lượng HTTP.
- **Cache Poisoning**: Kỹ thuật làm nhiễm độc bộ nhớ đệm, khiến hệ thống lưu trữ và trả về nội dung độc hại cho tất cả người dùng truy cập sau đó.
- **Endpoint**: Điểm cuối (địa chỉ URL cụ thể) của một dịch vụ hoặc API mà ứng dụng có thể gửi yêu cầu đến.
- **Obfuscation (Làm xáo trộn)**: Kỹ thuật làm mờ, biến đổi hoặc che giấu thông tin/dữ liệu để tránh bị các hệ thống quét an ninh phát hiện nhưng vẫn hoạt động được.
- **Downgrade**: Quá trình hạ cấp giao thức hoặc phiên bản công nghệ xuống mức thấp hơn (ví dụ từ HTTP/2 xuống HTTP/1.1) nhằm mục đích tương thích ngược hoặc khai thác lỗi.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/request-smuggling — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP WSTG — Testing for HTTP Request Smuggling. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling — phiên bản/trạng thái: latest; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/444.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** James Kettle. https://portswigger.net/research/http-desync-attacks — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S6]** RFC 9112 — HTTP/1.1, sections 6.3 and 11.2. https://www.rfc-editor.org/rfc/rfc9112.html — phiên bản/ngày: June 2022; truy cập: 2026-07-18.
