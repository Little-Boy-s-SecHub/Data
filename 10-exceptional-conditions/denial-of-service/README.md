# Denial of Service Attacks

> **CWE**: CWE-400 | **Phân loại**: System / Binary

## Kiến thức Nền tảng
Hãy tưởng tượng một tổng đài chăm sóc khách hàng chỉ có đúng 10 điện thoại viên. Bình thường, khi bạn gọi đến để yêu cầu trợ giúp, một quy trình kết nối tin cậy sẽ diễn ra gọi là **Bắt tay 3 bước (TCP 3-way handshake)**:
- Bước 1: Bạn nhấc máy gọi và nói: "Xin chào, tôi muốn kết nối!" (SYN).
- Bước 2: Điện thoại viên nhấc máy trả lời: "Vâng tôi nghe đây, bạn có nghe thấy tôi nói không?" (SYN-ACK) và tạm thời giữ máy để chờ phản hồi từ bạn.
- Bước 3: Bạn nói: "Tôi nghe rõ, chúng ta bắt đầu nói chuyện nhé!" (ACK). Kết nối chính thức được thiết lập.

Mối nguy hiểm xuất hiện khi một kẻ quấy rối cố tình phá hoại hệ thống. Hắn sử dụng hàng ngàn chiếc điện thoại tự động gọi liên tiếp đến tổng đài (gửi gói tin SYN), khiến tất cả 10 điện thoại viên đều phải nhấc máy và hỏi: "Tôi nghe đây..." (SYN-ACK). Tuy nhiên, kẻ quấy rối cố tình im lặng, không chịu trả lời bước 3 (ACK). Cả 10 điện thoại viên phải đứng chờ cuộc gọi mở một nửa này trong vô vọng.
Vì tài nguyên tổng đài có hạn (giới hạn nhóm kết nối - **connection pool limits**), 10 đường dây đều đã bị chiếm dụng hết sạch. Lúc này, nếu có một người dân thực sự gặp nạn gọi đến, hệ thống sẽ báo bận hoặc không thể tiếp nhận cuộc gọi. Đó chính là bản chất của **Tấn công Từ chối Dịch vụ (Denial of Service - DoS)**: làm tê liệt hệ thống bằng cách vắt kiệt mọi tài nguyên kết nối, khiến những người dùng hợp pháp bị chặn đứng ở cửa ra vào.

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Normal operation: Safe socket handler enforcing short timeouts and connection management
import socket
import select

def run_safe_server(host="127.0.0.1", port=8080):
    # Initialize a secure IPv4 TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable address reuse to avoid port binding delays
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to address and start listening with backlog limit
    server_socket.bind((host, port))
    server_socket.listen(10) # Restrict queue size for pending connections
    server_socket.setblocking(False) # Enable non-blocking mode for I/O multiplexing
    
    print(f"TCP server is running on {host}:{port}...")
    
    try:
        while True:
            # Use select to wait for incoming connections without blocking indefinitely
            readable, _, _ = select.select([server_socket], [], [], 5.0)
            
            for s in readable:
                if s is server_socket:
                    client_socket, addr = server_socket.accept()
                    # Enforce strict timeouts to disconnect idle or slow clients (mitigates Slowloris)
                    client_socket.settimeout(3.0)
                    
                    try:
                        data = client_socket.recv(1024)
                        if data:
                            # Send standard HTTP response
                            client_socket.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nResponse OK")
                    except socket.timeout:
                        print(f"Connection from {addr} closed due to inactivity timeout.")
                    except Exception as e:
                        print(f"Error handling connection: {e}")
                    finally:
                        # Explicitly close client socket to free connection slots immediately
                        client_socket.close()
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        server_socket.close()
```

## Mô tả lỗ hổng
Lỗ hổng **Denial of Service (DoS - Từ chối dịch vụ)** là điểm yếu trong cách hệ thống phân bổ và bảo vệ tài nguyên. Khi một ứng dụng hoặc hệ thống mạng quá ngây thơ, cho phép một cá nhân hoặc một nhóm máy tính yêu cầu tài nguyên không giới hạn, kẻ tấn công sẽ tìm cách làm quá tải hệ thống đó.

Hắn có thể:
- Gửi hàng triệu gói tin vô nghĩa để làm nghẽn băng thông mạng của bạn (như SYN flood).
- Mở hàng ngàn kết nối nhưng gửi dữ liệu nhỏ giọt cực chậm để máy chủ phải mệt mỏi chờ đợi (như Slowloris).
- Huy động cả một đội quân máy tính ma (botnet) để cùng lúc dồn dập tấn công từ nhiều hướng (DDoS).
Hậu quả là trang web hoặc dịch vụ của bạn bị đóng băng, tê liệt hoàn toàn, biến một dịch vụ trực tuyến thành một "thành phố chết" không thể tiếp cận đối với khách hàng thực sự.

## Cơ chế tấn công
Tấn công Từ chối Dịch vụ (DoS) có thể nhắm vào hạ tầng mạng hoặc trực tiếp vào logic xử lý của ứng dụng để làm cạn kiệt tài nguyên:

1. **TCP SYN Flood & Slowloris (Cơ bản)**:
   - **SYN Flood**: Gửi hàng loạt gói TCP SYN nhưng bỏ qua phản hồi SYN-ACK để chiếm dụng các khe kết nối mở một nửa.
   - **Slowloris**: Mở nhiều kết nối HTTP và gửi/nhận dữ liệu cực kỳ chậm để giữ các kết nối luôn bận rộn, làm cạn kiệt connection pool.

2. **Hash Collision DoS (Algorithmic Complexity DoS)**:
   - **Cơ chế**: Khi ứng dụng phân tách dữ liệu đầu vào (như các tham số POST request hoặc JSON) và lưu trữ chúng vào một bảng băm (Hash Map/Hash Table), nó sẽ tính giá trị băm (hash value) của các khóa (keys). Nếu xảy ra xung đột băm (hash collision) — khi nhiều khóa khác nhau có cùng một giá trị băm — bảng băm phải giải quyết bằng cách liên kết các phần tử này thành một danh sách liên kết (linked list) trên cùng một bucket. Kẻ tấn công gửi một lượng lớn các khóa được thiết kế đặc biệt để cố tình gây ra xung đột băm tối đa. Lúc này, độ phức tạp thời gian tìm kiếm và chèn của bảng băm từ trung bình $O(1)$ tăng vọt lên trường hợp xấu nhất là $O(N)$ hoặc $O(N^2)$, khiến CPU bị quá tải nghiêm trọng chỉ với một lượng dữ liệu đầu vào nhỏ.

3. **Algorithmic Complexity DoS - ReDoS (Regular Expression Denial of Service)**:
   - **Cơ chế**: Lỗ hổng xảy ra khi công cụ phân tích biểu thức chính quy (Regex Engine) sử dụng giải thuật quay lui (backtracking) gặp phải một chuỗi đầu vào không khớp nhưng có cấu trúc phức tạp. Khi sử dụng các regex chứa các nhóm lặp lồng nhau hoặc không xác định rõ ràng (ví dụ: `(a+)+`), regex engine phải thử mọi tổ hợp có thể trước khi kết luận chuỗi không khớp. Độ phức tạp thời gian trong trường hợp này tăng theo hàm mũ $O(2^N)$ đối với chiều dài chuỗi đầu vào $N$. Kẻ tấn công gửi một chuỗi đầu vào được thiết kế đặc biệt (như một chuỗi dài chứa toàn ký tự `a` và kết thúc bằng một ký tự khác) khiến CPU bị treo trong trạng thái tính toán vô hạn (regex loop / catastrophic backtracking).

4. **Amplification Attacks (DNS, NTP, Memcached)**:
   - **Cơ chế**: Đây là hình thức tấn công DDoS tầng mạng dựa trên giao thức UDP (không yêu cầu bắt tay). Kẻ tấn công giả mạo (spoof) địa chỉ IP nguồn trong các gói tin yêu cầu gửi đi thành địa chỉ IP của nạn nhân, sau đó gửi yêu cầu này đến các máy chủ trung gian mở trên internet (như Open DNS, NTP servers, hoặc Memcached).
   - **Hệ số khuếch đại (Amplification Factor)**: Các máy chủ trung gian này phản hồi các yêu cầu bằng các gói tin có kích thước lớn gấp nhiều lần gói tin yêu cầu ban đầu.
     - **DNS Amplification**: Gửi yêu cầu nhỏ (`ANY` record) nhận về phản hồi cực lớn chứa toàn bộ bản ghi DNS (hệ số khuếch đại khoảng 28x-54x).
     - **NTP Amplification**: Sử dụng lệnh `monlist` để lấy danh sách 600 địa chỉ IP kết nối gần nhất (hệ số khuếch đại lên tới 200x).
     - **Memcached Amplification**: Sử dụng giao thức UDP để yêu cầu dữ liệu lớn được lưu trữ sẵn (hệ số khuếch đại lên tới 10,000x - 50,000x).
   Toàn bộ lưu lượng phản hồi khổng lồ này sẽ đổ dồn vào IP của nạn nhân, làm nghẽn băng thông của họ.

5. **HTTP/2 Rapid Reset (CVE-2023-44487)**:
   - **Cơ chế**: HTTP/2 cho phép đa luồng (multiplexing) trên một kết nối TCP duy nhất, trong đó client có thể mở đồng thời nhiều luồng (streams) bằng cách gửi các khung hình `HEADERS`. HTTP/2 cũng định nghĩa khung hình `RST_STREAM` cho phép client hủy một stream bất kỳ lúc nào nếu không cần phản hồi nữa.
   - **Tấn công**: Kẻ tấn công gửi liên tục hàng loạt khung hình `HEADERS` để yêu cầu mở luồng, và ngay lập tức gửi khung hình `RST_STREAM` để hủy luồng đó trên cùng một kết nối TCP. Do stream bị hủy lập tức, server không cần gửi phản hồi (tiết kiệm băng thông cho kẻ tấn công) nhưng server vẫn phải tiêu tốn tài nguyên CPU và RAM để khởi tạo luồng, xử lý yêu cầu ban đầu và hủy luồng. Việc lặp lại hành động này với tốc độ cao khiến CPU của máy chủ web bị quá tải và cạn kiệt tài nguyên xử lý luồng cực nhanh mà không làm nghẽn băng thông mạng của cả hai bên.

## Biện pháp phòng thủ
- **Tóm tắt**: Bảo vệ hệ thống khỏi sự cạn kiệt tính khả dụng bằng cách triển khai các biện pháp bảo vệ nhiều lớp bao gồm giới hạn tốc độ (rate limiting), thời gian chờ kết nối (connection timeouts), và WAF.
- **Các bước chi tiết**:
  - Cấu hình giới hạn tốc độ trên các máy chủ web (ví dụ: limit_req_zone trong Nginx) để giới hạn tốc độ yêu cầu trên mỗi IP.
  - Thiết lập thời gian chờ kết nối và thân yêu cầu (body timeouts) ngắn trong cấu hình máy chủ web để tự động đóng các kết nối nhàn rỗi hoặc chậm chạp.
  - Kích hoạt TCP SYN cookies trên hệ điều hành để ngăn chặn việc cạn kiệt nhóm kết nối do tấn công SYN flood.
  - Triển khai các dịch vụ giảm thiểu DDoS chuyên dụng hoặc Tường lửa Ứng dụng Web (WAF) để hấp thụ và lọc lưu lượng tấn công phân tán.

## Code Example
### 1. Nginx Configuration (Slowloris & Rate Limiting & HTTP/2 Mitigation)
```nginx
# Configure rate limiting and connection timeouts in Nginx
http {
    # Limit requests to 10 per second per IP with a burst capacity of 20
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

    # Mitigate HTTP/2 Rapid Reset (CVE-2023-44487)
    # Restrict maximum concurrent streams per HTTP/2 connection
    http2_max_concurrent_streams 100;
    # Limit maximum requests that can be served through one keep-alive connection
    keepalive_requests 1000;

    server {
        listen 443 ssl http2;
        server_name example.com;

        # Mitigate Slowloris by setting short timeouts
        client_body_timeout 10s;
        client_header_timeout 10s;
        keepalive_timeout 5s 5s;
        send_timeout 10s;

        location / {
            limit_req zone=mylimit burst=20 nodelay;
            proxy_pass http://app_servers;
        }
    }
}
```

### 2. Regular Expression DoS (ReDoS)
```python
# === VULNERABLE: Regex with nesting qualifiers causing catastrophic backtracking ===
import re
import time

# Vulnerable regex: (a+)+$ matches groups of 'a's, but ends with a different character
# When evaluated against "aaaa...aaaX", it performs exponential backtracking
VULN_REGEX = re.compile(r"^(a+)+$")

def check_string_vuln(input_data):
    start_time = time.time()
    # Evaluating matching logic
    VULN_REGEX.match(input_data)
    duration = time.time() - start_time
    print(f"Match evaluated in {duration:.5f} seconds")

# Attack payload: 25 characters of 'a' followed by 'X'
# Will cause severe CPU spikes and take significant time to evaluate
# check_string_vuln("aaaaaaaaaaaaaaaaaaaaaaaaX")


# === SECURE: Linear-time regex or enforcing strict timeouts ===
# 1. Use a non-backtracking pattern (avoid nesting quantifiers)
SAFE_REGEX = re.compile(r"^a+$")

# 2. Alternatively, implement a regex timeout checker
import signal

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Regex matching timed out!")

def check_string_secure(input_data, timeout_seconds=1):
    # Enforce strict execution timeout for regex engines
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_seconds)
    try:
        SAFE_REGEX.match(input_data)
        print("Match completed safely")
    except TimeoutException:
        print("Regex execution blocked due to timeout")
    finally:
        signal.alarm(0) # Cancel the alarm
```

### 3. Hash Collision DoS (Python Implementation)
```python
# === VULNERABLE: Custom hash table without collision protection ===
class SimpleHashTable:
    def __init__(self, size=1024):
        self.size = size
        # Array of buckets storing key-value pairs
        self.table = [[] for _ in range(self.size)]

    def _hash(self, key):
        # A simple modulo hash function is highly vulnerable to intentional collisions
        return sum(ord(c) for c in key) % self.size

    def insert(self, key, value):
        h = self._hash(key)
        # Append to bucket. If collision occurs, it builds a linked list
        self.table[h].append((key, value))

    def get(self, key):
        h = self._hash(key)
        # Searching the bucket in O(N) linear time if there are collisions
        for k, v in self.table[h]:
            if k == key:
                return v
        return None

# === SECURE: Utilizing built-in randomized hashing ===
# Python's built-in dict uses randomized hash seeds (enabled by default)
# This prevents attackers from pre-computing colliding keys.
def process_request_parameters(user_params):
    # Safe: built-in dict hashes keys with a runtime-randomized seed
    safe_storage = {}
    for key, value in user_params.items():
        safe_storage[key] = value
    return safe_storage
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: CWE-400 (Uncontrolled Resource Consumption)

## Giải thích thuật ngữ
- **SYN (Synchronize)**: Gói tin khởi tạo yêu cầu thiết lập kết nối mạng trong giao thức TCP.
- **SYN-ACK**: Gói tin phản hồi của máy chủ để xác nhận yêu cầu kết nối từ client và sẵn sàng kết nối.
- **ACK (Acknowledgment)**: Gói tin xác nhận hoàn thành kết nối từ phía máy khách gửi lại cho máy chủ.
- **Half-open Connection (Kết nối mở một nửa)**: Trạng thái kết nối khi client mới chỉ gửi SYN, server phản hồi SYN-ACK nhưng client chưa gửi ACK cuối cùng để hoàn tất.
- **Connection Pool**: Nhóm các kết nối mạng được khởi tạo sẵn và duy trì liên tục để hệ thống tái sử dụng nhanh chóng.
- **Slowloris**: Kỹ thuật tấn công DoS bằng cách mở nhiều kết nối HTTP đến máy chủ và giữ các kết nối này luôn bận rộn bằng cách truyền dữ liệu cực kỳ chậm chạp.
- **Hash Table (Bảng băm)**: Cấu trúc dữ liệu lưu trữ các cặp khóa-giá trị, cho phép tìm kiếm dữ liệu cực kỳ nhanh chóng.
- **Hash Collision (Xung đột băm)**: Tình huống khi hai hoặc nhiều khóa khác nhau tạo ra cùng một giá trị băm trong bảng băm.
- **Backtracking (Quay lui)**: Thuật toán tìm kiếm giải pháp bằng cách thử từng khả năng và quay lại bước trước nếu gặp ngõ cụt.
- **Catastrophic Backtracking (Quay lui thảm họa)**: Hiện tượng công cụ Regex bị treo do số lượng khả năng thử nghiệm và quay lui tăng lên theo hàm mũ khi chuỗi nhập vào không khớp.
- **Amplification Factor (Hệ số khuếch đại)**: Chỉ số đo lường mức độ gia tăng kích thước của gói dữ liệu phản hồi so với gói dữ liệu yêu cầu ban đầu.
- **Botnet**: Mạng lưới các thiết bị hoặc máy tính bị nhiễm mã độc và bị kẻ tấn công điều khiển từ xa để tiến hành các cuộc tấn công quy mô lớn (DDoS).
- **Stream**: Luồng truyền dữ liệu độc lập cho phép nhiều yêu cầu/phản hồi đồng thời chạy trên một kết nối HTTP/2 duy nhất.
