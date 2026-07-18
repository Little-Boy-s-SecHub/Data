---
schema_version: 1
id: WEB-A10-DENIAL-OF-SERVICE
title: "Denial of Service Attacks"
slug: denial-of-service
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp: []
cwe:
  - CWE-400
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Denial of Service Attacks

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Denial of Service Attacks bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Denial of Service (DoS - Từ chối dịch vụ)** là điểm yếu trong cách hệ thống phân bổ và bảo vệ tài nguyên. Khi một ứng dụng hoặc hệ thống mạng quá ngây thơ, cho phép một cá nhân hoặc một nhóm máy tính yêu cầu tài nguyên không giới hạn, kẻ tấn công sẽ tìm cách làm quá tải hệ thống đó.

Hắn có thể:
- Gửi hàng triệu gói tin vô nghĩa để làm nghẽn băng thông mạng của bạn (như SYN flood).
- Mở hàng ngàn kết nối nhưng gửi dữ liệu nhỏ giọt cực chậm để máy chủ phải mệt mỏi chờ đợi (như Slowloris).
- Huy động cả một đội quân máy tính ma (botnet) để cùng lúc dồn dập tấn công từ nhiều hướng (DDoS).
Hậu quả là trang web hoặc dịch vụ của bạn bị đóng băng, tê liệt hoàn toàn, biến một dịch vụ trực tuyến thành một "thành phố chết" không thể tiếp cận đối với khách hàng thực sự.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** độ sẵn sàng, p95 latency, worker/queue, CPU và memory của dịch vụ lab.
- **Trust boundary:** request body, tham số regex hoặc burst request đi vào parser, regex engine và worker queue.
- **Actor:** client local không đặc quyền, bị giới hạn số request, kích thước input và thời gian chạy.
- **Điều kiện cần:** input gây khuếch đại chi phí hoặc chiếm tài nguyên không giới hạn; thiếu cap về size/depth/time/concurrency/queue tại đúng sink.
- **Điều kiện môi trường:** container local không outbound, có timeout cùng CPU/memory/PID cap; thu baseline latency và resource metrics trước thử nghiệm.

Một response chậm đơn lẻ không đủ kết luận DoS; phải chứng minh chi phí tăng bất thường hoặc tài nguyên vượt ngưỡng trong điều kiện fixture có thể lặp lại. [S1]

## 6. Cơ chế tấn công

Regex có backtracking siêu tuyến tính, body quá lớn hoặc concurrency không bị chặn có thể làm cạn CPU, memory hoặc worker. Phép đo phải so sánh cùng endpoint/input hợp lệ, tăng từng nấc bị giới hạn, và xác nhận bản sửa từ chối sớm trước tác vụ tốn tài nguyên. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy fixture trong container có `--cpus`, `--memory`, `--pids-limit` và timeout; bật metric cho latency, queue, CPU và memory.
2. **Input:** đo baseline với request nhỏ, rồi tăng có giới hạn độ dài regex/body hoặc burst tối đa theo bảng test.
3. **Thao tác:** chỉ thay một chiều mỗi lượt; ghi số request, kích thước, elapsed time, peak resource và status code.
4. **Expected result:** bản dễ lỗi vượt ngưỡng lab; bản sửa trả lỗi giới hạn sớm, giữ worker khả dụng và phục hồi về baseline sau lượt test.
5. **Cleanup:** dừng client/fixture, xóa queue/dữ liệu tạm và xác nhận resource trở về mức nền.
6. **Giới hạn an toàn:** không chạy payload trên Internet hay shared environment; dừng ngay khi chạm ngưỡng CPU/memory/latency đã định.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

<!-- payload-id: WEB-A10-DENIAL-OF-SERVICE-001 -->
<!-- context: Python 3.12 backtracking regex fixture in a CPU/memory-capped disposable container; pattern is fixed by the lab -->
<!-- prerequisites: limit input to at most 25 characters, use a two-second timeout and stop before the resource threshold -->
<!-- encoding: ASCII input consumed directly by the Python regex engine -->
<!-- expected-result: the vulnerable pattern shows increasing bounded elapsed time; the fixed linear pattern remains within the baseline envelope -->
<!-- risk: dos -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S4 -->
<!-- last-verified: 2026-07-17 -->
```text
aaaaaaaaaaaaaaaaaaaaaaaa!
```

Tấn công Từ chối Dịch vụ (DoS) có thể nhắm vào hạ tầng mạng hoặc trực tiếp vào logic xử lý của ứng dụng để làm cạn kiệt tài nguyên:

1. **TCP SYN Flood & Slowloris (Cơ bản)**:
   - **SYN Flood**: Gửi hàng loạt gói TCP SYN nhưng bỏ qua phản hồi SYN-ACK để chiếm dụng các khe kết nối mở một nửa.
   - **Slowloris**: Mở nhiều kết nối HTTP và gửi/nhận dữ liệu cực kỳ chậm để giữ các kết nối luôn bận rộn, làm cạn kiệt connection pool.

2. **Hash Collision DoS (Algorithmic Complexity DoS)**:
   - **Cơ chế**: Nếu nhiều khóa rơi vào cùng bucket, chi phí một thao tác có thể tiến tới $O(N)$ và chi phí chèn cả tập $N$ khóa có thể tiến tới $O(N^2)$. Cấu trúc bucket và cơ chế chống collision phụ thuộc runtime; không phải mọi hash table đều dùng linked list. Python bật hash randomization mặc định cho `str` và `bytes`, nhưng vẫn phải giới hạn số trường và kích thước request. [S3]

3. **Algorithmic Complexity DoS - ReDoS (Regular Expression Denial of Service)**:
   - **Cơ chế**: Một backtracking engine có thể thử rất nhiều cách phân hoạch khi pattern mơ hồ chứa quantifier lồng nhau, ví dụ `(a+)+`. Với một số pattern/input, thời gian tăng theo cấp số nhân; đây là xử lý rất lâu chứ không phải vòng lặp vô hạn. Engine tuyến tính hoặc pattern khác có thể không có hành vi này. [S4]

4. **Amplification Attacks (DNS, NTP, Memcached)**:
   - **Cơ chế**: Đây là hình thức tấn công DDoS tầng mạng dựa trên giao thức UDP (không yêu cầu bắt tay). Kẻ tấn công giả mạo (spoof) địa chỉ IP nguồn trong các gói tin yêu cầu gửi đi thành địa chỉ IP của nạn nhân, sau đó gửi yêu cầu này đến các máy chủ trung gian mở trên internet (như Open DNS, NTP servers, hoặc Memcached).
   - **Hệ số khuếch đại (Amplification Factor)**: Phản hồi lớn hơn request và bị gửi tới địa chỉ nguồn giả mạo. Hệ số thực tế phụ thuộc giao thức, cấu hình và kích thước dữ liệu; không dùng một con số cố định làm thuộc tính hiện hành. `monlist` là ví dụ NTP mang tính lịch sử và thường đã bị vô hiệu hóa trong triển khai được cập nhật.
   Toàn bộ lưu lượng phản hồi khổng lồ này sẽ đổ dồn vào IP của nạn nhân, làm nghẽn băng thông của họ.

5. **HTTP/2 Rapid Reset (CVE-2023-44487)**:
   - **Cơ chế**: HTTP/2 cho phép đa luồng (multiplexing) trên một kết nối TCP duy nhất, trong đó client có thể mở đồng thời nhiều luồng (streams) bằng cách gửi các khung hình `HEADERS`. HTTP/2 cũng định nghĩa khung hình `RST_STREAM` cho phép client hủy một stream bất kỳ lúc nào nếu không cần phản hồi nữa.
   - **Tấn công**: Kẻ tấn công gửi liên tục hàng loạt khung hình `HEADERS` để yêu cầu mở luồng, và ngay lập tức gửi khung hình `RST_STREAM` để hủy luồng đó trên cùng một kết nối TCP. Do stream bị hủy lập tức, server không cần gửi phản hồi (tiết kiệm băng thông cho kẻ tấn công) nhưng server vẫn phải tiêu tốn tài nguyên CPU và RAM để khởi tạo luồng, xử lý yêu cầu ban đầu và hủy luồng. Việc lặp lại hành động này với tốc độ cao khiến CPU của máy chủ web bị quá tải và cạn kiệt tài nguyên xử lý luồng cực nhanh mà không làm nghẽn băng thông mạng của cả hai bên.

## 9. Code dễ bị lỗi và code an toàn

### 1. Nginx 1.25+: giới hạn kết nối và request
```nginx
# Resource limits complement, but do not replace, vendor security updates
http {
    # Limit requests to 10 per second per IP with a burst capacity of 20
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

    # Bound concurrent streams and requests per connection
    http2_max_concurrent_streams 100;
    keepalive_requests 1000;

    server {
        listen 443 ssl;
        http2 on;
        server_name victim.lab.test;

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


# === SECURE FOR THIS LANGUAGE: remove the ambiguous nested quantifier ===
SAFE_REGEX = re.compile(r"^a+$")

def check_string_secure(input_data, max_length=256):
    # Length caps bound work and memory even when the pattern changes later
    if len(input_data) > max_length:
        raise ValueError("Input exceeds the documented limit")
    return SAFE_REGEX.fullmatch(input_data) is not None
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

# === SAFER: randomized string hashes plus explicit request limits ===
def process_request_parameters(user_params, max_fields=100):
    if len(user_params) > max_fields:
        raise ValueError("Too many request fields")
    safe_storage = {}
    for key, value in user_params.items():
        if not isinstance(key, str) or len(key) > 128:
            raise ValueError("Invalid key")
        safe_storage[key] = value
    return safe_storage
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Giới hạn tài nguyên, fail safely và xử lý mọi trạng thái ngoại lệ có thể đạt tới.
- Áp hard cap cho size/depth/time/concurrency/queue trước xử lý đắt đỏ và dùng thuật toán có chi phí bị chặn; rate limit chỉ là một lớp bổ sung.
- Dùng cùng một policy cho mọi route/operation tương đương; không chỉ sửa endpoint xuất hiện trong PoC.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Bảo vệ hệ thống khỏi sự cạn kiệt tính khả dụng bằng cách triển khai các biện pháp bảo vệ nhiều lớp bao gồm giới hạn tốc độ (rate limiting), thời gian chờ kết nối (connection timeouts), và WAF.
- **Các bước chi tiết**:
  - Cấu hình giới hạn tốc độ trên các máy chủ web (ví dụ: limit_req_zone trong Nginx) để giới hạn tốc độ yêu cầu trên mỗi IP.
  - Thiết lập thời gian chờ kết nối và thân yêu cầu (body timeouts) ngắn trong cấu hình máy chủ web để tự động đóng các kết nối nhàn rỗi hoặc chậm chạp.
  - Kích hoạt TCP SYN cookies trên hệ điều hành để ngăn chặn việc cạn kiệt nhóm kết nối do tấn công SYN flood.
  - Triển khai các dịch vụ giảm thiểu DDoS chuyên dụng hoặc Tường lửa Ứng dụng Web (WAF) để hấp thụ và lọc lưu lượng tấn công phân tán.

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

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-400. https://cwe.mitre.org/data/definitions/400.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** Python data model — hash randomization. https://docs.python.org/3/reference/datamodel.html — phiên bản/trạng thái: Python 3.14; truy cập: 2026-07-18.
- **[S4]** CWE-1333. https://cwe.mitre.org/data/definitions/1333.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
