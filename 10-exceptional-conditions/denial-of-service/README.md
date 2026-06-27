# Denial of Service Attacks

> **OWASP Top 10:2025**: A10:2025 – Mishandling of Exceptional Conditions | **CWE**: CWE-400 | **Phân loại**: System

## 🧱 Kiến thức Nền tảng
Tấn công Từ chối Dịch vụ (Denial of Service - DoS) hướng tới việc làm tê liệt hệ thống, khiến người dùng hợp lệ không thể truy cập tài nguyên. Để nhận diện và ngăn chặn hiệu quả các loại tấn công này ở tầng mạng và tầng ứng dụng, lập trình viên cần hiểu rõ hai khái niệm cốt lõi:

1. **TCP 3-way handshake (Bắt tay 3 bước TCP)**: Đây là quy trình chuẩn để thiết lập kết nối tin cậy giữa máy khách và máy chủ. Bước đầu tiên, máy khách gửi gói tin `SYN` (Synchronize). Bước thứ hai, máy chủ phản hồi bằng gói tin `SYN-ACK` (Synchronize-Acknowledgment) và dành riêng tài nguyên bộ nhớ cho kết nối này. Bước cuối cùng, máy khách gửi lại gói `ACK` (Acknowledgment) để xác nhận kết nối thành công. Trong tấn công SYN Flood, kẻ tấn công gửi hàng loạt gói `SYN` nhưng cố tình không gửi gói `ACK` phản hồi, khiến máy chủ rơi vào trạng thái chờ kết nối mở một nửa (half-open) cho đến khi cạn kiệt tài nguyên hệ thống.
2. **Connection pool limits (Giới hạn nhóm kết nối)**: Máy chủ web và hệ điều hành chỉ duy trì được một số lượng kết nối đồng thời tối đa nhất định (connection pool limit) do giới hạn về phần cứng như RAM, CPU và số lượng file descriptors. Khi kẻ tấn công thực hiện SYN Flood hoặc mở nhiều kết nối HTTP rồi truyền dữ liệu cực kỳ chậm (Slowloris), chúng sẽ chiếm dụng toàn bộ các khe kết nối (connection slots) trong pool. Kết quả là máy chủ không thể tiếp nhận thêm bất kỳ yêu cầu mới nào từ người dùng hợp pháp, dẫn tới tình trạng từ chối dịch vụ.

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

## 🔍 Mô tả lỗ hổng
Các cuộc tấn công Từ chối Dịch vụ (DoS) nhằm mục đích làm cho một trang web hoặc dịch vụ không khả dụng đối với người dùng hợp pháp bằng cách tràn ngập nó với các yêu cầu hoặc gói dữ liệu quá mức. Các cuộc tấn công này nhắm vào các tầng khác nhau của ngăn xếp mạng, từ các cuộc tấn công TCP SYN flood và Slowloris cho đến các hoạt động Từ chối Dịch vụ Phân tán (DDoS) khổng lồ được dàn dựng bởi botnet.

## ⚔️ Cơ chế tấn công
Trong một cuộc tấn công SYN flood, kẻ tấn công gửi một lượng lớn các gói TCP SYN và bỏ qua các phản hồi SYN-ACK, để lại các kết nối mở một nửa (half-open) làm cạn kiệt nhóm kết nối. Trong một cuộc tấn công Slowloris, kẻ tấn công mở các kết nối HTTP và đọc hoặc gửi dữ liệu cực kỳ chậm, chiếm dụng tất cả các khe kết nối của máy chủ và chặn lưu lượng truy cập hợp pháp.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Bảo vệ hệ thống khỏi sự cạn kiệt tính khả dụng bằng cách triển khai các biện pháp bảo vệ nhiều lớp bao gồm giới hạn tốc độ (rate limiting), thời gian chờ kết nối (connection timeouts), và WAF.
- **Các bước chi tiết**:
  - Cấu hình giới hạn tốc độ trên các máy chủ web (ví dụ: limit_req_zone trong Nginx) để giới hạn tốc độ yêu cầu trên mỗi IP.
  - Thiết lập thời gian chờ kết nối và thân yêu cầu (body timeouts) ngắn trong cấu hình máy chủ web để tự động đóng các kết nối nhàn rỗi hoặc chậm chạp.
  - Kích hoạt TCP SYN cookies trên hệ điều hành để ngăn chặn việc cạn kiệt nhóm kết nối do tấn công SYN flood.
  - Triển khai các dịch vụ giảm thiểu DDoS chuyên dụng hoặc Tường lửa Ứng dụng Web (WAF) để hấp thụ và lọc lưu lượng tấn công phân tán.

## 💻 Code Example
```configuration
# Configure rate limiting zone and connection timeouts in Nginx config
http {
    # limit requests to 10 per second per IP with a burst capacity of 20
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

    server {
        listen 80;
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

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lỗi đánh máy trong Slide 11 khi nhà cung cấp DNS nổi tiếng bị viết sai chính tả thành 'Dyno DNS' thay vì 'Dyn DNS'.
- **Nguồn tham khảo**: CWE-400 (Uncontrolled Resource Consumption)
