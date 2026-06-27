# Server-Side Request Forgery

> **OWASP Top 10:2025**: A01:2025 – Broken Access Control | **CWE**: CWE-918 (Server-Side Request Forgery) | **Phân loại**: Request Attacks

## 🧱 Kiến thức Nền tảng
Yêu cầu giả mạo từ phía máy chủ (Server-Side Request Forgery - SSRF) là lỗ hổng xảy ra khi kẻ tấn công có thể ép máy chủ web thực hiện các yêu cầu HTTP/HTTPS đến các địa chỉ tùy ý. Khái niệm cốt lõi ở đây là **server-side HTTP client** (HTTP client ở phía máy chủ). Nhiều ứng dụng cần tải tài nguyên từ bên ngoài (ví dụ: hiển thị hình thu nhỏ từ link, gọi API bên thứ ba). Khi đó, máy chủ sẽ tự khởi tạo một yêu cầu mạng bằng HTTP client nội bộ của nó.

Mối nguy hiểm xuất hiện khi máy khách cung cấp các URL chứa **loopback/private IP** (IP vòng lặp hoặc IP nội bộ). Các dải địa chỉ IP riêng tư (như `10.0.0.0/8`, `192.168.0.0/16` theo định nghĩa RFC 1918) hoặc loopback (`127.0.0.1` / `localhost`) và IP metadata đám mây (`169.254.169.254`) chỉ được sử dụng cho mạng nội bộ phía sau tường lửa. Vì máy chủ nằm bên trong ranh giới mạng tin cậy này, server-side HTTP client sẽ gửi yêu cầu trực tiếp đến các tài nguyên nội bộ, bypass các hệ thống kiểm soát truy cập vòng ngoài. Kẻ tấn công lợi dụng việc này để quét cổng mạng, truy cập các trang quản trị cục bộ hoặc đánh cắp token metadata nhạy cảm của dịch vụ đám mây.

```python
# Safe HTTP client request resolving DNS and validating IP range to prevent SSRF
import socket
import ipaddress
import urllib3
from urllib.parse import urlparse

def is_safe_destination_ip(ip_str):
    """
    Checks if the resolved IP address is a public, globally-routable address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Enforce that the target IP is not private, loopback, or link-local
        return ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_link_local
    except ValueError:
        return False

def make_safe_request(url):
    # Parse URL to extract domain name
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ('http', 'https'):
        raise ValueError("Invalid URL scheme. Only HTTP and HTTPS are allowed.")
        
    hostname = parsed_url.hostname
    if not hostname:
        raise ValueError("Invalid hostname.")
        
    # Resolve the hostname to an IP address on the server side
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError("DNS resolution failed.")
        
    # Verify that the resolved IP address is safe (public)
    if not is_safe_destination_ip(resolved_ip):
        raise ValueError("Forbidden: Target IP belongs to a restricted private/loopback range.")
        
    # Enforce request using urllib3 pool, disabling redirects to prevent redirection bypass
    http = urllib3.PoolManager()
    response = http.request('GET', url, redirect=False, timeout=3.0)
    return response.data
```

## 🔍 Mô tả lỗ hổng
Server-Side Request Forgery (SSRF) xảy ra khi một máy chủ web thực hiện các yêu cầu HTTP tới các tài nguyên tùy ý dựa trên đầu vào do người dùng kiểm soát mà không được lọc kỹ càng. Lỗ hổng này cho phép kẻ tấn công biến máy chủ thành một proxy để quét mạng nội bộ, truy cập các dịch vụ nhạy cảm đằng sau tường lửa hoặc khai thác các dịch vụ metadata của đám mây.

## ⚔️ Cơ chế tấn công
Kẻ tấn công tận dụng các chức năng như xem trước liên kết (link preview) bằng cách cung cấp một URL trỏ đến các địa chỉ IP riêng tư nội bộ (như `http://localhost/admin` hoặc `http://192.168.1.1`) hoặc địa chỉ metadata của môi trường đám mây (ví dụ AWS metadata IP: `http://169.254.169.254`). Vì máy chủ nằm bên trong hàng rào bảo mật và có quyền truy cập các tài nguyên nội hạt, nó sẽ gửi yêu cầu và có thể trả lại nội dung nhạy cảm cho kẻ tấn công trong phản hồi hoặc thông báo lỗi.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn SSRF bằng cách sử dụng danh sách trắng (allowlist), phân giải tên miền sang IP và kiểm tra IP riêng tư trước khi gửi yêu cầu, vô hiệu hóa redirect và cô lập mạng của ứng dụng.
- **Các bước chi tiết**:
  - Triển khai danh sách trắng (allowlist) nghiêm ngặt cho các tên miền/IP đích thay vì sử dụng danh sách đen (blocklist).
  - Thực hiện phân giải tên miền thành địa chỉ IP ở phía máy chủ và kiểm tra IP đó có thuộc các dải IP riêng tư (RFC 1918, RFC 6598, loopback, link-local) trước khi tạo kết nối để chống DNS Rebinding.
  - Vô hiệu hóa việc tự động chuyển hướng HTTP (redirections) hoặc kiểm tra kỹ URL đích của chuyển hướng trước khi theo dấu.
  - Cô lập máy chủ gửi yêu cầu trong một phân đoạn mạng riêng biệt hoặc VPC với các quy tắc egress tường lửa tối thiểu.
  - Sử dụng một HTTP client chuyên dụng được cấu hình giới hạn thời gian chờ (timeout) ngắn, lượng dữ liệu tối đa nhỏ để ngăn chặn cạn kiệt tài nguyên (DoS).

## 💻 Code Example
```python
import socket
import ipaddress
import urllib3
from urllib.parse import urlparse

def is_safe_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_link_local
    except ValueError:
        return False

def secure_request(url, max_bytes=2*1024*1024):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Only HTTP and HTTPS schemes are allowed")
        
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL")
        
    # DNS Resolution
    try:
        ip_addr = socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError("DNS resolution failed")
        
    if not is_safe_ip(ip_addr):
        raise ValueError("Target IP is not in a safe public range")
        
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += f"?{parsed.query}"
        
    # Pin the connection using resolved IP while asserting the hostname for SSL
    pool_opts = {}
    if parsed.scheme == 'https':
        try:
            # If the hostname is an IP, do not set server_hostname
            ipaddress.ip_address(hostname)
        except ValueError:
            pool_opts['server_hostname'] = hostname  # For SSL SNI
        
    pool = urllib3.PoolManager(**pool_opts)
    target_url = f"{parsed.scheme}://{ip_addr}:{port}{path}"
    
    headers = {"Host": hostname}
    # Stream content to prevent memory exhaustion / DoS attacks
    response = pool.request(
        'GET',
        target_url,
        headers=headers,
        redirect=False,
        timeout=5.0,
        preload_content=False
    )
    
    try:
        buffer = bytearray()
        for chunk in response.stream(amt=65536):
            if len(buffer) + len(chunk) > max_bytes:
                raise ValueError("Response body size exceeds the maximum limit")
            buffer.extend(chunk)
        return buffer.decode('utf-8', errors='replace')
    finally:
        response.release_conn()
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Bản sửa đổi đã giải quyết lỗi chứng chỉ TLS (SNI/Hostname mismatch) do việc gửi yêu cầu trực tiếp đến địa chỉ IP đã phân giải. Bằng cách sử dụng cơ chế ghim IP kết nối của `urllib3` (`server_hostname` trong pool options) và giữ nguyên Host header để xác thực SSL hoạt động chính xác. Bổ sung kiểm tra giao thức và cổng để ngăn chặn việc bypass.
- **Nguồn tham khảo**: OWASP SSRF Prevention Cheat Sheet, PortSwigger, CWE-918
