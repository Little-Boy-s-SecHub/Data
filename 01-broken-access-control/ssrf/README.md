# Server-Side Request Forgery

> **CWE**: CWE-918 (Server-Side Request Forgery) | **Phân loại**: Server-Side Request Forgery

## Kiến thức Nền tảng
Hãy tưởng tượng máy chủ web của bạn giống như một nhân viên hành chính ngồi trong văn phòng bảo mật của một tổng công ty. Văn phòng này nằm bên trong hàng rào bảo mật nghiêm ngặt. Người ngoài không thể tự ý đi vào các phòng ban nội bộ hay xem máy chủ cơ sở dữ liệu của công ty. Tuy nhiên, nhân viên hành chính này có một nhiệm vụ: "Nếu có ai gửi thư yêu cầu tải ảnh hoặc thông tin từ một địa chỉ web bên ngoài để đính kèm vào hồ sơ, nhân viên sẽ tự mình truy cập đường link đó, tải ảnh về và hiển thị lên màn hình".

Mối nguy hiểm xuất hiện khi một vị khách xấu gửi một yêu cầu có nội dung: "Hãy tải ảnh tại địa chỉ: `http://localhost/admin` hoặc `http://192.168.1.100` (địa chỉ của máy chủ nội bộ)". Vì nhân viên hành chính này đang ngồi *bên trong* mạng nội bộ tin cậy, nên anh ta có thể dễ dàng đi đến các địa chỉ nội hạt này mà không bị tường lửa ngăn chặn (được gọi là bypass tường lửa). Anh ta ngoan ngoãn truy cập vào trang quản trị nội bộ hoặc máy chủ chứa dữ liệu nhạy cảm, lấy thông tin về và gửi ngược lại cho kẻ tấn công bên ngoài. Trong thế giới mạng, hành vi lừa máy chủ thực hiện các yêu cầu nội bộ hoặc tùy ý này được gọi là **SSRF** (Server-Side Request Forgery - Yêu cầu giả mạo từ phía máy chủ).

Mối nguy hiểm này liên quan trực tiếp đến các địa chỉ **loopback/private IP** (IP vòng lặp hoặc IP nội bộ). Các dải địa chỉ IP riêng tư (như `10.0.0.0/8`, `192.168.0.0/16` theo định nghĩa RFC 1918) hoặc loopback (`127.0.0.1` / `localhost`) và IP metadata đám mây (`169.254.169.254`) chỉ được sử dụng cho mạng nội bộ phía sau tường lửa. Vì máy chủ nằm bên trong ranh giới mạng tin cậy này, server-side HTTP client sẽ gửi yêu cầu trực tiếp đến các tài nguyên nội bộ, bypass các hệ thống kiểm soát truy cập vòng ngoài. Kẻ tấn công lợi dụng việc này để quét cổng mạng, truy cập các trang quản trị cục bộ hoặc đánh cắp token metadata nhạy cảm của dịch vụ đám mây.

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

## Mô tả lỗ hổng
Lỗ hổng SSRF xảy ra khi ứng dụng cho phép người dùng truyền vào một địa chỉ URL và máy chủ sẽ tự động gửi yêu cầu đến URL đó mà không có bất kỳ bộ lọc hoặc bước xác thực an toàn nào. 

Lỗ hổng này cực kỳ nguy hiểm bởi vì nó biến máy chủ của bạn thành một "nội gián" hoặc một cầu nối trung gian (proxy) để kẻ tấn công khám phá và tấn công mạng nội bộ của bạn. Kẻ xấu có thể lợi dụng điều này để quét các cổng mạng đang mở trong hệ thống nội bộ, truy cập các cơ sở dữ liệu không công khai, hoặc nghiêm trọng hơn là đánh cắp mã khóa truy cập (metadata tokens) từ các dịch vụ điện toán đám mây (như AWS, Google Cloud, Azure). Điều này có thể dẫn đến việc kẻ tấn công chiếm toàn quyền kiểm soát toàn bộ cơ sở hạ tầng đám mây của doanh nghiệp.

## Cơ chế tấn công
Kẻ tấn công tận dụng các chức năng như xem trước liên kết (link preview) bằng cách cung cấp một URL trỏ đến các địa chỉ IP riêng tư nội bộ (như `http://localhost/admin` hoặc `http://192.168.1.1`) hoặc địa chỉ metadata của môi trường đám mây (ví dụ AWS metadata IP: `http://169.254.169.254`). Vì máy chủ nằm bên trong hàng rào bảo mật và có quyền truy cập các tài nguyên nội hạt, nó sẽ gửi yêu cầu và có thể trả lại nội dung nhạy cảm cho kẻ tấn công trong phản hồi hoặc thông báo lỗi.

## Biện pháp phòng thủ
- **Tóm tắt**: Ngăn chặn SSRF bằng cách sử dụng danh sách trắng (allowlist), phân giải tên miền sang IP và kiểm tra IP riêng tư trước khi gửi yêu cầu, vô hiệu hóa redirect và cô lập mạng của ứng dụng.
- **Các bước chi tiết**:
  - Triển khai danh sách trắng (allowlist) nghiêm ngặt cho các tên miền/IP đích thay vì sử dụng danh sách đen (blocklist).
  - Thực hiện phân giải tên miền thành địa chỉ IP ở phía máy chủ và kiểm tra IP đó có thuộc các dải IP riêng tư (RFC 1918, RFC 6598, loopback, link-local) trước khi tạo kết nối để chống DNS Rebinding.
  - Vô hiệu hóa việc tự động chuyển hướng HTTP (redirections) hoặc kiểm tra kỹ URL đích của chuyển hướng trước khi theo dấu.
  - Cô lập máy chủ gửi yêu cầu trong một phân đoạn mạng riêng biệt hoặc VPC với các quy tắc egress tường lửa tối thiểu.
  - Sử dụng một HTTP client chuyên dụng được cấu hình giới hạn thời gian chờ (timeout) ngắn, lượng dữ liệu tối đa nhỏ để ngăn chặn cạn kiệt tài nguyên (DoS).

## Code Example
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

## Xem thêm
- [XML External Entities](../../05-injection/xxe/) — Lỗ hổng XXE có thể được sử dụng để thực hiện các yêu cầu mạng SSRF trực tiếp từ máy chủ phân tích XML.

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP SSRF Prevention Cheat Sheet, PortSwigger, CWE-918

## Giải thích thuật ngữ
- **Server-Side Request Forgery (SSRF)**: Lỗ hổng giả mạo yêu cầu từ phía máy chủ, xảy ra khi ứng dụng gửi một yêu cầu mạng đến một địa chỉ do kẻ tấn công chỉ định.
- **Server-Side HTTP Client**: Công cụ hoặc thư viện phần mềm chạy trên máy chủ được sử dụng để gửi các yêu cầu HTTP/HTTPS sang các máy chủ khác.
- **Loopback IP / Localhost**: Địa chỉ IP vòng lặp (thường là `127.0.0.1` hoặc tên miền `localhost`) dùng để máy tính tự kết nối và giao tiếp với chính nó.
- **Private IP (IP nội bộ)**: Các dải địa chỉ IP (như `192.168.x.x` hoặc `10.x.x.x`) chỉ được sử dụng trong mạng nội bộ phía sau tường lửa và không thể định tuyến trực tiếp từ internet công cộng.
- **Metadata Service**: Dịch vụ cung cấp thông tin cấu hình và mã khóa truy cập của máy chủ ảo trong môi trường điện toán đám mây (thường nằm ở địa chỉ IP đặc biệt `169.254.169.254`).
- **DNS Rebinding**: Kỹ thuật tấn công lừa máy chủ gửi yêu cầu đến một địa chỉ IP nội bộ an toàn bằng cách thay đổi địa chỉ IP phân giải của tên miền đích ngay giữa hai lần truy cập liên tiếp.
- **VPC (Virtual Private Cloud)**: Mạng riêng ảo được cô lập trong môi trường điện toán đám mây để bảo vệ các tài nguyên hệ thống.
- **Egress Firewall Rules**: Quy tắc tường lửa kiểm soát lưu lượng dữ liệu đi ra ngoài từ hệ thống nội bộ.
