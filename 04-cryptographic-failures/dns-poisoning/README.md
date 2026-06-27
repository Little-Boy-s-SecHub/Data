# DNS Poisoning

> **OWASP Top 10:2025**: A04:2025 – Cryptographic Failures | **CWE**: CWE-350 | **Phân loại**: Network

## 🧱 Kiến thức Nền tảng
Hệ thống Tên Miền (DNS) phân giải tên miền thành địa chỉ IP để các thiết bị có thể kết nối với nhau. Quá trình này được chia thành hai cơ chế phân giải chính: **DNS resolution recursive (đệ quy)** và **authoritative (có thẩm quyền)**. Khi một máy khách bắt đầu tra cứu tên miền, bộ phân giải đệ quy (recursive resolver, thường của ISP hoặc DNS công cộng như Google) sẽ thay mặt máy khách gửi các truy vấn tuần tự qua nhiều máy chủ khác nhau để tìm ra câu trả lời. Ngược lại, máy chủ phân giải có thẩm quyền (authoritative name server) là nơi lưu trữ cấu hình bản ghi gốc của tên miền và đưa ra câu trả lời chính thức cuối cùng.

Để tăng tốc độ truy cập và giảm tải hệ thống, các bộ phân giải đệ quy sử dụng cơ chế **DNS caching (bộ nhớ đệm)** để lưu trữ các kết quả phân giải trong một khoảng thời gian xác định bởi chỉ số TTL. Tấn công đầu độc DNS (DNS Poisoning) xảy ra khi kẻ tấn công gửi hàng loạt phản hồi giả mạo chứa địa chỉ IP độc hại đến bộ phân giải đệ quy trước khi máy chủ authoritative kịp phản hồi. Nếu bộ phân giải chấp nhận gói tin giả mạo này, thông tin sai lệch sẽ bị lưu vào bộ nhớ đệm DNS. Các máy khách tiếp theo truy vấn tên miền đó sẽ bị điều hướng đến máy chủ giả mạo do kẻ tấn công kiểm soát.

### Minh họa hoạt động bình thường (Normal Operation)
```python
# Python code demonstrating normal domain resolution using a secure resolver configuration
import socket

def resolve_domain_normally(domain_name):
    # This performs a standard DNS lookup using the operating system's configured resolver
    # The OS handles caching and queries recursive DNS servers, which in turn query authoritative servers
    try:
        ip_address = socket.gethostbyname(domain_name)
        print(f"Resolved '{domain_name}' to IP: {ip_address}")
        return ip_address
    except socket.gaierror as error:
        print(f"Failed to resolve domain {domain_name}: {error}")
        return None

# Normal Operation: resolving a trusted domain
target_domain = "www.wikipedia.org"
ip = resolve_domain_normally(target_domain)
```

## 🔍 Mô tả lỗ hổng
Hệ thống Tên Miền (DNS) phân giải các tên miền dễ đọc thành các địa chỉ IP. Trong một cuộc tấn công đầu độc DNS (DNS poisoning), tin tặc chèn các bản ghi ánh xạ gian lận vào bộ nhớ đệm DNS của các hệ thống cục bộ, các bộ phân giải (resolver), hoặc ISP, chuyển hướng các yêu cầu tên miền hợp pháp đến các máy chủ do kẻ tấn công kiểm soát.

## ⚔️ Cơ chế tấn công
Kẻ tấn công tấn công tệp hosts của hệ thống cục bộ để ánh xạ các truy vấn tên miền cục bộ tới một IP mà chúng kiểm soát, hoặc khai thác các lỗ hổng trong bộ phân giải bộ đệm (caching resolver) của ISP, làm tràn ngập nó bằng các phản hồi truy vấn giả mạo ghi đè lên các bản ghi bộ nhớ đệm của các tên miền phổ biến để thu hoạch lưu lượng truy cập.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Bảo mật các hệ thống DNS chống lại đầu độc bộ nhớ đệm và thao túng bằng cách sử dụng xác thực mật mã (DNSSEC), vô hiệu hóa các truy vấn đệ quy và hạn chế chuyển vùng (zone transfers).
- **Các bước chi tiết**:
  - Kích hoạt xác thực DNSSEC (DNS Security Extensions) trên các bộ phân giải để xác thực tính xác thực của việc tra cứu tên miền bằng mật mã.
  - Vô hiệu hóa các truy vấn đệ quy ('recursion no;') trên các máy chủ DNS có thẩm quyền (authoritative) để ngăn chặn lạm dụng bộ phân giải mở.
  - Hạn chế các yêu cầu chuyển vùng ('allow-transfer') chỉ cho các địa chỉ IP máy chủ DNS phụ đáng tin cậy.
  - Bảo mật cấu hình máy khách DNS cục bộ và áp dụng các quyền truy cập tệp nghiêm ngặt đối với các tệp hosts cục bộ.

## 💻 Code Example
```configuration
// BIND (named.conf) hardening configuration options
options {
    directory "/var/named";
    
    // Enable DNSSEC validation on the resolver
    dnssec-validation yes;
    
    // Restrict zone transfer requests to authorized secondary DNS servers
    allow-transfer { 192.168.1.100; 192.168.1.101; };
    
    // Disable recursive queries on authoritative-only servers to prevent open resolver abuse
    recursion no;
};
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lỗi ở Slide 3 tuyên bố rằng các IP máy chủ DNS gốc được mã hóa cứng trong trình duyệt (thực tế chúng nằm trong gợi ý gốc (root hints) của bộ phân giải của HĐH). Đã sửa các phép so sánh JavaScript ('===', '!==') được sử dụng bên trong các khối mã C của các slide 7 & 8. Đã loại bỏ các tùy chọn BIND lỗi thời/không được hỗ trợ ('dnssec-enable', 'use-v4-map-ports') trong các cấu hình giảm thiểu.
- **Nguồn tham khảo**: CWE-350 (Trusting Aliases), RFC 2181
