# DNS Poisoning

> **CWE**: CWE-350 | **Phân loại**: Cryptographic Failures

## Kiến thức Nền tảng
Hãy tưởng tượng internet giống như một thành phố khổng lồ, nơi mỗi trang web là một ngôi nhà có địa chỉ số (được gọi là địa chỉ IP). Vì con người chúng ta không thể nhớ nổi những dãy số phức tạp này, chúng ta sử dụng tên miền (như `wikipedia.org`). Để tìm đường đi, các thiết bị của chúng ta phải hỏi một "người dẫn đường" gọi là **DNS resolver** (thường do nhà mạng cung cấp).

Khi bạn yêu cầu truy cập một trang web, người dẫn đường này sẽ thay bạn đi hỏi qua một chuỗi các máy chủ tên miền khác nhau (gọi là cơ chế phân giải đệ quy - **recursive resolution**), cho đến khi gặp được máy chủ giữ cuốn sổ địa chỉ gốc (gọi là máy chủ có thẩm quyền - **authoritative name server**). Sau khi nhận được địa chỉ IP chính xác, người dẫn đường sẽ ghi chép lại vào một cuốn sổ tay tạm thời (gọi là bộ nhớ đệm - **DNS cache**) với một thời hạn nhất định (**TTL**). Lần sau, nếu bạn hay ai đó trong khu vực hỏi lại tên miền đó, người dẫn đường chỉ cần lật sổ tay ra trả lời ngay lập tức mà không cần đi hỏi lại từ đầu, giúp việc lướt web nhanh hơn rất nhiều.

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

## Mô tả lỗ hổng
Lỗ hổng "Đầu độc DNS" (**DNS Poisoning** hay **DNS Cache Poisoning**) giống như việc kẻ xấu lẻn vào và tráo đổi địa chỉ ghi trong cuốn sổ tay (bộ nhớ đệm) của người dẫn đường. 

Khi người dẫn đường đang gửi câu hỏi đi tìm địa chỉ của một trang web phổ biến, kẻ tấn công nhanh tay gửi hàng loạt câu trả lời giả mạo chứa địa chỉ IP của một "ngôi nhà giả mạo" do chúng dựng sẵn. Nếu kẻ tấn công nhanh chân hơn máy chủ có thẩm quyền thật sự, người dẫn đường sẽ tin câu trả lời giả này và ghi địa chỉ độc hại vào bộ nhớ đệm. 

Hậu quả là từ thời điểm đó, bất kỳ người dùng nào yêu cầu truy cập trang web hợp pháp kia đều sẽ bị người dẫn đường chỉ sang trang web lừa đảo của kẻ tấn công. Lỗ hổng này cực kỳ nguy hiểm bởi vì nạn nhân hoàn toàn gõ đúng địa chỉ trang web trên trình duyệt, không hề có cảnh báo rõ ràng nào, nhưng dữ liệu nhạy cảm hay thông tin đăng nhập của họ lại trực tiếp đi vào tay kẻ xấu.

> **📌 Phân biệt DNS Cache Poisoning vs DNS Hijacking:**
> - **DNS Cache Poisoning** (bài này): Kẻ tấn công giả mạo gói tin UDP phản hồi truy vấn DNS, ghi bản ghi sai vào **bộ nhớ đệm (cache) của DNS resolver dùng chung** — ảnh hưởng đến nhiều người dùng cùng một lúc.
> - **DNS Hijacking**: Thay đổi DNS records trực tiếp trên authoritative name server, hoặc sửa file `/etc/hosts` / cài phần mềm độc hại trên **máy nạn nhân** — chỉ ảnh hưởng từng máy.
> Điểm khác biệt cốt lõi: Poisoning nhắm vào **shared resolver cache**, Hijacking nhắm vào **từng máy hoặc DNS server**.

## Cơ chế tấn công
Kẻ tấn công tấn công tệp hosts của hệ thống cục bộ để ánh xạ các truy vấn tên miền cục bộ tới một IP mà chúng kiểm soát, hoặc khai thác các lỗ hổng trong bộ phân giải bộ đệm (caching resolver) của ISP, làm tràn ngập nó bằng các phản hồi truy vấn giả mạo ghi đè lên các bản ghi bộ nhớ đệm của các tên miền phổ biến để thu hoạch lưu lượng truy cập.

### Minh họa DNS Cache Poisoning (Kaminsky Attack 2008):
```
# Minh họa DNS Cache Poisoning (Kaminsky Attack 2008)
# Bước 1: Gửi truy vấn DNS hàng loạt để kích hoạt resolver cache miss
→ Attacker: "Này resolver, www.victim-bank.com ở đâu?"
→ Resolver: (cache miss) → hỏi authoritative name server

# Bước 2: Trong lúc resolver chờ phản hồi, flood UDP giả mạo
→ Attacker: Gửi hàng nghìn gói UDP giả vờ là authoritative server
   với Transaction ID = 1, 2, 3, ... (đoán mò 16-bit ID)
   nói: "www.victim-bank.com = 1.2.3.4 (IP của attacker)"

# Bước 3: Nếu đoán đúng Transaction ID trước khi phản hồi thật về
→ Resolver lưu bản ghi sai vào cache
→ Mọi người dùng hỏi resolver này đều bị trỏ về 1.2.3.4

# Tại sao UDP dễ bị giả mạo?
# UDP là connectionless — không có bắt tay 3 bước như TCP
# Không có xác thực nguồn gốc → ai cũng có thể gửi gói UDP
# giả danh địa chỉ IP của authoritative name server
```

## Biện pháp phòng thủ
- **Tóm tắt**: Bảo mật các hệ thống DNS chống lại đầu độc bộ nhớ đệm và thao túng bằng cách sử dụng xác thực mật mã (DNSSEC), vô hiệu hóa các truy vấn đệ quy và hạn chế chuyển vùng (zone transfers).
- **Các bước chi tiết**:
  - Kích hoạt xác thực DNSSEC (DNS Security Extensions) trên các bộ phân giải để xác thực tính xác thực của việc tra cứu tên miền bằng mật mã.
  - Vô hiệu hóa các truy vấn đệ quy ('recursion no;') trên các máy chủ DNS có thẩm quyền (authoritative) để ngăn chặn lạm dụng bộ phân giải mở.
  - Hạn chế các yêu cầu chuyển vùng ('allow-transfer') chỉ cho các địa chỉ IP máy chủ DNS phụ đáng tin cậy.
  - Bảo mật cấu hình máy khách DNS cục bộ và áp dụng các quyền truy cập tệp nghiêm ngặt đối với các tệp hosts cục bộ.

## Code Example
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


## Xem thêm
- [Downgrade Attacks](../downgrade-attacks/) — Xem thêm bài học về Downgrade Attacks.

## Nguồn tham khảo
- **Nguồn tham khảo**: CWE-350 (Trusting Aliases), RFC 2181

## Giải thích thuật ngữ
- **DNS (Domain Name System)**: Hệ thống tên miền, đóng vai trò như một danh bạ điện thoại của Internet, giúp dịch các tên miền dễ nhớ (như wikipedia.org) sang địa chỉ IP dạng số mà máy tính có thể hiểu.
- **DNS Resolver**: Bộ phân giải DNS, là máy chủ trung gian tiếp nhận yêu cầu truy vấn tên miền từ thiết bị của người dùng và đi tìm địa chỉ IP tương ứng.
- **Authoritative Name Server**: Máy chủ DNS có thẩm quyền, là nơi lưu trữ cấu hình bản ghi gốc chính thức của một tên miền.
- **DNS Cache**: Bộ nhớ đệm DNS, nơi lưu trữ tạm thời các kết quả truy vấn tên miền trước đó để tăng tốc độ phản hồi cho các yêu cầu tiếp theo.
- **TTL (Time to Live)**: Thời gian tồn tại, là chỉ số xác định khoảng thời gian một bản ghi DNS được phép lưu lại trong bộ nhớ đệm trước khi bị xóa và cần được cập nhật mới.
- **DNSSEC (DNS Security Extensions)**: Tiêu chuẩn bảo mật mở rộng cho hệ thống DNS, sử dụng chữ ký số để xác thực tính toàn vẹn và nguồn gốc của dữ liệu DNS phản hồi, ngăn chặn việc giả mạo thông tin.
