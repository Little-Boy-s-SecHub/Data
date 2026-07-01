# Open Redirects

> **CWE**: CWE-601 (URL Redirection to Untrusted Site) | **Phân loại**: Client-Side Attacks

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đang đi mua sắm tại một trung tâm thương mại lớn và muốn tìm nhà vệ sinh. Bạn nhìn thấy một biển chỉ dẫn ghi: "Nhà vệ sinh: Đi thẳng". Bạn tin tưởng đi theo biển chỉ dẫn đó. Nhưng nếu một kẻ xấu lẻn vào và dán đè lên biển hướng dẫn một mũi tên chỉ sang cửa thoát hiểm dẫn thẳng ra một con hẻm tối tăm đầy cạm bẫy phía sau tòa nhà, bạn sẽ vô tình đi thẳng vào bẫy mà vẫn nghĩ mình đang đi đúng hướng. 

Trong thế giới mạng, hành động chuyển hướng này được thực hiện thông qua cơ chế **chuyển hướng HTTP (HTTP redirects)** với các mã trạng thái như `301` hoặc `302`. Khi bạn truy cập một liên kết (ví dụ: đăng nhập xong thì quay lại trang trước đó), máy chủ web sẽ gửi về trình duyệt một phản hồi kèm theo tiêu đề `Location` chứa địa chỉ đích tiếp theo. Trình duyệt của bạn sẽ tin tưởng tuyệt đối và tự động đưa bạn đến địa chỉ đó mà không hỏi lại. Lỗ hổng **Chuyển hướng hở** (Open Redirects) xảy ra khi lập trình viên thiết kế hệ thống chấp nhận một địa chỉ chuyển hướng do người dùng tự nhập vào (ví dụ: qua tham số `?next=...`) mà không kiểm tra xem địa chỉ đó dẫn đến đâu. Máy chủ cứ thế nhắm mắt đưa địa chỉ này vào tiêu đề `Location`, khiến trình duyệt tự động đưa người dùng đến bất kỳ trang web nào, kể cả những trang độc hại.

Để phòng ngừa, ứng dụng cần sử dụng các hàm phân tích cấu trúc URL để bóc tách và xác thực tên miền đích thuộc danh sách cho phép, hoặc ép buộc chỉ cho phép các đường dẫn tương đối (relative paths) bắt đầu bằng một dấu gạch chéo đơn duy nhất.

```python
# Safe redirection verifying host and scheme using Django utility to prevent Open Redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest

def safe_redirect(request):
    """
    Redirection view verifying that the 'next' URL parameter points to a trusted host.
    """
    # Retrieve the redirection destination parameter (defaults to home path '/')
    redirect_target = request.GET.get('next', '/')
    
    # Secure: Validate that the redirect URL has a safe scheme and points to our own host
    is_safe = url_has_allowed_host_and_scheme(
        url=redirect_target,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure()
    )
    
    if is_safe:
        # Perform HTTP 302 redirect if the target is verified as safe
        return redirect(redirect_target)
    else:
        # Reject redirection requests to untrusted external domains
        return HttpResponseBadRequest("Invalid redirect target: Access Denied.")
```

## Mô tả lỗ hổng
Lỗ hổng Open Redirects xảy ra khi ứng dụng chuyển hướng người dùng đến một trang web bên ngoài mà không hề xác thực xem trang web đó có an toàn hay không. 

Điểm nguy hiểm nhất của lỗ hổng này không nằm ở kỹ thuật tấn công phức tạp, mà nằm ở **nghệ thuật thao túng tâm lý** (phishing). Kẻ tấn công sẽ tạo ra một đường link bắt đầu bằng tên miền cực kỳ uy tín và quen thuộc của bạn (ví dụ: `https://bank.com/login?next=https://evil-bank.com/steal`). Khi người dùng nhìn vào đường link, họ thấy tên miền chính chủ nên hoàn toàn yên tâm nhấn vào và đăng nhập. Nhưng ngay sau khi đăng nhập thành công, máy chủ lại "vô tình" chuyển hướng họ sang trang web độc hại của kẻ tấn công có giao diện giống hệt trang ngân hàng để lừa họ nhập tiếp mã PIN, thông tin thẻ tín dụng, hoặc tự động tải mã độc về máy. Nạn nhân bị lừa mà không hề hay biết vì họ đã bắt đầu hành trình từ một trang web hoàn toàn chính thống.

## Cơ chế tấn công
Bước 1: Kẻ tấn công phát hiện trang web tin cậy có chức năng chuyển hướng sau đăng nhập thông qua tham số `next` (ví dụ: `https://bank.com/login?next=/dashboard`).
Bước 2: Kẻ tấn công tạo một liên kết trỏ tới trang web thật nhưng có tham số `next` dẫn tới trang web giả mạo: `https://bank.com/login?next=https://evil-bank.com/steal`.
Bước 3: Kẻ tấn công gửi liên kết này cho nạn nhân. Nạn nhân nhấn vào, thấy giao diện đăng nhập của `bank.com` nên tin tưởng nhập thông tin.
Bước 4: Sau khi đăng nhập thành công, máy chủ chuyển hướng nạn nhân sang `https://evil-bank.com/steal`. Trang này mô phỏng giao diện ngân hàng thông báo lỗi giao dịch để lừa nạn nhân nhập mã PIN hoặc thông tin thẻ.

### Ví dụ HTTP request minh họa Open Redirect:
```http
# URL trông hợp lệ vì domain là trusted-bank.com
GET /login?redirect=https://evil-phishing.com/fake-login HTTP/1.1
Host: trusted-bank.com

# Server phản hồi redirect mà không kiểm tra URL đích:
HTTP/1.1 302 Found
Location: https://evil-phishing.com/fake-login
# Nạn nhân bị chuyển đến trang giả mạo
```

## Biện pháp phòng thủ
- **Tóm tắt**: Lỗ hổng chuyển hướng hở xảy ra khi ứng dụng chấp nhận giá trị URL đích do người dùng kiểm soát và thực hiện chuyển hướng mà không có bất kỳ bước xác thực nào. Biện pháp phòng thủ bao gồm tránh dùng dữ liệu người dùng để xác định đích chuyển hướng, chỉ cho phép đường dẫn tương đối, hoặc kiểm tra URL đích theo danh sách cho phép nghiêm ngặt.
- **Các bước chi tiết**:
  - Tránh sử dụng trực tiếp dữ liệu người dùng để xác định đích chuyển hướng khi có thể.
  - Nếu bắt buộc phải dùng giá trị chuyển hướng do người dùng nhập, hãy ép buộc URL đó phải là đường dẫn tương đối (bắt đầu bằng dấu '/' đơn và không phải '//' hay một giao thức đầy đủ).
  - Duy trì danh sách cho phép (allow-list) nghiêm ngặt ở phía máy chủ về các tên miền được phép chuyển hướng ra ngoài.
  - Triển khai trang cảnh báo trung gian ('Bạn sắp rời khỏi trang này...') cho các chuyển hướng đến tên miền bên ngoài để thông báo cho người dùng về sự chuyển tiếp đó.

## Code Example
```python
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest

def safe_redirect_view(request):
    next_url = request.GET.get('next', '/')
    # Use Django's built-in secure helper to validate redirect target
    if url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return redirect(next_url)
    return HttpResponseBadRequest("Invalid redirect target")
```


## Xem thêm
- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A01:2021, CWE-601, PortSwigger Web Security Academy

## Giải thích thuật ngữ
- **HTTP Redirect (Chuyển hướng HTTP)**: Cơ chế của giao thức HTTP cho phép máy chủ yêu cầu trình duyệt của người dùng tự động chuyển từ địa chỉ này sang một địa chỉ khác (thông qua mã trạng thái 3xx và header Location).
- **Location Header**: Tiêu đề trong phản hồi HTTP của máy chủ chứa địa chỉ URL đích mà trình duyệt cần chuyển hướng tới.
- **Query Parameter (Tham số truy vấn)**: Phần thông tin nằm sau dấu chấm hỏi `?` trong một địa chỉ URL (ví dụ: `?next=home`), dùng để gửi dữ liệu từ client lên server.
- **Phishing (Tấn công giả mạo)**: Hình thức tấn công mạng mà kẻ xấu giả mạo thành một thực thể uy tín để lừa người dùng cung cấp thông tin nhạy cảm.
- **Allow-list (Danh sách cho phép/Danh sách trắng)**: Danh sách kiểm soát chỉ chứa các thực thể (như tên miền, IP, tệp tin) được xác định là an toàn và được phép truy cập.
- **Relative Path (Đường dẫn tương đối)**: Đường dẫn chỉ định vị trí của tài nguyên dựa trên thư mục hiện tại hoặc cùng tên miền (ví dụ: `/dashboard`), thay vì chứa toàn bộ tên miền đầy đủ (đường dẫn tuyệt đối).
