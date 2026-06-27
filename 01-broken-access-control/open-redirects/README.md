# Open Redirects

> **OWASP Top 10:2025**: A01:2025 – Broken Access Control | **CWE**: CWE-601 (URL Redirection to Untrusted Site) | **Phân loại**: Request Attacks

## 🧱 Kiến thức Nền tảng
Chuyển hướng hở (Open Redirects) là lỗ hổng bảo mật xảy ra khi một ứng dụng web chuyển hướng người dùng đến một địa chỉ URL bên ngoài do người dùng tự kiểm soát mà không được xác thực an sau khi cấu hình. Cơ chế này liên quan trực tiếp đến các mã trạng thái **301/302 redirects** của giao thức HTTP. Khi máy chủ web phản hồi với mã trạng thái `301 Moved Permanently` (chuyển hướng vĩnh viễn) hoặc `302 Found` (chuyển hướng tạm thời), nó đính kèm tiêu đề phản hồi `Location` chứa địa chỉ đích đến. Trình duyệt khi nhận phản hồi này sẽ tự động chuyển hướng người dùng sang URL được chỉ định.

Lỗ hổng xảy ra do việc thiếu xác thực cấu trúc tên miền trong **URL structure** (cấu trúc URL). Một URL đầy đủ bao gồm giao thức (scheme), tên miền (host/domain) và đường dẫn (path). Nếu ứng dụng chỉ nhận tham số chuyển hướng (ví dụ: `?next=https://evil.com`) và đưa trực tiếp vào tiêu đề `Location` mà không xác thực phần host của URL đó, kẻ tấn công có thể lừa nạn nhân truy cập liên kết thuộc tên miền tin cậy nhưng lại bị chuyển hướng đến trang web lừa đảo. Để phòng ngừa, ứng dụng cần sử dụng các hàm phân tích cấu trúc URL để bóc tách và xác thực tên miền đích thuộc danh sách cho phép, hoặc ép buộc chỉ cho phép các đường dẫn tương đối (relative paths) bắt đầu bằng một dấu gạch chéo đơn duy nhất.

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

## 🔍 Mô tả lỗ hổng
Chuyển hướng hở (Open Redirects) xảy ra khi ứng dụng điều hướng người dùng đến một URL bên ngoài được chỉ định thông qua tham số truy vấn (query parameter) mà không kiểm tra tính hợp lệ. Kẻ tấn công có thể lợi dụng tên miền đáng tin cậy của trang web để tạo ra các liên kết chuyển hướng đến các trang web giả mạo độc hại. Người dùng tin tưởng vào tên miền ban đầu sẽ click vào link, sau đó bị chuyển hướng và lừa đảo chiếm đoạt thông tin đăng nhập hoặc tải xuống mã độc.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công phát hiện trang web tin cậy có chức năng chuyển hướng sau đăng nhập thông qua tham số `next` (ví dụ: `https://bank.com/login?next=/dashboard`).
Bước 2: Kẻ tấn công tạo một liên kết trỏ tới trang web thật nhưng có tham số `next` dẫn tới trang web giả mạo: `https://bank.com/login?next=https://evil-bank.com/steal`.
Bước 3: Kẻ tấn công gửi liên kết này cho nạn nhân. Nạn nhân nhấn vào, thấy giao diện đăng nhập của `bank.com` nên tin tưởng nhập thông tin.
Bước 4: Sau khi đăng nhập thành công, máy chủ chuyển hướng nạn nhân sang `https://evil-bank.com/steal`. Trang này mô phỏng giao diện ngân hàng thông báo lỗi giao dịch để lừa nạn nhân nhập mã PIN hoặc thông tin thẻ.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Open redirect vulnerabilities occur when an application accepts user-controlled input that specifies an external URL and redirects the user to it without validation. Mitigation involves avoiding user-supplied redirect targets, enforcing relative paths, or validating redirects against a strict allow-list.
- **Các bước chi tiết**:
  - Avoid using user input directly to determine redirect destinations whenever possible.
  - If user-provided redirects are necessary, enforce that the redirect URL is relative (starts with a single '/' and not '//' or a protocol).
  - Maintain a strict server-side allow-list of permitted domains for external redirection.
  - Implement an intermediary warning page ('You are leaving this site...') for redirects to external domains to inform users of the transition.

## 💻 Code Example
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

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này đã được chỉnh sửa (FIXED). Đã sửa đổi hàm tự viết is_safe_url bị bypass thông qua giao thức 'javascript:' (gây ra XSS) và dấu gạch chéo ngược '\' (mà trình duyệt tự động chuẩn hóa thành '//'). Cập nhật mã nguồn Python sang sử dụng hàm chuẩn của Django: url_has_allowed_host_and_scheme để đảm bảo kiểm tra redirection an toàn tuyệt đối.
- **Nguồn tham khảo**: OWASP A01:2021, CWE-601, PortSwigger Web Security Academy
