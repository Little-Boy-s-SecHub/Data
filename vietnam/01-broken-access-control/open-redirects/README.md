---
schema_version: 1
id: WEB-A01-OPEN-REDIRECTS
title: "Open Redirects"
slug: open-redirects
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A01:2025
cwe:
  - CWE-601
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Open Redirects

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Open Redirects bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- HTTP 3xx và trường `Location`.

- Cách framework phân tích relative URL, absolute URL và authority.

- Allowlist đích chuyển hướng theo use case.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang đi mua sắm tại một trung tâm thương mại lớn và muốn tìm nhà vệ sinh. Bạn nhìn thấy một biển chỉ dẫn ghi: "Nhà vệ sinh: Đi thẳng". Bạn tin tưởng đi theo biển chỉ dẫn đó. Nhưng nếu một kẻ xấu lẻn vào và dán đè lên biển hướng dẫn một mũi tên chỉ sang cửa thoát hiểm dẫn thẳng ra một con hẻm tối tăm đầy cạm bẫy phía sau tòa nhà, bạn sẽ vô tình đi thẳng vào bẫy mà vẫn nghĩ mình đang đi đúng hướng. [S3]

Trong thế giới mạng, hành động chuyển hướng này được thực hiện thông qua cơ chế **chuyển hướng HTTP (HTTP redirects)** với các mã trạng thái như `301` hoặc `302`. Khi bạn truy cập một liên kết (ví dụ: đăng nhập xong thì quay lại trang trước đó), máy chủ web sẽ gửi về trình duyệt một phản hồi kèm theo tiêu đề `Location` chứa địa chỉ đích tiếp theo. Trình duyệt của bạn sẽ tin tưởng tuyệt đối và tự động đưa bạn đến địa chỉ đó mà không hỏi lại. Lỗ hổng **Chuyển hướng hở** (Open Redirects) xảy ra khi lập trình viên thiết kế hệ thống chấp nhận một địa chỉ chuyển hướng do người dùng tự nhập vào (ví dụ: qua tham số `?next=...`) mà không kiểm tra xem địa chỉ đó dẫn đến đâu. Máy chủ cứ thế nhắm mắt đưa địa chỉ này vào tiêu đề `Location`, khiến trình duyệt tự động đưa người dùng đến bất kỳ trang web nào, kể cả những trang độc hại. [S3]

Để phòng ngừa, ứng dụng cần sử dụng các hàm phân tích cấu trúc URL để bóc tách và xác thực tên miền đích thuộc danh sách cho phép, hoặc ép buộc chỉ cho phép các đường dẫn tương đối (relative paths) bắt đầu bằng một dấu gạch chéo đơn duy nhất. [S3]

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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Open Redirects xảy ra khi ứng dụng chuyển hướng người dùng đến một trang web bên ngoài mà không hề xác thực xem trang web đó có an toàn hay không. [S3]

Điểm nguy hiểm nhất của lỗ hổng này không nằm ở kỹ thuật tấn công phức tạp, mà nằm ở **nghệ thuật thao túng tâm lý** (phishing). Kẻ tấn công sẽ tạo ra một đường link bắt đầu bằng tên miền cực kỳ uy tín và quen thuộc của bạn (ví dụ: `https://bank.lab.test/login?next=https://callback.lab.test/steal`). Khi người dùng nhìn vào đường link, họ thấy tên miền chính chủ nên hoàn toàn yên tâm nhấn vào và đăng nhập. Nhưng ngay sau khi đăng nhập thành công, máy chủ lại "vô tình" chuyển hướng họ sang trang web độc hại của kẻ tấn công có giao diện giống hệt trang ngân hàng để lừa họ nhập tiếp mã PIN, thông tin thẻ tín dụng, hoặc tự động tải mã độc về máy. Nạn nhân bị lừa mà không hề hay biết vì họ đã bắt đầu hành trình từ một trang web hoàn toàn chính thống. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** trust của origin đăng nhập và dữ liệu người dùng có thể bị nhập nhầm tại origin khác.

- **Actor:** user chưa đăng nhập dùng Chromium được pin; không dùng credential thật.

- **Trust boundary:** tham số redirect/next đi vào Django 5.x response Location.

- **Điều kiện cần:** server cho phép absolute URL hoặc parsing sai allowlist; browser theo redirect.

- **Môi trường:** trusted-bank.lab.test và callback.lab.test cùng map loopback; proxy ghi redirect chain.

Chỉ kết luận open redirect khi server phát Location tới origin ngoài allowlist; liên kết chứa URL lạ nhưng bị từ chối không phải lỗ hổng. [S1]

## 6. Cơ chế tấn công

Ứng dụng đưa destination do client cung cấp vào Location mà không parse/allowlist đúng origin. Browser theo 3xx từ origin tin cậy sang callback không tin cậy. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy hai origin loopback bằng Django 5.x, pin Chromium và xóa history/cache.
2. **Baseline:** next=/dashboard chuyển hướng nội bộ sau đăng nhập synthetic.
3. **Thao tác:** gửi destination callback.lab.test rồi theo dõi Location và origin cuối; không nhập secret.
4. **Expected result:** bản lỗi tới callback lab; bản sửa từ chối absolute destination và vẫn chấp nhận relative path hợp lệ.
5. **Boundary:** thử scheme-relative, mixed case, userinfo và percent encoding theo kịch bản cố định.
6. **Cleanup:** xóa cookie/history và dừng cả hai origin.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Kẻ tấn công phát hiện trang web tin cậy có chức năng chuyển hướng sau đăng nhập thông qua tham số `next` (ví dụ: `https://bank.lab.test/login?next=/dashboard`).
Bước 2: Kẻ tấn công tạo một liên kết trỏ tới trang web thật nhưng có tham số `next` dẫn tới trang web giả mạo: `https://bank.lab.test/login?next=https://callback.lab.test/steal`.
Bước 3: Kẻ tấn công gửi liên kết này cho nạn nhân. Nạn nhân nhấn vào, thấy giao diện đăng nhập của `bank.lab.test` nên tin tưởng nhập thông tin.
Bước 4: Sau khi đăng nhập thành công, máy chủ chuyển hướng nạn nhân sang `https://callback.lab.test/steal`. Trang này mô phỏng giao diện ngân hàng thông báo lỗi giao dịch để lừa nạn nhân nhập mã PIN hoặc thông tin thẻ. [S3]

### Ví dụ HTTP request minh họa Open Redirect:
<!-- payload-id: WEB-A01-OPEN-REDIRECTS-001 -->
<!-- context: HTTP/1.1; Django 5.x fixture; trusted-bank.lab.test and callback.lab.test resolve to loopback; redirect validation model [S3] -->
<!-- prerequisites: run both origins locally with no Internet route; browser history and network log are cleared before each case -->
<!-- encoding: ASCII absolute HTTPS URL in the query; reserved characters remain percent-safe; raw harness emits CRLF -->
<!-- expected-result: vulnerable fixture returns Location to callback.lab.test; fixed fixture rejects it and accepts only a local relative path -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```http
# The visible request starts on the trusted lab origin
GET /login?next=https://callback.lab.test/fake-login HTTP/1.1
Host: trusted-bank.lab.test

# The vulnerable server reflects an unvalidated destination:
HTTP/1.1 302 Found
Location: https://callback.lab.test/fake-login
# The browser is redirected to the untrusted lab origin
```

## 9. Code dễ bị lỗi và code an toàn

```python
from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest

def redirect_vulnerable(request):
    # BAD: the client controls the destination
    return redirect(request.GET.get('next', '/'))

def redirect_secure(request):
    next_url = request.GET.get('next', '/')
    # GOOD: compare against a server-controlled canonical host
    if url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={settings.CANONICAL_HOST},
        require_https=True,
    ):
        return redirect(next_url)
    return HttpResponseBadRequest("Invalid redirect target")
```

## 10. Phát hiện

- Kiểm tra relative path hợp lệ, absolute URL ngoài allowlist và biến thể authority; quan sát `Location`. [S3]

- Review mọi chỗ dựng redirect từ query/form/header và helper validation của framework. [S3], [S4]

- Log redirect class, đích đã chuẩn hóa và quyết định allow/deny; tránh log token.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng đích cố định hoặc allowlist hẹp; validate scheme/host sau khi parse URL bằng helper phù hợp. [S3]

- Với luồng nội bộ, chỉ nhận relative path an toàn và không cho `//host` vượt policy. [S3], [S4]

### Defense-in-depth

- Trang cảnh báo chỉ hỗ trợ người dùng, không thay validation.

- Không đặt token nhạy cảm trong query của URL chuyển hướng.

## 12. Retest

- **Positive:** relative path hợp lệ chuyển đúng trang nội bộ.

- **Negative:** external host và scheme ngoài policy bị từ chối.

- **Boundary:** kiểm tra `//host`, userinfo, mixed case, encoded separator và port.

- **Telemetry:** log đích canonical và nhánh policy đã chọn.

## 13. Sai lầm thường gặp

- Kiểm tra URL bằng `startsWith` trên chuỗi thô.

- Allowlist substring thay vì scheme/host/port đã parse.

- Quên biến thể protocol-relative hoặc userinfo.

- Coi confirmation page là biện pháp gốc.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim kỹ thuật nhạy cảm có nguồn tham khảo ở mục 17 và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **HTTP redirect:** phản hồi 3xx thường cung cấp URI đích qua trường `Location`. [S3]

- **Allowlist đích:** tập scheme/host/port hoặc relative path được business flow cho phép. [S3]

- **Canonical URL:** URL sau khi được parser framework chuẩn hóa để so khớp policy. [S3], [S4]

## 16. Bài liên quan và đọc thêm

- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** OWASP Unvalidated Redirects and Forwards Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** Django 5.2 documentation — `url_has_allowed_host_and_scheme`. https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme — phiên bản: Django 5.2; truy cập: 2026-07-18.
