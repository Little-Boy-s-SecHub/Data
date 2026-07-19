---
schema_version: 1
id: WEB-A03-MALVERTISING
title: "Malvertising"
slug: malvertising
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A08:2025
cwe:
  - CWE-829
content_status: technical-review
payload_status: none
last_verified: null
---

# Malvertising

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Malvertising bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Third-party script execution và iframe sandbox.

- CSP, SRI và giới hạn của tài nguyên quảng cáo động.

- Browser fixture với ad origin và publisher origin tách biệt.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn sở hữu một tòa soạn báo điện tử lớn và uy tín. Để có thêm doanh thu duy trì hoạt động, bạn ký hợp đồng với một đại lý quảng cáo trung gian, cho phép họ treo một bảng hiệu điện tử động ở một góc trang báo. Đại lý này sẽ tự động thay đổi nội dung quảng cáo sau mỗi vài giây (gọi là **kiến trúc mạng lưới quảng cáo - ad network architecture**). Nội dung hiển thị trên bảng hiệu đó được tải trực tiếp từ máy chủ của đại lý, tòa soạn của bạn hoàn toàn không thể kiểm soát hay duyệt trước từng hình ảnh hoặc đoạn video được đưa lên. [S4]

Một ngày nọ, kẻ xấu hack được vào máy chủ của đại lý quảng cáo kia, hoặc đóng giả làm một khách hàng mua quảng cáo hợp pháp. Thay vì gửi lên một bức ảnh giới thiệu sản phẩm thông thường, chúng lại lén chèn vào đó một đoạn mã độc JavaScript (gọi là **nhúng mã kịch bản bên thứ ba - third-party script embedding**). Khi độc giả truy cập vào trang báo của bạn, trình duyệt của họ sẽ tự động tải đoạn mã độc này từ bảng hiệu quảng cáo về và chạy ngay lập tức. Vì đoạn mã chạy trực tiếp trên trình duyệt của người dùng dưới danh nghĩa trang báo uy tín của bạn, nó có thể âm thầm đọc trộm cookie phiên làm việc, tự động tải phần mềm độc hại về máy người dùng, hoặc đột ngột chuyển hướng họ sang một trang web lừa đảo. [S4]

Trong tích hợp thông thường, publisher nên cô lập nội dung quảng cáo vào frame có sandbox tối thiểu và không cấp quyền điều hướng cấp cao hay truy cập origin của publisher. Nếu buộc phải nạp một tài nguyên script bất biến, publisher có thể pin đúng bytes bằng Subresource Integrity và cấu hình CORS tương thích; SRI không phù hợp với nội dung quảng cáo thay đổi theo request. Cặp cấu hình tại mục 9 minh họa cùng use case mà không đặt input thực nghiệm ngoài mục 8. [S3]

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Quảng cáo độc hại** (Malvertising) xảy ra khi một trang web tin cậy tích hợp các đoạn mã hoặc khung hiển thị quảng cáo từ bên thứ ba mà không áp dụng các biện pháp cô lập bảo vệ cần thiết. [S4]

Mối nguy hiểm của Malvertising nằm ở chỗ nó phá vỡ tính toàn vẹn của ứng dụng web thông qua một con đường hoàn toàn hợp pháp. Chủ sở hữu trang web thường tin tưởng tuyệt đối vào các mạng lưới quảng cáo lớn, trong khi các mạng lưới này lại phân phối nội dung vô cùng năng động và khó kiểm soát. Nếu không sử dụng các cơ chế cô lập như thuộc tính `sandbox` cho thẻ iframe chứa quảng cáo, hoặc thiếu chính sách bảo mật nội dung (CSP) nghiêm ngặt để giới hạn nguồn chạy script, trang web của bạn sẽ vô tình trở thành bệ phóng giúp kẻ tấn công phát tán mã độc đến hàng triệu khách hàng tin cậy của mình. [S4]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** DOM/session của publisher lab và quyền điều hướng của ad frame.

- **Actor:** nội dung quảng cáo không tin cậy từ ads.lab.test; user dùng Chromium pin version.

- **Trust boundary:** iframe sandbox, CSP và script SRI khi publisher nạp tài nguyên third-party.

- **Điều kiện cần:** ad/script bị thay đổi và thiếu isolation/integrity phù hợp; dynamic ad không thể mặc nhiên dùng SRI.

- **Môi trường:** publisher/ads origin loopback, fixture script có bytes và SHA-384 cố định, không tải malware.

Với tài nguyên cross-origin, SRI cần response được chia sẻ qua CORS; `crossorigin="anonymous"` trên element không tự làm server trả ACAO. SRI chặn bytes khác hash đã pin, nhưng không bảo vệ khi attacker sửa được cả tài nguyên **và** HTML/build chứa hash, và không phù hợp với ad payload thay đổi theo request. [S3]

Chỉ dùng DOM marker/blocked navigation làm evidence; không phát hành quảng cáo độc hại hoặc tải file thực thi. [S1]

## 6. Cơ chế tấn công

Publisher nạp frame hoặc script từ ad origin. Nếu nội dung động có quyền vượt nhu cầu và thiếu sandbox/CSP/integrity phù hợp, thay đổi ở ad supply chain được thực thi trong capability rộng hơn dự kiến. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** chạy publisher và ads.lab.test loopback, pin Chromium, phục vụ analytics-v1.js đúng bytes đã ghi.
2. **Baseline:** sandboxed iframe hoạt động trong quyền tối thiểu; script pinned có hash đúng và mock ad origin trả ACAO cho publisher.
3. **Thao tác:** đổi một byte script để kiểm tra SRI; thử top navigation từ frame synthetic khi thiếu/có sandbox.
4. **Expected result:** browser chặn digest sai và sandbox chặn hành vi ngoài quyền; cấu hình lỗi chỉ tạo marker vô hại.
5. **Boundary:** kiểm tra CSP frame-src/script-src, ACAO thiếu/sai, redirect resource, hash trong publisher bị đổi và thay đổi version.
6. **Cleanup:** xóa cache/profile và dừng origins.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Kẻ tấn công mua một vị trí quảng cáo trên một mạng lưới quảng cáo (ad network) trung gian.
Bước 2: Kẻ tấn công chèn mã JavaScript độc hại vào nội dung quảng cáo thay vì hình ảnh thông thường.
Bước 3: Trang web đáng tin cậy tích hợp script của mạng lưới quảng cáo để hiển thị quảng cáo cho người dùng.
Bước 4: Khi người dùng truy cập trang web, trình duyệt của họ tải quảng cáo độc hại và tự động thực thi script độc hại, chuyển hướng người dùng đến trang lừa đảo hoặc tải xuống malware mà trang web chính không hề hay biết. [S4]

## 9. Code dễ bị lỗi và code an toàn

```html
<!-- VULNERABLE: dynamic ad script executes with the publisher's DOM authority -->
<script src="https://ads.lab.test/dynamic-ad.js"></script>
```

```html
<!-- SECURE: the same dynamic ad is isolated in a minimally privileged frame -->
<iframe
  src="https://ads.lab.test/render/ad-42"
  sandbox="allow-scripts"
  referrerpolicy="no-referrer"
  title="Quảng cáo tài trợ">
</iframe>
```

Publisher còn phải giới hạn `frame-src` tới ad origin và chỉ thêm sandbox token thật sự cần. Không thêm `allow-same-origin`, `allow-top-navigation` hoặc `allow-popups-to-escape-sandbox` theo thói quen vì các token đó trả lại capability. Với script immutable, dùng `integrity`/`crossorigin` và CORS phù hợp; dynamic ad không thể pin theo bytes ổn định nên phải giữ trong frame cô lập. [S3], [S4]

## 10. Phát hiện

- Nạp creative synthetic và xác nhận quyền DOM/network thực tế của script hoặc iframe. [S4]

- Review cách nhúng ad, sandbox token và tài nguyên nào có thể thay đổi mà không đổi URL. [S4]

- Thu frame tree, CSP violation và request origin; không gọi ad network thật.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Cô lập creative không tin cậy trong iframe sandbox với tập token tối thiểu theo chức năng. [S4]

- Không nhúng trực tiếp script quảng cáo có quyền same-origin nếu không có trust/provenance phù hợp. [S4]

### Defense-in-depth

- CSP giới hạn network/script của publisher theo use case.

- SRI chỉ phù hợp với tài nguyên immutable có digest được pin.

## 12. Retest

- **Positive:** creative hợp lệ hiển thị trong sandbox và không cần quyền dư thừa.

- **Negative:** creative synthetic không sửa DOM publisher hoặc điều hướng top-level.

- **Boundary:** nested frame, popup, form, redirect và creative update.

- **Telemetry:** đối chiếu frame permissions với network/DOM marker.

## 13. Sai lầm thường gặp

- Chỉ dựa vào CSP trong khi nhúng script bên thứ ba trực tiếp.

- Thêm `allow-scripts` và `allow-same-origin` mà không đánh giá origin.

- Dùng SRI cho URL nội dung thay đổi liên tục.

- Kết luận malware delivery khi chỉ thấy request quảng cáo.

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

- **Third-party script:** script từ bên ngoài chạy trong context của document khi được nhúng trực tiếp. [S4]

- **Iframe sandbox:** tập hạn chế capability của nội dung trong frame; token chỉ mở đúng quyền cần thiết. [S4]

- **SRI:** browser kiểm tra digest của resource phụ immutable trước khi sử dụng. [S3]

## 16. Bài liên quan và đọc thêm

- [Subdomain Squatting](../subdomain-squatting/) — Xem thêm bài học về Subdomain Squatting.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** W3C — Subresource Integrity. https://www.w3.org/TR/SRI/ — phiên bản/trạng thái: specification hiện hành; truy cập: 2026-07-17.
- **[S4]** WHATWG HTML Standard — iframe sandbox. https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox — phiên bản/trạng thái: Living Standard; truy cập: 2026-07-18.
