---
schema_version: 1
id: WEB-A02-CLICKJACKING
title: "Clickjacking"
slug: clickjacking
level: beginner
estimated_minutes: 35
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A06:2025
cwe:
  - CWE-1021
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Clickjacking

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Clickjacking bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Same-origin iframe behavior, user activation và CSS stacking.

- CSP `frame-ancestors` và `X-Frame-Options`.

- Playwright/Chromium fixture với hai loopback origin.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn đang lướt một ứng dụng trò chơi trên điện thoại và nhìn thấy một nút bấm to màu đỏ ghi: "Nhấn vào đây để nhận 1.000.000đ miễn phí!". Bạn hào hứng nhấn vào nút đó. Nhưng bạn không hề biết rằng, kẻ xấu đã khéo léo phủ một tấm kính trong suốt vô hình đè lên màn hình điện thoại của bạn. Trên tấm kính đó, ở đúng vị trí của nút "Nhận quà", có một nút bấm thực tế khác ghi: "Xác nhận chuyển khoản 1.000.000đ từ tài khoản ngân hàng của bạn". Khi ngón tay của bạn chạm xuống, cú nhấp chuột thực tế đã xuyên qua tấm kính vô hình đó và kích hoạt giao dịch chuyển tiền chứ không phải là nhận quà. [S3]

Kỹ thuật lừa đảo tinh vi này trong thế giới web được gọi là **Clickjacking** (Đánh cắp cú nhấp chuột) hay **UI Redressing** (Trang trí lại giao diện). Để thực hiện trò ảo thuật này, kẻ tấn công dựa vào ba công cụ cơ bản của HTML và CSS:
- **Thẻ iframe (`<iframe>`)**: Giống như một khung cửa sổ kính, thẻ này cho phép nhúng nguyên vẹn một trang web này vào bên trong một trang web khác. Kẻ tấn công sẽ nhúng trang web mục tiêu (như trang ngân hàng hoặc mạng xã hội) vào trang web bẫy của chúng.
- **CSS z-index**: Thuộc tính quyết định xem vật thể nào nằm đè lên vật thể nào. Kẻ tấn công đặt khung cửa sổ iframe này nằm ở lớp trên cùng, đè lên giao diện giả mạo.
- **CSS opacity**: Thuộc tính điều chỉnh độ trong suốt. Bằng cách đặt `opacity: 0`, kẻ tấn công làm cho khung cửa sổ iframe chứa trang web thật trở nên hoàn toàn vô hình đối với mắt thường, trong khi nó vẫn nằm sờ sờ ở đó chờ người dùng click vào. [S3]

```html
<!-- A legitimate HTML page showing a modal dialog with z-index and opacity, embedding a safe widget inside an iframe -->
<div class="page-container">
    <h1>Welcome to Our Service</h1>
    <p>Click below to preview our location map.</p>
    <button id="openMapBtn">View Map</button>

    <!-- Legitimate overlay using opacity for backdrop and z-index for proper layering -->
    <div id="modalBackdrop" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; display: none;"></div>

    <!-- Modal box placed above backdrop with higher z-index -->
    <div id="mapModal" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 600px; background: #fff; border-radius: 8px; z-index: 1001; display: none; padding: 20px;">
        <h2>Our Location</h2>
        <!-- Safe, visible iframe embedding a map with opacity set to 1 (visible) -->
        <iframe
            src="https://maps.lab.test/embed?place=fixture-city"
            width="100%"
            height="350"
            style="border: 0; opacity: 1.0;"
            title="Location Map"
            sandbox="allow-scripts allow-same-origin">
        </iframe>
        <button id="closeMapBtn" style="margin-top: 10px;">Close</button>
    </div>
</div>
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Clickjacking xảy ra khi một trang web hợp pháp cho phép bản thân nó bị nhúng vào các trang web khác (qua thẻ iframe) mà không hề có bất kỳ biện pháp tự vệ nào. [S3]

Lỗ hổng này vô cùng nguy hiểm vì nó biến sự tin tưởng và thao tác tự nguyện của người dùng thành công cụ gây hại cho chính họ. Người dùng nghĩ rằng họ đang click để chơi game, xem ảnh, hoặc tắt quảng cáo trên một trang web giải trí thông thường. Thế nhưng, thực tế là họ đang vô tình thực hiện các thao tác cực kỳ nhạy cảm trên trang web bị nhúng ẩn bên trên như: nhấn nút "Theo dõi" một tài khoản lạ, nhấn "Xóa tài khoản", hoặc tệ hơn là bấm "Xác nhận giao dịch tài chính". Do hành động này được thực hiện bởi chính người dùng đã đăng nhập hợp lệ, máy chủ của trang web thật sẽ xử lý yêu cầu đó như một hành động hoàn toàn bình thường, khiến người dùng bị thiệt hại mà không thể đổ lỗi cho lỗi hệ thống. [S3]


## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** thao tác theme-toggle synthetic; không dùng chuyển tiền/xóa dữ liệu.

- **Actor:** user dùng Chromium được pin và có session lab nếu route yêu cầu.

- **Trust boundary:** policy frame-ancestors/X-Frame-Options của ui-target.lab.test khi bị attacker.lab.test embed.

- **Điều kiện cần:** target cho phép framing, control căn đúng và click thật tới iframe.

- **Môi trường:** hai origin loopback, viewport cố định, không extension và không credential thật.

Ảnh chụp iframe không đủ bằng chứng; cần event/server log xác nhận click đã kích hoạt action ở target. [S1]

## 6. Cơ chế tấn công

Origin attacker đặt target trong iframe trong suốt và căn control thật lên decoy. Khi target không cấm framing, pointer event của user đi tới target và kích hoạt action dưới UI gây hiểu nhầm. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** map hai origin về loopback, pin Chromium/viewport và reset theme marker.
2. **Baseline:** action trực tiếp hoạt động; trang attacker chỉ hiển thị decoy khi chưa embed.
3. **Thao tác:** mở overlay và click tọa độ cố định; ghi frame tree, console và server event.
4. **Expected result:** bản lỗi đổi marker một lần; bản sửa với frame-ancestors 'none' chặn iframe và không đổi marker.
5. **Boundary:** kiểm tra SAMEORIGIN, nested frame và browser hỗ trợ CSP/XFO.
6. **Cleanup:** xóa profile browser và dừng hai origin.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review.

`static-verified` chỉ xác nhận cấu trúc và annotation đã qua gate tĩnh.

Trạng thái này không chứng minh payload hoạt động trên mọi phiên bản.

Trước khi chạy, phải đối chiếu context, điều kiện, encoding, expected result và risk.

Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Kẻ tấn công đặt iframe của ứng dụng mục tiêu trong suốt **phía trên** một decoy nhìn thấy được và căn control thật với vị trí click. Nếu một liên kết/div attacker nằm trên iframe và nhận pointer event thì click không tới target, nên đó không phải bằng chứng clickjacking của target. [S3]

### Ví dụ HTML iframe overlay minh họa Clickjacking:
<!-- payload-id: WEB-A02-CLICKJACKING-001 -->
<!-- context: UTF-8 HTML; pinned Chromium; attacker.lab.test embeds ui-target.lab.test, both mapped to loopback; frame-restriction model [S3] -->
<!-- prerequisites: target exposes only the harmless theme-toggle action; no authentication secret or real account is used -->
<!-- encoding: UTF-8 HTML served as text/html; the iframe URL is ASCII and requires no secondary decoding -->
<!-- expected-result: vulnerable fixture records one synthetic theme toggle; frame-ancestors 'none' blocks framing in the fixed fixture -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```html
<!-- Attacker-controlled lab page -->
<div style="position: relative;">
  <!-- Visible decoy aligned with the real control -->
  <button style="position: absolute; z-index: 1;">🎁 Nhận thưởng ngay!</button>

  <!-- Transparent iframe overlays a harmless action in the local fixture -->
  <iframe src="https://ui-target.lab.test/lab/toggle-theme"
    style="position: absolute;
           z-index: 2;        /* Keep the target above the decoy */
           opacity: 0;        /* Hide the target while preserving pointer input */
           width: 200px;
           height: 50px;">
  </iframe>
</div>
<!-- A click lands on the aligned control inside the transparent iframe -->
```

## 9. Code dễ bị lỗi và code an toàn

```configuration
# VULNERABLE Nginx server: framing policy is absent
server {
    listen 443 ssl;
    server_name ui-target.lab.test;
    location / { proxy_pass http://ui_backend; }
}

# SECURE Nginx server for the same UI
server {
    listen 443 ssl;
    server_name ui-target.lab.test;
    location / { proxy_pass http://ui_backend; }

    add_header Content-Security-Policy "frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;
}
```

## 10. Phát hiện

- Nhúng target từ origin khác, căn overlay và xác nhận hành động synthetic thực sự xảy ra. [S3]

- Kiểm tra `frame-ancestors`/`X-Frame-Options` trên mọi response có UI nhạy cảm. [S3], [S4]

- Thu browser console, frame tree và server log của thao tác; không dùng tài khoản thật.

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Gửi CSP `frame-ancestors` phù hợp để giới hạn origin được phép nhúng trang. [S4]

- Dùng `X-Frame-Options` cho client legacy khi cần, với semantics được kiểm tra. [S3]

### Defense-in-depth

- Yêu cầu xác nhận/re-auth cho thao tác nhạy cảm.

- SameSite cookie không thay thế frame restriction.

## 12. Retest

- **Positive:** trang được nhúng bởi origin allowlisted nếu use case yêu cầu.

- **Negative:** attacker origin không tạo được frame và không có side effect.

- **Boundary:** nested frame, redirect, response lỗi và browser được hỗ trợ.

- **Telemetry:** đối chiếu frame tree với request và action log.

## 13. Sai lầm thường gặp

- Chỉ dùng JavaScript frame-busting.

- Gửi header trên trang chính nhưng bỏ sót route/action nhạy cảm.

- Nhầm `frame-src` với `frame-ancestors`.

- Kết luận từ iframe hiển thị mà không chứng minh thao tác bị kích hoạt.

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

- **Clickjacking:** UI redressing khiến người dùng tương tác với nội dung nhúng mà không nhận biết đúng mục tiêu. [S3]

- **`frame-ancestors`:** CSP directive giới hạn origin được phép nhúng document. [S4]

- **Overlay:** lớp giao diện được căn trên/dưới target để đánh lạc hướng thao tác người dùng. [S3]

## 16. Bài liên quan và đọc thêm

- [Cross-Origin Resource Sharing](../cors/) — Xem thêm bài học về Cross-Origin Resource Sharing.

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S3]** OWASP Clickjacking Defense Cheat Sheet. https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-17.
- **[S4]** W3C Content Security Policy Level 3 — `frame-ancestors`. https://www.w3.org/TR/CSP/#directive-frame-ancestors — phiên bản/trạng thái: Working Draft hiện hành; truy cập: 2026-07-18.
