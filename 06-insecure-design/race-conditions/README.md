# Race Conditions (TOCTOU)

> **OWASP Top 10:2025**: A06:2025 – Insecure Design | **CWE**: CWE-362 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Trong lập trình đa luồng (multithreading) và xử lý đồng thời (concurrency), các tiến trình hoặc request có thể truy cập cùng một tài nguyên chia sẻ (shared resource) tại cùng một thời điểm. Hệ điều hành và web server xử lý nhiều request song song để tăng hiệu năng, nhưng điều này tạo ra nguy cơ khi nhiều thao tác đọc-ghi xảy ra đồng thời trên cùng một dữ liệu.

**TOCTOU (Time-of-Check to Time-of-Use)** là mô hình kinh điển: hệ thống kiểm tra một điều kiện (check), sau đó thực hiện hành động dựa trên kết quả kiểm tra đó (use). Khoảng thời gian giữa "check" và "use" chính là cửa sổ tấn công (race window) mà attacker có thể khai thác.

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

## 🔍 Mô tả lỗ hổng

Race condition xảy ra khi kết quả của chương trình phụ thuộc vào thứ tự thực thi không xác định của các tiến trình đồng thời. Attacker gửi nhiều request gần như đồng thời để khai thác khoảng trống giữa bước kiểm tra và bước thực thi. Các kịch bản phổ biến bao gồm: rút tiền nhiều lần vượt quá số dư, sử dụng mã giảm giá nhiều lần, bỏ phiếu/like trùng lặp, và đăng ký tài khoản trùng lặp vượt qua kiểm tra unique.

## ⚔️ Cơ chế tấn công

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

## 🛡️ Biện pháp phòng thủ

1. **Database-level locking**: Sử dụng `SELECT ... FOR UPDATE` hoặc optimistic locking với version column để serialize các thao tác trên cùng một bản ghi.
2. **Atomic operations**: Dùng câu lệnh SQL nguyên tử thay vì đọc-rồi-ghi riêng biệt.
3. **Distributed locks**: Sử dụng Redis lock hoặc database advisory lock cho hệ thống phân tán.
4. **Idempotency keys**: Yêu cầu client gửi kèm unique key cho mỗi thao tác, server từ chối các key trùng lặp.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/race-conditions
- OWASP: https://owasp.org/www-community/vulnerabilities/Race_Condition
- CWE: https://cwe.mitre.org/data/definitions/362.html
