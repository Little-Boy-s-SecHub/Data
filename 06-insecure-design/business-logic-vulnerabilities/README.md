# Business Logic Vulnerabilities

> **OWASP Top 10:2025**: A06:2025 – Insecure Design | **CWE**: CWE-840 | **Nguồn**: PortSwigger, OWASP, CWE MITRE

## 🧱 Kiến thức Nền tảng

Business logic (logic nghiệp vụ) là tập hợp các quy tắc và quy trình mà ứng dụng thực thi để đảm bảo hoạt động đúng theo yêu cầu kinh doanh. Ví dụ: một cửa hàng online có logic nghiệp vụ bao gồm — tính tổng giá đơn hàng, áp dụng mã giảm giá, kiểm tra tồn kho, xử lý thanh toán, và xác nhận đơn hàng.

Khác với các lỗ hổng kỹ thuật (SQL Injection, XSS), lỗi business logic không phải lỗi trong code mà là lỗi trong **thiết kế quy trình**. Developer có thể viết code hoàn toàn đúng cú pháp, nhưng thiếu validation ở các bước quan trọng hoặc không dự đoán được các trường hợp bất thường mà user có thể tạo ra.

Luồng mua hàng bình thường:

```javascript
// Normal e-commerce checkout flow
app.post('/api/checkout', async (req, res) => {
    const { items, couponCode } = req.body;
    
    // Step 1: Calculate subtotal from catalog prices
    let subtotal = 0;
    for (const item of items) {
        const product = await Product.findById(item.productId);
        subtotal += product.price * item.quantity;
    }
    
    // Step 2: Apply coupon discount
    let discount = 0;
    if (couponCode) {
        const coupon = await Coupon.findOne({ code: couponCode });
        discount = subtotal * (coupon.percentOff / 100);
    }
    
    // Step 3: Charge user
    const total = subtotal - discount;
    await chargePayment(req.user.id, total);
    
    return res.json({ status: 'success', total });
});
```

Luồng trên trông hợp lý, nhưng thiếu nhiều kiểm tra quan trọng: số lượng có thể âm? Giá có được lấy từ server hay client gửi lên? Mã giảm giá có bị áp dụng nhiều lần không?

## 🔍 Mô tả lỗ hổng

Business logic vulnerabilities xuất hiện khi ứng dụng không validate đầy đủ các bước trong quy trình nghiệp vụ, cho phép attacker thao túng giá, bỏ qua bước xác nhận, lạm dụng tính năng khuyến mãi, hoặc đưa dữ liệu bất hợp lý (như số lượng âm) vào hệ thống. Các lỗi này thường không bị phát hiện bởi scanner tự động vì chúng phụ thuộc vào ngữ cảnh nghiệp vụ cụ thể.

## ⚔️ Cơ chế tấn công

**1. Negative Quantity Attack — biến mua hàng thành hoàn tiền:**

```http
POST /api/cart/add HTTP/1.1
Content-Type: application/json

{
    "productId": "expensive-item-001",
    "quantity": -5,
    "price": 299.99
}
// Server calculates: 299.99 * (-5) = -1499.95
// This CREDITS the attacker's account instead of charging
```

**2. Price Manipulation — gửi giá từ client:**

```http
POST /api/checkout HTTP/1.1
Content-Type: application/json

{
    "items": [
        {"productId": "laptop-pro", "quantity": 1, "price": 0.01}
    ]
}
// If server trusts client-supplied price, attacker buys for $0.01
```

**3. Workflow Bypass — bỏ qua bước thanh toán:**

```http
// Skip payment step, go directly to order confirmation
POST /api/orders/confirm HTTP/1.1
Content-Type: application/json

{"orderId": "ORD-12345", "status": "paid"}
// If server doesn't verify payment was actually processed
```

## 🛡️ Biện pháp phòng thủ

1. **Server-side price calculation**: Luôn lấy giá sản phẩm từ database phía server, không bao giờ tin tưởng giá do client gửi lên.
2. **Input validation**: Kiểm tra số lượng phải là số nguyên dương, giá trị phải nằm trong phạm vi hợp lệ.
3. **Workflow enforcement**: Đảm bảo mỗi bước trong quy trình phải hoàn thành trước khi chuyển sang bước tiếp theo bằng state machine.
4. **Coupon controls**: Giới hạn số lần sử dụng, kiểm tra hạn sử dụng, và ngăn chặn stacking nhiều coupon nếu không cho phép.

## 💻 Code Example

```javascript
// VULNERABLE: trusts client input, no validation
app.post('/api/cart/add', async (req, res) => {
    const { productId, quantity, price } = req.body;
    // Accepts negative quantity and client-supplied price
    const lineTotal = price * quantity;
    await Cart.addItem(req.user.id, productId, quantity, lineTotal);
    res.json({ lineTotal });
});
```

```javascript
// SECURE: server-side validation and price lookup
app.post('/api/cart/add', async (req, res) => {
    const { productId, quantity } = req.body;
    
    // Validate quantity is a positive integer
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
        return res.status(400).json({ error: 'Invalid quantity (must be 1-100)' });
    }
    
    // Always fetch price from server database, never trust client
    const product = await Product.findById(productId);
    if (!product || !product.active) {
        return res.status(404).json({ error: 'Product not found' });
    }
    
    const lineTotal = product.price * quantity;
    await Cart.addItem(req.user.id, productId, quantity, lineTotal);
    res.json({ lineTotal, unitPrice: product.price });
});
```

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/logic-flaws
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- CWE: https://cwe.mitre.org/data/definitions/840.html
