# Business Logic Vulnerabilities

> **CWE**: CWE-840 | **Phân loại**: Insecure Design

## Kiến thức Nền tảng
Hãy nghĩ về quy trình hoạt động của một siêu thị tự phục vụ. Khi bạn vào mua hàng, siêu thị có những quy tắc bất di bất dịch: bạn chọn món đồ từ trên kệ, mang đến quầy thanh toán, nhân viên quét mã vạch để tính tổng tiền, bạn trả tiền, và cuối cùng nhân viên đưa hóa đơn cùng hàng hóa cho bạn ra về. Tập hợp các quy tắc và thứ tự thực hiện này được gọi là **logic nghiệp vụ (business logic)**.

Trong thế giới phần mềm, các lập trình viên sẽ dịch những quy trình thực tế này thành các dòng code để máy tính tự động xử lý. Tuy nhiên, khác với những lỗi kỹ thuật như SQL Injection hay XSS (nơi tin tặc chèn mã độc để phá hỏng hệ thống), lỗ hổng logic nghiệp vụ không nằm ở cú pháp code. Code vẫn chạy mượt mà, máy chủ không hề báo lỗi, nhưng điểm mấu chốt nằm ở **thiết kế quy trình bị lỗi**. Lập trình viên có thể viết code rất đẹp, nhưng lại quên mất việc đặt câu hỏi: "Nếu người dùng làm một hành động không theo lẽ thường thì sao?" hoặc "Liệu họ có thể nhảy cóc qua một bước quan trọng không?".

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

## Mô tả lỗ hổng
Lỗ hổng logic nghiệp vụ (Business Logic Vulnerabilities) xuất hiện khi ứng dụng tin tưởng người dùng một cách mù quáng và không kiểm tra chặt chẽ từng bước đi trong quy trình. 

Hãy tưởng tượng bạn có thể sửa đổi số lượng hàng cần mua thành số lượng âm trong giỏ hàng để tổng tiền hóa đơn trở thành số âm, rồi bắt siêu thị "hoàn tiền" ngược vào tài khoản của mình. Hoặc bạn tìm ra cách đi thẳng từ quầy chọn đồ ra cửa mà không cần ghé qua quầy thanh toán. 

Mối nguy hiểm cực kỳ lớn của lỗ hổng này là nó cho phép kẻ tấn công dễ dàng thao túng giá cả, lạm dụng các chương trình khuyến mãi, mua hàng miễn phí hoặc vượt quyền hạn để sử dụng các tính năng Premium. Điểm đáng sợ là các công cụ quét lỗ hổng tự động (scanners) thường hoàn toàn "mù" trước loại lỗi này, vì chúng chỉ tìm kiếm các lỗi cú pháp kỹ thuật chứ không thể hiểu được các quy tắc kinh doanh phức tạp của riêng bạn.

## Cơ chế tấn công
**1. Negative Quantity Attack — biến mua hàng thành hoàn tiền:**
Attacker gửi số lượng sản phẩm âm để tổng số tiền đơn hàng trở thành âm, từ đó nhận lại tiền hoàn vào tài khoản thay vì phải thanh toán.

**2. Price Manipulation — gửi giá từ client:**
Nếu máy chủ tin tưởng giá của mặt hàng do client gửi lên trong request body thay vì truy vấn từ database, attacker có thể sửa đổi giá sản phẩm thành `$0.01` để mua hàng giá rẻ.

**3. Workflow Bypass — bỏ qua bước thanh toán:**
Attacker gọi trực tiếp endpoint xác nhận đơn hàng thành công mà không thực hiện gọi API thanh toán ở bước trước đó.

**4. Coupon Stacking (Lạm dụng mã giảm giá):**
Hệ thống chỉ cho phép sử dụng một mã giảm giá cho mỗi đơn hàng. Tuy nhiên, nếu thiếu cơ chế khóa (locking) hoặc không lưu trạng thái mã giảm giá đã áp dụng, attacker có thể gửi nhiều yêu cầu áp dụng coupon song song (Race Condition) hoặc gửi một mảng chứa nhiều mã giảm giá cùng lúc để tích lũy giảm giá thành công nhiều lần, biến đơn hàng đắt tiền thành miễn phí hoặc thậm chí âm tiền.

**5. Referral System Abuse (Lạm dụng hệ thống giới thiệu):**
Ứng dụng tặng phần thưởng khi người dùng giới thiệu thành viên mới. Attacker viết script tự động hóa việc đăng ký tài khoản (sybil attack) bằng cách sử dụng email ảo và IP proxy khác nhau để tự nhận tiền thưởng/điểm giới thiệu vô hạn mà không bị chặn bởi các cơ chế chống gian lận hay xác thực bổ sung.

**6. Feature Flag Manipulation (Thao túng cờ tính năng):**
Ứng dụng kiểm soát quyền sử dụng tính năng đặc biệt (như tài khoản Premium, tính năng Beta) bằng cách kiểm tra các tham số truyền vào từ client (như Cookie `tier=free`, header `X-Premium-User: false`, hoặc thuộc tính JSON `is_beta: false`). Attacker dễ dàng thay đổi các giá trị này để vượt quyền và kích hoạt các tính năng trả phí.

**7. Multi-step Process Bypass (Bỏ qua quy trình nhiều bước):**
Đối với các quy trình cần thực hiện theo thứ tự (ví dụ: Bước 1: Chọn sản phẩm -> Bước 2: Tính phí vận chuyển và thuế -> Bước 3: Thanh toán -> Bước 4: Giao hàng), attacker phân tích luồng API và bỏ qua Bước 2 (để không bị tính phí vận chuyển) hoặc đi thẳng từ Bước 1 sang Bước 3, 4 bằng cách giả lập request trực tiếp lên API endpoint của bước sau.

**8. Time-based Logic Flaws (Lỗi logic dựa trên thời gian):**
Attacker khai thác các chương trình flash sale chỉ diễn ra trong thời gian ngắn hoặc các token khôi phục mật khẩu hết hạn sau một khoảng thời gian xác định. Lỗi xảy ra nếu server lấy mốc thời gian từ thiết bị của client hoặc không vô hiệu hóa token ngay khi phiên đăng nhập thay đổi, cho phép kẻ tấn công thay đổi múi giờ trên máy client hoặc gửi request đồng thời trước khi server kịp ghi nhận thời gian hết hạn (Race Window).

## Biện pháp phòng thủ
- **Tóm tắt**: Ngăn ngừa lỗi logic nghiệp vụ bằng cách thiết kế quy trình chặt chẽ, kiểm tra tính hợp lệ của mọi bước đi và tham số ở phía server, và triển khai State Machine.
- **Các bước chi tiết**:
  - **Server-side price calculation**: Luôn lấy giá sản phẩm từ database phía server, không bao giờ tin tưởng giá do client gửi lên.
  - **Input validation**: Kiểm tra số lượng phải là số nguyên dương, giá trị phải nằm trong phạm vi hợp lệ.
  - **Workflow enforcement with State Machine**: Triển khai cơ chế State Machine trên server để quản lý trạng thái phiên giao dịch của người dùng. Chỉ cho phép chuyển sang trạng thái tiếp theo khi trạng thái trước đó đã được xác nhận hoàn thành hợp lệ.
  - **Strict Coupon Registry**: Đảm bảo cấu trúc dữ liệu lưu trữ đơn hàng chỉ chấp nhận một coupon duy nhất hoặc có logic tính toán discount chặt chẽ, áp dụng cơ chế khóa phân tán (distributed locking) khi áp dụng mã giảm giá.
  - **Anti-Sybil controls**: Sử dụng captcha, giới hạn đăng ký trên mỗi IP/thiết bị, yêu cầu kích hoạt qua số điện thoại (OTP) trước khi trao thưởng referral.
  - **Server-side Feature Flags**: Chỉ bật tính năng dựa trên thông tin phiên làm việc được xác thực ở phía server (lấy từ Database/JWT an toàn), không dựa trên cookie hay tham số do client thay đổi được.
  - **Time-synchronization**: Luôn sử dụng thời gian của server (đồng bộ qua NTP) để kiểm tra tính hợp lệ của các sự kiện nhạy cảm về mặt thời gian.

## Code Example
```javascript
// === VULNERABLE CODE ===
const express = require('express');
const app = express();

// 1. Vulnerable to Multi-step Process Bypass (no state validation between steps)
app.post('/api/checkout/step3-payment', async (req, res) => {
    const { orderId, paymentDetails } = req.body;
    
    // DANGER: Directly charges and marks order as paid 
    // without verifying if Step 2 (shipping calculation and validation) was completed
    await processPayment(paymentDetails);
    await db.updateOrderStatus(orderId, 'paid');
    res.json({ success: true });
});

// 2. Vulnerable to Coupon Stacking (no check for already applied coupons)
let orderDiscount = 0;
app.post('/api/cart/apply-coupon', async (req, res) => {
    const { orderId, couponCode } = req.body;
    const coupon = await db.findCoupon(couponCode);
    
    // DANGER: Appends discount without clearing prior coupons or checking limit
    orderDiscount += coupon.value;
    res.json({ success: true, currentDiscount: orderDiscount });
});
```

```javascript
// === SECURE CODE ===
// 1. Secure Multi-step Workflow using State Verification
app.post('/api/checkout/step3-payment', async (req, res) => {
    const { orderId, paymentDetails } = req.body;
    const order = await db.getOrder(orderId);
    
    // SECURE: Enforce workflow state machine 
    // Only allow step 3 if step 2 (shipping_calculated) has been completed
    if (order.status !== 'shipping_calculated') {
        return res.status(400).json({ error: "Invalid workflow state. Complete shipping first." });
    }
    
    const paymentSuccess = await processPayment(paymentDetails);
    if (!paymentSuccess) {
        return res.status(400).json({ error: "Payment failed" });
    }
    
    await db.updateOrderStatus(orderId, 'paid');
    res.json({ success: true });
});

// 2. Secure Coupon Application (Strict Single Coupon Limit)
app.post('/api/cart/apply-coupon', async (req, res) => {
    const { orderId, couponCode } = req.body;
    
    // SECURE: Acquire lock to prevent race conditions during coupon application
    const lock = await acquireLock(orderId);
    try {
        const order = await db.getOrder(orderId);
        
        // SECURE: Enforce single coupon policy by resetting or rejecting if already present
        if (order.appliedCoupon) {
            return res.status(400).json({ error: "A coupon is already applied to this order." });
        }
        
        const coupon = await db.findCoupon(couponCode);
        if (!coupon || coupon.expired) {
            return res.status(400).json({ error: "Invalid or expired coupon" });
        }
        
        await db.applyCouponToOrder(orderId, coupon);
        res.json({ success: true, discount: coupon.value });
    } finally {
        await releaseLock(orderId);
    }
});
```

## Xem thêm
- [Race Conditions](../race-conditions/) — Tấn công khai thác điều kiện tranh chấp để gửi nhiều yêu cầu đồng thời nhằm phá vỡ logic nghiệp vụ (ví dụ như áp dụng mã giảm giá nhiều lần).

## Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/logic-flaws
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- CWE: https://cwe.mitre.org/data/definitions/840.html

## Giải thích thuật ngữ
- **Business Logic (Logic nghiệp vụ)**: Tập hợp các quy tắc, quy trình và luồng xử lý nghiệp vụ của một doanh nghiệp được lập trình vào hệ thống (ví dụ: quy trình thanh toán, áp dụng mã giảm giá, kiểm tra tồn kho).
- **Validation (Xác thực dữ liệu)**: Quá trình kiểm tra dữ liệu đầu vào để đảm bảo nó đúng định dạng, hợp lệ và an toàn trước khi đưa vào xử lý trong hệ thống.
- **Race Condition (Điều kiện tranh chấp)**: Một trạng thái lỗi xảy ra khi nhiều tiến trình hoặc luồng xử lý thực hiện các thao tác đọc/ghi trên cùng một vùng dữ liệu cùng một lúc, dẫn đến kết quả dữ liệu không chính xác.
- **State Machine (Máy trạng thái)**: Mô hình thiết kế phần mềm giúp quản lý các trạng thái của một quy trình (ví dụ: Chờ thanh toán -> Đã thanh toán -> Đang giao hàng), đảm bảo hệ thống chuyển đổi giữa các trạng thái một cách hợp lệ theo đúng thứ tự.
- **Sybil Attack**: Tấn công giả danh, kẻ tấn công tạo ra hàng loạt tài khoản hoặc danh tính ảo để lừa gạt hệ thống (như lạm dụng nhận thưởng giới thiệu thành viên mới).
- **Feature Flag (Cờ tính năng)**: Cơ chế cho phép bật hoặc tắt một chức năng cụ thể của ứng dụng ở chế độ chạy (runtime) mà không cần phải thay đổi hoặc triển khai lại mã nguồn.
