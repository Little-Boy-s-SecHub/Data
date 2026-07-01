# Session Fixation

> **CWE**: CWE-384 (Session Fixation) | **Phân loại**: Session Management

## Kiến thức Nền tảng
Hãy tưởng tượng bạn bước vào một khách sạn. Thay vì để nhân viên lễ tân cấp cho bạn một chiếc chìa khóa phòng ngẫu nhiên và mới tinh sau khi bạn làm thủ tục nhận phòng (xác thực), bạn lại nhặt một chiếc chìa khóa cũ bị vứt ngay trước sảnh và đưa cho lễ tân: "Tôi muốn dùng chiếc chìa khóa này cho phòng của mình". Nếu lễ tân đồng ý lập tức liên kết căn phòng của bạn với chiếc chìa khóa đó mà không nghi ngờ, bạn đã rơi vào cái bẫy. Kẻ xấu đã cố tình vứt chiếc chìa khóa đó ở sảnh và đánh sẵn một chiếc bản sao giống hệt. Ngay khi bạn cất hành lý vào phòng, chúng chỉ việc dùng chiếc chìa khóa bản sao kia để vào dọn sạch đồ của bạn. Đây chính là lỗ hổng **Cố định phiên làm việc (Session Fixation)**.

Để quản lý an toàn hệ thống, nhà phát triển cần kiểm soát chặt chẽ **vòng đời của phiên làm việc và cookie (session and cookies lifecycle)**. Cookie giống như chiếc thẻ phòng được trình duyệt lưu giữ. Để thẻ này không bị đọc trộm, nó cần được cài đặt các thuộc tính bảo vệ nghiêm ngặt:
- **HttpOnly**: Khóa không cho các mã script (JavaScript) đọc nội dung thẻ (chống XSS).
- **Secure**: Chỉ cho phép truyền thẻ qua các kênh HTTPS được mã hóa.
- **SameSite**: Hạn chế việc gửi thẻ khi đi từ các trang web khác (chống CSRF).

Đặc biệt, quy tắc vàng trong **quản lý vòng đời phiên (session lifecycle management)** là: ngay khi người dùng đăng nhập thành công hoặc nâng đặc quyền, máy chủ bắt buộc phải **hủy bỏ chiếc thẻ cũ** và **cấp một chiếc thẻ mới hoàn toàn ngẫu nhiên**. Việc này sẽ cắt đứt hoàn toàn cơ hội của bất kỳ kẻ xấu nào muốn phục kích bằng chiếc khóa cũ đã biết trước. Ngoài ra, máy chủ cũng cần tự động thu hồi thẻ nếu người dùng không hoạt động sau một thời gian (idle timeout) để đảm bảo an toàn tối đa.

```javascript
const express = require('express');
const app = express();

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.authenticate(username, password);
    
    if (!user) {
        return res.status(401).send("Invalid credentials");
    }
    
    // Keep temporary session data before destroying the old session
    const tempCart = req.session.cart;
    
    // Regenerate session ID immediately on privilege elevation (login)
    req.session.regenerate((err) => {
        if (err) {
            return res.status(500).send("Session regeneration failed");
        }
        
        // Populate the new session with authenticated user details
        req.session.userId = user.id;
        req.session.cart = tempCart;
        
        // Explicitly save the session to prevent write/read race conditions
        req.session.save((saveErr) => {
            if (saveErr) {
                return res.status(500).send("Failed to save secure session");
            }
            return res.json({ status: "Logged in and session regenerated successfully" });
        });
    });
});
```

## Mô tả lỗ hổng
Lỗ hổng Cố định phiên (Session Fixation) xảy ra khi ứng dụng web cho phép người dùng sử dụng tiếp mã định danh phiên (Session ID) cũ sau khi họ đã đăng nhập thành công. 

Mối nguy hiểm của lỗ hổng này nằm ở chỗ kẻ tấn công có thể chủ động tạo ra một mã Session ID hợp lệ, tìm cách cài cắm mã này vào trình duyệt của nạn nhân (ví dụ qua một liên kết chứa tham số session ID). Khi nạn nhân bấm vào và đăng nhập thành công, máy chủ liên kết tài khoản của nạn nhân với mã ID đó. Do kẻ tấn công đã nắm giữ mã này từ trước, chúng có thể dễ dàng truy cập thẳng vào tài khoản của nạn nhân mà không cần biết tên đăng nhập hay mật khẩu.

## Cơ chế tấn công
Bước 1: Kẻ tấn công (Mal) truy cập trang web mục tiêu và nhận được một Session ID hợp lệ chưa đăng nhập (ví dụ: `SID=XYZ123`).
Bước 2: Mal gửi cho nạn nhân (Vic) một liên kết dẫn tới trang web mục tiêu có đính kèm mã Session ID này trong query string: `https://target.com/login?session_id=XYZ123`.
Bước 3: Vic click vào link và tiến hành đăng nhập bằng tài khoản của mình. Ứng dụng chấp nhận Session ID `XYZ123` có sẵn từ URL và liên kết phiên đăng nhập của Vic vào mã ID này.
Bước 4: Vì Mal đã biết trước mã ID `XYZ123`, Mal cấu hình trình duyệt của mình sử dụng cookie `SID=XYZ123` và truy cập trực tiếp vào hệ thống để chiếm quyền điều khiển tài khoản của Vic.

## Biện pháp phòng thủ
- **Tóm tắt**: Session fixation is an attack where a malicious user forces another user's session identifier to a predetermined value, allowing them to hijack the session after authentication. Mitigation requires generating a new session identifier immediately upon any privilege level change, specifically during login.
- **Các bước chi tiết**:
  - Always invalidate the existing session and generate a new session identifier (session ID) immediately upon successful user login.
  - Implement proper session timeout mechanisms (both idle timeout and absolute timeout).
  - Secure cookies containing session identifiers by setting attributes: HttpOnly (prevent JS access), Secure (force HTTPS), and SameSite=Strict or SameSite=Lax.
  - Ensure session IDs are random, cryptographically strong, and generated by the server's security framework rather than accepted from client input.

## Code Example
```javascript
// User login endpoint in Express
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  if (user) {
    const tempCart = req.session.cart;
    // Regenerate session ID to prevent Session Fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).send('Session error');
      req.session.userId = user.id;
      req.session.cart = tempCart;
      // Fix: Explicitly save session to prevent write/read race conditions
      req.session.save((err) => {
        if (err) return res.status(500).send('Session error');
        res.send('Logged in successfully');
      });
    });
  } else {
    res.status(401).send('Invalid credentials');
  }
});
```

## Xem thêm
- [OAuth 2.0 Vulnerabilities](../oauth-vulnerabilities/README.md)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A07:2021, CWE-384

## Giải thích thuật ngữ
- **Session Fixation (Cố định phiên)**: Lớp lỗ hổng bảo mật xảy ra khi ứng dụng cho phép người dùng duy trì cùng một mã định danh phiên (Session ID) sau khi đăng nhập, tạo điều kiện cho tin tặc chiếm quyền điều khiển phiên bằng mã ID biết trước.
- **Session ID (Mã phiên)**: Một chuỗi ký tự ngẫu nhiên duy nhất được máy chủ tạo ra để nhận diện phiên làm việc hiện tại của một người dùng cụ thể trên ứng dụng web.
- **HttpOnly Cookie**: Thuộc tính bảo mật của cookie ngăn cản các mã script chạy trên trình duyệt (như JavaScript) truy cập vào giá trị của cookie, giúp giảm thiểu rủi ro bị đánh cắp cookie qua lỗ hổng XSS.
- **Secure Cookie**: Thuộc tính yêu cầu trình duyệt chỉ được phép truyền cookie này lên máy chủ thông qua kết nối HTTPS được mã hóa an toàn.
- **SameSite Cookie**: Thuộc tính kiểm soát việc cookie có được gửi kèm theo các yêu cầu từ trang web của bên thứ ba hay không, giúp ngăn chặn tấn công CSRF.
- **Session Lifecycle Management (Quản lý vòng đời phiên)**: Quy trình kiểm soát toàn bộ vòng đời của một phiên làm việc, từ lúc khởi tạo, gia hạn, cho đến khi hủy bỏ hoàn toàn khi người dùng đăng xuất hoặc phiên hết hạn.
