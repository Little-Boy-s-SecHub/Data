# Broken Access Control

> **CWE**: CWE-285 | **Phân loại**: Access Control

## Kiến thức Nền tảng
Hãy tưởng tượng bạn đăng ký dịch vụ tại một khách sạn lớn. Khi làm thủ tục tại quầy lễ tân, nhân viên sẽ kiểm tra chứng minh thư của bạn và đưa cho bạn một chiếc chìa khóa phòng. Quá trình kiểm tra chứng minh thư để xác định bạn là ai chính là **Authentication** (Xác thực). Còn việc chiếc chìa khóa đó chỉ mở được đúng căn phòng 204 bạn đã thuê, chứ không thể mở được phòng 205 bên cạnh hay phòng tổng thống, chính là **Authorization** (Phân quyền). 

Trong thế giới web cũng vậy. Khi bạn đăng nhập thành công, máy chủ (server) sẽ cấp cho trình duyệt của bạn một mã định danh gọi là **session token** (giống như chiếc chìa khóa phòng). Mỗi khi trình duyệt gửi yêu cầu lấy dữ liệu (qua cookie hoặc HTTP header), máy chủ chỉ cần kiểm tra mã này để biết bạn đã đăng nhập hay chưa. Tuy nhiên, một lỗ hổng nghiêm trọng sẽ xảy ra nếu người quản lý khách sạn "quên" cài đặt ổ khóa thông minh, chỉ cần bạn đi bộ hành lang và vặn tay nắm cửa phòng khác là cửa tự mở. Lỗ hổng **Kiểm soát truy cập bị lỗi** (Broken Access Control) xuất hiện khi máy chủ nhận được yêu cầu từ bạn, biết bạn đã đăng nhập, nhưng lại lười biếng không kiểm tra xem bạn có thực sự sở hữu căn phòng hay tài liệu mà bạn đang yêu cầu hay không. Họ chỉ tin tưởng mù quáng vào số phòng (ID tài nguyên) bạn gửi lên và mở toang cửa cho bạn vào.

```python
# Flask route verifying resource ownership based on authenticated session user ID
from flask import abort, jsonify
from flask_login import login_required, current_user
from models import Document

@app.route('/api/document/<int:doc_id>', methods=['GET'])
@login_required
def get_document(doc_id):
    # Retrieve the document from the database
    document = Document.query.get_or_404(doc_id)
    
    # Secure: Verify if the authenticated user owns this specific document
    if document.owner_id != current_user.id:
        # Deny access if user is not the owner
        abort(403, description="Access denied: You do not own this resource.")
        
    # Return the document data if authorized
    return jsonify(document.to_json())
```

## Mô tả lỗ hổng
Nhiều nhà phát triển web thường ngây thơ nghĩ rằng: "Nếu mình đặt tên trang web là một chuỗi ký tự ngẫu nhiên siêu dài và không để link ở đâu cả, thì đố ai mà tìm được!". Phương pháp này được gọi là "bảo mật bằng cách ẩn mình" (security through obscurity) và nó hoàn toàn vô dụng. Kẻ tấn công chỉ cần tìm được một manh mối nhỏ, hoặc viết một đoạn mã tự động dò tìm các địa chỉ URL theo quy luật, là có thể lục lọi mọi ngóc ngách của hệ thống. 

Lỗ hổng Broken Access Control cực kỳ nguy hiểm bởi vì nó không đòi hỏi kỹ thuật cao siêu. Nó giống như việc kẻ xấu chỉ cần sửa đổi số phòng trên chiếc chìa khóa của họ, và máy chủ ngay lập tức cho phép họ đọc trộm tin nhắn, rút tiền từ tài khoản của người khác, hoặc thậm chí là chiếm quyền điều khiển toàn bộ hệ thống của quản trị viên. Mọi quyết định phân quyền bắt buộc phải được máy chủ kiểm tra nghiêm ngặt cho mỗi một yêu cầu, dù là nhỏ nhất, chứ không bao giờ được tin tưởng vào giao diện hiển thị hay các tham số từ phía người dùng gửi lên.

## Cơ chế tấn công
Kẻ tấn công nhận thấy rằng các thông cáo báo chí nhạy cảm của một công ty được đăng bằng cách sử dụng một quy ước đặt tên có thể đoán trước được và kiểm tra một URL tiềm năng trước ngày công bố chính thức. Khi nhận thấy máy chủ không thực thi quyền ủy quyền, kẻ tấn công viết một kịch bản để thu thập các tài liệu trước khi phát hành nhằm giành được lợi thế không công bằng trên thị trường chứng khoán.

### Ví dụ HTTP request minh họa vi phạm Access Control:
```http
# Normal user accessing their own profile
GET /api/users/1234/profile HTTP/1.1
Authorization: Bearer user_token_1234

# Horizontal escalation: change ID to access another user
GET /api/users/5678/profile HTTP/1.1
Authorization: Bearer user_token_1234
# If server returns 200 with user 5678's data → IDOR vulnerability

# Vertical escalation: access admin endpoint
GET /api/admin/users HTTP/1.1
Authorization: Bearer user_token_1234
# If server returns admin data → BFLA vulnerability
```

## Biện pháp phòng thủ
- **Tóm tắt**: Thực thi kiểm soát truy cập ở phía máy chủ đối với mỗi yêu cầu, áp dụng Nguyên tắc Đặc quyền Tối thiểu (Principle of Least Privilege) và xác thực quyền sở hữu tài nguyên.
- **Các bước chi tiết**:
  - Xác thực quyền hạn của người dùng ở phía máy chủ cho mỗi yêu cầu, thay vì dựa vào việc ẩn hoặc che giấu ở cấp độ giao diện người dùng (UI).
  - Kiểm tra quyền sở hữu tài nguyên (ví dụ: so sánh ID chủ sở hữu tài nguyên với ID phiên hiện tại) và từ chối truy cập với mã HTTP 403 nếu chúng không khớp.
  - Sử dụng các định danh an toàn về mặt mật mã, ngẫu nhiên và không thể đoán trước (như UUID) cho các URL nhạy cảm.
  - Triển khai phần mềm trung gian xác thực và phân quyền tập trung để tránh các kiểm tra thủ công lặp đi lặp lại và dễ xảy ra lỗi trong các trình xử lý định tuyến (route handlers).

## Code Example
```python
# Flask route with server-side ownership check to prevent IDOR
from flask import abort, request, jsonify
from flask_login import login_required, current_user
from models import Account

@app.route('/api/account/<int:account_id>', methods=['GET'])
@login_required
def get_account_details(account_id):
    # Retrieve resource
    account = Account.query.get_or_404(account_id)
    
    # Safety check: Ensure user and owner IDs are valid and not None
    if not current_user or current_user.id is None or account.user_id is None:
        abort(403)
        
    # Enforce authorization: Check if current logged-in user owns the account
    if account.user_id != current_user.id and not current_user.is_admin:
        # Log access denial
        app.logger.warning(f"User {current_user.id} unauthorized access attempt to Account {account_id}")
        abort(403) # Forbidden
        
    return jsonify(account.to_json())
```


## Xem thêm
- [Broken Function Level Authorization (BFLA)](../bfla/) — Xem thêm bài học về Broken Function Level Authorization (BFLA).

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A01:2021-Broken Access Control, CWE-285 (Improper Authorization)

## Giải thích thuật ngữ
- **Authentication (Xác thực)**: Quá trình xác minh danh tính của một người dùng (xác định xem "họ là ai", ví dụ qua tên đăng nhập và mật khẩu).
- **Authorization (Phân quyền)**: Quá trình xác định những quyền hạn và tài nguyên mà người dùng đã xác thực được phép truy cập hoặc thao túng (xác định xem "họ được làm gì").
- **Session Token (Mã phiên làm việc)**: Một chuỗi ký tự ngẫu nhiên duy nhất được máy chủ cấp cho người dùng sau khi đăng nhập thành công, dùng để nhận diện người dùng trong các yêu cầu tiếp theo mà không cần đăng nhập lại.
- **HTTP Request/Response**: Giao thức truyền tải siêu văn bản, là cách thức trao đổi dữ liệu giữa máy khách (client) gửi yêu cầu và máy chủ (server) trả lời kết quả trong môi trường web.
- **Cookie**: Các mẩu dữ liệu nhỏ được lưu trữ trên trình duyệt của người dùng, thường dùng để lưu session token nhằm duy trì trạng thái đăng nhập.
- **UUID (Universally Unique Identifier)**: Mã định danh duy nhất toàn cầu, là một chuỗi ký tự ngẫu nhiên dài có độ bảo mật cao, cực kỳ khó đoán hoặc trùng lặp.
- **IDOR (Insecure Direct Object Reference)**: Lỗ hổng tham chiếu đối tượng trực tiếp không an toàn, xảy ra khi kẻ tấn công thay đổi ID của tài nguyên để truy cập trái phép dữ liệu của người khác.
- **BFLA (Broken Function Level Authorization)**: Lỗ hổng kiểm soát quyền truy cập cấp chức năng bị lỗi, xảy ra khi người dùng có quyền hạn thấp thực hiện được các chức năng của người có quyền hạn cao hơn (như Admin).
