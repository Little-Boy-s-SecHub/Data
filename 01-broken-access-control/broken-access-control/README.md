# Broken Access Control

> **OWASP Top 10:2025**: A01:2025 – Broken Access Control | **CWE**: CWE-285 | **Phân loại**: Authorization

## 🧱 Kiến thức Nền tảng
Kiểm soát truy cập bị lỗi (Broken Access Control) là lỗ hổng bảo mật nghiêm trọng xảy ra khi ứng dụng không thực thi đúng các quy tắc phân quyền ở phía máy chủ. Để hiểu rõ cơ chế này, chúng ta cần phân biệt khái niệm **auth vs authz**. Trong đó, *authentication (xác thực - auth)* là quá trình xác minh danh tính của người dùng (họ là ai, ví dụ đăng nhập bằng mật khẩu). Ngược lại, *authorization (phân quyền - authz)* quyết định những hành động hoặc tài nguyên nào mà người dùng đó được phép truy cập sau khi đã xác thực.

Trong ứng dụng web, sau khi xác thực thành công, máy chủ sẽ cấp cho máy khách một **session token** (mã phiên làm việc). Mã này được gửi kèm trong mỗi **HTTP request/response** tiếp theo (thường qua cookie hoặc tiêu đề HTTP) để máy chủ nhận diện trạng thái đăng nhập mà không yêu cầu người dùng nhập lại mật khẩu. Lỗ hổng xảy ra khi máy chủ nhận HTTP request nhưng không thực hiện kiểm tra quyền sở hữu đối với tài nguyên được yêu cầu (authz) từ session token của người dùng hiện tại, mà chỉ tin tưởng hoàn toàn vào tham số ID do client gửi lên. Việc này cho phép kẻ tấn công sửa đổi ID tài nguyên trong yêu cầu để xem hoặc sửa dữ liệu của người dùng khác một cách trái phép.

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

## 🔍 Mô tả lỗ hổng
Bảo mật thông qua sự mơ hồ (security through obscurity), chẳng hạn như dựa vào các URL không được liên kết hoặc không thể đoán trước (như UUID), là một cách không hiệu quả để bảo vệ dữ liệu nhạy cảm. Nếu các đường dẫn đến dữ liệu nhạy cảm có thể đoán trước được, kẻ tấn công có thể viết kịch bản để khám phá và thu hoạch chúng. Các quyết định kiểm soát truy cập phải được đánh giá ở phía máy chủ cho mỗi yêu cầu đơn lẻ.

## ⚔️ Cơ chế tấn công
Kẻ tấn công nhận thấy rằng các thông cáo báo chí nhạy cảm của một công ty được đăng bằng cách sử dụng một quy ước đặt tên có thể đoán trước được và kiểm tra một URL tiềm năng trước ngày công bố chính thức. Khi nhận thấy máy chủ không thực thi quyền ủy quyền, kẻ tấn công viết một kịch bản để thu thập các tài liệu trước khi phát hành nhằm giành được lợi thế không công bằng trên thị trường chứng khoán.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Thực thi kiểm soát truy cập ở phía máy chủ đối với mỗi yêu cầu, áp dụng Nguyên tắc Đặc quyền Tối thiểu (Principle of Least Privilege) và xác thực quyền sở hữu tài nguyên.
- **Các bước chi tiết**:
  - Xác thực quyền hạn của người dùng ở phía máy chủ cho mỗi yêu cầu, thay vì dựa vào việc ẩn hoặc che giấu ở cấp độ giao diện người dùng (UI).
  - Kiểm tra quyền sở hữu tài nguyên (ví dụ: so sánh ID chủ sở hữu tài nguyên với ID phiên hiện tại) và từ chối truy cập với mã HTTP 403 nếu chúng không khớp.
  - Sử dụng các định danh an toàn về mặt mật mã, ngẫu nhiên và không thể đoán trước (như UUID) cho các URL nhạy cảm.
  - Triển khai phần mềm trung gian xác thực và phân quyền tập trung để tránh các kiểm tra thủ công lặp đi lặp lại và dễ xảy ra lỗi trong các trình xử lý định tuyến (route handlers).

## 💻 Code Example
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

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: FIXED
- **Ghi chú kỹ thuật**: Đã sửa lỗi một ví dụ về route Flask thiếu các import cần thiết (jsonify, login_required) và so sánh trực tiếp các thuộc tính ID người dùng mà không kiểm tra giá trị None, điều này sẽ bỏ qua việc xác thực nếu cả hai đều có giá trị null.
- **Nguồn tham khảo**: OWASP A01:2021-Broken Access Control, CWE-285 (Improper Authorization)
