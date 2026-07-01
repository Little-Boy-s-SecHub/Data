# Mass Assignment

> **CWE**: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) | **Phân loại**: Insecure Design

## Kiến thức Nền tảng
Hãy tưởng tượng khi bạn điền một tờ phiếu thông tin cá nhân để mở thẻ thư viện. Tờ phiếu có các ô như "Họ và tên", "Số điện thoại" và "Địa chỉ". Tuy nhiên, ở góc dưới cùng của tờ phiếu có một ô dành riêng cho nhân viên ghi là "Nhóm quyền hạn: Đọc giả thường / Quản trị viên". Lập trình viên thiết kế hệ thống này theo cách: chỉ cần nhập tất cả những gì người dùng viết trên tờ phiếu trực tiếp vào hệ thống lưu trữ mà không hề kiểm tra xem người dùng có lén viết vào ô của nhân viên hay không. Hành vi tự động điền này tương tự như **Gán thuộc tính hàng loạt (Mass Assignment)**.

Trong các trang web hiện đại, lập trình viên sử dụng một công nghệ gọi là **ORM (Object-Relational Mapping)** để làm cầu nối chuyển đổi các hàng dữ liệu trong bảng database thành các đối tượng dễ lập trình. Để đỡ tốn công gõ code gán từng thuộc tính (như `tên = dữ liệu.tên`, `email = dữ liệu.email`), các framework hỗ trợ cơ chế tự động liên kết dữ liệu (**data binding**), cho phép bê nguyên toàn bộ gói dữ liệu người dùng gửi lên gán thẳng vào cơ sở dữ liệu.

Chính sự tiện lợi này đã tạo ra lỗ hổng bảo mật. Nếu kẻ xấu phát hiện ra cơ chế này, chúng có thể tự điền thêm các trường nhạy cảm như `is_admin: true` hoặc `role: "admin"` vào gói dữ liệu gửi lên. Máy chủ ORM do không được cấu hình chặn lọc sẽ tự động cập nhật giá trị đó vào hồ sơ của kẻ xấu, giúp chúng nghiễm nhiên bước lên làm Quản trị viên của hệ thống mà không cần mật khẩu đặc biệt nào. Để phòng tránh, lập trình viên cần sử dụng các đối tượng trung gian gọi là **DTO (Data Transfer Objects)** như một bộ lọc thông minh, chỉ cho phép những dữ liệu hợp lệ đi vào cơ sở dữ liệu.

#### Minh họa hoạt động bình thường (Normal Operation)
```python
# Secure ORM model data binding using Pydantic as a Data Transfer Object (DTO)
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# SQLAlchemy Database Model representing the user entity
class UserModel(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    email = Column(String(100))
    is_admin = Column(Boolean, default=False)  # Sensitive attribute

# Pydantic schema acting as a secure DTO for user updates
# It explicitly excludes the sensitive 'is_admin' field from client input
class UserUpdateDTO(BaseModel):
    username: str
    email: EmailStr

def update_user_profile(db_session, user_id, request_data):
    # Parse and validate incoming data using the DTO
    # Unwanted fields like 'is_admin' sent by the client will be discarded
    validated_dto = UserUpdateDTO(**request_data)
    
    # Retrieve the database model object
    user_record = db_session.query(UserModel).filter(UserModel.id == user_id).first()
    if not user_record:
        raise ValueError("User not found")
        
    # Safely bind only the validated parameters to the ORM model
    user_record.username = validated_dto.username
    user_record.email = validated_dto.email
    
    db_session.commit()
```

## Mô tả lỗ hổng
Lỗ hổng Gán thuộc tính hàng loạt (Mass Assignment) xảy ra khi máy chủ web tự động chấp nhận và ghi đè toàn bộ dữ liệu do người dùng gửi lên vào các đối tượng dữ liệu nội bộ của hệ thống mà không qua một màng lọc nào. 

Mối nguy hiểm của lỗ hổng này nằm ở chỗ kẻ tấn công có thể lén lút chèn thêm các tham số đặc biệt vào yêu cầu gửi đi nhằm tự động thay đổi các thuộc tính nhạy cảm mà đáng ra họ không được quyền đụng tới (như nâng cấp tài khoản lên Admin, thay đổi số dư ví tiền, hoặc đổi chủ sở hữu của tài nguyên). Lỗi này thường rất dễ khai thác vì kẻ tấn công chỉ cần thêm một dòng thuộc tính nhỏ vào request JSON của họ.

## Cơ chế tấn công
Bước 1: Kẻ tấn công đăng ký một tài khoản mới trên hệ thống thông qua biểu mẫu đăng ký thông thường.
Bước 2: Kẻ tấn công kiểm tra dữ liệu gửi lên và thấy request chứa JSON như `{"username": "mal", "password": "123"}`.
Bước 3: Kẻ tấn công phán đoán đối tượng User trong database có trường `is_admin`, nên gửi lại request đăng ký bổ sung thuộc tính này: `{"username": "mal", "password": "123", "is_admin": true}`.
Bước 4: Máy chủ tự động giải nén toàn bộ JSON đầu vào và gán trực tiếp vào đối tượng User trong DB mà không chọn lọc, giúp tài khoản mới của kẻ tấn công có ngay quyền quản trị.

## Biện pháp phòng thủ
- **Tóm tắt**: Mass assignment occurs when an application automatically binds user-supplied input parameters to internal model objects or database records without filtering, allowing attackers to modify fields they shouldn't (e.g., roles or admin status). Mitigation relies on explicit white-listing of permitted parameters or using dedicated Data Transfer Objects (DTOs).
- **Các bước chi tiết**:
  - Define explicit Data Transfer Objects (DTOs) or input models containing only the fields that are meant to be user-writable.
  - Implement strict parameter allow-listing (such as Rails' strong parameters) to whitelist acceptable properties before binding.
  - Avoid binding request payloads directly to database entity/model objects that represent sensitive schema structures.
  - Configure the ORM or framework to ignore or throw errors on undefined/unpermitted properties in request payloads.

## Code Example
```python
from pydantic import BaseModel, EmailStr

class UserUpdateSchema(BaseModel):
    # Only allow updating name, bio, and email; sensitive fields like is_admin/role are excluded
    name: str
    bio: str
    email: EmailStr
```

## Xem thêm
- [Các bài học liên quan trong cùng thư mục](../)

## Nguồn tham khảo
- **Nguồn tham khảo**: OWASP A08:2021, CWE-915

## Giải thích thuật ngữ
- **Mass Assignment (Gán hàng loạt)**: Cơ chế của các framework tự động ánh xạ trực tiếp tất cả các tham số từ yêu cầu HTTP đầu vào vào các thuộc tính của một đối tượng dữ liệu trong hệ thống.
- **ORM (Object-Relational Mapping)**: Kỹ thuật lập trình giúp chuyển đổi dữ liệu giữa các hệ thống cơ sở dữ liệu quan hệ (như SQL) và ngôn ngữ lập trình hướng đối tượng, biến các bảng dữ liệu thành các đối tượng dễ quản lý trong code.
- **Data Binding (Ràng buộc dữ liệu)**: Quá trình tự động đồng bộ hóa và gán dữ liệu giữa giao diện người dùng (hoặc yêu cầu HTTP) với mô hình dữ liệu của ứng dụng.
- **DTO (Data Transfer Object)**: Một mẫu thiết kế phần mềm, tạo ra các đối tượng trung gian chỉ chứa các thuộc tính cụ thể được phép chuyển giao dữ liệu giữa các tầng của ứng dụng, giúp lọc bỏ các dữ liệu không an toàn do client gửi lên.
- **Allowlist (Danh sách trắng)**: Biện pháp bảo mật hoạt động theo nguyên tắc từ chối tất cả mặc định, chỉ chấp nhận những mục nằm trong danh sách đã được xác định là an toàn và cho phép từ trước.
