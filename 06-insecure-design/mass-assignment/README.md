# Mass Assignment

> **OWASP Top 10:2025**: A06:2025 – Insecure Design | **CWE**: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) | **Phân loại**: File & Data

## 🧱 Kiến thức Nền tảng
Gán thuộc tính hàng loạt (Mass Assignment) là lỗ hổng phát sinh khi ứng dụng tự động đưa trực tiếp tất cả dữ liệu từ HTTP request vào cơ sở dữ liệu. Lỗ hổng này liên quan chặt chẽ đến cơ chế ORM model data binding (liên kết dữ liệu của mô hình ORM).

Các framework phát triển web hiện đại thường sử dụng Object-Relational Mapping (ORM) để ánh xạ các bảng cơ sở dữ liệu thành các lớp (classes) đối tượng trong bộ nhớ. Tính năng data binding tự động ánh xạ các tham số từ JSON hoặc Form POST gửi lên từ client vào các thuộc tính của đối tượng ORM để giảm thiểu lượng code phải viết thủ công.

Tuy nhiên, nếu nhà phát triển sử dụng cơ chế liên kết dữ liệu ORM này mà không giới hạn hay phân lọc các trường, kẻ tấn công có thể gửi thêm các cặp key-value không mong muốn (ví dụ như `is_admin: true` hoặc `role: "admin"`) trong payload yêu cầu. ORM sẽ tự động ràng buộc các giá trị này vào thực thể và lưu xuống cơ sở dữ liệu, cho phép kẻ tấn công sửa đổi các trường nhạy cảm và nâng cao đặc quyền. Để phòng chống, lập trình viên cần sử dụng các đối tượng truyền dữ liệu (DTOs - Data Transfer Objects) chuyên biệt, hoặc thiết lập danh sách trắng (allowlist) quy định rõ ràng chỉ có những trường dữ liệu cụ thể nào mới được phép cập nhật từ client.

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

## 🔍 Mô tả lỗ hổng
Gán thuộc tính hàng loạt (Mass Assignment) xảy ra khi ứng dụng tự động ánh xạ trực tiếp toàn bộ dữ liệu đầu vào từ HTTP request vào các đối tượng dữ liệu trong bộ nhớ hoặc cơ sở dữ liệu. Kẻ tấn công có thể thêm các tham số không mong muốn (ví dụ: 'is_admin': true) vào request gửi lên máy chủ. Nếu ứng dụng không lọc hoặc ràng buộc các thuộc tính được phép cập nhật, thuộc tính nhạy cảm đó sẽ bị thay đổi và kẻ tấn công có thể chiếm quyền quản trị.

## ⚔️ Cơ chế tấn công
Bước 1: Kẻ tấn công đăng ký một tài khoản mới trên hệ thống thông qua biểu mẫu đăng ký thông thường.
Bước 2: Kẻ tấn công kiểm tra dữ liệu gửi lên và thấy request chứa JSON như `{"username": "mal", "password": "123"}`.
Bước 3: Kẻ tấn công phán đoán đối tượng User trong database có trường `is_admin`, nên gửi lại request đăng ký bổ sung thuộc tính này: `{"username": "mal", "password": "123", "is_admin": true}`.
Bước 4: Máy chủ tự động giải nén toàn bộ JSON đầu vào và gán trực tiếp vào đối tượng User trong DB mà không chọn lọc, giúp tài khoản mới của kẻ tấn công có ngay quyền quản trị.

## 🛡️ Biện pháp phòng thủ
- **Tóm tắt**: Mass assignment occurs when an application automatically binds user-supplied input parameters to internal model objects or database records without filtering, allowing attackers to modify fields they shouldn't (e.g., roles or admin status). Mitigation relies on explicit white-listing of permitted parameters or using dedicated Data Transfer Objects (DTOs).
- **Các bước chi tiết**:
  - Define explicit Data Transfer Objects (DTOs) or input models containing only the fields that are meant to be user-writable.
  - Implement strict parameter allow-listing (such as Rails' strong parameters) to whitelist acceptable properties before binding.
  - Avoid binding request payloads directly to database entity/model objects that represent sensitive schema structures.
  - Configure the ORM or framework to ignore or throw errors on undefined/unpermitted properties in request payloads.

## 💻 Code Example
```python
from pydantic import BaseModel, EmailStr

class UserUpdateSchema(BaseModel):
    # Only allow updating name, bio, and email; sensitive fields like is_admin/role are excluded
    name: str
    bio: str
    email: EmailStr
```

## 📚 Ghi chú kỹ thuật & Nguồn tham khảo
- **Trạng thái kiểm định**: PASS
- **Ghi chú kỹ thuật**: Trong Milestone 2, bài học này có trạng thái PASS. Ví dụ an toàn thể hiện việc sử dụng Data Transfer Object (DTO) hoặc whitelist các thuộc tính được phép gán thay vì tự động ánh xạ trực tiếp toàn bộ dữ liệu từ HTTP Request vào cơ sở dữ liệu.
- **Nguồn tham khảo**: OWASP A08:2021, CWE-915
