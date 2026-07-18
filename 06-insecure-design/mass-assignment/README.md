---
schema_version: 1
id: WEB-A06-MASS-ASSIGNMENT
title: "Mass Assignment"
slug: mass-assignment
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A08:2025
cwe:
  - CWE-915
content_status: technical-review
payload_status: none
last_verified: null
---

# Mass Assignment

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Mass Assignment bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

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

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng Gán thuộc tính hàng loạt (Mass Assignment) xảy ra khi máy chủ web tự động chấp nhận và ghi đè toàn bộ dữ liệu do người dùng gửi lên vào các đối tượng dữ liệu nội bộ của hệ thống mà không qua một màng lọc nào.

Mối nguy hiểm của lỗ hổng này nằm ở chỗ kẻ tấn công có thể lén lút chèn thêm các tham số đặc biệt vào yêu cầu gửi đi nhằm tự động thay đổi các thuộc tính nhạy cảm mà đáng ra họ không được quyền đụng tới (như nâng cấp tài khoản lên Admin, thay đổi số dư ví tiền, hoặc đổi chủ sở hữu của tài nguyên). Lỗi này thường rất dễ khai thác vì kẻ tấn công chỉ cần thêm một dòng thuộc tính nhỏ vào request JSON của họ.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** role, ownership và field model do server quản lý.
- **Actor, xác thực và role:** role user tạo/cập nhật profile của chính mình.
- **Điều kiện khai thác:** automatic binding copy field client vào property được bảo vệ.
- **Browser, proxy, framework và phiên bản:** ORM/serializer được pin với database tổng hợp; HTTP loopback; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với mass assignment, automatic binding copy field client vào property được bảo vệ. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy ORM/serializer được pin với database tổng hợp; HTTP loopback; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case mass assignment; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “automatic binding copy field client vào property được bảo vệ”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của mass assignment; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

Bước 1: Kẻ tấn công đăng ký một tài khoản mới trên hệ thống thông qua biểu mẫu đăng ký thông thường.
Bước 2: Kẻ tấn công kiểm tra dữ liệu gửi lên và thấy request chứa JSON như `{"username": "mal", "password": "123"}`.
Bước 3: Kẻ tấn công phán đoán đối tượng User trong database có trường `is_admin`, nên gửi lại request đăng ký bổ sung thuộc tính này: `{"username": "mal", "password": "123", "is_admin": true}`.
Bước 4: Máy chủ tự động giải nén toàn bộ JSON đầu vào và gán trực tiếp vào đối tượng User trong DB mà không chọn lọc, giúp tài khoản mới của kẻ tấn công có ngay quyền quản trị.

## 9. Code dễ bị lỗi và code an toàn

Hai endpoint sau dùng FastAPI 0.111.x và Pydantic 2.x cho cùng use case cập nhật hồ sơ. Gán mọi key từ body vào model persistence cho phép client chạm tới field nhạy cảm; schema allowlist chỉ đưa các field nghiệp vụ được phép vào lệnh update. [S2]

### Không an toàn (vulnerable): gán mọi key từ body

```python
from typing import Any
from fastapi import Body

@app.patch('/users/me')
def update_profile_vulnerable(payload: dict[str, Any] = Body(...)):
    user = current_user()
    for field, value in payload.items():
        # Vulnerable: client-controlled fields reach the persistence model
        setattr(user, field, value)
    db.commit()
    return user
```

### An toàn (secure): schema allowlist cho field được phép

```python
from pydantic import BaseModel, EmailStr

class UserUpdateSchema(BaseModel):
    name: str | None = None
    bio: str | None = None
    email: EmailStr | None = None

@app.patch('/users/me')
def update_profile_secure(payload: UserUpdateSchema):
    user = current_user()
    for field, value in payload.model_dump(exclude_unset=True).items():
        # Secure: only fields declared in UserUpdateSchema can reach the model
        setattr(user, field, value)
    db.commit()
    return user
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Chỉ nhận DTO field allowlist; gán protected field từ server context.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

- **Tóm tắt**: Mass assignment occurs when an application automatically binds user-supplied input parameters to internal model objects or database records without filtering, allowing attackers to modify fields they shouldn't (e.g., roles or admin status). Mitigation relies on explicit white-listing of permitted parameters or using dedicated Data Transfer Objects (DTOs).
- **Các bước chi tiết**:
  - Define explicit Data Transfer Objects (DTOs) or input models containing only the fields that are meant to be user-writable.
  - Implement strict parameter allow-listing (such as Rails' strong parameters) to whitelist acceptable properties before binding.
  - Avoid binding request payloads directly to database entity/model objects that represent sensitive schema structures.
  - Configure the ORM or framework to ignore or throw errors on undefined/unpermitted properties in request payloads.

## 12. Retest

- **Positive case:** luồng hợp lệ vẫn hoạt động đúng cho actor và dữ liệu được phép.
- **Negative case:** cùng input/tài nguyên nhưng actor hoặc context không được phép bị từ chối mà không rò rỉ chi tiết nhạy cảm.
- **Boundary case:** kiểm tra giá trị rỗng, cực biên, encoding khác, request lặp, trạng thái phiên hết hạn và đường dẫn/operation tương đương.
- **Telemetry:** xác nhận policy decision, application log, proxy log và datastore side effect khớp correlation ID.
- **Regression:** lưu testcase tối thiểu tái hiện lỗi cũ và testcase chứng minh bản sửa không phụ thuộc WAF/rate limit.

## 13. Sai lầm thường gặp

- Chỉ kiểm tra status code hoặc chuỗi phản hồi mà không xác nhận side effect và log.
- Dùng payload đúng cú pháp nhưng sai DBMS, browser, framework, protocol hoặc injection context.
- Coi UUID, rate limit, WAF, CSP hoặc input validation chung là bản sửa cho một kiểm soát gốc khác.
- Chỉ sửa một route trong khi cùng sink/policy được dùng ở route khác.
- Đánh dấu `verified` dù nguồn, phiên bản fixture hoặc evidence payload chưa được lưu.

## 14. Tóm tắt và checklist

- [ ] Root cause, hậu quả và kỹ thuật khai thác đã được tách riêng.
- [ ] Actor, role/authentication, trust boundary, công nghệ và phiên bản đã rõ.
- [ ] Payload có ID duy nhất, context, encoding, điều kiện, expected result, risk, validation và source.
- [ ] Code dễ lỗi/an toàn dùng cùng framework, phiên bản và use case.
- [ ] Kiểm soát bắt buộc không bị thay thế bằng defense-in-depth.
- [ ] Positive, negative, boundary case và telemetry đã qua retest.
- [ ] Claim nhạy cảm có source marker và mọi link chỉ nằm ở mục 16–17.
- [ ] Cleanup hoàn tất; không còn secret, target thật, callback Internet hoặc dữ liệu khách hàng.

## 15. Giải thích thuật ngữ

- **Mass Assignment (Gán hàng loạt)**: Cơ chế của các framework tự động ánh xạ trực tiếp tất cả các tham số từ yêu cầu HTTP đầu vào vào các thuộc tính của một đối tượng dữ liệu trong hệ thống.
- **ORM (Object-Relational Mapping)**: Kỹ thuật lập trình giúp chuyển đổi dữ liệu giữa các hệ thống cơ sở dữ liệu quan hệ (như SQL) và ngôn ngữ lập trình hướng đối tượng, biến các bảng dữ liệu thành các đối tượng dễ quản lý trong code.
- **Data Binding (Ràng buộc dữ liệu)**: Quá trình tự động đồng bộ hóa và gán dữ liệu giữa giao diện người dùng (hoặc yêu cầu HTTP) với mô hình dữ liệu của ứng dụng.
- **DTO (Data Transfer Object)**: Một mẫu thiết kế phần mềm, tạo ra các đối tượng trung gian chỉ chứa các thuộc tính cụ thể được phép chuyển giao dữ liệu giữa các tầng của ứng dụng, giúp lọc bỏ các dữ liệu không an toàn do client gửi lên.
- **Allowlist (Danh sách trắng)**: Biện pháp bảo mật hoạt động theo nguyên tắc từ chối tất cả mặc định, chỉ chấp nhận những mục nằm trong danh sách đã được xác định là an toàn và cho phép từ trước.

## 16. Bài liên quan và đọc thêm

- [Các bài học liên quan trong cùng thư mục](../)

## 17. Tài liệu tham khảo

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** CWE-915. https://cwe.mitre.org/data/definitions/915.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
