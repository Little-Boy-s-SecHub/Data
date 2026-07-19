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
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Insecure Deserialization by the root cause instead of just describing the consequences. 
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploitable. 
- Conduct controlled testing in a local lab and differentiate between expected results and false positives. 
- Choose the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow in Insecure Deserialization scenarios and how to apply input handling across trust boundaries.
- Distinguish between authentication, authorization, and validation.
- Know how to read code/configuration in the language or framework present in the example.
- Have a local lab isolated, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine you want to send a complete assembled Lego house to a friend far away through the mail. Carrying the entire house to send it is impossible. So, you decide to dismantle the house into individual bricks, neatly pack them into a box along with an assembly instruction manual. This process of dismantling and packing is **Serialization** — converting a complex object in a computer's memory into a simple sequence of bytes or characters for easy storage or transmission.

When your friend receives the box of bricks, they open it and reassemble the Lego house according to the original blueprint. This process of restoration is **Deserialization**.

Almost every programming language has this assembly and disassembly toolkit: Java uses `ObjectInputStream`/`ObjectOutputStream`, Python uses `pickle`, and PHP uses `serialize()`/`unserialize()`.

The story becomes dangerous when the 'Lego box sender' is not your friend, but a cunning attacker. He doesn’t send ordinary bricks; he includes a 'malicious' instruction manual. In the programming world, objects often automatically trigger cleanup or default initialization actions after being assembled — called **magic methods** (like `__wakeup()` of PHP, `readObject()` of Java, or `__reduce__()` of Python). If your system blindly follows this malicious instruction manual, it will inadvertently assemble a 'bomb' that destroys the system itself, leveraging existing command blocks in the application (called a **gadget chain**) to execute destructive actions.

Below is a normal serialization example in Java:

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

## 4. Description and Root Cause

The **Insecure Deserialization** vulnerability occurs when an application is too naive, ready to reassemble any data object sent by the user without checking whether it contains a trap. An attacker simply swaps the contents of the serialized object with a data string containing malicious code.

Once this toxic box is opened and assembled, the consequences will be extremely unpredictable:
- **Remote Code Execution (RCE)**: An attacker can command the server to run any command, similar to seizing full control of your computer remotely. This is the worst-case scenario and extremely common for this vulnerability.
- **Privilege Escalation**: Simply slightly changing an attribute in the box (for example, changing the role from `"user"` to `"admin"`), the attacker suddenly gains full administrative privileges.
- **Denial-of-Service Attack (DoS)**: Sending infinitely nested objects causes the server to exhaust resources, shutting down due to overload.
- **Data Tampering**: Silently modifying the application's state or operational logic without anyone noticing.

> **Reference:** the technical claims in the lesson are marked with a source; when applying in practice, cross-check with the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** object graph, application state, and process runtime.
- **Actor, authentication, and role:** user role sends serialized cookie/body; no filesystem role.
- **Exploitation conditions:** deserializer builds type/gadget chosen by actor according to integrity/type policy.
- **Browser, proxy, framework, and version:** Python 3.12 container, Java 17, and .NET legacy isolated, no-network; must record actual image/package version along with evidence.
- **Mandatory evidence:** with correlation ID, must link input, decisions of control, and impact on the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For insecure deserialization, the deserializer constructs a type/gadget chosen by the actor according to the integrity/type policy. The positive case must prove that the input reaches the correct sink and produces the described effect; the negative case, when origin control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Python 3.12, Java 17, and .NET legacy containers separately, no-network; only load synthetic data, enable application/proxy/datastore logging, and attach correlation ID.
2. **Baseline:** send a valid input for the insecure deserialization use case; save raw request/response, decide policy and asset state before testing.
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change only one variable at a time and comply with the request cap.
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the mechanism “deserializer constructs type/gadget chosen by actor according to integrity/type policy”; secure fixture must block before side effects and boundary input must fail closed.
5. **Cleanup:** delete data, markers, and logs of insecure deserialization; revoke related session/cache, restore snapshot, and ensure no test callbacks/processes remain.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

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
**Java ysoserial gadget chain** (using the ysoserial tool):

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
**Attack Variants on Other Platforms:**

1. **.NET BinaryFormatter & Newtonsoft.Json TypeNameHandling**:
   - **BinaryFormatter**: The default binary serialization format of .NET. When calling Deserialize, the program will automatically reconstruct the entire object graph from the data stream. An attacker can use available system classes (such as ObjectDataProvider or ActivitySurrogateSelector) as a gadget chain (created via reflection) to execute malicious code.
   - **Newtonsoft.Json TypeNameHandling**: In the Newtonsoft.Json library, the TypeNameHandling property allows specifying the type of an object directly in the JSON string via the $type property. If this configuration is set to any value other than None (e.g., Auto or All) and deserializes input from users, an attacker can inject special classes like WindowsIdentity to trigger code execution when the JSON string is parsed.

2. **Ruby Marshal.load**:
   - The binary serialization protocol in Ruby uses `Marshal.dump` and `Marshal.load`. The `Marshal.load` function deserializes binary data directly without performing safety checks. By crafting a forged serialized byte string containing preloaded classes (for example, `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` in older Rails versions), an attacker can trigger the invocation of `system` or `eval` when Ruby attempts to restore or clean up the object's memory.

3. **YAML Deserialization (unsafe yaml.load)**:
   - YAML parsers (such as `PyYAML` in Python) provide an extended feature that allows creating objects directly from the text representation of YAML through special tags.
   - If an application uses the `yaml.load()` function (using PyYAML's default Loader before version 6.0) on unvalidated input data, an attacker can inject `!!python/object/apply:subprocess.Popen` or `!!python/object/new:os.system` tags along with command parameters to execute system commands as soon as the YAML parse function is called.

4. **ASP.NET ViewState without MAC**:
   - `ViewState` is used by ASP.NET to maintain the state of controls on the web interface between requests, and it is serialized using `ObjectStateFormatter`. To protect integrity, ASP.NET uses a Message Authentication Code (MAC) encrypted with `machineKey` configured on the server.
   - If the ViewState MAC is disabled by configuring `<pages enableViewStateMac="false" />` or if an attacker knows the secret key `machineKey`, the attacker can freely modify the binary ViewState data, insert a deserialization payload generated by `ysoserial.net` (for example using gadget chains `ActivitySurrogateSelector` or `TypeConfuseDelegate`) to achieve remote code execution on the IIS server when the page is loaded.

## 9. Vulnerable Code and Secure Code

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

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Insecure Deserialization, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload chain.
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact.
- Scanner or WAF alerts are only investigative signals; they are not the sole proof that the vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Use the DTO simple schema and verify integrity before parsing; do not accept native object graph.
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With Insecure Deserialization, the following measures help reduce the blast radius or increase detection capability. Rate limiting, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

```java
// Java 9+ ObjectInputFilter — only allow specific classes
ObjectInputStream ois = new ObjectInputStream(inputStream);
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.*;!*"  // Allow only classes in com.myapp.dto, reject everything else
);
ois.setObjectInputFilter(filter);
```
- **Summary**: Avoid Insecure Deserialization by limiting deserialization of untrusted data, using a class whitelist, signing and verifying data before processing. 
- **Detailed steps**:
  - **Do not deserialize data from untrusted sources** — this is the most effective measure. Use JSON or simple alternative data formats.
  - **Whitelist allowed classes** — in Java, use `ObjectInputFilter` (Java 9+).
  - **Sign and verify serialized data** — use HMAC to ensure integrity before deserialization.
  - **Remove gadget chains** — remove unnecessary libraries (Commons Collections, Spring Beans) from the classpath.
  - **Monitor and alert** — log all deserialization activities, alert when abnormal classes are detected.

## 12. Retest

- **Positive case:** with Insecure Deserialization, valid flows still work correctly for allowed actors and data.  
- **Negative case:** the same input/resource but for unauthorized actors or contexts should be denied without leaking sensitive details.  
- **Boundary case:** test empty values, edge limits, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Recheck:** keep a minimal scenario reproducing old errors and demonstrate the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Insecure Deserialization without verifying side effects and logs.  
- Use a payload with correct syntax but wrong DBMS, browser, framework, protocol, or injection context.  
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for another original control.  
- Only fix one route while the same sink/policy is used in another route.  
- Conclude that a vulnerability exists without saving the source, fixture version, and observable evidence.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup is complete; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **Serialization**: The process of converting a data structure or complex object in memory into an intermediate format (byte stream or text characters) for storage or transmission.
- **Deserialization**: The reverse process of serialization, reconstructing the original object in memory from the intermediate format.
- **Magic Methods**: Special methods in object-oriented programming (usually starting with double underscores like `__wakeup`) automatically called by the system when a special event occurs, such as when an object is restored.
- **Classpath**: A path containing classes and libraries that a Java application can locate and use during runtime.
- **Gadget Chain**: A chain of available functions/classes in an application that an attacker cleverly combines to execute malicious code during deserialization.
- **Payload**: Malicious code or data designed to exploit a security vulnerability.
- **Remote Code Execution**: A vulnerability that allows an attacker to execute arbitrary commands directly on a target server remotely.
- **Privilege Escalation**: The act of taking higher privileges than the original legal privileges of an account.
- **Denial of Service**: An attack that drains system resources, preventing normal users from accessing the service.
- **Webshell**: Malicious code uploaded to a web server, giving an attacker a remote administration interface to control that server.
- **Polymorphic**: The ability to handle objects of different data types through a common interface.
- **Hash-based Message Authentication Code**: A message authentication code using a hash function combined with a secret key, ensuring that data is not altered during transmission.

## 16. Related Lessons and Further Reading

- [Prototype Pollution](../prototype-pollution/) — Prototype pollution vulnerability in JavaScript, often combined with Deserialization to exploit runtime.
- [Code Injection](../../05-injection/code-injection/) — Directly inject malicious code into the application processing flow.
- [Remote Code Execution](../../10-exceptional-conditions/remote-code-execution/) — Execute code from a remote source, the most dangerous consequence of unsafe deserialization.

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/deserialization — version/status: current version; accessed: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/ — version/status: current version; accessed: 2026-07-18.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/502.html — version/status: current version; accessed: 2026-07-18.
- **[S4]** ysoserial. https://github.com/frohoff/ysoserial — version/status: current version; accessed: 2026-07-18.
- **[S5]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18.