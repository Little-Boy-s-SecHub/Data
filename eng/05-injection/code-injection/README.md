---
schema_version: 1
id: WEB-A05-CODE-INJECTION
title: "Code Injection"
slug: code-injection
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A05:2025
cwe:
  - CWE-94
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Code Injection

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Code Injection by root cause instead of just describing the consequences. 
- Identify trust boundary, asset, actor, and the necessary conditions for the vulnerability to be exploited. 
- Perform controlled testing in a local lab and distinguish expected results from false positives.
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Can read expressions, callables, and namespaces in Python 3.12, JavaScript, or PHP.  
- Can distinguish a syntax parser from a code execution evaluator and recognize data crossing the trust boundary.  
- Understands the basic nodes of Python AST and how to write tests for an allowlist arithmetic grammar.  
- Has a calculator fixture on loopback, does not mount secrets, and has outbound network disabled.

## 3. Background Knowledge

Dynamic evaluations like Python, JavaScript, and string parsing code of the corresponding language are assessed by API, `eval()`, `eval()`, and PHP. If the string is affected by untrusted input, that code runs with the permissions and scope provided by the runtime for the call. This is code injection; command injection is another case, where input modifies the commands passed to the operating system or shell. [S1] [S2] [S3]

```python
# Simple calculator — legitimate use of eval (still risky)
expression = "2 + 3 * 4"
result = eval(expression)  # Returns 14
print(f"Result: {result}")
```

## 4. Description and Root Cause

The root cause is that untrusted data crosses the trust boundary and is interpreted by the runtime as code instead of data. The impact depends on the objects, modules, files, network, and operating system privileges that the process actually has; it cannot be inferred as RCE or read secrets just from evaluating a numeric expression. [S2] [S3]

## 5. Threat Model and Exploitation Conditions

- **Assets:** runtime processes, secrets, and application data that the process can access.

- **Actor:** public users or role users sending expressions; they do not have operating system accounts.

- **Exploitation conditions:** untrusted expressions go into the evaluator and are interpreted as code. [S1] [S5] [S6]

- **Runtime:** fixture pin Python 3.12, Node.js 20 and PHP 8.3 on loopback; lesson does not generalize results across evaluators.

- **Evidence:** saving input, the sink was called, and the marker returned; the calculation `2+2` does not prove code injection.

## 6. Attack Mechanism

For code injection, untrusted expressions entering `eval()` or equivalent API are interpreted as code. A positive case must prove that the input reaches the correct sink and creates a marker that does not belong to the arithmetic grammar; a negative case must be rejected by the parser allowlist. The conclusion only applies to runtimes pinned in section 5. [S1] [S5] [S6]

## 7. Testing in an Authorized Lab

1. **Setup:** launch Python 3.12/Flask 3.x and Node.js 20/Express 4.x fixtures on loopback; no browser needed; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input for the code injection use case; record raw request/response, determine policy and asset status before the test.
3. **Input and operation:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and adhere to the request cap.
4. **Expected result:** consider a fixture vulnerable as positive only when logs demonstrate the mechanism of “untrusted expressions going into eval/Function and interpreted as code”; secure fixtures must block before side effects, and boundary inputs must fail closed.
5. **Cleanup:** delete data, markers, and code injection logs; revoke related sessions/cache, revert snapshots, and confirm no remaining test callbacks/processes.
6. **Safety limits:** run only on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks do not yet have runtime evidence; they only run in the context that has been annotated.

**Python eval() exploitation**:

<!-- claim-source: [S1] -->
<!-- payload-id: WEB-A05-CODE-INJECTION-001 -->
<!-- context: Python 3.12 expression passed to eval() in an isolated calculator fixture -->
<!-- prerequisites: loopback-only fixture; no filesystem or network access required -->
<!-- encoding: query component is percent-encoded once as UTF-8; Python source uses literal ASCII quotes and underscores -->
<!-- expected-result: response contains CODE_INJECTION_LAB, proving non-arithmetic code evaluation -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S5 -->
<!-- last-verified: 2026-07-17 -->
```python
# Vulnerable calculator endpoint
user_input = request.args.get('expr')
result = eval(user_input)

# Harmless lab input that invokes a non-arithmetic callable:
# expr=__import__('builtins').str('CODE_INJECTION_LAB')
```

**JavaScript eval() exploitation**:

<!-- claim-source: [S5] -->
<!-- payload-id: WEB-A05-CODE-INJECTION-002 -->
<!-- context: Node.js 20.x Express calculator fixture using direct eval() -->
<!-- prerequisites: loopback-only fixture; no filesystem or network access required -->
<!-- encoding: URLSearchParams percent-encodes String('CODE_INJECTION_LAB') once in UTF-8 -->
<!-- expected-result: response contains CODE_INJECTION_LAB instead of an arithmetic result -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S6 -->
<!-- last-verified: 2026-07-17 -->
```javascript
// Vulnerable template processing
app.get('/calc', (req, res) => {
    let expr = req.query.expr;
    let result = eval(expr);  // DANGER: Direct eval of user input
    res.send(`Result: ${result}`);
});

// Harmless lab input that is valid JavaScript but not arithmetic:
// /calc?expr=String('CODE_INJECTION_LAB')
```

**PHP eval() exploitation**:

<!-- claim-source: [S6] -->
<!-- payload-id: WEB-A05-CODE-INJECTION-003 -->
<!-- context: PHP 8.3 calculator fixture using eval() -->
<!-- prerequisites: loopback-only fixture; no filesystem or network access required -->
<!-- encoding: code query value is UTF-8 and percent-encoded once, including parentheses and quotes -->
<!-- expected-result: response prints CODE_INJECTION_LAB, proving arbitrary PHP statements are evaluated -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1 -->
<!-- last-verified: 2026-07-17 -->
```php
<?php
// Vulnerable dynamic code execution
$code = $_GET['code'];
eval($code);  // DANGER: Arbitrary PHP execution

// Harmless lab input:
// ?code=print('CODE_INJECTION_LAB');
?>
```

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
from flask import Flask, request

app = Flask(__name__)

@app.route('/calculate')
def calculate():
    expression = request.args.get('expr', '0')
    # DANGER: eval() executes arbitrary Python code
    result = eval(expression)
    return f"Result: {result}"


# === SECURE CODE ===
import ast
import operator
from flask import Flask, request

app = Flask(__name__)

# Whitelist of safe operations
SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def safe_eval(expr):
    """Evaluate arithmetic expressions using AST parsing"""
    tree = ast.parse(expr, mode='eval')

    def _eval(node):
        # Only allow numbers
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        # Only allow whitelisted binary operations
        elif isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPS:
            left = _eval(node.left)
            right = _eval(node.right)
            return SAFE_OPS[type(node.op)](left, right)
        # Only allow top-level Expression wrapper
        elif isinstance(node, ast.Expression):
            return _eval(node.body)
        else:
            raise ValueError(f"Unsupported operation: {type(node).__name__}")

    return _eval(tree)

@app.route('/calculate')
def calculate():
    expression = request.args.get('expr', '0')
    try:
        # Safe AST-based evaluation — no arbitrary code execution
        result = safe_eval(expression)
        return f"Result: {result}"
    except (ValueError, SyntaxError) as e:
        return f"Invalid expression", 400
```

## 10. Detection

- Find `eval`, `exec`, `Function`, and API dynamically compiled; trace data from request, queue, or datastore.

- Record the type AST as accepted or rejected, but do not record the full expression that may contain sensitive data.

- Warning when the calculator receives an identifier, attribute, call, or node other than allowed numbers and operators.

- The marker must show that the evaluator called code outside the arithmetic grammar; the HTTP 500 error is not enough to conclude.

## 11. Defense

### Compulsory control

- Eliminate dynamic execution; use a parser or AST allowlist that only supports the necessary arithmetic grammar.

- Reject all nodes outside the allowlist, including call, attribute, subscript, name, and comprehension. [S2] [S3]

### Defense-in-depth

- Run the calculator without privileges, without mounting secrets, and without allowing outbound network to reduce impact if the parser fails. [S3]

- Set limits on length, depth AST, CPU, and time so that a valid expression does not consume excessive resources.

- If the operation truly needs to run code provided by the user, use isolated boundaries designed for hostile code and still treat that as a risk surface; a single container does not replace the elimination of dangerous sinks. [S3]

## 12. Retest

- **Positive case:** `2 + 3 * 4` still returns `14` through the parser allowlist used in the fix.  
- **Negative case:** `__import__('builtins').str('CODE_INJECTION_LAB')` is rejected before any callable is invoked.  
- **Boundary case:** test negative numbers, division by 0, empty expressions, very large numbers, deeply nested AST and nodes `Name`/`Attribute`/`Call`.  
- **Telemetry:** logs indicate the rejected node and corresponding route; no file, process, or network side effects in the fixture.  
- **Regression:** run together with the direct test suite using `safe_eval()` and via the endpoint to prevent cases where another route still calls `eval()`.

## 13. Common Mistakes

- Use regex to 'filter dangerous characters' and then still pass the remaining string into the evaluator.

- Allow all `ast.Name` or `ast.Attribute` because it was thought that parsing AST was equivalent to being safe.

- Delete `eval()` at the main endpoint but overlook the worker, rule engine, or template helper using the same data.

- Conclude RCE only because the numeric expression is calculated correctly; the test must go beyond business grammar with a harmless marker.

- Reducing privileges or running in a container is a fix for interpreting untrusted input like code.

## 14. Summary and Checklist

- [ ] Accurately identified which input reaches `eval` or an equivalent evaluator.  
- [ ] Probe only calls harmless callables and does not access files, processes, or the network.  
- [ ] Parser fixes errors only allowing numeric literals and the listed business operators.  
- [ ] Tests reject `Name`, `Attribute`, `Call`, `Subscript`, and AST that exceed limits.  
- [ ] Valid calculator still gives correct results after removing dynamic evaluation.  
- [ ] Runtime, source, and static state of each payload are correctly recorded.

## 15. Glossary

- **Code Injection**: A vulnerability that allows an attacker to insert and execute malicious code within the context of the programming language. 
- **Dynamic Code Evaluation**: The ability to execute strings of characters as source code at runtime. 
- **RCE (Remote Code Execution)**: The ability to execute code remotely; this may be an effect of code injection but is not automatically demonstrated by every expression evaluation sink. 
- **Runtime Environment**: The execution environment of the application at runtime. 
- **AST (Abstract Syntax Tree)**: A tree structure representing syntax; only safe when the application rejects all nodes and operators outside the permitted business grammar. [S3]

## 16. Related Lessons and Further Reading

- [Command Execution](../command-execution/) — Directly execute commands on the target server's operating system.
- [Insecure Deserialization](../../08-data-integrity-failures/insecure-deserialization/) — Unsafe deserialization can lead to the instantiation of malicious objects causing code injection or remote code execution.

## 17. References

- **[S1]** Python 3.12 Documentation — Built-in `eval`. https://docs.python.org/3.12/library/functions.html#eval — version/status: Python 3.12; accessed: 2026-07-18.
- **[S2]** OWASP. https://owasp.org/www-community/attacks/Code_Injection — version/status: current version; accessed: 2026-07-17.
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/94.html — version/status: current version; accessed: 2026-07-17.
- **[S5]** MDN — JavaScript `eval()`. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval — version/status: current version; accessed: 2026-07-18.
- **[S6]** PHP Manual — `eval`. https://www.php.net/manual/en/function.eval.php — version/status: PHP 8.x; accessed: 2026-07-18.