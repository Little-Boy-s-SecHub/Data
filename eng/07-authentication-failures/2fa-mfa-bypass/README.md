---
schema_version: 1
id: WEB-A07-2FA-MFA-BYPASS
title: "2FA/MFA Bypass"
slug: 2fa-mfa-bypass
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A07:2025
cwe:
  - CWE-308
  - CWE-287
content_status: technical-review
payload_status: none
last_verified: null
---

# 2FA/MFA Bypass

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain 2FA/MFA Bypass using the root cause instead of just describing the consequence.
- Identify the trust boundary, asset, actor, and necessary conditions for the vulnerability to be exploited.
- Conduct controlled testing in a local lab and distinguish the expected result from false positives.
- Choose the original control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow of the 2FA/MFA Bypass scenario and how to apply input handling across trust boundaries. 
- Differentiate authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing permissions.

## 3. Background Knowledge

Imagine protecting your account like going through a high-security door. Instead of just using a regular lock (password) that can be peeked at by malicious actors, you install an additional two-factor (2FA) or multi-factor authentication system (MFA). This security door requires you to provide three different sets of evidence to prove your identity:  
1. **Something you know**: Password, personal PIN code.  
2. **Something you have**: Phone receiving messages, physical security key (YubiKey), OTP code-generating app.  
3. **Something you are**: Fingerprint, retina scan, or facial recognition.

The most common 2FA process nowadays is to use a one-time code OTP sent via SMS/Email or automatically generated every 30 seconds by an Authenticator app (called **TOTP**). Although in theory, this second layer of protection is extremely robust, in reality, if the system designer is careless, attackers can still easily find a way around to completely bypass this verification step.

Typical 2FA process:

```python
# Normal 2FA verification flow
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # Step 1: Password correct — generate and send OTP
        otp = generate_otp(length=6)
        store_otp(user.id, otp, ttl=300)  # Valid for 5 minutes
        send_sms(user.phone, f"Your code: {otp}")

        # Store partial session (NOT fully authenticated yet)
        session['pending_2fa_user'] = user.id
        session['2fa_verified'] = False
        return redirect('/verify-2fa')

    return "Invalid credentials", 401

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    user_id = session.get('pending_2fa_user')
    submitted_otp = request.form['otp']

    if verify_otp(user_id, submitted_otp):
        session['2fa_verified'] = True
        session['authenticated_user'] = user_id
        return redirect('/dashboard')

    return "Invalid OTP", 401
```
In theory, 2FA significantly increases security, but in practice, many implementations have flaws that allow attackers to completely bypass the second authentication step.

## 4. Description and Root Cause

The Two-Factor Authentication (2FA/MFA Bypass) bypass vulnerability occurs when the application does not strictly enforce the second-layer authentication check across the entire system.

The danger of this vulnerability lies in the fact that, after obtaining the victim's password, an attacker can easily bypass the OTP code entry step in multiple ways: directly accessing internal application links without going through the code entry page, modifying the server response from "wrong OTP" to "correct OTP" on the browser, repeatedly trying thousands of OTP codes until success due to the system lacking rate limiting, or tricking users through real-time phishing websites to steal already authenticated session cookies.

> **Reference:** Technical claims in the lesson are marked with source markers; when applying in practice, refer to the version/framework being used: [S1], [S2], [S3], [S4], [S5].

## 5. Threat Model and Exploitation Conditions

- **Assets:** MFA challenge state and session assurance.  
- **Actor, authentication, and role:** actor has password fixture but has not completed MFA; target role is user.  
- **Exploitation conditions:** server provides session/protected route after one factor or without binding challenge.  
- **Browser, proxy, framework, and version:** auth fixture Flask/Express, TOTP library, and pinned Chromium/proxy; must record actual image/package version along with evidence.  
- **Mandatory evidence:** together with ID correlation, must link input, control decision, and impact the correct asset; individual status code is not sufficient. [S1]

## 6. Attack Mechanism

For 2fa mfa bypass, the server grants session/protected route after one factor or does not bind the challenge. The positive case must demonstrate the input reaching the correct sink and creating the described impact; the negative case when root control is enabled must be blocked before the side effect. The conclusion only applies to the environment pinned in item 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** start the Flask/Express auth fixture, TOTP library, and pinned Chromium/proxy; only load synthetic data, enable application/proxy/datastore logs, and attach correlation ID.
2. **Baseline:** send a valid input of the 2fa mfa bypass use case; record raw request/response, decide policy and asset state before the test.
3. **Input and actions:** use exactly one scenario/input variable described in section 8; change one variable at a time and comply with the request cap.
4. **Expected result:** consider a fixture vulnerable as positive only when logs show the mechanism of the “server issuing session/protected route after one factor or without binding challenge”; secure fixture must block before side effect, and boundary input must fail closed.
5. **Cleanup:** delete data, marker, and logs of 2fa mfa bypass; revoke related session/cache, revert snapshot, and confirm no remaining test callback/process.
6. **Safety limits:** only run on loopback/`.lab.test`; do not use real targets, credentials, or data; OOB/DoS/state-changing must have network/CPU/memory/request cap.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**1. Direct Endpoint Access — bypassing the OTP input page:**
If the server only checks whether the user has entered the correct password without checking the `2fa_verified` flag, the attacker only needs to log in with the password and directly access `/dashboard` via proxy/HTTP client.

**2. Response Manipulation — modifying responses in the proxy:**
The attacker enters OTP incorrectly, the server returns `401 Unauthorized` or `{"success": false}`. The attacker intercepts the response using Burp Suite and modifies it to `200 OK` or `{"success": true}` to trick the client-side into redirecting.

**3. OTP Brute Force — trying all combinations:**
The OTP 6-digit code has 1,000,000 values. If the verifier does not limit the total number of attempts per challenge/account/device and the challenge does not expire, the probability of guessing correctly increases with the number of attempts; the time required depends on actual throughput, so it cannot be generally stated as 'a few minutes'.

**4. Backup Code Abuse:**
The attacker guesses or brute-forces static recovery codes (backup codes) generated when setting up 2FA, especially if these codes are not rate-limited or are not invalidated after use.

**5. SIM Swapping & SS7 Interception:**
- **SIM Swapping**: The attacker uses social engineering techniques targeting mobile network employees to convince them to transfer the victim's phone number to a new SIM SIM under the attacker's control, thereby receiving all SMS messages containing the OTP code.
- **SS7 Interception**: Exploiting design vulnerabilities in the SS7 signaling network of telecom operators to eavesdrop and reroute SMS messages containing the OTP code across the transmission path without physical interaction.

**6. Real-time Phishing (Evilginx Proxy Flow):**  
The attacker sets up an intermediate reverse proxy server (such as Evilginx). The victim accesses a phishing link that looks legitimate, enters their password and the code OTP. The proxy forwards this information in real-time to the original server and receives back the victim's fully authenticated Session Cookie, allowing the attacker to bypass 2FA using the stolen session.

**7. TOTP Time Window Abuse:**
- **Time window skew**: The server accepts OTP codes generated from the very distant past or future (e.g., ±10 minutes instead of the default ±30 seconds) to avoid device time drift errors. An attacker can reuse an OTP code that has just expired.
- **No one-time enforcement**: The server accepts OTP codes multiple times within the same time period (30 seconds). An attacker can replay an OTP code that was captured before the 30-second period ends.

**8. Authentication Downgrade:**  
The attacker deliberately requests to downgrade the authentication method to the weakest type. For example, instead of using a high-security Hardware Key (FIDO2), the attacker requests a 2FA reset using a weak security question or sends OTP via email/SMS that has been compromised by exploiting old API or API specifically for mobile.

## 9. Vulnerable Code and Secure Code

```python
# === VULNERABLE CODE ===
import time
import pyotp

# 1. Vulnerable to TOTP Time Window Abuse & Replay Attack
def verify_totp_unsafe(user_totp_secret, submitted_code):
    totp = pyotp.TOTP(user_totp_secret)
    # DANGER: Validating with a huge time window of 5 minutes (valid_window=10 means +/- 10 intervals of 30s)
    # DANGER: Does not check if the code was already used within this window
    is_valid = totp.verify(submitted_code, valid_window=10)
    return is_valid

# 2. Vulnerable to Authentication Downgrade
@app.route('/api/mfa/challenge', methods=['POST'])
def mfa_challenge_unsafe():
    user = get_user(request.json['user_id'])
    # DANGER: Allows the client to request a weaker fallback channel (like SMS)
    # even if they have a hardware key (FIDO2) configured.
    requested_channel = request.json.get('fallback_channel', 'FIDO2')

    if requested_channel == 'SMS':
        send_sms_otp(user.phone)
        return {"status": "sms_sent"}
    return {"status": "awaiting_fido2"}
```

```python
# === SECURE CODE ===
import pyotp
from redis import Redis

redis_client = Redis(host='localhost', port=6379, db=0)

# 1. Secure TOTP Verification with Replay Prevention and Strict Window
def verify_totp_secure(user_id, user_totp_secret, submitted_code):
    totp = pyotp.TOTP(user_totp_secret)

    # SECURE: Only allow +/- 30 seconds drift (valid_window=1 means current and immediate adjacent)
    # verify_result returns the timestamp index if valid, else None
    verified_time = totp.verify(submitted_code, valid_window=1, for_time=time.time())

    if verified_time is None:
        return False

    # SECURE: Prevent replay attacks by checking if the code has already been used
    replay_key = f"totp_used:{user_id}:{submitted_code}"
    # Set expiration equal to double the window size (60s)
    if not redis_client.set(replay_key, "1", ex=60, nx=True):
        return False # Code was already used within the valid window

    return True

# 2. Prevent Authentication Downgrade
def initiate_mfa_secure(user):
    # SECURE: Enforce MFA based on user's strongest configured method
    if user.has_fido2_configured:
        return {"required_method": "FIDO2", "details": get_fido2_challenge(user)}
    elif user.has_totp_configured:
        return {"required_method": "TOTP"}
    else:
        # Fall back to SMS only if no stronger method is configured
        send_sms_otp(user.phone)
        return {"required_method": "SMS"}
```

## 10. Detection

- Log the actor/session, route or operation, and object/resource related to 2FA/MFA Bypass, the results of policy and correlation ID; do not log secrets or full tokens.  
- Compare authorization/validation failures with a valid baseline and alert based on behavior chains, not just a single payload chain.  
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether there was any impact.  
- Scanner or WAF alert is only an investigation signal; it is not the sole evidence that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Only raise assurance after factor two has been verified and the user, session, action, and expiry are bound. 
- Apply the same control to all routes, operations, and equivalent processing paths; failure must stop before side effects.

### Defense-in-depth

With 2FA/MFA Bypass, the measures below help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictability, WAF, CSP, or general validation should not be used to replace the original control.

- **Summary**: Two-factor authentication security by enforcing 2FA status checks on all API endpoints, limiting code entry attempts (rate limit), and defending against replay attacks. 
- **Detailed steps**:
  - **Server-side 2FA enforcement**: Check the `2fa_verified` flag on **all** protected endpoints, not just on the OTP page.
  - **Attempt limiting**: Limit the number of tries per challenge and account; invalidate old challenges, gradually increase wait times, and avoid hard account locks that could be exploited to cause DoS.
  - **One-Time Use Enforcement**: Store the history of OTP codes successfully used during the current cycle (e.g., using Redis cache) and reject if the code is submitted again.
  - **Tighten TOTP Time Window**: Only accept a maximum deviation of 1 cycle (± 30 seconds) and synchronize the NTP server.
  - **Secure Authentication Flow**: Do not allow downgrading authentication to a less secure method without strict verification.
  - **Phishing-resistant methods preferred**: WebAuthn/FIDO2 reduces real-time phishing risk; TOTP avoids relying on SMS but can still be phished. Removing SMS eliminates the specific risk of SIM swap/SS7 on that factor, but does not remove all account takeover paths.

## 12. Retest

- **Positive case:** with 2FA/MFA Bypass, the valid flow still works correctly for the actor and permitted data.  
- **Negative case:** with the same input/resource, if the actor or context is not allowed, it should be rejected without leaking sensitive details.  
- **Boundary case:** test empty values, edge extremes, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decision, application log, proxy log, and datastore side effects match correlation ID.  
- **Recheck:** save the minimal script that reproduces the old error and prove the fix does not depend on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of 2FA/MFA Bypass without verifying side effects and logs.  
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context.  
- Treat UUID, rate limit, WAF, CSP, or general input validation as fixed for another original control.  
- Only fix one route while the same sink/policy is used in another route.  
- Conclude that a vulnerability exists without saving the source, fixture version, and observed evidence.

## 14. Summary and Checklist

- [ ] Root cause, consequences, and exploitation techniques have been separated.  
- [ ] Actor, role/authentication, trust boundary, technology, and version are clear.  
- [ ] Payload has a unique ID, context, encoding, conditions, expected result, risk, validation, and source.  
- [ ] Code prone to errors/unsafe uses the same framework, version, and use case.  
- [ ] Mandatory controls cannot be replaced with defense-in-depth.  
- [ ] Positive, negative, boundary cases, and telemetry have been retested.  
- [ ] Sensitive technical claims have references in section 17, and all links are only in sections 16–17.  
- [ ] Cleanup completed; no secrets, real targets, Internet callbacks, or customer data remain.

## 15. Glossary

- **2FA / MFA (Two-Factor / Multi-Factor Authentication)**: An authentication mechanism that requires the user to provide two or more independent verification factors before granting account access.  
- **TOTP (Time-based One-Time Password)**: An algorithm that generates one-time passwords that change continuously over time (usually every 30 seconds), synchronized between the user's device and the server.  
- **Brute-Force (Exhaustive Attack)**: A technique for guessing passwords or OTP codes by automatically trying all possible character or number combinations until the correct one is found.  
- **SIM Swapping**: A type of fraud in which hackers convince telecom operators to transfer the victim's phone number to a new SIM SIM card under their control, in order to steal OTP codes sent via SMS.  
- **SS7 Interception**: A technique exploiting vulnerabilities in the SS7 telecommunications signaling network to intercept and read SMS messages containing OTP codes in transit.  
- **Reverse Proxy**: An intermediary server that receives requests from clients and forwards them to one or more backend servers, often used by hackers as a middleman to steal real-time session cookies.

## 16. Related Lessons and Further Reading

- [User Enumeration](../user-enumeration/README.md)

## 17. References

- **[S1]** PortSwigger. https://portswigger.net/web-security/authentication/multi-factor — version/status: current edition; access: 2026-07-18. 
- **[S2]** OWASP. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication — version/status: current edition; access: 2026-07-18. 
- **[S3]** CWE. https://cwe.mitre.org/data/definitions/308.html — version/status: current edition; access: 2026-07-18. 
- **[S4]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current edition; access: 2026-07-18. 
- **[S5]** CWE-287. https://cwe.mitre.org/data/definitions/287.html — version/status: current edition; access: 2026-07-18.