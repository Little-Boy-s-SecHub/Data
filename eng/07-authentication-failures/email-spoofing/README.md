---
schema_version: 1
id: WEB-A07-EMAIL-SPOOFING
title: "Email Spoofing"
slug: email-spoofing
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - A08:2025
cwe:
  - CWE-345
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Email Spoofing

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Email Spoofing by root cause instead of just describing the consequences. 
- Identify trust boundaries, assets, actors, and necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Select the root control, implement the fix, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- Grasp the HTTP request/response flow in the Email Spoofing scenario and how to apply input handling across trust boundaries. 
- Distinguish authentication, authorization, and validation. 
- Be able to read code/configuration in the language or framework appearing in the example. 
- Have a local isolated lab, synthetic data, observable logs, and clear testing rights.

## 3. Background Knowledge

Imagine a traditional mailbox in front of your house. Someone could write a handwritten letter, label the sender as "Tax Office" or "Your Bank," and then put it into the mailbox. Since no postal worker goes to verify who actually wrote the letter, you are very likely to trust it and follow the instructions in the letter. This flaw is similar to how the basic email sending protocol on the Internet works, called **SMTP (Simple Mail Transfer Protocol)**.

SMTP basically separates the identity in the envelope (`MAIL FROM`) from the `From:` field displayed in the message content; the display field itself does not prove that the sender owns that domain. Modern mail systems may require authentication when relaying and apply SPF, DKIM, DMARC along with other filters, so the likelihood of spam being accepted depends on the sending/receiving server's policy. [S3]

To patch this serious vulnerability, three "security checkpoints" were added to the DNS system of the domain (SPF, DKIM, and DMARC):
1. **SPF (Sender authentication)**: Acts like a registry of authorized mail servers. When receiving mail from `nganhang.com`, the receiving server checks DNS to see if the IP address of the sending server is included in the SPF list permitted by the bank.
2. **DKIM (Internal authentication signature)**: Functions like sealing a letter with wax for security. The sending mail server uses a secret cryptographic key to digitally sign the email. The receiving server obtains the public key from DNS of the sender's domain to verify. If the seal is broken or doesn’t match, the email is considered forged or tampered with during transmission.
3. **DMARC (policy and alignment)**: DMARC matches the domain in the `From:` field with the identifier authenticated by SPF or DKIM. Mail passes DMARC if at least one mechanism passes the check **and** is aligned; if not, the receiver considers policies `none`, `quarantine`, or `reject` published by the domain. The receiver still retains the right to apply local policies. [S3]

```dns
; DNS TXT Records for SPF, DKIM, and DMARC configurations

; 1. SPF Record: Only allow Google Workspace and the server IP 198.51.100.1 to send mail, hard-fail all others
victim.lab.test.             IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.mail-provider.lab.test -all"

; 2. DKIM Record: Publishes the RSA public key for verification of signing signature under selector 'default'
default._domainkey.victim.lab.test. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y..."

; 3. DMARC Record: Request reject policy when neither SPF nor DKIM produces an aligned pass
_dmarc.victim.lab.test.      IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@victim.lab.test"
```

## 4. Description and Root Cause

Email spoofing occurs when the recipient or the mail receiving infrastructure trusts the displayed identity without sufficient authentication and alignment, or when the SPF/DKIM/DMARC policy is missing or incorrectly implemented. This is not a statement that every SMTP server allows unauthenticated relay. [S3]

The danger of this vulnerability is extremely high, serving as a powerful weapon for phishing attacks. Hackers can impersonate bank emails notifying that an account has been locked, or pretend to be a partner requesting contract payment to a different account. Since the email header appears exactly like the real address, users are very easily tricked into clicking on malicious links, entering login information, or transferring money directly to the hackers without any suspicion.

> **Reference source:** technical claims in the lesson are tagged with source markers; when applying in practice, compare with the version/framework being used: [S1], [S2], [S3].

## 5. Threat Model and Exploitation Conditions

- **Assets:** reliability of visible From and results SPF/DKIM/DMARC.  
- **Actor, authentication, and role:** SMTP sender outside does not own victim.lab.test; has no application role.  
- **Exploitation conditions:** receiver/display of visible From when authentication/alignment is missing or fail-open.  
- **Browser, proxy, framework, and version:** SMTP/DNS local resolver pinned to domain/IP specific; does not send to Internet; must store actual image/package version along with evidence.  
- **Mandatory evidence:** together with correlation ID must link input, control decisions, and impact on the correct asset; individual status codes are insufficient. [S1]

## 6. Attack Mechanism

For email spoofing, the receiver/display shows the visible From when authentication/alignment is missing or fail-open. The positive case must prove that the input reaches the correct sink and creates the described impact; the negative case, when native control is enabled, must be blocked before any side effect. The conclusion only applies to the environment pinned in section 5. [S1]

## 7. Testing in an Authorized Lab

1. **Setup:** launch the SMTP/DNS local resolver pinned to the domain/IP dedicated; do not send to the Internet; only load synthetic data, enable application/proxy/datastore logs, and attach ID correlation.  
2. **Baseline:** send a valid input for the email spoofing use case; save raw request/response, decide on policy and asset state before the test.  
3. **Input and actions:** use exactly one core payload from item 8 in the annotated context; change one variable at a time and comply with the request cap.  
4. **Expected result:** consider a vulnerable fixture positive only when logs demonstrate the “receiver/display visible From when authentication/alignment is missing or fail-open” mechanism; the secure fixture must block before side effects and boundary input must fail closed.  
5. **Cleanup:** delete email spoofing data, markers, and logs; revoke related session/cache, revert snapshot, and confirm there are no remaining callback/test processes.  
6. **Safety limits:** run only on loopback/`.lab.test`; do not use target, credentials, or real data; OOB/DoS/state-changing must have network/CPU/memory/request caps.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

The attacker forges the 'From' email address to look like a legitimate service provider and sends a password change alert. This link directs the victim to a credential-collecting page that looks very realistic. When the victim enters their old password, the website records that password and redirects them to the real website to avoid suspicion.

### Example of raw SMTP session spoofing the sender's address:<!-- payload-id: WEB-A07-EMAIL-SPOOFING-001 -->
<!-- context: SMTP test server that accepts mail only inside an isolated lab -->
<!-- prerequisites: local sink mailbox; no Internet relay; SPF/DKIM/DMARC result headers observable -->
<!-- encoding: SMTP commands are ASCII with CRLF line endings; DATA headers/body end with CRLF dot CRLF -->
<!-- expected-result: sink mailbox preserves distinct envelope-from and RFC5322.From values for policy inspection -->
<!-- risk: state-changing -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S3 -->
<!-- last-verified: 2026-07-17 -->
```smtp
# Connect only to the isolated SMTP fixture.
EHLO callback.lab.test
MAIL FROM: <sender@callback.lab.test>
RCPT TO: <learner@victim.lab.test>
DATA

From: Lab Executive <executive@victim.lab.test>
To: learner@victim.lab.test
Subject: SMTP identity-alignment lab
Reply-To: sender@callback.lab.test

This message contains no link, credential request, or financial instruction.
.
# The sink must show the header From separately from the envelope sender.
```

## 9. Vulnerable Code and Secure Code

Two configurations DNS are applied to the same lab domain. SPF allows any sender without creating an authorization boundary; in the safe configuration, SPF limits the sender and DMARC requires rejection when both SPF and DKIM do not create an aligned pass. DMARC should only be switched to enforcement after the valid mail flow inventory has been confirmed. [S3] [S4]

### Not safe (vulnerable): SPF allows all senders, DMARC has no enforcement

```configuration
victim.lab.test. IN TXT "v=spf1 +all"
_dmarc.victim.lab.test. IN TXT "v=DMARC1; p=none; pct=100"
```
### Secure: only authorize senders who have inventory and have enabled DMARC enforcement

```configuration
# Authorize only reviewed senders and fail all other SPF evaluations
victim.lab.test. IN TXT "v=spf1 ip4:198.51.100.1 include:_spf.mail-provider.lab.test -all"

# Reject messages when neither SPF nor DKIM produces an aligned pass
_dmarc.victim.lab.test. IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@victim.lab.test"
```

## 10. Detection

- Log the actor/session, route or operation, object/resource related to Email Spoofing, policy results, and correlation ID; do not log secrets or entire tokens. 
- Compare authorization/validation failures with a valid baseline and alert according to behavior chains, not just a single payload. 
- Combine application telemetry, reverse proxy, and datastore to confirm whether the request reached the sink and whether it had any impact. 
- Scanner or WAF alerts are only investigation signals; they are not the sole proof that a vulnerability exists. [S1]

## 11. Defense

### Compulsory control

- Deploy SPF, aligned DKIM, and DMARC enforcement; protect the signing key. 
- Apply the same controls to all routes, operations, and equivalent processing paths; failures must stop before side effects.

### Defense-in-depth

With Email Spoofing, the following measures help reduce the blast radius or increase detection capability. Rate limit, UUID unpredictable, WAF, CSP, or general validation should not be used as a substitute for original controls.

- **Summary**: Deploy DNS, SPF, DKIM, and DMARC records to authenticate legitimate senders and verify email integrity. 
- **Detailed steps**:
  - Create DNS Sender Policy Framework (SPF) records to accurately specify which mail servers are allowed to send emails for your domain.
  - Deploy DomainKeys Identified Mail (DKIM) to sign outgoing mail headers with a cryptographic private key, verifying the integrity of the mail.
  - Publish DMARC and check alignment with the `From:` field. DMARC is successful when SPF or DKIM result in a pass and are aligned; policies `quarantine`/`reject` apply when DMARC fails, depending on the receiver's decision. [S3]
  - Enable DMARC reporting features to monitor who is sending emails using your domain identity.
  - Integrate inbound mail filters to block emails failing sender checks and train staff to recognize social engineering techniques.

## 12. Retest

- **Positive case:** with Email Spoofing, the valid flow still works correctly for authorized actors and data.  
- **Negative case:** with the same input/resources but unauthorized actor or context, it should be denied without leaking sensitive details.  
- **Boundary case:** check empty values, edge cases, different encodings, repeated requests, expired session states, and equivalent paths/operations.  
- **Telemetry:** confirm policy decisions, application logs, proxy logs, and datastore side effects match correlation ID.  
- **Re-test:** save minimal scripts to reproduce old bugs and demonstrate fixes without depending on WAF/rate limit.

## 13. Common Mistakes

- Only check the status code or response string of Email Spoofing without verifying side effects and logs. 
- Use a correctly formatted payload but with the wrong DBMS, browser, framework, protocol, or injection context. 
- Consider UUID, rate limit, WAF, CSP, or general input validation as a fix for a different root control. 
- Only fix one route while the same sink/policy is used on another route. 
- Conclude that a vulnerability exists without recording the source, fixture version, and observable evidence.

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

- **SMTP (Simple Mail Transfer Protocol)**: The standard network protocol used to send and transmit email between servers on the Internet.
- **SPF (Sender Policy Framework)**: The DNS record helps authenticate email by specifying a list of IP addresses of servers authorized to send email on behalf of a specific domain.
- **DKIM (DomainKeys Identified Mail)**: An email authentication method by attaching a cryptographic digital signature to the email, helping receiving servers verify that the email is actually sent from that domain and that the content has not been altered.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: A security policy combining two mechanisms, SPF and DKIM, guiding receiving servers on how to handle fake emails (accept, quarantine, or reject) and send reports to the domain owner.
- **Phishing (Deceptive Attack)**: A network scam technique using email or fake websites to trick users into revealing sensitive information such as passwords or credit card information.
- **DNS Record (DNS Record)**: Configuration lines stored in the domain system, containing information such as the IP address of the domain (A record), mail server configuration (MX record), or authentication configurations (TXT record).

## 16. Related Lessons and Further Reading

- [Related lessons in the same folder ](../)

## 17. References

- **[S1]** OWASP Top 10:2025. https://owasp.org/Top10/2025/ — version/status: current version; accessed: 2026-07-18. 
- **[S2]** CWE-345. https://cwe.mitre.org/data/definitions/345.html — version/status: current version; accessed: 2026-07-18. 
- **[S3]** RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC). https://www.rfc-editor.org/rfc/rfc7489.html — version/status: RFC 7489; accessed: 2026-07-18. 
- **[S4]** RFC 7208 — Sender Policy Framework (SPF) for Authorizing Use of Domains in Email. https://www.rfc-editor.org/rfc/rfc7208.html — version/status: RFC 7208; accessed: 2026-07-18.