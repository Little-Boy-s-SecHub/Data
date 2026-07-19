---
schema_version: 1
id: WEB-A11-BROKEN-AUTHENTICATION
title: "API Broken Authentication"
slug: broken-authentication
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
  - authentication-vs-authorization
owasp:
  - API2:2023
cwe:
  - CWE-287
  - CWE-306
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# API Broken Authentication

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

- Identify authentication errors in API token, session, API key, and OAuth flow.
- Distinguish authentication failure from authorization failure.
- Retest using expired token, token with wrong audience, revoked token, and requests without a token.

## 2. Prerequisites

- Bearer token, API key, session cookie, and basic OAuth/OIDC. 
- JWT claims such as `iss`, `aud`, `exp`, `sub`.
- Rate limiting and lockout on the login endpoint.

## 3. Background Knowledge

Authentication identifies who the actor is. API Broken Authentication occurs when the server accepts weak credentials, contextually incorrect tokens, expired tokens, API exposed keys, or login flows are not properly restricted. [S1]

## 4. Description and Root Cause

The root cause is often token authentication lacking issuer/audience/expiry checks, API key not being rotated, sensitive endpoint allowing anonymous access, or refresh token logic not binding to client/session. [S1]

## 5. Threat Model and Exploitation Conditions

- **Assets:** identity, access token, refresh token, API key, and session.
- **Actor:** client not logged in, regular user, expired token, or token from a different environment.
- **Trust boundary:** credentials from the request entering the authentication middleware.
- **Necessary condition:** middleware accepts invalid credentials or skips authentication for sensitive routes.
- **Environment:** local fixture with issuer, audience, and synthetic token.

## 6. Attack Mechanism

Actor tries a request without a token, an expired token, a token with the wrong audience, or API key revoked. Evidence is needed to prove the request is processed as a valid actor, not just an unusual error message.

## 7. Testing in an Authorized Lab

1. Seed a valid token and three invalid tokens: expired, wrong audience, revoked.
2. Call the sensitive endpoint with each token.
3. Record middleware decision, route handler log, and status.
4. Expect fix to only allow the valid token to reach the handler.
5. Cleanup token/key fixture and log.

## 8. Payloads and Scope of Applicability

**Token sai audience**

<!-- payload-id: WEB-A11-BROKEN-AUTHENTICATION-001 -->
<!-- context: HTTP/1.1 GET against local API fixture at 127.0.0.1:18080; case: WEB-A11-BROKEN-AUTHENTICATION-001 -->
<!-- prerequisites: token is synthetic, signed by lab issuer, but aud is api-staging instead of api-prod -->
<!-- encoding: ASCII request headers; token placeholder is not a real secret -->
<!-- expected-result: vulnerable fixture accepts the wrong-audience token; fixed fixture rejects it before route handling -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S1,S2,S3 -->
<!-- last-verified: 2026-07-18 -->
```http
GET /api/me HTTP/1.1
Host: api.victim.lab.test
Authorization: Bearer TOKEN_WITH_WRONG_AUDIENCE
Accept: application/json
```

## 9. Vulnerable Code and Secure Code

```python
# VULNERABLE: verifies signature but not audience or revocation.
claims = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_aud": False})

# SECURE: pins issuer, audience, expiry and revocation state.
claims = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],
    issuer="https://issuer.lab.test",
    audience="api-prod",
)
if is_revoked(claims["jti"]):
    raise Unauthorized()
```

## 10. Detection

- Log credential type, token issuer/audience, expiry class, and auth decision.
- Do not log raw token or API key.
- Warning of wrong token audience/issuer is accepted.

## 11. Defense

### Compulsory control

- Verify issuer, audience, expiry, signature, and revocation.
- Do not allow sensitive routes to bypass authentication middleware.
- Rotate API key and bind the key with scope/client.

### Defense-in-depth

- Rate limit login/refresh token.
- Use short-lived access token and refresh token rotation.
- Warn about unusual credential reuse.

## 12. Retest

- **Positive:** valid token can access endpoint with the correct scope.
- **Negative:** missing/expired/wrong-audience/revoked token is rejected.
- **Boundary:** clock skew, key rotation, multi-issuer.
- **Telemetry:** middleware decision matches response.

## 13. Common Mistakes

- Decode JWT without fully verifying the claim. 
- Use a single API long-term key for multiple clients. 
- Only protect UI while ignoring mobile/internal endpoints.

## 14. Summary and Checklist

- [ ] All sensitive routes go through the authentication middleware.
- [ ] Token validation checks issuer, audience, expiry, and algorithm.
- [ ] Refresh/API key has rotation and revocation.
- [ ] Negative tests do not touch the route handler.

## 15. Glossary

- **Authentication:** verify who the actor is.
- **Audience:** API expected to receive the token.
- **Revocation:** revoke the credential before its natural expiration.

## 16. Related Lessons and Further Reading

- [JWT Attacks](../../07-authentication-failures/jwt-attacks/)
- [OAuth Vulnerabilities](../../07-authentication-failures/oauth-vulnerabilities/)
- [API Rate Limiting](../api-rate-limiting/)

## 17. References

- **[S1]** OWASP API Security Top 10 2023 — API2 Broken Authentication. https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ — current version; accessed: 2026-07-18.
- **[S2]** CWE-287 — Improper Authentication. https://cwe.mitre.org/data/definitions/287.html — current version; accessed: 2026-07-18.
- **[S3]** CWE-306 — Missing Authentication for Critical Function. https://cwe.mitre.org/data/definitions/306.html — current version; accessed: 2026-07-18.