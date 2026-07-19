---
schema_version: 1
id: WEB-A02-SUBDOMAIN-TAKEOVER
title: "Subdomain Takeover"
slug: subdomain-takeover
level: intermediate
estimated_minutes: 50
prerequisites:
  - http-fundamentals
  - authorized-security-testing
owasp:
  - A01:2025
cwe:
  - CWE-284
content_status: technical-review
payload_status: static-verified
last_verified: null
---

# Subdomain Takeover

> [!CAUTION]
> Only practice on systems you own or are explicitly authorized. Use synthetic data, disposable fixtures, and limit resources; do not send payloads to the Internet or real targets.

## 1. Learning Objectives

After this lesson, you can:

- Explain Subdomain Takeover by root cause instead of just describing the consequences. 
- Identify trust boundaries, assets, actors, and the necessary conditions for the vulnerability to be exploited. 
- Conduct controlled testing in a local lab and distinguish expected results from false positives. 
- Choose root controls, deploy fixes, and retest using positive, negative, and boundary cases.

## 2. Prerequisites

- DNS CNAME/alias and the resource lifecycle at the provider.

- Difference between dangling DNS and NXDOMAIN.

- Inventory owners, zones, and provider bindings.

## 3. Background Knowledge

Imagine your company rents a booth at a large shopping mall to display products. To make it easier for customers to find their way, you put up a large sign at the intersection that reads: 'Company A Home Appliances Booth: Go straight to Lot 12 in the shopping mall.' Everything goes smoothly. After a while, your company decides to close this booth and return Lot 12 to the shopping mall. However, your staff forgets to remove the sign at the intersection. The sign still stands there, continuing to direct customers to Lot 12. [S5]

A bad person walked by, saw that Lot 12 was currently empty and the sign was still valid. He immediately went to meet the shopping center management, rented that exact Lot 12, decorated it exactly like your previous stall but inside sold counterfeit and fake goods to deceive the trusting customers following the sign. [S5]

In the online world, this vulnerability occurs with the **DNS (Domain Name System)**. Companies often create **CNAME (Canonical Name)** records to point their subdomains (e.g., `docs.company.lab.test`) to third-party cloud hosting services (such as AWS S3, GitHub Pages, Heroku, Azure). When the company stops using that cloud service (deletes the bucket, deletes the application) but forgets to delete the corresponding CNAME record in their DNS configuration, they create an 'orphaned' (dangling CNAME) record. [S5]

```bash
# Normal DNS configuration in the loopback fixture
$ dig @127.0.0.1 -p 5353 blog.company.lab.test CNAME +short
bound.provider.lab.test.

# DNS resolution chain:
# blog.company.lab.test → CNAME → bound.provider.lab.test → A → 127.0.0.1
# Browser requests the lab subdomain and receives content from the provider mock
```

```text
# Example synthetic DNS zone; no public provider names
; Subdomain CNAME records pointing to external services
blog.company.lab.test.     IN  CNAME  bound.provider.lab.test.
docs.company.lab.test.     IN  CNAME  unused.provider.lab.test.
status.company.lab.test.   IN  CNAME  status.provider.lab.test.
landing.company.lab.test.  IN  CNAME  landing.provider.lab.test.
```
Normal operating process: DNS CNAME points to the cloud service → cloud service receives the request → returns valid content. However, problems arise when the organization **stops using the cloud service** (deletes the S3 bucket, unprovisions the Heroku app) but **forgets to delete the CNAME record** in DNS. [S5]

## 4. Description and Root Cause

The **Subdomain Takeover** vulnerability requires two conditions: the organization’s DNS still points to a deprovisioned resource, and the provider still allows another actor to claim that binding. Dangling CNAME or a single 404 string are just signals; they are not proof of claimability. If the takeover is successful, the actor can control the content on the subdomain. Cookie leakage only occurs with cookies that have `Domain` covering the subdomain or other logic sending secrets to that host; host-only cookies are not automatically sent. CSP/CORS are only affected if the policy actually trusts an origin that has been taken over. [S5], [S6]


## 5. Threat Model and Exploitation Conditions

- **Assets:** DNS synthetic binding between docs.company.lab.test and mock provider.

- **Actor:** authorized reviewer; does not register/claim the actual provider's resources.

- **Trust boundary:** lifecycle DNS of the organization and ownership binding at the provider.

- **Necessary condition:** a dangling record and provider confirmation that another actor can claim the correct binding; fingerprint/404 is not enough.

- **Environment:** DNS 127.0.0.1:5353, provider mock 127.0.0.1:9080, no public resolver/Internet.

The lab results are only DANGLING_SIGNAL_ONLY; the conclusion of the takeover really requires evidence of claimability allowed by the provider/owner. [S5], [S6]

## 6. Attack Mechanism

DNS still resolves subdomain to bindings that have been abandoned by the provider. Takeover only occurs if the provider allows another actor to claim the correct binding; fingerprint response only supports investigation. [S5], [S6]

## 7. Testing in an Authorized Lab

1. **Setup:** load DNS and synthetic provider-state; block Internet; enable query/mock log.
2. **Baseline:** record bound returns BOUND_IN_FIXTURE.
3. **Action:** check unused record using local dig/curl or offline function, do not resolve public domain.
4. **Expected result:** tool returns DANGLING_SIGNAL_ONLY, does not return VULNERABLE and does not self-claim resources.
5. **Boundary:** check CNAME chain, missing records and unknown provider state.
6. **Cleanup:** delete zone/mock state and confirm network log only has loopback.

## 8. Payloads and Scope of Applicability

The blocks below are minimal lab examples according to the context recorded in the annotation. Before use, check the framework/version, encoding, expected result, and risk; only run in an authorized local fixture. Extended payload belongs to `security_cheatsheet.md`; lessons only retain the core examples.

**Check dangling CNAME in local fixture**

<!-- payload-id: WEB-A02-SUBDOMAIN-TAKEOVER-001 -->
<!-- context: dig 9.18 and curl; DNS fixture at 127.0.0.1:5353; HTTP fixture at 127.0.0.1:9080; dangling-DNS model [S5] -->
<!-- prerequisites: no public resolver, provider account, or Internet route is used -->
<!-- encoding: UTF-8 shell source with ASCII DNS names; dig/curl construct DNS and HTTP framing; no user-controlled byte sequence -->
<!-- expected-result: DNS returns unused.provider.lab.test and the mock provider reports UNBOUND; this proves only the lab fixture state -->
<!-- risk: non-destructive -->
<!-- runnable: false -->
<!-- validation: static-verified -->
<!-- sources: S5 -->
<!-- last-verified: 2026-07-17 -->
```bash
dig @127.0.0.1 -p 5353 docs.company.lab.test CNAME +short
curl --fail-with-body -H 'Host: unused.provider.lab.test' \
  http://127.0.0.1:9080/status
```

## 9. Vulnerable Code and Secure Code

For example, using Python 3.12 and the same offline inventory fixture DNS; it does not resolve DNS or send HTTP. The fingerprint is only an investigative signal, while the claimable status must be confirmed with evidence authorized by the provider. [S5]

### Not safe (vulnerable): consider fingerprint as evidence of takeover

```python
FIXTURE_RECORDS = {
    "docs.company.lab.test": "unused.provider.lab.test",
    "status.company.lab.test": "bound.provider.lab.test",
}

FIXTURE_BINDINGS = {
    "unused.provider.lab.test": False,
    "bound.provider.lab.test": True,
}

def classify_vulnerable(fingerprint_seen):
    # Vulnerable: a response fingerprint cannot prove provider claimability
    return "TAKEOVER_CONFIRMED" if fingerprint_seen else "NO_FINDING"
```
### Secure: keep the result in a state requiring provider review

```python
def review_fixture(subdomain, records, bindings):
    # Secure: classify synthetic evidence without claiming real-world takeover
    cname_target = records.get(subdomain)
    if cname_target is None:
        return {"subdomain": subdomain, "status": "NO_CNAME_IN_FIXTURE"}

    if cname_target not in bindings:
        return {
            "subdomain": subdomain,
            "cname": cname_target,
            "status": "MANUAL_PROVIDER_REVIEW_REQUIRED",
        }

    if bindings[cname_target] is False:
        return {
            "subdomain": subdomain,
            "cname": cname_target,
            "status": "DANGLING_SIGNAL_ONLY",
            "note": "Provider-authorized claimability evidence is still required",
        }

    return {
        "subdomain": subdomain,
        "cname": cname_target,
        "status": "BOUND_IN_FIXTURE",
    }


result = review_fixture(
    "docs.company.lab.test",
    FIXTURE_RECORDS,
    FIXTURE_BINDINGS,
)
assert result["status"] == "DANGLING_SIGNAL_ONLY"
```
Prevention must tie the DNS lifecycle with the resource lifecycle. Terraform dependency only orders within the same plan/apply or full-stack destroy; it does not automatically delete the record when someone deprovisions the provider resource through a different flow. [S5]

```terraform
# resource "aws_s3_bucket" "docs" {
#   bucket = "company-docs"
# }
#
# resource "aws_route53_record" "docs_cname" {
#   zone_id = aws_route53_zone.main.zone_id
#   name    = "docs.company.lab.test"
#   type    = "CNAME"
#   ttl     = 300
#   records = [aws_s3_bucket.docs.website_endpoint]
#   # Remove or rebind this record in the same reviewed change BEFORE the
#   # provider resource is deprovisioned; inspect the plan for both actions.
# }
```

## 10. Detection

- Resolve the record and then check the provider binding using a mock; DNS pointing to the destination is not enough to prove takeover. [S5]

- Review asset inventory and the deprovision order between the resource and DNS. [S5]

- Log zone, record, resource owner, and binding status; do not attempt to claim the real service.

## 11. Defense

### Compulsory control

- Delete or update DNS before releasing third-party resources; confirm that the binding is no longer claimable. [S5]

- Maintain inventory linked to records with the owner and lifecycle of the provider resource. [S5]

### Defense-in-depth

- Periodically scan dangling records and alert when the target changes status.

- Reduce trust cookie/CORS/CSP for wildcard subdomain.

## 12. Retest

- **Positive:** the record currently in use still maps to a resource owned by the organization.

- **Negative:** the deprovision workflow deletes DNS before the resource is released.

- **Boundary:** alias chain, wildcard, multiple accounts/regions, and propagation delay.

- **Telemetry:** cross-check DNS answer, inventory, and provider ownership.

## 13. Common Mistakes

- Call every CNAME error a takeover.

- Claim real resources to 'verify' without authorization.

- Delete the resource first, then wait for TTL before deleting DNS.

- Overlooked wildcards and records managed by other teams.

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

- **Dangling DNS:** the record still points to a third-party resource that has been deleted or released. [S5]

- **Provider binding:** the provider-side link between a custom domain and the resource/account that owns it. [S5]

- **Subdomain takeover:** another actor claims the binding of DNS of the referenced organization. [S5]

## 16. Related Lessons and Further Reading

- [Clickjacking](../clickjacking/) — See more lessons about Clickjacking.

## 17. References

- **[S5]** Microsoft Learn — Prevent dangling DNS entries and avoid subdomain takeover. https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover — updated: 2026-01-12; accessed: 2026-07-17.
- **[S6]** MDN — Set-Cookie `Domain` and host-only cookies. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie — version/status: current version; accessed: 2026-07-17.