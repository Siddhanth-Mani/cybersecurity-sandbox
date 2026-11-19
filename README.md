# Web Application Security Sandbox & Guide

An interactive study guide to six web-security topics. Each topic has a reference tab and a hands-on lab that runs entirely in your browser.

**Live:** https://siddhanth-mani.github.io/cybersecurity-sandbox/

| Topic | Reference | Interactive lab |
| --- | --- | --- |
| Reconnaissance | Passive vs active recon, attack-surface mapping, common commands | Paste HTTP response headers to see missing security headers and leaked server versions |
| SSRF | Metadata access, internal port scanning, protocol abuse, blind SSRF | Outbound-URL validator that blocks private IPs, metadata hosts and dangerous schemes, and explains why |
| Authentication | Broken auth and access control, privilege escalation, JWT pitfalls | Password-policy checker, plus a JWT builder and decoder that flags `alg:none`, key confusion and expired tokens |
| Injection | SQLi, command injection, SSTI, XXE, LDAP/XPath | Payload scanner, and a mock database comparing string concatenation with a prepared statement |
| Request smuggling | CL.TE and TE.CL, impact scenarios | Request-framing inspector that detects Content-Length vs Transfer-Encoding conflicts |
| WAFs | Common evasion techniques and best practices | Shows how encodings and case changes alter a payload, to explain why signature-only WAF rules aren't enough |

Each topic ends with the defensive controls that prevent it.

`cyber_demo.py` is a companion command-line script that walks through the same concepts offline. It makes no network requests and needs only Python 3.

```bash
python cyber_demo.py
```

## Built with security in mind

- Static HTML, CSS and vanilla JavaScript, with no build step and no back end. Nothing you type leaves the browser.
- A strict Content Security Policy: scripts load only from this site, there are no inline handlers, and `connect-src 'none'` means the page can't send data anywhere.
- All user input is HTML-escaped before it's displayed. The JWT decoder treats token contents as untrusted, because they are.

## Responsible use

This is for learning. The labs only analyse text you paste in and never contact other systems. Only test systems you own or have written permission to test.
