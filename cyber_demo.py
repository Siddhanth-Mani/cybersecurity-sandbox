#!/usr/bin/env python3
"""
=============================================================
  CYBERSECURITY TESTING CONCEPTS — DEMONSTRATION SCRIPT
  Educational reference only. Do not use against systems
  you do not own or have explicit written permission to test.
=============================================================
"""

import sys
import re
import json
import urllib.parse
import html
import sqlite3
import hmac
import hashlib
import base64
import textwrap
from typing import Optional

# Reconfigure stdout to use UTF-8 to prevent encoding errors on Windows terminal consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


# ─────────────────────────────────────────────
#  SECTION 1: RECONNAISSANCE HELPERS
# ─────────────────────────────────────────────

class Recon:
    """Passive/active information-gathering concepts."""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
    }

    @staticmethod
    def parse_headers(raw: str) -> dict:
        """
        Parse raw HTTP response headers and flag security-relevant ones.
        (Simulated — no live requests made.)
        """
        headers = {}
        for line in raw.strip().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        print("\n[ RECON ] Header Analysis")
        print("─" * 40)
        for sh in security_headers:
            present = sh in headers
            status = "✓ PRESENT" if present else "✗ MISSING"
            print(f"  {status:12} {sh}")
        return headers

    @staticmethod
    def fingerprint_server(server_header: str) -> dict:
        """Extract technology info from Server header."""
        patterns = {
            "Apache": r"Apache/([\d.]+)",
            "Nginx":  r"nginx/([\d.]+)",
            "IIS":    r"IIS/([\d.]+)",
        }
        result = {"raw": server_header, "detected": {}}
        for tech, pattern in patterns.items():
            m = re.search(pattern, server_header, re.I)
            if m:
                result["detected"][tech] = m.group(1)
        return result


# ─────────────────────────────────────────────
#  SECTION 2: SSRF CONCEPTS
# ─────────────────────────────────────────────

class SSRFDemo:
    """
    Demonstrates SSRF detection and prevention logic.
    No actual outbound requests are made.
    """

    # Private / internal IP ranges that should be blocked
    BLOCKED_PREFIXES = (
        "127.", "10.", "192.168.", "172.16.", "172.17.",
        "172.18.", "172.19.", "172.20.", "169.254.",  # link-local / metadata
        "::1", "fc00:", "fd",
    )

    BLOCKED_SCHEMES = {"file", "gopher", "dict", "ftp", "jar", "netdoc"}

    @classmethod
    def is_safe_url(cls, url: str) -> tuple[bool, str]:
        """
        Validate a URL against SSRF prevention rules.
        Returns (is_safe, reason).
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False, "URL parse error"

        scheme = parsed.scheme.lower()
        if scheme in cls.BLOCKED_SCHEMES:
            return False, f"Blocked scheme: {scheme}"

        if scheme not in {"http", "https"}:
            return False, f"Non-HTTP scheme: {scheme}"

        host = parsed.hostname or ""

        # Reject if host resolves to a blocked prefix (simplified check)
        for prefix in cls.BLOCKED_PREFIXES:
            if host.startswith(prefix):
                return False, f"Private/internal address: {host}"

        # Reject common metadata endpoint hostnames
        if host in {"metadata.google.internal", "instance-data"}:
            return False, f"Cloud metadata hostname: {host}"

        return True, "OK"

    @staticmethod
    def demo():
        test_urls = [
            "https://example.com/api/data",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://internal:70/_GET%20/admin",
            "http://192.168.1.1/router-admin",
            "http://metadata.google.internal/computeMetadata/v1/",
            "https://legitimate-partner.com/webhook",
        ]

        print("\n[ SSRF ] URL Validation Demo")
        print("─" * 55)
        print(f"  {'URL':<45} RESULT")
        print("─" * 55)
        for url in test_urls:
            safe, reason = SSRFDemo.is_safe_url(url)
            display_url = url[:43] + ".." if len(url) > 45 else url
            mark = "✓ ALLOW" if safe else f"✗ BLOCK ({reason})"
            print(f"  {display_url:<45} {mark}")


# ─────────────────────────────────────────────
#  SECTION 3: AUTHENTICATION & AUTHORIZATION
# ─────────────────────────────────────────────

class AuthDemo:
    """Demonstrates secure auth patterns and common weaknesses."""

    @staticmethod
    def check_password_strength(password: str) -> dict:
        """Evaluate password against common security policies."""
        checks = {
            "min_length_8":  len(password) >= 8,
            "min_length_12": len(password) >= 12,
            "uppercase":     bool(re.search(r"[A-Z]", password)),
            "lowercase":     bool(re.search(r"[a-z]", password)),
            "digit":         bool(re.search(r"\d", password)),
            "special":       bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
            "no_common":     password.lower() not in {
                "password", "123456", "qwerty", "admin", "letmein"
            },
        }
        score = sum(checks.values())
        strength = "Weak" if score < 4 else "Fair" if score < 6 else "Strong"
        return {"checks": checks, "score": score, "strength": strength}

    @staticmethod
    def verify_jwt_structure(token: str) -> dict:
        """
        Decode and inspect a JWT without verifying the signature.
        Demonstrates the "alg:none" vulnerability check.
        """
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}

        def b64_decode(s: str) -> dict:
            padding = 4 - len(s) % 4
            s += "=" * (padding % 4)
            try:
                return json.loads(base64.urlsafe_b64decode(s))
            except Exception:
                return {}

        header = b64_decode(parts[0])
        payload = b64_decode(parts[1])

        warnings = []
        if header.get("alg", "").lower() == "none":
            warnings.append("CRITICAL: alg=none — signature not verified!")
        if header.get("alg", "") == "HS256" and "RS" in str(header):
            warnings.append("WARNING: Possible algorithm confusion attack")
        if not payload.get("exp"):
            warnings.append("WARNING: No expiration (exp) claim set")

        return {
            "header":   header,
            "payload":  payload,
            "warnings": warnings,
            "signed":   bool(parts[2]),
        }

    @staticmethod
    def demo():
        print("\n[ AUTH ] Password Strength Checker")
        print("─" * 40)
        for pw in ["password", "Admin1!", "Tr0ub4dor&3"]:
            result = AuthDemo.check_password_strength(pw)
            print(f"  '{pw}' → {result['strength']} (score {result['score']}/7)")

        print("\n[ AUTH ] JWT Structure Inspection")
        print("─" * 40)
        # Example JWT with alg:none (unsigned)
        fake_header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        fake_payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"superuser"}').rstrip(b"=").decode()
        none_jwt = f"{fake_header}.{fake_payload}."
        result = AuthDemo.verify_jwt_structure(none_jwt)
        print(f"  Payload: {result['payload']}")
        for w in result["warnings"]:
            print(f"  ⚠  {w}")


# ─────────────────────────────────────────────
#  SECTION 4: INJECTION CONCEPTS
# ─────────────────────────────────────────────

class InjectionDemo:
    """Safe demonstration of injection detection and prevention."""

    # Common SQL injection patterns
    SQLI_PATTERNS = [
        r"'[;\s]",            # quote + semicolon/whitespace
        r"--\s",              # SQL comment
        r"/\*.*?\*/",         # block comment
        r"\bUNION\b",         # UNION keyword
        r"\bSELECT\b",        # SELECT keyword
        r"0x[0-9a-f]+",       # hex encoding
        r"SLEEP\s*\(",        # time-based blind
        r"WAITFOR\s+DELAY",   # MSSQL time-based
        r"OR\s+1\s*=\s*1",    # tautology
    ]

    @classmethod
    def detect_sqli(cls, input_str: str) -> list[str]:
        """Return list of detected SQLi patterns."""
        found = []
        for pattern in cls.SQLI_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                found.append(pattern)
        return found

    @staticmethod
    def safe_query_demo():
        """Show safe (parameterized) vs unsafe query construction."""
        # Unsafe — DO NOT DO THIS
        user_input = "admin' OR '1'='1"
        unsafe_query = f"SELECT * FROM users WHERE username = '{user_input}'"

        # Safe — parameterized query
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'admin', 'administrator')")
        conn.execute("INSERT INTO users VALUES (2, 'alice', 'user')")
        conn.commit()

        print("\n[ INJECTION ] SQL Injection Demo")
        print("─" * 55)
        print(f"  Unsafe query (never do this):")
        print(f"    {unsafe_query}")
        print()

        # Parameterized — the injection attempt returns nothing
        cur = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (user_input,)  # treated as literal string, not SQL
        )
        rows = cur.fetchall()
        print(f"  Parameterized query result for input '{user_input}':")
        print(f"    Rows returned: {len(rows)} (injection failed — correct!)")
        conn.close()

    @staticmethod
    def detect_xss(input_str: str) -> tuple[bool, str]:
        """Detect and sanitize potential XSS in input."""
        xss_patterns = [r"<script", r"javascript:", r"onerror=", r"onload=", r"<iframe"]
        detected = any(re.search(p, input_str, re.I) for p in xss_patterns)
        safe = html.escape(input_str)
        return detected, safe

    @staticmethod
    def demo():
        InjectionDemo.safe_query_demo()

        print("\n[ INJECTION ] SQLi Pattern Detection")
        print("─" * 40)
        inputs = [
            "john.doe",
            "admin'--",
            "1 OR 1=1",
            "1; DROP TABLE users--",
            "normal_user123",
        ]
        for inp in inputs:
            hits = InjectionDemo.detect_sqli(inp)
            status = f"⚠ FLAGGED ({len(hits)} pattern(s))" if hits else "✓ Clean"
            print(f"  {inp!r:<30} {status}")

        print("\n[ INJECTION ] XSS Detection & Sanitization")
        print("─" * 40)
        xss_inputs = [
            '<script>alert("XSS")</script>',
            'Hello, <b>world</b>!',
            '<img src=x onerror=alert(1)>',
        ]
        for inp in xss_inputs:
            detected, safe = InjectionDemo.detect_xss(inp)
            label = "⚠ XSS detected" if detected else "✓ Clean"
            print(f"  Input:     {inp!r}")
            print(f"  Sanitized: {safe!r}  [{label}]")
            print()


# ─────────────────────────────────────────────
#  SECTION 5: HTTP REQUEST SMUGGLING
# ─────────────────────────────────────────────

class SmugglingDemo:
    """Explains request smuggling concepts through simulation."""

    @staticmethod
    def detect_te_cl_conflict(headers: dict) -> dict:
        """
        Check if a request has both Content-Length and Transfer-Encoding,
        which creates the parsing ambiguity smuggling exploits.
        """
        has_cl = "Content-Length" in headers
        has_te = "Transfer-Encoding" in headers
        conflict = has_cl and has_te

        result = {
            "Content-Length":    headers.get("Content-Length"),
            "Transfer-Encoding": headers.get("Transfer-Encoding"),
            "conflict":          conflict,
        }
        if conflict:
            result["risk"] = (
                "POTENTIAL SMUGGLING VECTOR: Both Content-Length and "
                "Transfer-Encoding present. RFC 7230 §3.3.3 says Transfer-Encoding "
                "wins, but inconsistent server implementations create exploitable gaps."
            )
        return result

    @staticmethod
    def demo():
        print("\n[ HTTP SMUGGLING ] Header Conflict Detection")
        print("─" * 55)

        scenarios = [
            {
                "name": "Normal request",
                "headers": {"Content-Type": "application/json", "Content-Length": "42"},
            },
            {
                "name": "CL.TE conflict (potential smuggling)",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
            },
            {
                "name": "TE only (normal chunked)",
                "headers": {"Transfer-Encoding": "chunked"},
            },
        ]

        for s in scenarios:
            result = SmugglingDemo.detect_te_cl_conflict(s["headers"])
            conflict_flag = "⚠ CONFLICT" if result["conflict"] else "✓ OK"
            print(f"\n  Scenario: {s['name']}")
            print(f"  Status:   {conflict_flag}")
            if result.get("risk"):
                for line in textwrap.wrap(result["risk"], 60):
                    print(f"  Risk:     {line}")


# ─────────────────────────────────────────────
#  SECTION 6: WAF BYPASS CONCEPTS
# ─────────────────────────────────────────────

class WAFDemo:
    """Demonstrates WAF evasion techniques (for understanding, not exploitation)."""

    @staticmethod
    def generate_bypass_variants(payload: str) -> list[dict]:
        """Generate common bypass encoding variants of a payload."""
        variants = [
            {
                "technique": "Original",
                "payload": payload,
            },
            {
                "technique": "URL encoded",
                "payload": urllib.parse.quote(payload),
            },
            {
                "technique": "Double URL encoded",
                "payload": urllib.parse.quote(urllib.parse.quote(payload)),
            },
            {
                "technique": "HTML entity encoded",
                "payload": html.escape(payload),
            },
            {
                "technique": "Mixed case (SQL)",
                "payload": re.sub(
                    r"[a-zA-Z]",
                    lambda m: m.group().upper() if hash(m.start()) % 2 else m.group().lower(),
                    payload
                ),
            },
            {
                "technique": "SQL comment insertion",
                "payload": re.sub(r"\s+", "/**/", payload),
            },
        ]
        return variants

    @staticmethod
    def demo():
        payload = "' UNION SELECT username, password FROM users--"
        variants = WAFDemo.generate_bypass_variants(payload)

        print("\n[ WAF ] Bypass Encoding Techniques (educational)")
        print("─" * 60)
        print(f"  Base payload: {payload!r}\n")
        for v in variants:
            print(f"  [{v['technique']}]")
            print(f"  {v['payload'][:80]}")
            print()


# ─────────────────────────────────────────────
#  MAIN RUNNER
# ─────────────────────────────────────────────

def banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║   CYBERSECURITY TESTING CONCEPTS — EDUCATIONAL DEMO      ║
║   For authorized testing and learning purposes only.     ║
╚══════════════════════════════════════════════════════════╝
""")

def main():
    banner()

    # 1. Recon
    sample_headers = """Server: Apache/2.4.51 (Ubuntu)
X-Powered-By: PHP/8.1.2
Content-Type: text/html; charset=UTF-8
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff"""
    Recon.parse_headers(sample_headers)

    # 2. SSRF
    SSRFDemo.demo()

    # 3. Auth
    AuthDemo.demo()

    # 4. Injection
    InjectionDemo.demo()

    # 5. HTTP Smuggling
    SmugglingDemo.demo()

    # 6. WAF Bypass (understanding only)
    WAFDemo.demo()

    print("\n[ DONE ] All concept demonstrations complete.")
    print("─" * 60)
    print("  Remember: Always obtain written authorization before")
    print("  testing any system you do not personally own.\n")


if __name__ == "__main__":
    main()
