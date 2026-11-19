// Safe initialization check to prevent DOMContentLoaded race conditions
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAll);
} else {
  initAll();
}

function initAll() {
  initTabs();
  initTemplateLoaders();
  initCopyButtons();
  initReconLab();
  initSSRFLab();
  initAuthLab();
  initInjectionLab();
  initSmugglingLab();
  initWafLab();
}

/* ==========================================================================
   GLOBAL UTILITIES
   ========================================================================== */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function safeCopy(text, btnElement) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showCopiedFeedback(btnElement);
    }).catch(err => {
      fallbackCopy(text, btnElement);
    });
  } else {
    fallbackCopy(text, btnElement);
  }
}

function fallbackCopy(text, btnElement) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  textArea.style.top = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
    showCopiedFeedback(btnElement);
  } catch (err) {
    console.error('Fallback Copy failed: ', err);
  }
  document.body.removeChild(textArea);
}

function showCopiedFeedback(btnElement) {
  if (!btnElement) return;
  const originalText = btnElement.innerHTML;
  btnElement.textContent = 'Copied';
  btnElement.style.color = 'var(--green)';
  setTimeout(() => {
    btnElement.innerHTML = originalText;
    btnElement.style.color = '';
  }, 1500);
}

function initCopyButtons() {
  document.querySelectorAll('.copy-action-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-copy-target');
      const targetElement = document.getElementById(targetId);
      if (targetElement) {
        const textToCopy = targetElement.innerText || targetElement.textContent;
        safeCopy(textToCopy, btn);
      }
    });
  });
}

function updateConsoleLed(consoleElement, state) {
  const windowFrame = consoleElement.closest('.terminal-window');
  if (!windowFrame) return;
  const led = windowFrame.querySelector('.terminal-led');
  if (!led) return;
  
  led.className = 'terminal-led'; // Reset classes
  if (state) {
    led.classList.add(state); // 'running', 'alert', 'clean'
  }
}

/* ==========================================================================
   TABS SWITCHING SYSTEM
   ========================================================================== */
function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const section = btn.closest('.section');
      
      section.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      section.querySelectorAll('.tab-content').forEach(panel => {
        panel.classList.remove('active');
      });
      section.querySelector(`#${targetId}`).classList.add('active');
    });
  });
}

/* ==========================================================================
   QUICK TEMPLATES LOAD SYSTEM
   ========================================================================== */
const TEMPLATES = {
  recon: {
    apache: `HTTP/1.1 200 OK\nDate: Wed, 10 Jun 2026 12:00:00 GMT\nServer: Apache/2.4.51 (Ubuntu)\nX-Powered-By: PHP/8.1.2\nContent-Type: text/html; charset=UTF-8\nX-Frame-Options: SAMEORIGIN\nX-Content-Type-Options: nosniff\nConnection: keep-alive`,
    nginx: `HTTP/1.1 200 OK\nServer: nginx/1.21.6\nDate: Wed, 10 Jun 2026 12:05:00 GMT\nContent-Type: text/html\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\nContent-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com;\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin`,
    aws: `HTTP/1.1 302 Found\nDate: Wed, 10 Jun 2026 12:10:00 GMT\nContent-Type: text/html\nConnection: keep-alive\nSet-Cookie: AWSALB=uKzV1928371982739812; Path=/; Expires=Wed, 17 Jun 2026 12:10:00 GMT\nLocation: /login\nServer: CloudFront`
  },
  ssrf: {
    aws: "http://169.254.169.254/latest/meta-data/",
    gcp: "http://metadata.google.internal/computeMetadata/v1/",
    local: "http://192.168.1.1/router-admin",
    evasion: "http://0x7f000001/admin",
    safe: "https://api.github.com/users/octocat"
  },
  jwt: {
    valid: (() => {
      const header = b64urlEncode({ alg: "RS256", typ: "JWT" });
      const payload = b64urlEncode({ sub: "john_doe", role: "user", exp: Math.floor(Date.now() / 1000) + 3600 });
      return `${header}.${payload}.signature_hash_bytes`;
    })(),
    none: (() => {
      const header = b64urlEncode({ alg: "none", typ: "JWT" });
      const payload = b64urlEncode({ sub: "admin", role: "superuser" });
      return `${header}.${payload}.`;
    })(),
    expired: (() => {
      const header = b64urlEncode({ alg: "RS256", typ: "JWT" });
      const payload = b64urlEncode({ sub: "alice_web", role: "editor", exp: Math.floor(Date.now() / 1000) - 600 });
      return `${header}.${payload}.signature_hash_bytes`;
    })(),
    confusion: (() => {
      const header = b64urlEncode({ alg: "HS256", typ: "JWT" });
      const payload = b64urlEncode({ sub: "admin", role: "admin", note: "Algorithm RS256 public key confusion exploit check" });
      return `${header}.${payload}.forged_hmac_signature`;
    })()
  },
  injection: {
    sqli: "admin' OR '1'='1",
    stacked: "1; DROP TABLE users; --",
    xss: "<script>alert(document.cookie)</script>",
    ssti: "{{7*7}}",
    xxe: '<?xml version="1.0" encoding="ISO-8859-1"?>\n<!DOCTYPE foo [ \n  <!ENTITY xxe SYSTEM "file:///etc/passwd"> \n]>\n<foo>&xxe;</foo>'
  },
  smuggling: {
    valid: `POST /index.html HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 11\n\nhello=world`,
    clte: `POST /index.html HTTP/1.1\nHost: target.com\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nG`,
    tecl: `POST /index.html HTTP/1.1\nHost: target.com\nContent-Length: 4\nTransfer-Encoding: chunked\n\n5\nGPOST\n0`
  }
};

function b64urlEncode(obj) {
  const str = JSON.stringify(obj);
  // Support UTF-8 encoding safely in base64
  const base64 = btoa(unescape(encodeURIComponent(str)));
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function initTemplateLoaders() {
  document.querySelectorAll('.template-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-type');
      const key = btn.getAttribute('data-key');
      const targetInputId = btn.getAttribute('data-input-target');
      
      const targetInput = document.getElementById(targetInputId);
      if (targetInput && TEMPLATES[type] && TEMPLATES[type][key]) {
        targetInput.value = TEMPLATES[type][key];
        
        // Dispatch input event for real-time validators
        targetInput.dispatchEvent(new Event('input'));
      }
    });
  });
}

/* ==========================================================================
   1. RECON LABORATORY
   ========================================================================== */
function initReconLab() {
  const input = document.getElementById('recon-headers-input');
  const btn = document.getElementById('recon-analyze-btn');
  const output = document.getElementById('recon-output');
  
  if (!btn || !input || !output) return;

  const analyze = () => {
    updateConsoleLed(output, 'running');
    const raw = input.value.trim();
    if (!raw) {
      output.innerHTML = '<span class="comment">// Please paste raw HTTP response headers or click one of the templates above.</span>';
      updateConsoleLed(output, '');
      return;
    }

    const headers = {};
    raw.split(/\r?\n/).forEach(line => {
      const parts = line.split(':');
      if (parts.length >= 2) {
        const key = parts[0].trim().toLowerCase();
        const value = parts.slice(1).join(':').trim();
        headers[key] = value;
      }
    });

    const securityHeaders = [
      { name: "Strict-Transport-Security", desc: "Forces HTTPS connections to resist Man-in-the-Middle attacks" },
      { name: "Content-Security-Policy", desc: "Mitigates Cross-Site Scripting (XSS) and content injection by specifying trusted sources" },
      { name: "X-Frame-Options", desc: "Protects against Clickjacking framing attacks" },
      { name: "X-Content-Type-Options", desc: "Prevents browsers from sniffing MIME types away from declared Content-Type" },
      { name: "Referrer-Policy", desc: "Restricts referrer header metadata leaks across origins" },
      { name: "Permissions-Policy", desc: "Controls browser API permissions (camera, location, payment gateways)" }
    ];

    let htmlReport = '';
    htmlReport += `<div class="console-alert info">> Passive header security scan completed.</div>\n`;
    htmlReport += `<strong>Security Header Coverage:</strong>\n`;
    htmlReport += `─`.repeat(45) + `\n`;

    let missingCount = 0;
    securityHeaders.forEach(sh => {
      const lowerName = sh.name.toLowerCase();
      const present = lowerName in headers;
      const status = present 
        ? `<span class="tag safe">✓ PRESENT</span>` 
        : `<span class="tag critical">✗ MISSING</span>`;
      
      if (!present) missingCount++;
      
      htmlReport += `${status.padEnd(25)} <strong>${sh.name}</strong>\n`;
      if (present) {
        htmlReport += `  <span class="comment">Value: ${escapeHtml(headers[lowerName])}</span>\n`;
      } else {
        htmlReport += `  <span class="comment">Risk: Lack of defense against: ${sh.desc}</span>\n`;
      }
      htmlReport += '\n';
    });

    // Technology Fingerprinting
    const serverHeader = headers['server'];
    const xPoweredBy = headers['x-powered-by'];
    let versionAlert = false;
    
    if (serverHeader || xPoweredBy) {
      htmlReport += `\n<strong>Technology Signature Fingerprints:</strong>\n`;
      htmlReport += `─`.repeat(45) + `\n`;
      if (serverHeader) htmlReport += `Server Signature: "${escapeHtml(serverHeader)}"\n`;
      if (xPoweredBy) htmlReport += `Runtime Powered By: "${escapeHtml(xPoweredBy)}"\n`;
      
      const detections = [];
      if (serverHeader) {
        if (/apache\/([\d.]+)/i.test(serverHeader)) {
          detections.push(`Apache HTTP Server v${serverHeader.match(/apache\/([\d.]+)/i)[1]}`);
          versionAlert = true;
        }
        if (/nginx\/([\d.]+)/i.test(serverHeader)) {
          detections.push(`Nginx Web Server v${serverHeader.match(/nginx\/([\d.]+)/i)[1]}`);
          versionAlert = true;
        }
        if (/iis\/([\d.]+)/i.test(serverHeader)) {
          detections.push(`Microsoft IIS Server v${serverHeader.match(/iis\/([\d.]+)/i)[1]}`);
          versionAlert = true;
        }
        if (/cloudflare/i.test(serverHeader)) {
          detections.push(`Cloudflare Edge proxy network proxy node`);
        }
      }
      
      if (xPoweredBy) {
        if (/php\/([\d.]+)/i.test(xPoweredBy)) {
          detections.push(`PHP Engine Runtime v${xPoweredBy.match(/php\/([\d.]+)/i)[1]}`);
          versionAlert = true;
        }
        if (/asp\.net/i.test(xPoweredBy)) {
          detections.push(`ASP.NET framework engine backend`);
        }
        if (/express/i.test(xPoweredBy)) {
          detections.push(`NodeJS Express application runtime`);
        }
      }

      if (detections.length > 0) {
        detections.forEach(det => {
          htmlReport += `<span class="tag warn">FINGERPRINTED</span> ${det}\n`;
        });
        if (versionAlert) {
          htmlReport += `\n<div class="console-alert warning"><strong>WARNING:</strong> Exposing specific version numbers enables hackers to search for targeted CVE exploits. Banner stripping is recommended.</div>`;
        }
      } else {
        htmlReport += `<span class="tag info">GENERAL INFO</span> Version details obscured. Good practice.`;
      }
    } else {
      htmlReport += `\n<span class="tag safe">✓ PASS</span> Technology banners stripped (Server and X-Powered-By are missing). No passive fingerprint found.`;
    }

    output.innerHTML = htmlReport;
    updateConsoleLed(output, (missingCount > 2 || versionAlert) ? 'alert' : 'clean');
  };

  btn.addEventListener('click', analyze);
  input.addEventListener('input', analyze);
  if (input.value.trim()) analyze();
}

/* ==========================================================================
   2. SSRF LABORATORY
   ========================================================================== */
function initSSRFLab() {
  const input = document.getElementById('ssrf-url-input');
  const btn = document.getElementById('ssrf-validate-btn');
  const output = document.getElementById('ssrf-output');

  // Returns a reason string when the host is loopback, private, link-local or unspecified, else null.
  // The URL parser has already normalised hex, octal and integer IPv4 forms (0x7f000001 -> 127.0.0.1).
  function privateAddressReason(host) {
    const h = host.replace(/^\[|\]$/g, '');
    if (h === 'localhost' || h.endsWith('.localhost')) return 'loopback name';
    const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
      const a = Number(v4[1]), b = Number(v4[2]);
      if (a === 127) return 'loopback (127.0.0.0/8)';
      if (a === 10) return 'private (10.0.0.0/8)';
      if (a === 172 && b >= 16 && b <= 31) return 'private (172.16.0.0/12)';
      if (a === 192 && b === 168) return 'private (192.168.0.0/16)';
      if (a === 169 && b === 254) return 'link-local (169.254.0.0/16)';
      if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade NAT (100.64.0.0/10)';
      if (a === 0) return 'unspecified (0.0.0.0/8)';
      return null;
    }
    if (h.includes(':')) {
      if (h === '::1') return 'IPv6 loopback';
      if (h === '::') return 'IPv6 unspecified';
      if (/^f[cd][0-9a-f]{0,2}:/.test(h)) return 'IPv6 unique local (fc00::/7)';
      if (/^fe[89ab][0-9a-f]?:/.test(h)) return 'IPv6 link-local (fe80::/10)';
      const mapped = h.match(/^::ffff:(.+)$/);
      if (mapped) {
        const m = mapped[1];
        if (m.includes('.')) return privateAddressReason(m);
        const parts = m.split(':');
        if (parts.length === 2) {
          const hi = parseInt(parts[0], 16), lo = parseInt(parts[1], 16);
          return privateAddressReason([hi >> 8, hi & 255, lo >> 8, lo & 255].join('.'));
        }
      }
    }
    return null;
  }
  const blockedSchemes = ["file", "gopher", "dict", "ftp", "jar", "netdoc"];
  const blockedHosts = ["metadata.google.internal", "metadata", "instance-data", "169.254.169.254", "[fd00:ec2::254]"];

  const dangerousPorts = {
    "21": "FTP",
    "22": "SSH",
    "23": "TEL",
    "25": "SMTP",
    "53": "DNS",
    "80": "HTTP",
    "443": "HTTPS",
    "3306": "SQL",
    "5432": "PG",
    "6379": "RED",
    "8080": "ADM",
    "27017": "MON"
  };

  if (!btn || !input || !output) return;

  const validate = () => {
    updateConsoleLed(output, 'running');
    resetSSRFPorts();
    
    const urlStr = input.value.trim();
    if (!urlStr) {
      output.innerHTML = '<span class="comment">// Enter a URL target to validate SSRF filtering rules.</span>';
      updateConsoleLed(output, '');
      return;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(urlStr);
    } catch (e) {
      output.innerHTML = `<div class="console-alert critical">✗ BLOCK: Invalid URL format or missing protocol (e.g. http://)</div>`;
      updateConsoleLed(output, 'alert');
      return;
    }

    const scheme = parsedUrl.protocol.replace(':', '').toLowerCase();
    const host = parsedUrl.hostname.toLowerCase();
    const port = parsedUrl.port;
    
    // Highlight port scanner nodes
    // Helper to find mapped port node and highlight it
    const highlightPortNode = (p, status) => {
      const node = document.querySelector(`#ssrf-port-grid .port-node[data-port="${p}"]`);
      if (node) {
        node.className = `port-node scanned-${status}`;
        const label = dangerousPorts[p] || 'PORT';
        node.innerHTML = `<span>${label}:${p}</span><span class="node-status">${status}</span>`;
      }
    };
    
    // Set all default nodes as scanned-closed
    Object.keys(dangerousPorts).forEach(p => {
      highlightPortNode(p, 'closed');
    });

    // 1. Scheme checks
    if (blockedSchemes.includes(scheme)) {
      output.innerHTML = `<div class="console-alert critical">✗ BLOCK: Access denied to protocol scheme: "${scheme}://"</div>\n` +
        `<strong>Reason:</strong> Schema abuse leads to arbitrary local file retrieval (file://) or raw TCP socket interaction (gopher://).\n\n` +
        `<span class="tag critical">Attack vector: Scheme Bypass</span>`;
      updateConsoleLed(output, 'alert');
      
      if (port) highlightPortNode(port, 'blocked');
      return;
    }

    if (scheme !== 'http' && scheme !== 'https') {
      output.innerHTML = `<div class="console-alert critical">✗ BLOCK: Protocol must be HTTP or HTTPS, got "${scheme}://"</div>`;
      updateConsoleLed(output, 'alert');
      return;
    }

    // 2. Hostname check (AWS/GCP metadata endpoints)
    if (blockedHosts.includes(host)) {
      output.innerHTML = `<div class="console-alert critical">✗ BLOCK: Cloud provider metadata server access blocked ("${host}")</div>\n` +
        `<strong>Reason:</strong> Cloud providers expose security credentials and IAM instance identity tokens at these static internal domains.\n\n` +
        `<span class="tag critical">Attack vector: Metadata Exfiltration</span>`;
      updateConsoleLed(output, 'alert');
      
      // Assume port 80/443 for metadata
      highlightPortNode(port || '80', 'blocked');
      return;
    }

    // 3. Subnet checks (resolving local subnets)
    const blockedPrefixFound = privateAddressReason(host);

    if (blockedPrefixFound) {
      output.innerHTML = `<div class="console-alert critical">✗ BLOCK: Internal address, ${blockedPrefixFound}: "${escapeHtml(host)}"</div>\n` +
        `<strong>Reason:</strong> Localhost loopback and private subnets cannot be queried. Prevents attackers scanning internal networks from outside.\n\n` +
        `<span class="tag critical">Attack vector: Local Host Discovery</span>`;
      updateConsoleLed(output, 'alert');
      
      const activePort = port || (scheme === 'https' ? '443' : '80');
      highlightPortNode(activePort, 'blocked');
      return;
    }

    // 4. Port checks
    let portWarningHtml = '';
    const activePort = port || (scheme === 'https' ? '443' : '80');
    
    if (port && dangerousPorts[port]) {
      portWarningHtml = `\n<div class="console-alert warning"><strong>⚠ HIGH RISK PORT DETECTED:</strong> Port ${port} is associated with database/admin management.</div>\n` +
        `Even if host validation passes, fetching endpoints on non-standard database/administration ports opens vectors for service interaction.`;
      
      highlightPortNode(port, 'blocked');
      updateConsoleLed(output, 'alert');
    } else {
      highlightPortNode(activePort, 'open');
      updateConsoleLed(output, 'clean');
    }

    output.innerHTML = `<div class="console-alert success">✓ ALLOW: Outbound URL validated as SAFE.</div>\n` +
      `<strong>Parsed Scheme:</strong> ${scheme}://\n` +
      `<strong>Validated Host:</strong> ${host}\n` +
      `<strong>Port:</strong> ${port || 'default (80/443)'}\n` +
      `<strong>Status:</strong> Allowed fetch call.` + portWarningHtml;
  };

  btn.addEventListener('click', validate);
  input.addEventListener('input', validate);
  if (input.value.trim()) validate();
}

function resetSSRFPorts() {
  const dangerousPorts = {
    "21": "FTP", "22": "SSH", "23": "TEL", "25": "SMTP",
    "53": "DNS", "80": "HTTP", "443": "HTTPS", "3306": "SQL",
    "5432": "PG", "6379": "RED", "8080": "ADM", "27017": "MON"
  };
  
  Object.keys(dangerousPorts).forEach(port => {
    const node = document.querySelector(`#ssrf-port-grid .port-node[data-port="${port}"]`);
    if (node) {
      node.className = 'port-node';
      node.innerHTML = `<span>${dangerousPorts[port]}:${port}</span>`;
    }
  });
}

/* ==========================================================================
   3. AUTHENTICATION & AUTHORIZATION LABORATORY
   ========================================================================== */
function initAuthLab() {
  // Password Strength segmented bar
  const pwInput = document.getElementById('auth-pw-input');
  const pwSegments = document.querySelectorAll('.pw-segment');
  const pwLabel = document.getElementById('auth-pw-label');
  
  const rules = {
    min8: document.getElementById('pw-rule-min8'),
    min12: document.getElementById('pw-rule-min12'),
    upper: document.getElementById('pw-rule-upper'),
    lower: document.getElementById('pw-rule-lower'),
    digit: document.getElementById('pw-rule-digit'),
    special: document.getElementById('pw-rule-special'),
    noCommon: document.getElementById('pw-rule-nocommon')
  };

  const commonPasswords = ["password", "123456", "qwerty", "admin", "letmein"];

  if (pwInput && pwLabel && pwSegments.length > 0) {
    pwInput.addEventListener('input', () => {
      const pw = pwInput.value;
      
      if (!pw) {
        pwLabel.textContent = 'Awaiting input';
        pwLabel.style.color = 'var(--muted)';
        pwSegments.forEach(seg => seg.style.backgroundColor = '');
        Object.values(rules).forEach(elem => { if (elem) elem.classList.remove('met'); });
        return;
      }

      const checks = {
        min8: pw.length >= 8,
        min12: pw.length >= 12,
        upper: /[A-Z]/.test(pw),
        lower: /[a-z]/.test(pw),
        digit: /\d/.test(pw),
        special: /[!@#$%^&*(),.?":{}|<>]/.test(pw),
        noCommon: !commonPasswords.includes(pw.toLowerCase())
      };

      let score = 0;
      Object.keys(checks).forEach(key => {
        const met = checks[key];
        if (met) score++;
        const ruleElem = rules[key];
        if (ruleElem) {
          if (met) {
            ruleElem.classList.add('met');
          } else {
            ruleElem.classList.remove('met');
          }
        }
      });

      let activeBars = 0;
      let barColor = '';
      let textLabel = '';

      if (score <= 3) {
        activeBars = Math.max(1, Math.min(2, score));
        barColor = 'var(--red)';
        textLabel = 'WEAK PASSWORD';
      } else if (score <= 6) {
        activeBars = score === 4 ? 2 : score === 5 ? 3 : 4;
        barColor = 'var(--yellow)';
        textLabel = 'FAIR PASSWORD';
      } else {
        activeBars = 5;
        barColor = 'var(--green)';
        textLabel = 'STRONG PASSWORD';
      }

      pwSegments.forEach((seg, index) => {
        if (index < activeBars) {
          seg.style.backgroundColor = barColor;
        } else {
          seg.style.backgroundColor = '';
        }
      });

      pwLabel.textContent = `${textLabel} (${score}/7 criteria met)`;
      pwLabel.style.color = barColor;
    });
  }

  // JWT Decoder
  const jwtInput = document.getElementById('auth-jwt-input');
  const jwtBtn = document.getElementById('auth-jwt-btn');
  const jwtOutput = document.getElementById('auth-jwt-output');

  if (jwtBtn && jwtInput && jwtOutput) {
    const decodeJwt = () => {
      updateConsoleLed(jwtOutput, 'running');
      const token = jwtInput.value.trim();
      if (!token) {
        jwtOutput.innerHTML = '<span class="comment">// Paste a JWT or load one of the presets above.</span>';
        updateConsoleLed(jwtOutput, '');
        return;
      }

      const parts = token.split('.');
      if (parts.length !== 3) {
        jwtOutput.innerHTML = `<span class="tag critical">Error</span> Invalid JWT structure.\nExpected 3 dot-separated segments.`;
        updateConsoleLed(jwtOutput, 'alert');
        return;
      }

      function safeB64Decode(str) {
        try {
          let cleanStr = str.replace(/-/g, '+').replace(/_/g, '/');
          const padding = 4 - (cleanStr.length % 4);
          if (padding < 4) {
            cleanStr += '='.repeat(padding);
          }
          return JSON.parse(atob(cleanStr));
        } catch (e) {
          return null;
        }
      }

      const header = safeB64Decode(parts[0]);
      const payload = safeB64Decode(parts[1]);

      if (!header || !payload) {
        jwtOutput.innerHTML = `<span class="tag critical">Error</span> Failed to base64url-decode JWT segments.`;
        updateConsoleLed(jwtOutput, 'alert');
        return;
      }

      let alerts = [];
      const alg = header.alg ? String(header.alg).toLowerCase() : '';
      let isCritical = false;
      let isWarning = false;
      
      if (alg === 'none') {
        alerts.push(`<div class="console-alert critical"><strong>CRITICAL VULNERABILITY (alg:none):</strong>\nSignature validation disabled by the token header. Any user claims inside this token can be modified/forged by attackers.</div>`);
        isCritical = true;
      }
      
      if (alg === 'hs256') {
        const jsonHeader = JSON.stringify(header).toUpperCase();
        const jsonPayload = JSON.stringify(payload).toUpperCase();
        if (jsonHeader.includes('RS') || jsonPayload.includes('RS') || token.includes('RS')) {
          alerts.push(`<div class="console-alert warning"><strong>WARNING (Key Confusion Risk):</strong>\nServer uses symmetric HMAC HS256 to verify asymmetric RS256 keys. Attacker could forge tokens using the public key as the secret key.</div>`);
          isWarning = true;
        }
      }

      if (!payload.exp) {
        alerts.push(`<div class="console-alert warning"><strong>WARNING (Missing Expiry):</strong>\nToken lacks expiration claim (exp). If intercepted, it is valid forever.</div>`);
        isWarning = true;
      } else {
        const expMs = payload.exp * 1000;
        const expired = Date.now() > expMs;
        if (expired) {
          alerts.push(`<div class="console-alert critical"><strong>EXPIRED TOKEN:</strong>\nToken expired on ${new Date(expMs).toUTCString()}.</div>`);
          isCritical = true;
        } else {
          alerts.push(`<div class="console-alert success"><strong>ACTIVE TOKEN:</strong>\nToken is valid. Expires on ${new Date(expMs).toUTCString()}.</div>`);
        }
      }

      let resultHtml = '';
      if (alerts.length > 0) {
        resultHtml += alerts.join('\n') + '\n';
      }

      // Token contents are attacker-controlled: escape them before they reach innerHTML.
      resultHtml += `<strong>Decoded Header:</strong>\n${escapeHtml(JSON.stringify(header, null, 2))}\n\n`;
      resultHtml += `<strong>Decoded Payload Claims:</strong>\n${escapeHtml(JSON.stringify(payload, null, 2))}\n\n`;
      resultHtml += `<strong>Signature Verification Block:</strong>\n`;
      if (parts[2]) {
        resultHtml += `[${escapeHtml(parts[2].substring(0, 24))}...] Raw signature segment present. Verification status: <span class="tag info">Awaiting Key</span>`;
      } else {
        resultHtml += `<span class="tag critical">Unsigned Token</span> No signature segment attached.`;
      }

      jwtOutput.innerHTML = resultHtml;
      
      if (isCritical) {
        updateConsoleLed(jwtOutput, 'alert');
      } else if (isWarning) {
        updateConsoleLed(jwtOutput, 'alert'); // warnings light up red/yellow as well
      } else {
        updateConsoleLed(jwtOutput, 'clean');
      }
    };

    jwtBtn.addEventListener('click', decodeJwt);
    jwtInput.addEventListener('input', decodeJwt);
    if (jwtInput.value.trim()) decodeJwt();
  }

  // JWT Generator Form Listeners
  const subField = document.getElementById('jwt-sub-input');
  const roleField = document.getElementById('jwt-role-input');
  const expField = document.getElementById('jwt-exp-input');
  const algSelect = document.getElementById('jwt-alg-select');

  const updateGeneratedToken = () => {
    if (!subField || !roleField || !expField || !algSelect || !jwtInput) return;
    
    const sub = subField.value.trim();
    const role = roleField.value.trim();
    const expSeconds = parseInt(expField.value, 10);
    const alg = algSelect.value;
    
    const headerObj = { alg: alg, typ: "JWT" };
    const payloadObj = { sub: sub, role: role };
    if (!isNaN(expSeconds) && expSeconds > 0) {
      payloadObj.exp = Math.floor(Date.now() / 1000) + expSeconds;
    }
    
    const headerB64 = b64urlEncode(headerObj);
    const payloadB64 = b64urlEncode(payloadObj);
    
    let signature = 'signature_hash_bytes';
    if (alg.toLowerCase() === 'none') {
      signature = '';
    } else if (alg.toLowerCase() === 'hs256') {
      signature = 'hmac_sha256_hash';
    }
    
    jwtInput.value = `${headerB64}.${payloadB64}.${signature}`;
  };

  [subField, roleField, expField, algSelect].forEach(element => {
    if (element) {
      element.addEventListener('input', updateGeneratedToken);
      element.addEventListener('change', updateGeneratedToken);
    }
  });

  if (subField || roleField || expField || algSelect) {
    updateGeneratedToken();
  }
}

/* ==========================================================================
   4. INJECTION LABORATORY
   ========================================================================== */
function initInjectionLab() {
  const input = document.getElementById('injection-input');
  const btn = document.getElementById('injection-analyze-btn');
  const output = document.getElementById('injection-output');
  const dbOutput = document.getElementById('injection-db-output');

  const sqliPatterns = [
    { regex: /'[;\s]/, desc: "Quote followed by semicolon/whitespace" },
    { regex: /--\s/, desc: "SQL comment marker" },
    { regex: /\/\*.*?\*\//, desc: "Inline comments (/**/)" },
    { regex: /\bUNION\b/i, desc: "UNION query clause" },
    { regex: /\bSELECT\b/i, desc: "SELECT query clause" },
    { regex: /0x[0-9a-f]+/i, desc: "Hex encoded string" },
    { regex: /SLEEP\s*\(/i, desc: "Time-based blind injection (SLEEP)" },
    { regex: /WAITFOR\s+DELAY/i, desc: "MSSQL Wait delay (WAITFOR)" },
    { regex: /OR\s+\d\s*=\s*\d/i, desc: "Tautology (e.g. OR 1=1)" }
  ];

  const xssPatterns = [
    { regex: /<script/i, desc: "HTML Script tag element" },
    { regex: /javascript:/i, desc: "JavaScript protocol handler" },
    { regex: /onerror=/i, desc: "Inline onerror attribute" },
    { regex: /onload=/i, desc: "Inline onload attribute" },
    { regex: /<iframe/i, desc: "Inline iframe resource loader" }
  ];

  const sstiPatterns = [
    { regex: /\{\{[\s\S]*?\}\}/, desc: "Jinja/Twig/Vue template syntax" },
    { regex: /\$\{[\s\S]*?\}/, desc: "ES6 or Thymeleaf expression syntax" },
    { regex: /#\{[\s\S]*?\}/, desc: "JSF/Facelets expression syntax" }
  ];

  if (!btn || !input || !output || !dbOutput) return;

  const analyze = () => {
    updateConsoleLed(output, 'running');
    updateConsoleLed(dbOutput, 'running');
    
    const text = input.value.trim();
    if (!text) {
      output.innerHTML = '<span class="comment">// Enter input query payload to execute scan.</span>';
      dbOutput.innerHTML = '<span class="comment">// Mock database query result panel.</span>';
      updateConsoleLed(output, '');
      updateConsoleLed(dbOutput, '');
      return;
    }

    let sqliHits = [];
    sqliPatterns.forEach(p => { if (p.regex.test(text)) sqliHits.push(p.desc); });

    let xssHits = [];
    xssPatterns.forEach(p => { if (p.regex.test(text)) xssHits.push(p.desc); });

    let sstiHits = [];
    sstiPatterns.forEach(p => { if (p.regex.test(text)) sstiHits.push(p.desc); });

    const threatFound = (sqliHits.length > 0 || xssHits.length > 0 || sstiHits.length > 0);

    let scanHtml = '';
    if (threatFound) {
      scanHtml += `<div class="console-alert critical">⚠ THREAT PATTERN MATCHED: Input contains injection elements!</div>\n`;
      if (sqliHits.length > 0) {
        scanHtml += `<strong>SQL Injection signatures detected:</strong>\n`;
        sqliHits.forEach(h => scanHtml += `  - MATCH: ${h}\n`);
      }
      if (xssHits.length > 0) {
        scanHtml += `<strong>Cross-Site Scripting (XSS) signatures detected:</strong>\n`;
        xssHits.forEach(h => scanHtml += `  - MATCH: ${h}\n`);
      }
      if (sstiHits.length > 0) {
        scanHtml += `<strong>Template/Expression (SSTI) signatures detected:</strong>\n`;
        sstiHits.forEach(h => scanHtml += `  - MATCH: ${h}\n`);
      }
      updateConsoleLed(output, 'alert');
    } else {
      scanHtml += `<div class="console-alert success">✓ INPUT CLEAN: No common injection signatures matched.</div>\n`;
      updateConsoleLed(output, 'clean');
    }

    scanHtml += `\n<strong>Sanitized Output (HTML Entity Escaped):</strong>\n${escapeHtml(text)}\n`;
    output.innerHTML = scanHtml;

    // Database Mock execution
    const unsafeQuery = `SELECT * FROM users WHERE username = '${text}'`;
    let dbHtml = '';
    dbHtml += `<strong>[UNSAFE SQL CONCATENATION]</strong>\n`;
    dbHtml += `Generated Statement: <span style="color: var(--red)">${escapeHtml(unsafeQuery)}</span>\n`;
    
    // Simulate concatenation exploit rows
    const isExploited = text.includes("'") && (text.toLowerCase().includes("or") || text.includes("--"));
    
    if (isExploited) {
      dbHtml += `Simulation Status: <span style="color: var(--red)">EXPLOITED! (Query parsed tautology)</span>\n`;
      dbHtml += `Database Records Returned (Bypassed Credentials):\n`;
      
      const mockDatabaseRows = [
        { id: 1, username: "admin", role: "administrator", email: "admin@corp.internal" },
        { id: 2, username: "alice", role: "developer", email: "alice@corp.internal" },
        { id: 3, username: "bob", role: "moderator", email: "bob@corp.internal" }
      ];
      
      dbHtml += JSON.stringify(mockDatabaseRows, null, 2);
      updateConsoleLed(dbOutput, 'alert');
    } else {
      dbHtml += `Simulation Status: Executed (0 rows returned or matched credentials).\n`;
      updateConsoleLed(dbOutput, 'clean');
    }

    dbHtml += `\n\n<strong>[SAFE PREPARED STATEMENT]</strong>\n`;
    dbHtml += `Prepared Statement: SELECT * FROM users WHERE username = ?\n`;
    dbHtml += `Bound parameter value: ? = "${escapeHtml(text)}"\n`;
    dbHtml += `Simulation Status: <span style="color: var(--green)">SUCCESS (0 rows returned)</span>\n`;
    dbHtml += `Reason: The query interpreter evaluates the entire payload as a literal string value for username. SQL commands are ignored.`;
    
    dbOutput.innerHTML = dbHtml;
  };

  btn.addEventListener('click', analyze);
  input.addEventListener('input', analyze);
  if (input.value.trim()) analyze();
}

/* ==========================================================================
   5. HTTP REQUEST SMUGGLING LABORATORY
   ========================================================================== */
function initSmugglingLab() {
  const input = document.getElementById('smuggling-headers-input');
  const btn = document.getElementById('smuggling-analyze-btn');
  const output = document.getElementById('smuggling-output');

  if (!btn || !input || !output) return;

  const analyze = () => {
    updateConsoleLed(output, 'running');
    const raw = input.value.trim();
    if (!raw) {
      output.innerHTML = '<span class="comment">// Paste HTTP request headers or click a template above.</span>';
      updateConsoleLed(output, '');
      return;
    }

    let hasCl = false;
    let hasTe = false;
    let clVal = '';
    let teVal = '';

    raw.split(/\r?\n/).forEach(line => {
      const parts = line.split(':');
      if (parts.length >= 2) {
        const key = parts[0].trim().toLowerCase();
        const value = parts.slice(1).join(':').trim();
        if (key === 'content-length') {
          hasCl = true;
          clVal = value;
        }
        if (key === 'transfer-encoding') {
          hasTe = true;
          teVal = value;
        }
      }
    });

    let htmlReport = '';
    if (hasCl && hasTe) {
      htmlReport += `<div class="console-alert critical"><strong>⚠ DANGER: Header framing conflict detected! (Possible Smuggling Vector)</strong></div>\n`;
      htmlReport += `<strong>Message framing fields analyzed:</strong>\n`;
      htmlReport += `  - Content-Length: <code>${escapeHtml(clVal)}</code>\n`;
      htmlReport += `  - Transfer-Encoding: <code>${escapeHtml(teVal)}</code>\n\n`;
      
      // Classify smuggling type
      let type = "CL.TE or TE.CL";
      if (teVal.toLowerCase() === 'chunked') {
        type = "CL.TE / TE.CL boundary conflict";
      }

      htmlReport += `<strong>Smuggling Classification:</strong> ${type}\n`;
      htmlReport += `─`.repeat(45) + `\n`;
      htmlReport += `<strong>Vulnerability Analysis:</strong>\n`;
      htmlReport += `When an edge proxy (front-end) and a backend application server process message boundaries differently:\n`;
      htmlReport += `1. **If Front-end uses Content-Length** and **Backend uses Transfer-Encoding** (CL.TE), the backend processes the chunked payload and stops early. The remaining data is left in the socket buffer, prefixing the next user's incoming request.\n`;
      htmlReport += `2. **If Front-end uses Transfer-Encoding** and **Backend uses Content-Length** (TE.CL), the frontend forwards the entire chunked packet, but the backend reads only the Content-Length size, treating the rest of the chunk as a separate smuggled request.`;
      updateConsoleLed(output, 'alert');
    } else {
      htmlReport += `<div class="console-alert success">✓ FRAMING STABLE: No header smuggling conflict found.</div>\n`;
      htmlReport += `<strong>Analyzed parameters:</strong>\n`;
      htmlReport += `  - Content-Length present: ${hasCl ? 'Yes (' + clVal + ')' : 'No'}\n`;
      htmlReport += `  - Transfer-Encoding present: ${hasTe ? 'Yes (' + teVal + ')' : 'No'}\n\n`;
      htmlReport += `Both headers must be present to create the parsing boundary collision. Edge rules are compliant.`;
      updateConsoleLed(output, 'clean');
    }

    output.innerHTML = htmlReport;
  };

  btn.addEventListener('click', analyze);
  input.addEventListener('input', analyze);
  if (input.value.trim()) analyze();
}

/* ==========================================================================
   6. WAF BYPASS LABORATORY
   ========================================================================== */
function initWafLab() {
  const input = document.getElementById('waf-payload-input');
  const btn = document.getElementById('waf-generate-btn');
  const output = document.getElementById('waf-output');

  if (!btn || !input || !output) return;

  const generate = () => {
    updateConsoleLed(output, 'running');
    const payload = input.value.trim();
    if (!payload) {
      output.innerHTML = '<span class="comment">// Enter payload to generate encoding bypass mutations.</span>';
      updateConsoleLed(output, '');
      return;
    }

    const variants = [
      {
        tech: "Original Payload",
        val: payload
      },
      {
        tech: "URL Encoded",
        val: encodeURIComponent(payload)
      },
      {
        tech: "Double URL Encoded",
        val: encodeURIComponent(encodeURIComponent(payload))
      },
      {
        tech: "HTML Entity Encoded",
        val: htmlEncode(payload)
      },
      {
        tech: "SQL Mixed Case Mutation",
        val: mixedCase(payload)
      },
      {
        tech: "SQL Inline Comment Obfuscation",
        val: inlineCommentSQL(payload)
      },
      {
        tech: "Hex Character Codes",
        val: hexEncode(payload)
      },
      {
        tech: "Base64 Obfuscation",
        val: btoa(payload)
      }
    ];

    let htmlReport = '';
    htmlReport += `<div class="console-alert info">> Mutated payloads generated. Use these to test WAF parsing rules.</div>\n`;
    htmlReport += `<div class="bypass-list">\n`;
    
    variants.forEach((v, index) => {
      const uniqueId = `waf-val-${index}`;
      htmlReport += `  <div class="bypass-item">\n`;
      htmlReport += `    <div class="bypass-item-header">\n`;
      htmlReport += `      <span class="bypass-tech">${v.tech}</span>\n`;
      htmlReport += `      <button type="button" class="bypass-copy-btn" data-copy-id="${uniqueId}">Copy</button>\n`;
      htmlReport += `    </div>\n`;
      htmlReport += `    <div class="bypass-val" id="${uniqueId}">${escapeHtml(v.val)}</div>\n`;
      htmlReport += `  </div>\n`;
    });

    htmlReport += `</div>`;
    output.innerHTML = htmlReport;
    updateConsoleLed(output, 'clean');
  };

  btn.addEventListener('click', generate);
  input.addEventListener('input', generate);
  // one delegated listener instead of inline onclick handlers (keeps the strict CSP working)
  output.addEventListener('click', e => {
    const b = e.target.closest('.bypass-copy-btn');
    if (!b) return;
    const src = document.getElementById(b.dataset.copyId);
    if (src) safeCopy(src.textContent, b);
  });
  if (input.value.trim()) generate();
}

/* ==========================================================================
   ALGORITHM MUTATION HELPERS
   ========================================================================== */
function htmlEncode(str) {
  let buf = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code > 127 || [34, 38, 39, 60, 62, 40, 41, 45, 59].includes(code)) {
      buf.push('&#' + code + ';');
    } else {
      buf.push(str.charAt(i));
    }
  }
  return buf.join('');
}

function mixedCase(str) {
  return str.split('').map((char, index) => {
    return index % 2 === 0 ? char.toUpperCase() : char.toLowerCase();
  }).join('');
}

function inlineCommentSQL(str) {
  return str.replace(/\s+/g, '/**/');
}

function hexEncode(str) {
  let hex = '';
  for(let i=0; i<str.length; i++) {
    hex += '\\x' + str.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return hex;
}
