# Full Security Assessment Tool

Comprehensive, automated security assessment tool covering **all 7 evaluation scope areas** required for enterprise security compliance:

1. **Authentication and Session Management** (cookie flags `HttpOnly`, `Secure`, `SameSite`, session token lifecycle)
2. **Authorization and Access Control** (unauthenticated access to internal/admin routes, middleware bot gate bypass)
3. **Input Validation and Data Handling** (dependency vulnerabilities via `npm audit` + SAST detection of DOM XSS sinks via `trustedHtml` bypass)
4. **API Security** (CORS wildcard reflection, wildcard origins on routes accepting Authorization, HTTP method tampering)
5. **Client-Side Security Controls** (missing headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, plus cryptographically broken static CSP nonces)
6. **Secure Communication Mechanisms** (Strict-Transport-Security / HSTS enforcement)
7. **Data Storage and Privacy Protections** (unencrypted sensitive state in `localStorage`, unconsented analytics tracking telemetry)

---

## Deliverables Compliance
Every discovered vulnerability includes:
- **Title**
- **Description**
- **Affected Component**
- **Severity Rating & CVSS v3.1** (Score, Rating, and Vector String)
- **Steps to Reproduce**
- **Safe Proof of Concept (PoC)** (curl request, response snippets, or code references)
- **Business Impact Assessment**
- **Remediation Recommendations**

---

## Setup & Running

### 1. Start the Target Application
Run your target application (e.g. World Monitor dev server):
```powershell
cd D:\2\worldmonitor
npm run dev
# Starts World Monitor on http://localhost:3000 (or http://localhost:5173)
```

### 2. Run the Assessment Tool
```powershell
cd D:\2
$env:SOURCE_DIR="D:\2\worldmonitor"
$env:APP_URL="http://localhost:3000"
$env:PORT="4500"
node server.js
```

### 3. Access Dashboard & Export Report
1. Open **`http://localhost:4500`** in your browser.
2. Click **"Run Full Assessment"** to scan all 7 scopes simultaneously.
3. Filter findings by scope using the interactive filter tabs.
4. Click **"Download Report (Markdown)"** or **"Download Report (JSON)"** to export complete assessment deliverables ready for review.
