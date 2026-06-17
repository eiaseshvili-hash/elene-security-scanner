# API Documentation

## Project

Elene's Security Scanner Platform

## Author

Elene Iaseshvili

## Base URL

Production:

~~~text
https://elene.exe.ge
~~~

Local / server internal:

~~~text
http://172.19.0.1:8090
~~~

## 1. Web Routes

### 1.1 Home Page

~~~http
GET /
~~~

Renders the main scanner page.

Purpose:

- displays the domain/email scan form;
- allows the user to enter a target;
- validates the target before redirecting to the report page.

Response:

~~~text
HTML page
~~~

---

### 1.2 Report Page

~~~http
GET /scan?domain=example.com
~~~

Renders the full technical report page for a domain or email sender domain.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| domain | string | yes | Domain or email address to scan |

Example:

~~~http
GET /scan?domain=example.com
~~~

Email example:

~~~http
GET /scan?domain=support@example.com
~~~

Response:

~~~text
HTML report page
~~~

Main report modules:

- detected issues;
- domain information;
- threat analysis;
- DNS records;
- mail security;
- email trust summary;
- website and headers;
- network diagnostics;
- PDF export.

---

### 1.3 PDF Export

~~~http
GET /scan/export.pdf?domain=example.com
~~~

Generates and downloads a PDF version of the report.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| domain | string | yes | Domain or email address to export report for |

Example:

~~~http
GET /scan/export.pdf?domain=example.com
~~~

Response:

~~~http
Content-Type: application/pdf
Content-Disposition: attachment
~~~

Technical flow:

1. Backend receives the target.
2. Playwright Chromium opens the report page in PDF mode.
3. Non-essential UI elements are hidden.
4. A clean PDF report is generated.
5. The file is returned as a downloadable response.

## 2. API Routes

All API routes are registered under the `/api` prefix.

---

## 2.1 Health Check

~~~http
GET /api/health
~~~

Checks whether the backend application is running.

Response example:

~~~json
{
  "ok": true,
  "app": "elene-project",
  "status": "running",
  "time": "2026-06-17T10:00:00.000Z"
}
~~~

Use case:

- server status monitoring;
- quick deployment verification;
- demo readiness check.

---

## 2.2 Validate Target

~~~http
GET /api/validate-target?target=example.com
POST /api/validate-target
~~~

Validates a domain or email address before starting the scan.

Accepted query/body parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| target | string | yes | Domain or email address |
| domain | string | optional | Alternative parameter name |

Valid domain example:

~~~http
GET /api/validate-target?target=example.com
~~~

Valid email example:

~~~http
GET /api/validate-target?target=support@example.com
~~~

Successful response:

~~~json
{
  "ok": true,
  "type": "domain",
  "input": "example.com",
  "domain": "example.com",
  "message": "Target found."
}
~~~

Email response:

~~~json
{
  "ok": true,
  "type": "email",
  "input": "support@example.com",
  "domain": "example.com",
  "message": "Target found."
}
~~~

Invalid format response:

~~~json
{
  "ok": false,
  "reason": "invalid_domain",
  "message": "Enter a valid domain, for example example.com."
}
~~~

Not found response:

~~~json
{
  "ok": false,
  "reason": "not_found",
  "type": "domain",
  "input": "not-real-domain.example",
  "domain": "not-real-domain.example",
  "message": "This domain was not found in public DNS."
}
~~~

Technical flow:

1. Request is received by `validateScanTargetApi`.
2. Input is trimmed and parsed.
3. System detects whether input is a domain or email.
4. Email input is converted to its domain part.
5. Domain format is validated.
6. DNS existence is checked through NS, A, AAAA and MX lookups.
7. JSON response is returned.

---

## 2.3 Domain Scan API

~~~http
GET /api/scan-domain?domain=example.com
~~~

Returns the complete report object as JSON.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| domain | string | yes | Domain or email address to scan |

Example:

~~~http
GET /api/scan-domain?domain=example.com
~~~

Response:

~~~json
{
  "domain": "example.com",
  "dnsReport": {},
  "sslReport": {},
  "httpReport": {},
  "mailReport": {},
  "threatReport": {},
  "scoreReport": {}
}
~~~

Technical flow:

1. Request is handled by `scanDomainApi`.
2. Backend calls `buildDomainReport`.
3. The report builder calls multiple services.
4. Results are merged into a single report object.
5. JSON response is returned.

Used services:

- DNS service;
- SSL service;
- HTTP service;
- Mail service;
- Domain info service;
- Threat service;
- Score service.

---

## 2.4 Diagnostics API

~~~http
GET /api/diagnostics?domain=example.com
POST /api/diagnostics
~~~

Runs network diagnostics for the target domain.

Accepted parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| domain | string | yes | Domain to diagnose |

Example:

~~~http
GET /api/diagnostics?domain=example.com
~~~

Response example:

~~~json
{
  "ok": true,
  "domain": "example.com",
  "ping": "...",
  "traceroute": "..."
}
~~~

Technical flow:

1. Request is handled by `runDiagnosticsApi`.
2. Backend normalizes the target domain.
3. Diagnostics service runs ping/traceroute logic.
4. Output is returned as structured JSON.
5. Frontend displays the result in terminal-style blocks.

Use case:

- check network reachability;
- inspect latency;
- inspect routing path;
- debug connectivity issues.

---

## 2.5 Threat Analysis API

~~~http
GET /api/threat-analysis?domain=example.com
POST /api/threat-analysis
~~~

Runs heuristic threat analysis for a domain.

Accepted parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| domain | string | yes | Domain to analyze |

Example:

~~~http
GET /api/threat-analysis?domain=example.com
~~~

Response example:

~~~json
{
  "ok": true,
  "domain": "example.com",
  "riskLevel": "low",
  "signals": []
}
~~~

Technical flow:

1. Request is handled by `runThreatAnalysisApi`.
2. Backend calls the threat analysis service.
3. The service fetches website response data.
4. It checks redirects, forms, password fields, sensitive keywords, external scripts and obfuscation indicators.
5. A heuristic risk result is returned.

Important note:

Threat analysis is heuristic. It does not replace antivirus scanning, malware sandboxing or enterprise security gateways.

## 3. Main Backend Services

### 3.1 DNS Service

Function:

~~~text
getDnsReport(domain)
~~~

Responsible for:

- A records;
- AAAA records;
- NS records;
- MX records;
- TXT records;
- SPF;
- DMARC;
- SOA;
- CAA;
- DS.

### 3.2 Mail Service

Function:

~~~text
getMailReport(domain, dnsReport)
~~~

Responsible for:

- MX detection;
- SPF analysis;
- SPF policy detection;
- DMARC detection;
- DMARC policy detection;
- DKIM selector checks;
- MTA-STS;
- TLS-RPT;
- email trust scoring.

### 3.3 SSL Service

Function:

~~~text
getSslReport(domain)
~~~

Responsible for:

- certificate availability;
- issuer;
- valid from;
- valid to;
- remaining days;
- certificate validity status.

### 3.4 HTTP Service

Function:

~~~text
getHttpReport(domain)
~~~

Responsible for:

- reachable status;
- HTTP status code;
- redirect chain;
- final URL;
- response headers;
- security headers.

### 3.5 Threat Service

Function:

~~~text
getThreatReport(input)
~~~

Responsible for:

- page metadata;
- forms;
- password fields;
- sensitive words;
- external scripts;
- obfuscation signals;
- redirects;
- heuristic risk level.

### 3.6 Diagnostics Service

Function:

~~~text
getDiagnosticsReport(input)
~~~

Responsible for:

- ping output;
- traceroute output;
- network reachability information.

### 3.7 Score Service

Function:

~~~text
calculateScore({ dnsReport, sslReport, httpReport, mailReport })
~~~

Responsible for:

- combining scan signals;
- calculating overall score;
- generating grade-level summary.

## 4. Error Handling

The backend uses async route handlers and centralized error middleware.

Common error scenarios:

- missing domain parameter;
- invalid target format;
- DNS lookup failure;
- HTTP request timeout;
- unavailable website;
- PDF generation failure;
- diagnostics command failure.

The system returns user-readable messages and avoids exposing internal server details.

## 5. Security Notes

- Real `.env` file is ignored by Git.
- `.env.example` is included for setup documentation.
- No GitHub token or secret value is stored in the repository.
- The scanner only uses public technical information.
- The system does not access private inboxes or private DNS zones.
