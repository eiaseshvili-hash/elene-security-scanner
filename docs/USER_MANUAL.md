# User Manual

## Project

Elene's Security Scanner Platform

## Author

Elene Iaseshvili

## 1. Purpose

This user manual explains how to use Elene's Security Scanner Platform to scan domains and email sender domains.

The platform is designed for users who want to quickly inspect public technical trust signals of a domain, website or email sender domain.

## 2. Home Page

The home page contains the main scanner form.

User actions:

1. Open the platform.
2. Enter a domain or email address.
3. Click the scan button.
4. Wait for validation.
5. View the generated report.

Supported input examples:

~~~text
example.com
support@example.com
~~~

Invalid examples:

~~~text
random text
https://example.com/path
example
~~~

If the input is invalid or the domain does not exist in public DNS, the system displays an error message and does not start the scan.

## 3. Domain Scan Use Case

Use case:

A user wants to check the public technical configuration of a domain.

Steps:

1. Enter `example.com`.
2. Click scan.
3. System validates the domain.
4. System opens the report page.
5. User reviews DNS, SSL, HTTP headers, threat analysis and mail security sections.

Expected result:

The platform displays a complete technical report for the domain.

## 4. Email Sender Domain Scan Use Case

Use case:

A user receives an email from an unknown sender and wants to check the sender domain.

Steps:

1. Enter `support@example.com`.
2. System extracts `example.com`.
3. System checks the email sender domain configuration.
4. User reviews Email Trust Summary and Mail Security sections.

Expected result:

The platform shows whether the sender domain has strong, partial or weak public email authentication signals.

Important note:

The platform checks the sender domain configuration. It does not prove that a specific email message was actually sent by the mailbox owner.

## 5. Report Page

The report page contains the full technical result.

Main sections:

- Report Header
- Detected Issues
- Domain Information
- Threat Analysis
- Technical Footprint
- Network Diagnostics
- DNS Records
- Mail Security
- Email Trust Summary
- Website and Headers
- PDF Export

## 6. Detected Issues

This section shows the most important warnings found during the scan.

Examples:

- missing DMARC policy;
- missing security header;
- weak email authentication configuration;
- DNSSEC-related missing record;
- unreachable website response.

## 7. DNS Records

This section displays public DNS records.

Supported record types:

- A
- AAAA
- NS
- MX
- TXT
- SPF
- DMARC
- SOA
- CAA
- DS

The user can review the technical DNS configuration of the scanned domain.

## 8. Mail Security

This section checks email security configuration.

Checked signals:

- MX
- SPF
- DKIM
- DMARC
- MTA-STS
- TLS-RPT

The section helps users understand how well the domain is protected against email spoofing.

## 9. Website and Headers

This section displays:

- reachable status;
- HTTP status code;
- redirect count;
- final URL;
- Strict-Transport-Security;
- Content-Security-Policy;
- X-Frame-Options;
- X-Content-Type-Options;
- Referrer-Policy;
- Permissions-Policy.

Missing headers are shown as technical warnings, not as final proof of malicious behavior.

## 10. Threat Analysis

Threat Analysis shows heuristic suspicious indicators.

The system checks:

- login forms;
- password fields;
- sensitive keywords;
- external scripts;
- redirect behavior;
- obfuscation indicators;
- SSL trust;
- IP information.

The result should be treated as a technical signal, not as an antivirus verdict.

## 11. Network Diagnostics

The user can run network diagnostics from the report page.

The diagnostics module displays:

- ping output;
- traceroute output;
- latency and routing information.

This is useful for connectivity and availability checks.

## 12. PDF Export

The user can export the report by clicking `Export Full Report`.

Expected behavior:

1. The export button shows loading progress.
2. Backend generates the PDF.
3. Browser downloads the report file.
4. No blank browser tab is opened.

## 13. Screenshot References

Screenshots should be included in the final written report for:

- home page;
- valid domain scan;
- email sender scan;
- invalid input validation;
- report page;
- DNS Records section;
- Mail Security section;
- Website and Headers section;
- PDF export result.

