# Technical Report

## Project Title

Elene's Security Scanner Platform

## Author

Elene Iaseshvili

## 1. Project Overview

Elene's Security Scanner Platform is a web-based security analysis platform designed to inspect public technical trust signals of domains and email sender domains.

The system allows a user to enter a domain or email address and receive a structured report containing DNS records, mail security configuration, SSL certificate status, HTTP response information, security headers, heuristic threat indicators, network diagnostics and PDF export.

The project was developed as a bachelor project prototype with a focus on practical cybersecurity analysis, clean user interface, modular backend structure and live demonstration readiness.

## 2. Problem Statement

Users frequently receive unknown links, domains and email messages. Determining whether a sender domain or website has a reliable technical configuration usually requires multiple separate tools and technical knowledge.

A complete manual check may involve DNS lookup tools, SSL inspection tools, HTTP header analyzers, mail authentication validators and network diagnostic utilities.

The main problem addressed by this project is the lack of a single simple platform that combines these public trust signals into one readable technical report.

## 3. Project Goal

The goal of the project is to build a functional platform that can:

- validate a domain or email address before scanning;
- check public DNS configuration;
- analyze email authentication records;
- inspect SSL certificate status;
- inspect HTTP response and security headers;
- identify basic heuristic threat indicators;
- provide live network diagnostics;
- export the final report as a PDF file;
- present all results in a clean and user-friendly interface.

The system is not an antivirus, malware sandbox or final reputation authority. It analyzes public technical signals and presents them in a structured form.

## 4. Functional Requirements

The platform supports the following functional requirements:

- domain scan;
- email sender domain scan;
- invalid input prevention;
- DNS records lookup;
- MX, SPF, DMARC and DKIM checks;
- SSL certificate analysis;
- HTTP status and redirect analysis;
- security headers inspection;
- heuristic threat analysis;
- ping and traceroute diagnostics;
- PDF report export;
- responsive web interface.

## 5. Non-Functional Requirements

The platform is designed according to the following non-functional requirements:

- stable live demo execution;
- clear and minimal user interface;
- modular backend architecture;
- readable report output;
- safe environment variable handling;
- no secret values in the public repository;
- responsive layout for desktop and mobile screens;
- maintainable source code structure;
- version control through Git and GitHub.

## 6. Technology Stack

The project uses the following technologies:

- Node.js for server-side runtime;
- Express.js for web server and routing;
- EJS for server-side page rendering;
- Vanilla JavaScript for frontend interactions;
- CSS for interface styling;
- Node.js DNS resolver for DNS lookups;
- Axios for HTTP requests;
- Playwright Chromium for PDF generation;
- PM2 for production process management;
- Git and GitHub for version control.

## 7. System Architecture

The system follows a modular server-rendered architecture.

Main layers:

- Client Layer: browser, forms, report UI and frontend interactions;
- Routing Layer: web routes and API routes;
- Controller Layer: request handling and response preparation;
- Service Layer: DNS, SSL, HTTP, mail, threat and diagnostics logic;
- View Layer: EJS templates;
- Static Layer: CSS and frontend assets.

The user submits a target from the homepage. The backend validates the input, builds the report object through multiple services and renders the report page using EJS templates.

## 8. Main Data Flow

The main scan flow is:

1. User enters a domain or email address.
2. Frontend sends validation request to `/api/validate-target`.
3. Backend validates format and checks DNS existence.
4. If valid, the user is redirected to `/scan?domain=...`.
5. Backend normalizes the target.
6. Report builder calls DNS, mail, SSL, HTTP, domain info, threat and score services.
7. Results are merged into one report object.
8. EJS renders the final report page.
9. User can run diagnostics or export the report as PDF.

## 9. Report Page Modules

The report page contains the following modules:

### 9.1 Report Header

Displays the scanned domain and provides the PDF export action.

### 9.2 Detected Issues

Shows the most important detected configuration problems and warnings.

### 9.3 Domain Information

Displays public domain-related information such as registrar, nameservers, creation date, expiration date and status when available.

### 9.4 Threat Analysis

Uses heuristic checks to identify suspicious indicators such as login forms, sensitive keywords, redirects, external scripts and JavaScript obfuscation signals.

### 9.5 Technical Footprint

Summarizes technical indicators extracted from the domain, webpage and threat analysis process.

### 9.6 Network Diagnostics

Provides live ping and traceroute style diagnostic output.

### 9.7 DNS Records

Displays public DNS records such as A, AAAA, NS, MX, TXT, SPF, DMARC, SOA, CAA and DS.

### 9.8 Mail Security

Checks sender domain mail security configuration including MX, SPF, DKIM, DMARC, MTA-STS and TLS-RPT.

### 9.9 Email Trust Summary

Appears for email-based scans and summarizes the sender domain trust level as High, Medium or Low.

### 9.10 Website and Headers

Inspects HTTP status, redirects, final URL and key security headers.

### 9.11 PDF Export

Generates a clean PDF version of the report through Playwright Chromium.

## 10. Security Considerations

The platform does not store scanned targets in a database and does not require user authentication.

Sensitive configuration values are stored in `.env` and excluded from Git through `.gitignore`.

The public repository includes `.env.example` instead of real environment values.

The scanner only uses public technical data and does not access private mailboxes, private DNS zones or protected systems.

## 11. Limitations

The platform has the following limitations:

- DKIM detection depends on known selector patterns;
- threat analysis is heuristic and not a malware sandbox;
- HTTP headers may differ depending on region, user-agent or CDN behavior;
- DNS results may be affected by propagation time;
- mail security checks validate domain configuration, not a specific email message.

## 12. Future Improvements

Future versions may include:

- user accounts;
- scan history;
- scheduled monitoring;
- more DKIM selector discovery methods;
- deeper reputation intelligence;
- external threat intelligence integrations;
- admin dashboard;
- report sharing links.

## 13. Conclusion

Elene's Security Scanner Platform provides a practical and unified way to inspect public domain and email security signals.

The platform combines several technical checks into one readable report and can be used as a live demonstration prototype for cybersecurity-oriented domain trust analysis.
