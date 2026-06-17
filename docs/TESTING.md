# Testing Documentation

## Project

Elene's Security Scanner Platform

## Author

Elene Iaseshvili

## 1. Testing Goal

The goal of testing is to verify that the platform works correctly during live demo and handles common user scenarios safely.

## 2. Test Environment

Production-like environment:

- Node.js application
- PM2 process manager
- public domain access
- internal server port `172.19.0.1:8090`
- GitHub source code repository

## 3. Smoke Tests

### 3.1 Health Check

Endpoint:

~~~http
GET /api/health
~~~

Expected result:

~~~json
{
  "ok": true,
  "app": "elene-project",
  "status": "running"
}
~~~

### 3.2 Home Page

Test:

Open the home page.

Expected result:

- page loads successfully;
- scanner form is visible;
- layout is responsive;
- no visible server error.

### 3.3 Valid Domain Scan

Input:

~~~text
example.com
~~~

Expected result:

- validation succeeds;
- report page opens;
- DNS and website sections are displayed.

### 3.4 Valid Email Scan

Input:

~~~text
support@example.com
~~~

Expected result:

- system extracts domain part;
- report page opens;
- Email Trust Summary is displayed;
- Mail Security section is displayed.

### 3.5 Invalid Text Input

Input:

~~~text
random text
~~~

Expected result:

- scan does not start;
- user receives validation error;
- report page is not opened.

### 3.6 Nonexistent Domain

Input:

~~~text
not-real-domain-example-12345.com
~~~

Expected result:

- DNS existence check fails;
- user receives not found message;
- scan does not start.

### 3.7 PDF Export

Test:

Click `Export Full Report`.

Expected result:

- loading state appears;
- PDF is generated;
- PDF downloads successfully;
- no blank tab is opened.

### 3.8 Network Diagnostics

Test:

Run diagnostics from report page.

Expected result:

- ping result is displayed;
- traceroute result is displayed;
- output is shown in terminal-style blocks.

## 4. Security Tests

Checked items:

- `.env` is not committed;
- `node_modules` is not committed;
- generated PDFs are ignored;
- GitHub token is not stored in repository;
- invalid input is blocked before scan;
- unknown domains do not redirect to report page.

## 5. Repository Verification

Expected GitHub structure:

- `src/`
- `views/`
- `public/`
- `docs/`
- `.env.example`
- `.gitignore`
- `README.md`
- `package.json`
- `package-lock.json`

Expected version control evidence:

- meaningful commits;
- documentation branches;
- merged pull requests;
- clean main branch.

## 6. Live Demo Checklist

Before presentation:

- PM2 process is running;
- GitHub repository is accessible;
- home page loads;
- domain scan works;
- email scan works;
- validation error works;
- report page loads;
- PDF export works;
- diagnostics works.

