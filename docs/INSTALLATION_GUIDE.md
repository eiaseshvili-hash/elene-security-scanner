# Installation and Configuration Guide

## Project

Elene's Security Scanner Platform

## Author

Elene Iaseshvili

## 1. Requirements

Required software:

- Node.js 20 or newer
- npm
- Git
- PM2 for production process management
- Playwright Chromium for PDF export
- Linux server environment for production deployment

## 2. Clone Repository

~~~bash
git clone https://github.com/eiaseshvili-hash/elene-security-scanner.git
cd elene-security-scanner
~~~

## 3. Install Dependencies

~~~bash
npm install
~~~

Main dependencies:

- express
- ejs
- dotenv
- axios
- helmet
- morgan
- validator
- playwright
- sharp

## 4. Environment Configuration

Create `.env` file from `.env.example`:

~~~bash
cp .env.example .env
~~~

Example configuration:

~~~env
APP_NAME="Elene Project"
APP_ENV=production
APP_URL=https://elene.exe.ge

HOST=172.19.0.1
PORT=8090

RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=60
~~~

The `.env` file contains runtime configuration and must not be committed to GitHub.

## 5. Development Run

~~~bash
npm run dev
~~~

This starts the application in development mode using Node.js watch mode.

## 6. Production Run

~~~bash
npm start
~~~

For production process management, PM2 can be used:

~~~bash
pm2 start src/server.js --name elene-project
pm2 save
~~~

Restart command:

~~~bash
pm2 restart elene-project
~~~

Status check:

~~~bash
pm2 status
~~~

## 7. Playwright Setup

PDF export requires Playwright Chromium.

Install browser binaries:

~~~bash
npx playwright install chromium
~~~

The export endpoint uses Chromium to render the report page and generate a PDF file.

## 8. Application Routes

Web routes:

- `/`
- `/scan?domain=example.com`
- `/scan/export.pdf?domain=example.com`

API routes:

- `/api/health`
- `/api/validate-target`
- `/api/scan-domain`
- `/api/diagnostics`
- `/api/threat-analysis`

## 9. Deployment Notes

Production deployment flow:

1. Pull latest code from GitHub.
2. Install dependencies with `npm install`.
3. Configure `.env`.
4. Install Playwright Chromium.
5. Start or restart the app with PM2.
6. Verify `/api/health`.
7. Test home page and scan page.

Health check:

~~~bash
curl http://172.19.0.1:8090/api/health
~~~

Expected response:

~~~json
{
  "ok": true,
  "app": "elene-project",
  "status": "running"
}
~~~

## 10. Security Notes

- `.env` is excluded from Git.
- `node_modules` is excluded from Git.
- generated PDF files are excluded from Git.
- zip archives are excluded from Git.
- only `.env.example` is included for documentation.
- GitHub tokens and server credentials must never be stored in the repository.

## 11. Verification Checklist

Before live demo:

- application is running with PM2;
- `/api/health` returns success;
- home page opens correctly;
- valid domain scan works;
- email scan works;
- invalid input validation works;
- PDF export works;
- diagnostics module works;
- GitHub repository is up to date.
