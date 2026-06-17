# Elene's Security Scanner Platform

Elene's Security Scanner Platform is a web-based domain, DNS, email security, SSL, HTTP headers and threat signal scanner built as a bachelor project prototype.

The platform allows users to enter a domain or email address and receive a structured technical report about public trust signals of the target domain.

## Main Features

- Domain and email input validation
- Public DNS record lookup
- MX, SPF, DMARC and DKIM checks
- Email sender domain trust summary
- SSL certificate inspection
- HTTP status and redirect analysis
- Security headers inspection
- Heuristic threat analysis
- Network diagnostics
- PDF report export
- Responsive web interface

## Technology Stack

- Node.js
- Express.js
- EJS templates
- Vanilla JavaScript
- CSS
- Node.js DNS resolver
- Axios
- Playwright Chromium
- PM2 for production process management

## Project Structure

~~~text
elene-project/
├── public/
│   └── assets/
│       └── css/
├── src/
│   ├── controllers/
│   ├── routes/
│   ├── services/
│   ├── utils/
│   └── server.js
├── views/
│   ├── pages/
│   └── partials/
├── .env.example
├── .gitignore
├── package.json
├── package-lock.json
└── README.md
~~~

## Installation

~~~bash
npm install
cp .env.example .env
npm start
~~~

## Environment Variables

~~~env
APP_NAME="Elene Project"
APP_ENV=production
APP_URL=https://elene.exe.ge

HOST=172.19.0.1
PORT=8090

RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=60
~~~

## Available Scripts

~~~bash
npm start
npm run dev
~~~

## Web Routes

| Method | Route | Description |
|---|---|---|
| GET | `/` | Home page with scanner form |
| GET | `/scan?domain=example.com` | Full technical report page |
| GET | `/scan/export.pdf?domain=example.com` | PDF export of the report |

## API Routes

| Method | Route | Description |
|---|---|---|
| GET | `/api/health` | Health check endpoint |
| GET | `/api/validate-target?target=example.com` | Validates domain or email before scan |

## Example Usage

Domain scan:

~~~text
example.com
~~~

Email sender domain scan:

~~~text
support@example.com
~~~

The platform extracts the domain from the email address and checks the public mail security configuration of that sender domain.

## Important Notes

This platform checks public technical trust signals. It does not prove that a specific email was actually sent by the mailbox owner and it does not replace an antivirus, malware sandbox or enterprise security gateway.

The threat analysis module is heuristic and should be interpreted as a technical signal, not as a final security verdict.

## Bachelor Project Components

This repository contains the source code of the working prototype. The full bachelor project package also includes:

- Technical documentation
- Architecture and UML diagrams
- API documentation
- Installation and configuration guide
- User manual
- Final presentation slide deck
- Live demo

## Author

Elene Iaseshvili
