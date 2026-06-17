# Architecture and System Diagrams

## Project

Elene's Security Scanner Platform

## Author

Elene Iaseshvili

## 1. System Architecture Diagram

~~~mermaid
flowchart TD
    User[User Browser] --> Home[Home Page]
    Home --> ValidateAPI[/API: validate-target/]
    ValidateAPI --> DNSResolver[DNS Resolver]

    ValidateAPI -->|Valid target| ScanPage[Report Page]
    ScanPage --> ReportController[Domain Report Controller]

    ReportController --> DNSService[DNS Service]
    ReportController --> SSLService[SSL Service]
    ReportController --> HTTPService[HTTP Service]
    ReportController --> MailService[Mail Security Service]
    ReportController --> DomainInfoService[Domain Info Service]
    ReportController --> ThreatService[Threat Analysis Service]
    ReportController --> ScoreService[Score Service]

    DNSService --> PublicDNS[Public DNS Records]
    SSLService --> TLS[SSL/TLS Certificate]
    HTTPService --> Website[Target Website]
    MailService --> MailDNS[MX/SPF/DKIM/DMARC Records]
    DomainInfoService --> Whois[WHOIS/RDAP Data]
    ThreatService --> PageSignals[HTML, Redirects, Forms, Scripts]

    ReportController --> ReportObject[Unified Report Object]
    ReportObject --> EJS[EJS Templates]
    EJS --> UI[Rendered Report Page]
~~~

## 2. Request Flow Diagram

~~~mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant A as API
    participant D as DNS Resolver
    participant R as Report Builder
    participant S as Services
    participant V as EJS View

    U->>F: Enter domain or email
    F->>A: GET /api/validate-target
    A->>D: Check NS/A/AAAA/MX records
    D-->>A: DNS result
    A-->>F: Validation response

    alt Valid target
        F->>R: GET /scan?domain=target
        R->>S: Run DNS, SSL, HTTP, Mail, Threat checks
        S-->>R: Service reports
        R->>V: Send unified report object
        V-->>U: Render report page
    else Invalid target
        F-->>U: Show validation error
    end
~~~

## 3. Report Builder Component Diagram

~~~mermaid
flowchart LR
    Input[Normalized Target] --> Builder[buildDomainReport]

    Builder --> DNS[getDnsReport]
    Builder --> SSL[getSslReport]
    Builder --> HTTP[getHttpReport]
    Builder --> Mail[getMailReport]
    Builder --> DomainInfo[getDomainInfoReport]
    Builder --> Threat[getThreatReport]
    Builder --> Score[calculateScore]

    DNS --> Report[Report Object]
    SSL --> Report
    HTTP --> Report
    Mail --> Report
    DomainInfo --> Report
    Threat --> Report
    Score --> Report

    Report --> Page[Report Page]
    Report --> PDF[PDF Export]
    Report --> API[JSON API Response]
~~~

## 4. Use Case Diagram

~~~mermaid
flowchart TD
    User[User]

    User --> UC1[Scan domain]
    User --> UC2[Scan email sender domain]
    User --> UC3[View DNS records]
    User --> UC4[View mail security]
    User --> UC5[View website headers]
    User --> UC6[Run network diagnostics]
    User --> UC7[Export report as PDF]

    UC1 --> System[Elene Security Scanner Platform]
    UC2 --> System
    UC3 --> System
    UC4 --> System
    UC5 --> System
    UC6 --> System
    UC7 --> System
~~~

## 5. Deployment Diagram

~~~mermaid
flowchart TD
    Browser[User Browser] --> HTTPS[HTTPS Request]
    HTTPS --> Proxy[Web Server / Reverse Proxy]
    Proxy --> NodeApp[Node.js Express App]
    NodeApp --> PM2[PM2 Process Manager]
    NodeApp --> PublicInternet[Public Internet Services]

    PublicInternet --> DNS[DNS Resolvers]
    PublicInternet --> Websites[Target Websites]
    PublicInternet --> MailRecords[Mail DNS Records]
    PublicInternet --> SSL[SSL Certificate Data]

    NodeApp --> Playwright[Playwright Chromium]
    Playwright --> PDF[Generated PDF Report]

    NodeApp --> Views[EJS Views]
    NodeApp --> Static[Public CSS Assets]
~~~

## 6. Data Flow Summary

The system receives a domain or email address from the user and validates it before running the scan.

For email input, the system extracts the domain part and performs all technical checks against that sender domain.

The backend collects public data from DNS, SSL, HTTP, mail security and threat analysis services. These results are merged into a unified report object and rendered through EJS templates.

The same report object can be used for the web report page, JSON API response and PDF export.

## 7. Architecture Notes

The project follows a modular architecture:

- routes define web and API endpoints;
- controllers handle request processing;
- services contain technical scan logic;
- utilities normalize input and handle async operations;
- views render the user interface;
- public assets control styling and frontend presentation.

This separation improves maintainability and makes each module easier to test and document.
