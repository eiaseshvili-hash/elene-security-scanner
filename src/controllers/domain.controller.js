import dns from "node:dns/promises";
import { normalizeDomain, detectScanInputType } from "../utils/domain.util.js";
import { getDomainInfoReport } from "../services/domain-info.service.js";
import { getDnsReport } from "../services/dns.service.js";
import { getSslReport } from "../services/ssl.service.js";
import { getHttpReport } from "../services/http.service.js";
import { getMailReport } from "../services/mail.service.js";
import { calculateScore } from "../services/score.service.js";
import { getThreatReport } from "../services/threat.service.js";
import { chromium } from "playwright";

const DOMAIN_REGEX = /^(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;

function parseScanTarget(input) {
  const raw = String(input || "").trim();

  if (!raw) {
    return {
      ok: false,
      reason: "empty",
      message: "Enter a domain or email address."
    };
  }

  if (raw.includes("://") || raw.includes("/") || raw.includes("?") || raw.includes("#")) {
    return {
      ok: false,
      reason: "invalid_format",
      message: "Enter only a domain or email address, not a full URL."
    };
  }

  if (raw.includes("@")) {
    if (!EMAIL_REGEX.test(raw)) {
      return {
        ok: false,
        reason: "invalid_email",
        message: "Enter a valid email address."
      };
    }

    const domain = raw.split("@").pop().toLowerCase();

    if (!DOMAIN_REGEX.test(domain)) {
      return {
        ok: false,
        reason: "invalid_email_domain",
        message: "The email domain format is invalid."
      };
    }

    return {
      ok: true,
      type: "email",
      input: raw,
      domain
    };
  }

  const domain = raw.toLowerCase();

  if (!DOMAIN_REGEX.test(domain)) {
    return {
      ok: false,
      reason: "invalid_domain",
      message: "Enter a valid domain, for example example.com."
    };
  }

  return {
    ok: true,
    type: "domain",
    input: domain,
    domain
  };
}

async function domainExistsInDns(domain) {
  const checks = [
    () => dns.resolveNs(domain),
    () => dns.resolve4(domain),
    () => dns.resolve6(domain),
    () => dns.resolveMx(domain)
  ];

  for (const check of checks) {
    try {
      const records = await check();
      if (Array.isArray(records) && records.length > 0) {
        return true;
      }
    } catch {
      // try next DNS record type
    }
  }

  return false;
}

export async function validateScanTargetApi(req, res) {
  const parsed = parseScanTarget(req.query.target || req.body?.target || req.query.domain || req.body?.domain);

  if (!parsed.ok) {
    return res.status(400).json(parsed);
  }

  const exists = await domainExistsInDns(parsed.domain);

  if (!exists) {
    return res.status(404).json({
      ok: false,
      reason: "not_found",
      type: parsed.type,
      input: parsed.input,
      domain: parsed.domain,
      message: parsed.type === "email"
        ? "The email domain was not found in public DNS."
        : "This domain was not found in public DNS."
    });
  }

  return res.json({
    ok: true,
    type: parsed.type,
    input: parsed.input,
    domain: parsed.domain,
    message: "Target found."
  });
}

function buildEmailTrustReport({ originalInput, domain, mailReport }) {
  if (!originalInput || !originalInput.includes("@")) return null;

  const hasMx = Boolean(mailReport?.hasMx);
  const spfOk = mailReport?.spf?.analysis?.status === "ok";
  const dkimFound = Boolean(mailReport?.dkim?.found);
  const dmarcPolicy = mailReport?.dmarc?.analysis?.policy || null;
  const dmarcProtected = ["quarantine", "reject"].includes(dmarcPolicy);
  const mtaStsFound = Boolean(mailReport?.mtaSts?.found);
  const tlsRptFound = Boolean(mailReport?.tlsRpt?.found);

  let score = 0;

  if (hasMx) score += 20;
  if (spfOk) score += 20;
  if (dkimFound) score += 20;
  if (dmarcProtected) score += 25;
  if (mtaStsFound) score += 8;
  if (tlsRptFound) score += 7;

  let level = "high";
  let verdict = "High trust";
  let summary = "This sender domain has strong mail authentication signals.";

  if (score < 45) {
    level = "low";
    verdict = "Low trust";
    summary = "This sender domain has weak or missing mail authentication. Treat unexpected messages with caution.";
  } else if (score < 75) {
    level = "medium";
    verdict = "Medium trust";
    summary = "This sender domain has some valid mail security signals, but important protections are missing.";
  }

  const checks = [
    {
      label: "Email format",
      status: "ok",
      value: "Valid format"
    },
    {
      label: "Sender domain",
      status: "ok",
      value: domain
    },
    {
      label: "MX records",
      status: hasMx ? "ok" : "warning",
      value: hasMx ? "Mail servers found" : "No mail servers found"
    },
    {
      label: "SPF",
      status: spfOk ? "ok" : "warning",
      value: mailReport?.spf?.analysis?.message || "Not checked"
    },
    {
      label: "DKIM",
      status: dkimFound ? "ok" : "warning",
      value: dkimFound
        ? `Found selector: ${mailReport.dkim.foundSelectors.join(", ")}`
        : "No common DKIM selector detected"
    },
    {
      label: "DMARC",
      status: dmarcProtected ? "ok" : "warning",
      value: dmarcPolicy ? `p=${dmarcPolicy}` : "DMARC record is missing"
    }
  ];

  const warnings = checks
    .filter((check) => check.status !== "ok")
    .map((check) => `${check.label}: ${check.value}`);

  return {
    checked: true,
    email: originalInput,
    domain,
    score,
    level,
    verdict,
    summary,
    checks,
    warnings,
    note: "This check validates the sender domain security. It does not prove that the mailbox owner actually sent the message."
  };
}

export async function buildDomainReport(input) {
  const scanInputType = detectScanInputType(input);
  const originalInput = typeof input === "string" ? input.trim() : "";
  const domain = normalizeDomain(input);

  const [domainInfoReport, dnsReport] = await Promise.all([
    getDomainInfoReport(domain),
    getDnsReport(domain)
  ]);

  const [sslReport, httpReport, mailReport] = await Promise.all([
    getSslReport(domain),
    getHttpReport(domain),
    getMailReport(domain, dnsReport)
  ]);

  const emailTrustReport = scanInputType === "email"
    ? buildEmailTrustReport({ originalInput, domain, mailReport })
    : null;

  const scoreReport = calculateScore({
    dnsReport,
    sslReport,
    httpReport,
    mailReport
  });

  const threatReport = await getThreatReport(domain).catch((error) => {
    return {
      checked: true,
      domain,
      resolvedIps: [],
      scannedAt: new Date().toISOString(),
      verdict: "Analysis unavailable",
      level: "medium",
      score: 0,
      findings: [
        {
          severity: "medium",
          area: "Threat analysis",
          message: error.message || "Threat analysis could not be completed."
        }
      ],
      screenshot: {
        captured: false,
        url: null,
        error: error.message || "Screenshot unavailable"
      },
      checks: {
        domainAgeDays: null,
        registrar: domainInfoReport.registrar || null,
        sslValid: sslReport.valid,
        sslIssuer: sslReport.issuer,
        finalUrl: httpReport.finalUrl,
        statusCode: httpReport.statusCode,
        contentType: httpReport.headers?.["content-type"] || null,
        html: {
          checked: false
        }
      }
    };
  });

  return {
    domain,
    originalInput,
    scanInputType,
    scannedAt: new Date().toISOString(),
    domainInfoReport,
    dnsReport,
    sslReport,
    httpReport,
    mailReport,
    emailTrustReport,
    scoreReport,
    threatReport
  };
}

export async function renderDomainReport(req, res) {
  const report = await buildDomainReport(req.query.domain);

  return res.render("pages/report", {
    title: `${report.domain} Security Report`,
    description: `Technical security report for ${report.domain}`,
    report,
    pdfMode: req.query.pdf === "1"
  });
}

export async function scanDomainApi(req, res) {
  const input = req.body?.domain || req.query?.domain;
  const report = await buildDomainReport(input);

  return res.json({
    ok: true,
    report
  });
}

export async function exportDomainReportPdf(req, res) {
  const input = req.query.domain;

  if (!input) {
    return res.status(400).json({
      ok: false,
      message: "Domain or email address is required"
    });
  }

  const normalizedDomain = normalizeDomain(input);
  const protocol = req.headers["x-forwarded-proto"] || req.protocol || "http";
  const host = req.get("host");
  const reportUrl = `${protocol}://${host}/scan?domain=${encodeURIComponent(input)}&pdf=1`;

  let browser;

  try {
    browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"]
    });

    const page = await browser.newPage({
      viewport: {
        width: 1240,
        height: 1754
      }
    });

    await page.route("**/*", (route) => {
  const type = route.request().resourceType();

  if (["image", "media"].includes(type)) {
    return route.abort();
  }

  return route.continue();
});

    await page.goto(reportUrl, {
      waitUntil: "domcontentloaded",
      timeout: 45000
    });

    await page.waitForTimeout(100);
    await page.emulateMedia({ media: "print" });

    const pdfBuffer = await page.pdf({
      format: "A4",
      scale: 0.78,
      printBackground: true,
      preferCSSPageSize: true,
      margin: {
        top: "10mm",
        right: "10mm",
        bottom: "10mm",
        left: "10mm"
      }
    });

    const safeDomain = normalizedDomain.replace(/[^a-z0-9.-]/gi, "-").toLowerCase();

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeDomain}-security-report.pdf"`
    );

    return res.send(pdfBuffer);
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}