import axios from "axios";
import dns from "node:dns/promises";
import net from "node:net";
import { normalizeDomain } from "../utils/domain.util.js";
import { getDomainInfoReport } from "./domain-info.service.js";
import { getSslReport } from "./ssl.service.js";
import { captureWebsiteScreenshot } from "./screenshot.service.js";

const REQUEST_TIMEOUT_MS = 9000;
const MAX_HTML_BYTES = 350000;

const suspiciousWords = [
  "login",
  "verify",
  "wallet",
  "password",
  "bank",
  "paypal",
  "crypto",
  "airdrop",
  "bonus",
  "free",
  "gift",
  "security",
  "account",
  "confirm",
  "update",
  "support",
  "recovery"
];

const suspiciousTlds = [
  "zip",
  "mov",
  "top",
  "xyz",
  "click",
  "fit",
  "rest",
  "country",
  "stream",
  "gq",
  "tk",
  "ml",
  "cf"
];

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return true;

  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;

    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;

    return false;
  }

  const value = ip.toLowerCase();

  return (
    value === "::1" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80") ||
    value.startsWith("::ffff:127.") ||
    value.startsWith("::ffff:10.") ||
    value.startsWith("::ffff:192.168.")
  );
}

function getRootTld(domain) {
  return domain.split(".").pop()?.toLowerCase() || "";
}

function getDomainAgeDays(createdAt) {
  if (!createdAt) return null;

  const createdDate = new Date(createdAt);
  if (Number.isNaN(createdDate.getTime())) return null;

  return Math.floor((Date.now() - createdDate.getTime()) / 86400000);
}

function findSuspiciousWords(text) {
  const lower = String(text || "").toLowerCase();

  return suspiciousWords.filter((word) => lower.includes(word));
}

function countMatches(text, regex) {
  return (String(text || "").match(regex) || []).length;
}

function analyzeHtml(html, domain) {
  const safeHtml = String(html || "").slice(0, MAX_HTML_BYTES);
  const lower = safeHtml.toLowerCase();

  const forms = countMatches(lower, /<form[\s>]/g);
  const passwordFields = countMatches(lower, /type=["']?password["']?/g);
  const iframes = countMatches(lower, /<iframe[\s>]/g);
  const scripts = countMatches(lower, /<script[\s>]/g);
  const externalScripts = countMatches(lower, /<script[^>]+src=["']https?:\/\//g);
  const suspiciousTextWords = findSuspiciousWords(lower);
  const hasObfuscatedJavascript =
    /eval\s*\(|atob\s*\(|fromcharcode|document\.write\s*\(/i.test(safeHtml);

  const actionExternal = /<form[^>]+action=["']https?:\/\//i.test(safeHtml);
  const hasLoginSignals = forms > 0 && passwordFields > 0;

  return {
    checked: true,
    forms,
    passwordFields,
    iframes,
    scripts,
    externalScripts,
    suspiciousTextWords,
    hasLoginSignals,
    hasExternalFormAction: actionExternal,
    hasObfuscatedJavascript
  };
}

function addFinding(findings, severity, area, message) {
  findings.push({ severity, area, message });
}

function calculateThreatScore({ domain, domainInfo, ssl, http, html }) {
  let score = 100;
  const findings = [];

  const tld = getRootTld(domain);
  const ageDays = getDomainAgeDays(domainInfo.createdAt);
  const domainWords = findSuspiciousWords(domain);

  if (suspiciousTlds.includes(tld)) {
    score -= 15;
    addFinding(findings, "medium", "Domain", `Domain uses a higher-risk TLD: .${tld}`);
  }

  if (domain.includes("xn--")) {
    score -= 18;
    addFinding(findings, "high", "Domain", "Domain uses punycode, which can be used for lookalike phishing.");
  }

  if (domainWords.length) {
    score -= 8;
    addFinding(findings, "low", "Domain", `Domain contains sensitive keywords: ${domainWords.join(", ")}`);
  }

  if (ageDays !== null && ageDays < 30) {
    score -= 18;
    addFinding(findings, "high", "Domain age", "Domain is very new, which increases phishing risk.");
  } else if (ageDays !== null && ageDays < 180) {
    score -= 8;
    addFinding(findings, "medium", "Domain age", "Domain is relatively new.");
  }

  if (!ssl.valid) {
    score -= 18;
    addFinding(findings, "high", "SSL", "SSL certificate is not fully valid.");
  }

  if (!http.reachable) {
    score -= 10;
    addFinding(findings, "medium", "Website", "Website could not be reached for content inspection.");
  }

  if (http.finalUrl && !String(http.finalUrl).startsWith("https://")) {
    score -= 10;
    addFinding(findings, "medium", "Website", "Final URL is not using HTTPS.");
  }

  if (html.checked) {
    if (html.hasLoginSignals) {
      score -= 10;
      addFinding(findings, "medium", "Content", "Page contains login form and password field.");
    }

    if (html.hasExternalFormAction) {
      score -= 18;
      addFinding(findings, "high", "Content", "Form submits data to an external URL.");
    }

    if (html.hasObfuscatedJavascript) {
      score -= 15;
      addFinding(findings, "high", "Content", "Page contains obfuscated JavaScript patterns.");
    }

    if (html.iframes > 0) {
      score -= 5;
      addFinding(findings, "low", "Content", "Page contains iframe embeds.");
    }

    if (html.suspiciousTextWords.length >= 4) {
      score -= 8;
      addFinding(findings, "medium", "Content", `Page contains sensitive words: ${html.suspiciousTextWords.slice(0, 8).join(", ")}`);
    }
  }

  const finalScore = Math.max(0, Math.min(100, score));

  let verdict = "Low risk";
  let level = "low";

  if (finalScore < 45) {
    verdict = "High risk";
    level = "high";
  } else if (finalScore < 75) {
    verdict = "Needs review";
    level = "medium";
  }

  return {
    score: finalScore,
    level,
    verdict,
    findings
  };
}

async function assertPublicTarget(domain) {
  const records = await dns.lookup(domain, { all: true });

  if (!records.length) {
    throw new Error("Domain does not resolve to an IP address");
  }

  const blocked = records.some((record) => isPrivateIp(record.address));

  if (blocked) {
    throw new Error("Private or local network targets are not allowed");
  }

  return records.map((record) => record.address);
}

async function fetchWebsite(domain) {
  try {
    const response = await axios.get(`https://${domain}`, {
      timeout: REQUEST_TIMEOUT_MS,
      maxRedirects: 5,
      responseType: "text",
      maxContentLength: MAX_HTML_BYTES,
      validateStatus: () => true,
      headers: {
        "User-Agent": "EleneThreatScanner/1.0"
      }
    });

    return {
      reachable: true,
      finalUrl: response.request?.res?.responseUrl || `https://${domain}`,
      statusCode: response.status,
      contentType: response.headers?.["content-type"] || null,
      html: typeof response.data === "string" ? response.data.slice(0, MAX_HTML_BYTES) : ""
    };
  } catch (error) {
    return {
      reachable: false,
      finalUrl: null,
      statusCode: null,
      contentType: null,
      html: "",
      error: error.message
    };
  }
}

export async function getThreatReport(input) {
  const domain = normalizeDomain(input);

  const resolvedIps = await assertPublicTarget(domain);

  const [domainInfo, ssl, website] = await Promise.all([
    getDomainInfoReport(domain),
    getSslReport(domain),
    fetchWebsite(domain)
  ]);

  const screenshot = await captureWebsiteScreenshot(domain, website.finalUrl);

  const html = website.html
    ? analyzeHtml(website.html, domain)
    : { checked: false };

  const result = calculateThreatScore({
    domain,
    domainInfo,
    ssl,
    http: website,
    html
  });

  return {
    checked: true,
    domain,
    resolvedIps,
    scannedAt: new Date().toISOString(),
    verdict: result.verdict,
    level: result.level,
    score: result.score,
    findings: result.findings,
    screenshot,
    checks: {
      domainAgeDays: getDomainAgeDays(domainInfo.createdAt),
      registrar: domainInfo.registrar || null,
      sslValid: ssl.valid,
      sslIssuer: ssl.issuer,
      finalUrl: website.finalUrl,
      statusCode: website.statusCode,
      contentType: website.contentType,
      html
    }
  };
}