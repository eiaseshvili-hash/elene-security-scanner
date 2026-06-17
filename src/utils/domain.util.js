import validator from "validator";
import { domainToASCII } from "url";

function extractEmailAddress(value) {
  const angleMatch = value.match(/<([^<>@\s]+@[^<>\s]+)>/);
  if (angleMatch?.[1]) return angleMatch[1];

  const mailtoClean = value.replace(/^mailto:/i, "").trim();

  if (validator.isEmail(mailtoClean)) {
    return mailtoClean;
  }

  return null;
}

function extractDomainFromInput(input) {
  let value = input.trim().toLowerCase();

  const email = extractEmailAddress(value);
  if (email) {
    return email.split("@").pop();
  }

  value = value.replace(/^https?:\/\//i, "");
  value = value.replace(/^www\./i, "");
  value = value.split("/")[0];
  value = value.split("?")[0];
  value = value.split("#")[0];
  value = value.replace(/\.$/, "");

  return value;
}

export function normalizeDomain(input) {
  if (!input || typeof input !== "string") {
    const error = new Error("Domain or email address is required");
    error.statusCode = 400;
    throw error;
  }

  const extractedDomain = extractDomainFromInput(input);
  const asciiDomain = domainToASCII(extractedDomain);

  if (!asciiDomain || !validator.isFQDN(asciiDomain, { require_tld: true, allow_underscores: false })) {
    const error = new Error("Invalid domain or email address format");
    error.statusCode = 400;
    throw error;
  }

  return asciiDomain;
}

export function detectScanInputType(input) {
  if (!input || typeof input !== "string") return "domain";

  const value = input.trim().toLowerCase();
  const email = extractEmailAddress(value);

  return email ? "email" : "domain";
}

export function getRootUrl(domain) {
  return `https://${domain}`;
}