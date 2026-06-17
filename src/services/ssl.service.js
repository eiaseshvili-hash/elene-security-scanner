import tls from "node:tls";

const TLS_TIMEOUT_MS = 8000;

function normalizeAltNames(subjectAltName = "") {
  return subjectAltName
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => item.replace(/^DNS:/i, "").trim())
    .filter(Boolean);
}

function matchesDomain(domain, name) {
  const cleanDomain = domain.toLowerCase();
  const cleanName = String(name || "").toLowerCase();

  if (!cleanName) return false;
  if (cleanName === cleanDomain) return true;

  if (cleanName.startsWith("*.")) {
    const base = cleanName.slice(2);
    return cleanDomain.endsWith(`.${base}`) && cleanDomain.split(".").length === base.split(".").length + 1;
  }

  return false;
}

function getNameValue(value) {
  if (!value) return null;
  if (typeof value === "string") return value;
  return value.CN || value.O || value.OU || null;
}

function parseDate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

export async function getSslReport(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: TLS_TIMEOUT_MS
    });

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();

      const validFromDate = parseDate(cert.valid_from);
      const validToDate = parseDate(cert.valid_to);
      const now = new Date();

      const altNames = normalizeAltNames(cert.subjectaltname);
      const subjectName = getNameValue(cert.subject);
      const issuerName = getNameValue(cert.issuer);

      const domainMatch =
        altNames.some((name) => matchesDomain(domain, name)) ||
        matchesDomain(domain, subjectName);

      const expired = validToDate ? validToDate < now : false;
      const notYetValid = validFromDate ? validFromDate > now : false;

      const valid = Boolean(cert.raw && socket.authorized && domainMatch && !expired && !notYetValid);

      socket.end();

      resolve({
        checked: true,
        valid,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || null,
        domainMatch,
        expired,
        notYetValid,
        issuer: issuerName,
        subject: subjectName,
        serialNumber: cert.serialNumber || null,
        validFrom: validFromDate ? validFromDate.toISOString() : null,
        validTo: validToDate ? validToDate.toISOString() : null,
        daysRemaining: validToDate ? Math.ceil((validToDate - now) / 86400000) : null,
        altNames
      });
    });

    socket.once("timeout", () => {
      socket.destroy();
      resolve({
        checked: true,
        valid: false,
        error: "TLS connection timed out"
      });
    });

    socket.once("error", (error) => {
      resolve({
        checked: true,
        valid: false,
        error: error.message
      });
    });
  });
}