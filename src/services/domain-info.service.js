import axios from "axios";
import net from "net";

const RDAP_TIMEOUT_MS = 8000;
const WHOIS_TIMEOUT_MS = 8000;

const TLD_WHOIS_FALLBACKS = {
  ge: "whois.nic.ge",
  com: "whois.verisign-grs.com",
  net: "whois.verisign-grs.com",
  org: "whois.pir.org",
  info: "whois.afilias.net",
  biz: "whois.biz",
  io: "whois.nic.io",
  eu: "whois.eu",
  co: "whois.nic.co",
  me: "whois.nic.me"
};

function unique(values) {
  return [...new Set(values.filter(Boolean).map((item) => String(item).trim()).filter(Boolean))];
}

function getTld(domain) {
  return domain.split(".").pop().toLowerCase();
}

function cleanValue(value) {
  if (!value) return null;
  const cleaned = String(value).trim();
  return cleaned || null;
}

function parseDate(value) {
  const cleaned = cleanValue(value);
  if (!cleaned) return null;

  const date = new Date(cleaned);
  if (Number.isNaN(date.getTime())) return cleaned;

  return date.toISOString();
}

function parseVcardEmails(entity) {
  const emails = [];
  const vcard = entity?.vcardArray?.[1];

  if (!Array.isArray(vcard)) return emails;

  for (const item of vcard) {
    if (Array.isArray(item) && item[0] === "email" && item[3]) {
      emails.push(item[3]);
    }
  }

  return emails;
}

function getRdapEventDate(events = [], names = []) {
  const wanted = names.map((name) => name.toLowerCase());

  const event = events.find((item) => {
    const action = String(item.eventAction || "").toLowerCase();
    return wanted.includes(action);
  });

  return parseDate(event?.eventDate);
}

function parseRdap(data) {
  const registrarEntity = data.entities?.find((entity) => {
    const roles = entity.roles || [];
    return roles.includes("registrar");
  });

  const registrarName = registrarEntity?.vcardArray?.[1]?.find((item) => {
    return Array.isArray(item) && item[0] === "fn";
  })?.[3];

  const allEmails = [];

  for (const entity of data.entities || []) {
    allEmails.push(...parseVcardEmails(entity));

    for (const subEntity of entity.entities || []) {
      allEmails.push(...parseVcardEmails(subEntity));
    }
  }

  return {
    source: "RDAP",
    registrar: cleanValue(data.registrarName || registrarName),
    createdAt: getRdapEventDate(data.events, ["registration"]),
    expiresAt: getRdapEventDate(data.events, ["expiration"]),
    updatedAt: getRdapEventDate(data.events, ["last changed", "last update of rdap database"]),
    statuses: unique(data.status || []),
    nameservers: unique((data.nameservers || []).map((item) => item.ldhName || item.unicodeName)),
    emails: unique(allEmails),
    rawAvailable: true
  };
}

async function getRdapData(domain) {
  try {
    const response = await axios.get(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      timeout: RDAP_TIMEOUT_MS,
      validateStatus: (status) => status >= 200 && status < 500,
      headers: {
        "User-Agent": "EleneScanner/1.0"
      }
    });

    if (response.status >= 400 || !response.data) {
      return null;
    }

    return parseRdap(response.data);
  } catch {
    return null;
  }
}

function queryWhois(server, query) {
  return new Promise((resolve) => {
    let data = "";
    const socket = net.createConnection(43, server);

    socket.setTimeout(WHOIS_TIMEOUT_MS);

    socket.on("connect", () => {
      socket.write(`${query}\r\n`);
    });

    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });

    socket.on("end", () => {
      resolve(data);
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve("");
    });

    socket.on("error", () => {
      socket.destroy();
      resolve("");
    });
  });
}

async function discoverWhoisServer(tld) {
  const fallback = TLD_WHOIS_FALLBACKS[tld] || null;
  const ianaResponse = await queryWhois("whois.iana.org", tld);

  const match = ianaResponse.match(/^whois:\s*(.+)$/im);
  const discovered = match ? match[1].trim() : null;

  return discovered || fallback;
}

function extractLines(raw, patterns) {
  const values = [];

  for (const originalLine of raw.split(/\r?\n/)) {
    const line = originalLine.trim();

    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match?.[1]) values.push(match[1].trim());
    }
  }

  return unique(values);
}

function parseWhois(raw, server) {
  if (!raw) {
    return {
      source: "WHOIS",
      whoisServer: server,
      rawAvailable: false
    };
  }

  const registrar = extractLines(raw, [
    /^registrar:\s*(.+)$/im,
    /^sponsoring registrar:\s*(.+)$/im
  ])[0];

  const createdAt = extractLines(raw, [
    /^creation date:\s*(.+)$/im,
    /^created:\s*(.+)$/im,
    /^registered on:\s*(.+)$/im,
    /^domain registration date:\s*(.+)$/im
  ])[0];

  const expiresAt = extractLines(raw, [
    /^registry expiry date:\s*(.+)$/im,
    /^expiry date:\s*(.+)$/im,
    /^expiration date:\s*(.+)$/im,
    /^expires:\s*(.+)$/im,
    /^domain expiration date:\s*(.+)$/im
  ])[0];

  const updatedAt = extractLines(raw, [
    /^updated date:\s*(.+)$/im,
    /^last updated:\s*(.+)$/im,
    /^modified:\s*(.+)$/im
  ])[0];

  const statuses = extractLines(raw, [
    /^domain status:\s*(.+)$/im,
    /^status:\s*(.+)$/im
  ]);

  const nameservers = extractLines(raw, [
    /^name server:\s*(.+)$/im,
    /^nserver:\s*(.+)$/im,
    /^nameserver:\s*(.+)$/im
  ]).map((item) => item.split(/\s+/)[0].toLowerCase());

  const emails = extractLines(raw, [
    /([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i
  ]);

  return {
    source: "WHOIS",
    whoisServer: server,
    registrar: cleanValue(registrar),
    createdAt: parseDate(createdAt),
    expiresAt: parseDate(expiresAt),
    updatedAt: parseDate(updatedAt),
    statuses: unique(statuses),
    nameservers: unique(nameservers),
    emails: unique(emails),
    rawAvailable: true
  };
}

function mergeDomainInfo(domain, rdapInfo, whoisInfo) {
  return {
    checked: true,
    domain,
    source: rdapInfo?.source || whoisInfo?.source || "Unavailable",
    whoisServer: whoisInfo?.whoisServer || null,
    registrar: rdapInfo?.registrar || whoisInfo?.registrar || null,
    createdAt: rdapInfo?.createdAt || whoisInfo?.createdAt || null,
    expiresAt: rdapInfo?.expiresAt || whoisInfo?.expiresAt || null,
    updatedAt: rdapInfo?.updatedAt || whoisInfo?.updatedAt || null,
    statuses: unique([...(rdapInfo?.statuses || []), ...(whoisInfo?.statuses || [])]),
    nameservers: unique([...(rdapInfo?.nameservers || []), ...(whoisInfo?.nameservers || [])]),
    emails: unique([...(rdapInfo?.emails || []), ...(whoisInfo?.emails || [])]),
    rdapAvailable: Boolean(rdapInfo?.rawAvailable),
    whoisAvailable: Boolean(whoisInfo?.rawAvailable)
  };
}

export async function getDomainInfoReport(domain) {
  const tld = getTld(domain);

  const [rdapInfo, whoisServer] = await Promise.all([
    getRdapData(domain),
    discoverWhoisServer(tld)
  ]);

  const whoisRaw = whoisServer ? await queryWhois(whoisServer, domain) : "";
  const whoisInfo = whoisServer ? parseWhois(whoisRaw, whoisServer) : null;

  return mergeDomainInfo(domain, rdapInfo, whoisInfo);
}