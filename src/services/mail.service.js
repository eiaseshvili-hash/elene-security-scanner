import dns from "dns/promises";
import { createPublicKey } from "crypto";

const publicDnsResolver = new dns.Resolver();
publicDnsResolver.setServers(["1.1.1.1", "8.8.8.8"]);

const SPF_LOOKUP_MECHANISMS = ["include", "a", "mx", "ptr", "exists", "redirect"];
const SPF_LOOKUP_LIMIT = 10;

const DKIM_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "k2",
  "mail",
  "dkim",
  "s1",
  "s2",
  "smtp",
  "zoho",
  "zmail",
  "mandrill",
  "sendgrid",
  "mailgun",
  "amazonses",
  "fm1",
  "fm2"
];

async function safeResolveTxt(name) {
  try {
    const rows = await publicDnsResolver.resolveTxt(name);
    return rows.map((row) => row.join(""));
  } catch {
    return [];
  }
}

function uniqueTxtRecords(records) {
  return [...new Set(records.filter(Boolean))];
}

function parseTagRecord(record) {
  const tags = {};

  if (!record) return tags;

  record
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .forEach((part) => {
      const separatorIndex = part.indexOf("=");
      if (separatorIndex === -1) return;

      const key = part.slice(0, separatorIndex).trim().toLowerCase();
      const value = part.slice(separatorIndex + 1).trim();
      if (key) tags[key] = value;
    });

  return tags;
}

function parseSpfMechanisms(record) {
  return record
    .split(/\s+/)
    .map((part) => part.trim())
    .filter(Boolean)
    .filter((part) => !part.toLowerCase().startsWith("v=spf1"));
}

function getSpfMechanismName(mechanism) {
  const clean = mechanism.replace(/^[+~?-]/, "").toLowerCase();
  return clean.split(/[/:=]/)[0];
}

function getSpfAllPolicy(mechanisms) {
  const all = mechanisms.find((mechanism) => getSpfMechanismName(mechanism) === "all");
  if (!all) return null;

  const qualifier = all[0];

  if (qualifier === "-") {
    return {
      value: "-all",
      label: "Hard fail",
      strength: "strong",
      description: "Only declared senders should be accepted."
    };
  }

  if (qualifier === "~") {
    return {
      value: "~all",
      label: "Soft fail",
      strength: "moderate",
      description: "Undeclared senders are suspicious, but may still pass depending on the receiver."
    };
  }

  if (qualifier === "?") {
    return {
      value: "?all",
      label: "Neutral",
      strength: "weak",
      description: "SPF does not give receivers a clear reject signal."
    };
  }

  return {
    value: "+all",
    label: "Pass all",
    strength: "dangerous",
    description: "Any sender can pass SPF for this domain."
  };
}

function getSpfLookupCount(mechanisms) {
  const lookupMechanisms = mechanisms.filter((mechanism) => {
    const name = getSpfMechanismName(mechanism);
    return SPF_LOOKUP_MECHANISMS.includes(name);
  });

  return {
    count: lookupMechanisms.length,
    limit: SPF_LOOKUP_LIMIT,
    mechanisms: lookupMechanisms
  };
}

function analyzeSpf(spfRecords) {
  if (!spfRecords.length) {
    return {
      status: "missing",
      message: "SPF record is missing",
      lookupCount: 0,
      lookupLimit: SPF_LOOKUP_LIMIT,
      allPolicy: null,
      mechanisms: [],
      recommendation: "Add an SPF TXT record that only authorizes the mail services used by this domain."
    };
  }

  if (spfRecords.length > 1) {
    return {
      status: "warning",
      message: "Multiple SPF records detected",
      lookupCount: 0,
      lookupLimit: SPF_LOOKUP_LIMIT,
      allPolicy: null,
      mechanisms: [],
      recommendation: "Merge all SPF rules into one TXT record. Multiple SPF records cause SPF validation to fail."
    };
  }

  const record = spfRecords[0];
  const mechanisms = parseSpfMechanisms(record);
  const lookup = getSpfLookupCount(mechanisms);
  const allPolicy = getSpfAllPolicy(mechanisms);

  if (lookup.count > SPF_LOOKUP_LIMIT) {
    return {
      status: "warning",
      message: `SPF exceeds the ${SPF_LOOKUP_LIMIT} DNS lookup limit`,
      lookupCount: lookup.count,
      lookupLimit: SPF_LOOKUP_LIMIT,
      lookupMechanisms: lookup.mechanisms,
      allPolicy,
      mechanisms,
      recommendation: "Reduce include, a, mx, ptr, exists or redirect mechanisms so SPF stays within the 10 lookup limit."
    };
  }

  if (allPolicy?.strength === "strong") {
    return {
      status: "ok",
      message: "SPF is configured with a strict fail policy",
      lookupCount: lookup.count,
      lookupLimit: SPF_LOOKUP_LIMIT,
      lookupMechanisms: lookup.mechanisms,
      allPolicy,
      mechanisms,
      recommendation: null
    };
  }

  if (allPolicy?.strength === "moderate") {
    return {
      status: "warning",
      message: "SPF uses a soft fail policy",
      lookupCount: lookup.count,
      lookupLimit: SPF_LOOKUP_LIMIT,
      lookupMechanisms: lookup.mechanisms,
      allPolicy,
      mechanisms,
      recommendation: "Use -all when every legitimate sender is already included in SPF."
    };
  }

  if (allPolicy?.strength === "weak" || allPolicy?.strength === "dangerous") {
    return {
      status: "warning",
      message: "SPF policy is weak",
      lookupCount: lookup.count,
      lookupLimit: SPF_LOOKUP_LIMIT,
      lookupMechanisms: lookup.mechanisms,
      allPolicy,
      mechanisms,
      recommendation: "Replace ?all or +all with -all after confirming all legitimate senders are listed."
    };
  }

  return {
    status: "warning",
    message: "SPF exists but final all policy is missing",
    lookupCount: lookup.count,
    lookupLimit: SPF_LOOKUP_LIMIT,
    lookupMechanisms: lookup.mechanisms,
    allPolicy,
    mechanisms,
    recommendation: "Finish the SPF record with -all after listing every authorized sender."
  };
}

function buildDmarcRecommendation(domain) {
  return `v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}; ruf=mailto:dmarc@${domain}; fo=1; pct=100; adkim=s; aspf=s`;
}

function parseDmarcRecord(record) {
  const tags = parseTagRecord(record);
  const policy = tags.p?.toLowerCase() || null;

  return {
    tags,
    policy,
    subdomainPolicy: tags.sp?.toLowerCase() || null,
    rua: tags.rua || null,
    ruf: tags.ruf || null,
    pct: tags.pct || null,
    adkim: tags.adkim || null,
    aspf: tags.aspf || null,
    fo: tags.fo || null
  };
}

function analyzeDmarc(dmarcRecords, domain) {
  if (!dmarcRecords.length) {
    return {
      status: "missing",
      policy: null,
      parsed: null,
      message: "DMARC record is missing",
      recommendation: buildDmarcRecommendation(domain),
      explanation: "DMARC tells mail receivers how to handle messages that fail SPF or DKIM alignment."
    };
  }

  if (dmarcRecords.length > 1) {
    return {
      status: "warning",
      policy: null,
      parsed: null,
      message: "Multiple DMARC records detected",
      recommendation: "Keep only one TXT record on _dmarc and merge the required tags into it.",
      explanation: "Multiple DMARC records make DMARC validation unreliable."
    };
  }

  const parsed = parseDmarcRecord(dmarcRecords[0]);

  if (parsed.policy === "reject") {
    return {
      status: "ok",
      policy: parsed.policy,
      parsed,
      message: "DMARC is configured with reject policy",
      recommendation: null,
      explanation: "Failed messages should be rejected by receivers."
    };
  }

  if (parsed.policy === "quarantine") {
    return {
      status: "ok",
      policy: parsed.policy,
      parsed,
      message: "DMARC is configured with quarantine policy",
      recommendation: "Move to p=reject after monitoring reports and confirming legitimate mail passes SPF or DKIM alignment.",
      explanation: "Failed messages should be placed into spam or quarantine."
    };
  }

  if (parsed.policy === "none") {
    return {
      status: "warning",
      policy: parsed.policy,
      parsed,
      message: "DMARC exists but policy is monitoring only",
      recommendation: "Change p=none to p=quarantine first, then move to p=reject after validation.",
      explanation: "p=none collects reports but does not protect the domain from spoofed mail."
    };
  }

  return {
    status: "warning",
    policy: parsed.policy,
    parsed,
    message: "DMARC exists but policy is unclear",
    recommendation: "Use a clear p=quarantine or p=reject policy and include reporting addresses.",
    explanation: "A valid DMARC record needs a clear p= policy."
  };
}

function getDkimKeyLength(publicKey) {
  if (!publicKey) return null;

  try {
    const keyObject = createPublicKey({
      key: Buffer.from(publicKey, "base64"),
      format: "der",
      type: "spki"
    });

    return keyObject.asymmetricKeyDetails?.modulusLength || null;
  } catch {
    const bytes = Buffer.from(publicKey, "base64").length;
    if (!bytes) return null;
    if (bytes >= 500) return 4096;
    if (bytes >= 260) return 2048;
    if (bytes >= 130) return 1024;
    return null;
  }
}

function analyzeDkimRecord(record) {
  const tags = parseTagRecord(record);
  const publicKey = tags.p || "";
  const flags = tags.t ? tags.t.split(":").map((flag) => flag.trim()).filter(Boolean) : [];
  const keyLength = getDkimKeyLength(publicKey);
  const revoked = Object.prototype.hasOwnProperty.call(tags, "p") && publicKey.length === 0;
  const testing = flags.includes("y");

  let status = "ok";
  let message = "DKIM key is published";

  if (revoked) {
    status = "warning";
    message = "DKIM key is revoked or empty";
  } else if (keyLength && keyLength < 1024) {
    status = "warning";
    message = "DKIM key is shorter than recommended";
  } else if (testing) {
    status = "warning";
    message = "DKIM key is in testing mode";
  }

  return {
    status,
    message,
    tags,
    keyType: tags.k || "rsa",
    keyLength,
    testing,
    revoked,
    flags
  };
}

function getMailHealthScore({ hasMx, spf, dmarc, dkim, mtaSts, tlsRpt }) {
  let score = 0;

  if (hasMx) score += 10;
  if (spf.analysis.status === "ok") score += 20;
  if (dkim.found) score += 25;
  if (["quarantine", "reject"].includes(dmarc.analysis.policy)) score += 30;
  if (mtaSts.found) score += 8;
  if (tlsRpt.found) score += 7;

  return Math.max(0, Math.min(100, score));
}

export async function getMailReport(domain, dnsReport) {
  const mxRecords = dnsReport.records.MX?.values || [];
  const spfRecords = dnsReport.records.SPF?.values || [];
  const dmarcRecordsFromDnsReport = dnsReport.records.DMARC?.values || [];

  const [liveDmarcRecords, mtaStsRecords, tlsRptRecords, bimiRecords] = await Promise.all([
    safeResolveTxt(`_dmarc.${domain}`),
    safeResolveTxt(`_mta-sts.${domain}`),
    safeResolveTxt(`_smtp._tls.${domain}`),
    safeResolveTxt(`default._bimi.${domain}`)
  ]);

  const dmarcRecords = uniqueTxtRecords([
    ...dmarcRecordsFromDnsReport,
    ...liveDmarcRecords.filter((value) => value.toLowerCase().startsWith("v=dmarc1"))
  ]);

  const dkimChecks = await Promise.all(
    DKIM_SELECTORS.map(async (selector) => {
      const name = `${selector}._domainkey.${domain}`;
      const values = await safeResolveTxt(name);
      const dkimValues = values.filter((value) => value.toLowerCase().startsWith("v=dkim1"));
      const analyses = dkimValues.map((value) => analyzeDkimRecord(value));

      return {
        selector,
        name,
        found: dkimValues.length > 0,
        values: dkimValues,
        analyses
      };
    })
  );

  const spf = {
    found: spfRecords.length > 0,
    records: spfRecords,
    analysis: analyzeSpf(spfRecords)
  };

  const dmarc = {
    found: dmarcRecords.length > 0,
    records: dmarcRecords,
    analysis: analyzeDmarc(dmarcRecords, domain)
  };

  const dkim = {
    checkedSelectors: DKIM_SELECTORS,
    found: dkimChecks.some((item) => item.found),
    foundSelectors: dkimChecks.filter((item) => item.found).map((item) => item.selector),
    results: dkimChecks
  };

  const mtaSts = {
    found: mtaStsRecords.some((value) => value.toLowerCase().startsWith("v=stsv1")),
    records: mtaStsRecords
  };

  const tlsRpt = {
    found: tlsRptRecords.some((value) => value.toLowerCase().startsWith("v=tlsrptv1")),
    records: tlsRptRecords
  };

  const bimi = {
    found: bimiRecords.some((value) => value.toLowerCase().startsWith("v=bimi1")),
    records: bimiRecords
  };

  const mailHealthScore = getMailHealthScore({
    hasMx: mxRecords.length > 0,
    spf,
    dmarc,
    dkim,
    mtaSts,
    tlsRpt
  });

  return {
    checked: true,
    hasMx: mxRecords.length > 0,
    mxRecords,
    spf,
    dmarc,
    dkim,
    mtaSts,
    tlsRpt,
    bimi,
    mailHealthScore
  };
}