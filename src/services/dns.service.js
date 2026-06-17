import dns from "dns/promises";

const DNS_TIMEOUT_MS = 6000;

const recordTypes = ["A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA", "DS"];

async function withTimeout(promise, timeoutMs = DNS_TIMEOUT_MS) {
  let timer;

  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error("DNS lookup timeout");
      error.code = "ETIMEOUT";
      reject(error);
    }, timeoutMs);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function safeResolve(domain, type) {
  try {
    const values = await withTimeout(dns.resolve(domain, type));

    return {
      type,
      found: Array.isArray(values) ? values.length > 0 : Boolean(values),
      values: values || [],
      error: null
    };
  } catch (error) {
    return {
      type,
      found: false,
      values: [],
      error: normalizeDnsError(error)
    };
  }
}

async function safeTxt(domain, label = "TXT") {
  try {
    const values = await withTimeout(dns.resolveTxt(domain));
    const flattened = values.map((row) => row.join(""));

    return {
      type: label,
      found: flattened.length > 0,
      values: flattened,
      error: null
    };
  } catch (error) {
    return {
      type: label,
      found: false,
      values: [],
      error: normalizeDnsError(error)
    };
  }
}

function normalizeDnsError(error) {
  if (!error) return null;

  if (error.code === "ENODATA") return "No records found";
  if (error.code === "ENOTFOUND") return "Domain not found";
  if (error.code === "ETIMEOUT" || error.code === "ETIMEOUT") return "Lookup timeout";
  if (error.code === "ESERVFAIL") return "DNS server failure";
  if (error.code === "ENOTIMP") return "Record type not supported";

  return error.code || error.message || "Lookup failed";
}

function extractSpf(txtValues) {
  return txtValues.filter((value) => value.toLowerCase().startsWith("v=spf1"));
}

function extractDmarc(txtValues) {
  return txtValues.filter((value) => value.toLowerCase().startsWith("v=dmarc1"));
}

export async function getDnsReport(domain) {
  const resolved = await Promise.all(recordTypes.map((type) => safeResolve(domain, type)));
  const records = Object.fromEntries(resolved.map((item) => [item.type, item]));

  const rootTxt = await safeTxt(domain, "TXT");
  const dmarcTxt = await safeTxt(`_dmarc.${domain}`, "DMARC");

  records.TXT = rootTxt;
  records.SPF = {
    type: "SPF",
    found: extractSpf(rootTxt.values).length > 0,
    values: extractSpf(rootTxt.values),
    error: null
  };

  records.DMARC = {
    type: "DMARC",
    found: extractDmarc(dmarcTxt.values).length > 0,
    values: extractDmarc(dmarcTxt.values),
    error: dmarcTxt.error
  };

  return {
    domain,
    records,
    summary: {
      hasA: records.A.found,
      hasAAAA: records.AAAA.found,
      hasNS: records.NS.found,
      hasMX: records.MX.found,
      hasSPF: records.SPF.found,
      hasDMARC: records.DMARC.found,
      hasCAA: records.CAA.found,
      hasDNSSEC: records.DS.found
    }
  };
}