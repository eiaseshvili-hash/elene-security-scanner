import axios from "axios";

const HTTP_TIMEOUT_MS = 8000;

const securityHeaders = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy"
];

function pickHeaders(headers) {
  const picked = {};

  for (const key of securityHeaders) {
    picked[key] = headers[key] || null;
  }

  picked.server = headers.server || null;
  picked["content-type"] = headers["content-type"] || null;

  return picked;
}

function buildHeaderChecks(headers) {
  return securityHeaders.map((header) => ({
    name: header,
    found: Boolean(headers[header]),
    value: headers[header] || null
  }));
}

export async function getHttpReport(domain) {
  const startUrl = `https://${domain}`;

  try {
    const response = await axios.get(startUrl, {
      timeout: HTTP_TIMEOUT_MS,
      maxRedirects: 6,
      validateStatus: () => true,
      headers: {
        "User-Agent": "EleneScanner/1.0"
      }
    });

    const finalUrl = response.request?.res?.responseUrl || startUrl;
    const redirects = response.request?._redirectable?._redirectCount || 0;
    const headers = response.headers || {};

    return {
      checked: true,
      reachable: true,
      startUrl,
      finalUrl,
      statusCode: response.status,
      statusText: response.statusText,
      redirects,
      headers: pickHeaders(headers),
      securityHeaders: buildHeaderChecks(headers),
      hasHsts: Boolean(headers["strict-transport-security"]),
      hasCsp: Boolean(headers["content-security-policy"]),
      hasFrameOptions: Boolean(headers["x-frame-options"]),
      hasContentTypeOptions: Boolean(headers["x-content-type-options"]),
      hasReferrerPolicy: Boolean(headers["referrer-policy"]),
      hasPermissionsPolicy: Boolean(headers["permissions-policy"])
    };
  } catch (error) {
    return {
      checked: true,
      reachable: false,
      startUrl,
      finalUrl: null,
      statusCode: null,
      statusText: null,
      redirects: 0,
      headers: {},
      securityHeaders: [],
      error: error.code || error.message || "HTTP check failed"
    };
  }
}