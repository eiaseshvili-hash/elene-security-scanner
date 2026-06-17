function addIssue(issues, severity, area, message) {
  issues.push({
    severity,
    area,
    message
  });
}

export function calculateScore({ dnsReport, sslReport, httpReport, mailReport }) {
  let score = 100;
  const issues = [];

  if (!dnsReport.summary.hasA && !dnsReport.summary.hasAAAA) {
    score -= 18;
    addIssue(issues, "high", "DNS", "No A or AAAA records were found.");
  }

  if (!dnsReport.summary.hasNS) {
    score -= 12;
    addIssue(issues, "high", "DNS", "No nameserver records were found.");
  }

  if (!dnsReport.summary.hasDNSSEC) {
    score -= 6;
    addIssue(issues, "low", "DNS", "DNSSEC DS record was not found.");
  }

  if (!dnsReport.summary.hasCAA) {
    score -= 4;
    addIssue(issues, "low", "DNS", "CAA record was not found.");
  }

  if (!mailReport.hasMx) {
    score -= 12;
    addIssue(issues, "medium", "Mail", "MX records were not found.");
  }

  if (!mailReport.spf.found) {
    score -= 10;
    addIssue(issues, "medium", "Mail", "SPF record is missing.");
  } else if (mailReport.spf.analysis.status === "warning") {
    score -= 5;
    addIssue(issues, "low", "Mail", mailReport.spf.analysis.message);
  }

  if (!mailReport.dmarc.found) {
    score -= 12;
    addIssue(issues, "medium", "Mail", "DMARC record is missing.");
  } else if (mailReport.dmarc.analysis.status === "warning") {
    score -= 6;
    addIssue(issues, "low", "Mail", mailReport.dmarc.analysis.message);
  }

  if (!sslReport.valid) {
    score -= 20;
    addIssue(issues, "high", "SSL", sslReport.error || sslReport.authorizationError || "SSL certificate is not fully valid.");
  } else if (sslReport.daysRemaining !== null && sslReport.daysRemaining <= 14) {
    score -= 8;
    addIssue(issues, "medium", "SSL", "SSL certificate expires soon.");
  }

  if (!httpReport.reachable) {
    score -= 18;
    addIssue(issues, "high", "Website", httpReport.error || "Website is not reachable over HTTPS.");
  } else {
    if (!httpReport.hasHsts) {
      score -= 6;
      addIssue(issues, "low", "Headers", "Strict-Transport-Security header is missing.");
    }

    if (!httpReport.hasCsp) {
      score -= 6;
      addIssue(issues, "low", "Headers", "Content-Security-Policy header is missing.");
    }

    if (!httpReport.hasFrameOptions) {
      score -= 4;
      addIssue(issues, "low", "Headers", "X-Frame-Options header is missing.");
    }

    if (!httpReport.hasContentTypeOptions) {
      score -= 4;
      addIssue(issues, "low", "Headers", "X-Content-Type-Options header is missing.");
    }

    if (!httpReport.hasReferrerPolicy) {
      score -= 3;
      addIssue(issues, "low", "Headers", "Referrer-Policy header is missing.");
    }

    if (!httpReport.hasPermissionsPolicy) {
      score -= 3;
      addIssue(issues, "low", "Headers", "Permissions-Policy header is missing.");
    }
  }

  const normalizedScore = Math.max(0, Math.min(100, score));

  return {
    score: normalizedScore,
    grade: getGrade(normalizedScore),
    issues,
    issueCount: issues.length
  };
}

function getGrade(score) {
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Good";
  if (score >= 55) return "Needs improvement";
  return "Weak";
}