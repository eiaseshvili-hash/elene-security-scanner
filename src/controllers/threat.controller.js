import { getThreatReport } from "../services/threat.service.js";

export async function runThreatAnalysisApi(req, res) {
  const target = req.method === "POST"
    ? req.body?.target || req.body?.domain || req.body?.url
    : req.query?.target || req.query?.domain || req.query?.url;

  const report = await getThreatReport(target);

  return res.json({
    ok: true,
    report
  });
}