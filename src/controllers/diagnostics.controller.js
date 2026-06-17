import { getDiagnosticsReport } from "../services/diagnostics.service.js";

export async function runDiagnosticsApi(req, res) {
  const target = req.method === "POST"
    ? req.body?.target || req.body?.domain || req.body?.ip
    : req.query?.target || req.query?.domain || req.query?.ip;

  const report = await getDiagnosticsReport(target);

  return res.json({
    ok: true,
    report
  });
}