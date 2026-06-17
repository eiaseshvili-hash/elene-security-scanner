import { Router } from "express";
import { scanDomainApi, validateScanTargetApi } from "../controllers/domain.controller.js";
import { runDiagnosticsApi } from "../controllers/diagnostics.controller.js";
import { runThreatAnalysisApi } from "../controllers/threat.controller.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const router = Router();

router.get("/health", (req, res) => {
  return res.json({
    ok: true,
    app: "elene-project",
    status: "running",
    time: new Date().toISOString()
  });
});

router.get("/validate-target", asyncHandler(validateScanTargetApi));
router.post("/validate-target", asyncHandler(validateScanTargetApi));

router.get("/scan-domain", asyncHandler(scanDomainApi));

router.get("/diagnostics", asyncHandler(runDiagnosticsApi));
router.post("/diagnostics", asyncHandler(runDiagnosticsApi));

router.get("/threat-analysis", asyncHandler(runThreatAnalysisApi));
router.post("/threat-analysis", asyncHandler(runThreatAnalysisApi));

export default router;