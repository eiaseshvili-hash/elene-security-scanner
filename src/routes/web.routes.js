import { Router } from "express";
import { renderHomePage } from "../controllers/page.controller.js";
import { renderDomainReport, exportDomainReportPdf } from "../controllers/domain.controller.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const router = Router();

router.get("/", renderHomePage);
router.get("/scan/export.pdf", asyncHandler(exportDomainReportPdf));
router.get("/scan", asyncHandler(renderDomainReport));

export default router;