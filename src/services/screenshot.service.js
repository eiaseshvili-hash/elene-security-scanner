import { chromium } from "playwright";
import sharp from "sharp";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SCREENSHOT_DIR = path.resolve(__dirname, "../../public/generated/screenshots");
const SCREENSHOT_TTL_MS = 5 * 60 * 1000;

async function ensureScreenshotDir() {
  await fs.mkdir(SCREENSHOT_DIR, { recursive: true });
}

async function removeFileLater(filePath) {
  setTimeout(async () => {
    try {
      await fs.unlink(filePath);
    } catch {
      // ignore cleanup errors
    }
  }, SCREENSHOT_TTL_MS).unref();
}

async function cleanupOldScreenshots() {
  try {
    await ensureScreenshotDir();

    const files = await fs.readdir(SCREENSHOT_DIR);
    const now = Date.now();

    await Promise.all(
      files
        .filter((file) => file.endsWith(".webp"))
        .map(async (file) => {
          const filePath = path.join(SCREENSHOT_DIR, file);
          const stat = await fs.stat(filePath);

          if (now - stat.mtimeMs > SCREENSHOT_TTL_MS) {
            await fs.unlink(filePath);
          }
        })
    );
  } catch {
    // ignore cleanup errors
  }
}

function normalizeScreenshotUrl(domain, finalUrl) {
  const rawUrl = finalUrl || `https://${domain}`;
  const url = new URL(rawUrl);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Unsupported screenshot URL protocol");
  }

  return url.toString();
}

export async function captureWebsiteScreenshot(domain, finalUrl = null) {
  await cleanupOldScreenshots();
  await ensureScreenshotDir();

  const targetUrl = normalizeScreenshotUrl(domain, finalUrl);
  const fileName = `${domain.replace(/[^a-z0-9.-]/gi, "-")}-${crypto.randomUUID()}.webp`;
  const filePath = path.join(SCREENSHOT_DIR, fileName);

  let browser;

  try {
    browser = await chromium.launch({
      headless: true
    });

    const page = await browser.newPage({
      viewport: {
        width: 1365,
        height: 768
      },
      deviceScaleFactor: 1
    });

    await page.goto(targetUrl, {
      waitUntil: "domcontentloaded",
      timeout: 15000
    });

    await page.waitForTimeout(1200);

    const pngBuffer = await page.screenshot({
      fullPage: false,
      type: "png"
    });

    await sharp(pngBuffer)
      .resize({
        width: 1100,
        withoutEnlargement: true
      })
      .webp({
        quality: 78
      })
      .toFile(filePath);

    await removeFileLater(filePath);

    return {
      captured: true,
      url: `/generated/screenshots/${fileName}`,
      expiresInSeconds: Math.floor(SCREENSHOT_TTL_MS / 1000)
    };
  } catch (error) {
    return {
      captured: false,
      url: null,
      error: error.message
    };
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}