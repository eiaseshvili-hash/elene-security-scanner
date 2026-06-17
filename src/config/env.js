import dotenv from "dotenv";

dotenv.config();

export const env = {
  appName: process.env.APP_NAME || "Elene Project",
  appEnv: process.env.APP_ENV || "development",
  appUrl: process.env.APP_URL || "http://localhost:8090",

  host: process.env.HOST || "172.19.0.1",
  port: Number(process.env.PORT || 8090),

  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 60000),
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX || 60)
};

export const isProduction = env.appEnv === "production";