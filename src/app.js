import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import path from "path";
import { fileURLToPath } from "url";

import { env, isProduction } from "./config/env.js";
import webRoutes from "./routes/web.routes.js";
import apiRoutes from "./routes/api.routes.js";
import { notFoundHandler, errorHandler } from "./middlewares/error.middleware.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootPath = path.resolve(__dirname, "..");

const app = express();

app.set("appName", env.appName);
app.set("view engine", "ejs");
app.set("views", path.join(rootPath, "views"));

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(morgan(isProduction ? "combined" : "dev"));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.use(express.static(path.join(rootPath, "public"), {
  maxAge: isProduction ? "7d" : 0,
  etag: true
}));

app.use("/", webRoutes);
app.use("/api", apiRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;