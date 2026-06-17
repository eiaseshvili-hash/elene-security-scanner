import app from "./app.js";
import { env } from "./config/env.js";

app.listen(env.port, env.host, () => {
  console.log(`${env.appName} running on http://${env.host}:${env.port}`);
});