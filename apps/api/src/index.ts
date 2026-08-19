import { loadConfig } from "./config.js";
import { createServer } from "./server.js";

const config = loadConfig();
const app = await createServer(config);

try {
  await app.listen({ port: config.port, host: "0.0.0.0" });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
