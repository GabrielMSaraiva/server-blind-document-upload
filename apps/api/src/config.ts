import "dotenv/config";

export type ApiConfig = {
  port: number;
  baseUrl: string;
  webOrigin: string;
  localStorageRoot: string;
};

export function loadConfig(): ApiConfig {
  return {
    port: Number.parseInt(process.env.API_PORT ?? "4000", 10),
    baseUrl: process.env.API_BASE_URL ?? "http://localhost:4000",
    webOrigin: process.env.WEB_ORIGIN ?? "http://localhost:5173",
    localStorageRoot: process.env.LOCAL_STORAGE_ROOT ?? ".local-storage",
  };
}
