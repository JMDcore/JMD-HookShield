import { resolve } from "node:path";
import { parseMasterKey } from "@hookshield/security";

export interface AppConfig {
  databasePath: string;
  masterKey: Buffer;
  port: number;
  webOrigin: string;
  demoMode: boolean;
  secureCookies: boolean;
}

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const databasePath = overrides.databasePath ?? process.env.HOOKSHIELD_DATABASE_PATH ?? ".data/hookshield.db";
  return {
    databasePath: databasePath === ":memory:" ? databasePath : resolve(databasePath),
    masterKey: overrides.masterKey ?? parseMasterKey(process.env.HOOKSHIELD_MASTER_KEY),
    port: overrides.port ?? Number(process.env.HOOKSHIELD_API_PORT ?? 8787),
    webOrigin: overrides.webOrigin ?? process.env.HOOKSHIELD_WEB_ORIGIN ?? "http://localhost:3000",
    demoMode: overrides.demoMode ?? process.env.HOOKSHIELD_DEMO_MODE === "true",
    secureCookies: overrides.secureCookies ?? process.env.NODE_ENV === "production"
  };
}
