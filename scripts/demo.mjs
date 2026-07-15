import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));

const demoEnv = {
  ...process.env,
  HOOKSHIELD_MASTER_KEY: Buffer.alloc(32, 42).toString("base64"),
  HOOKSHIELD_DATABASE_PATH: join(projectRoot, ".data", "hookshield.db"),
  HOOKSHIELD_API_PORT: "8787",
  HOOKSHIELD_WEB_ORIGIN: "http://localhost:3000",
  HOOKSHIELD_DEMO_MODE: "true",
  NEXT_PUBLIC_API_URL: "http://localhost:8787",
  NEXT_PUBLIC_DEMO_MODE: "true",
  NODE_ENV: "development"
};

function run(command, args, options = {}) {
  return spawn(command, args, {
    env: demoEnv,
    stdio: "inherit",
    shell: false,
    cwd: projectRoot,
    ...options
  });
}

const seed = run("pnpm", ["demo:seed"]);
const seedCode = await new Promise((resolve) => seed.once("exit", resolve));
if (seedCode !== 0) process.exit(Number(seedCode ?? 1));

const dev = run("pnpm", ["dev"]);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => dev.kill(signal));
}
dev.once("exit", (code) => process.exit(Number(code ?? 0)));
