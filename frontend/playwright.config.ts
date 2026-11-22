import { defineConfig } from "@playwright/test";
const browserPort = Number(process.env.SECAGENT_FRONTEND_PORT || '5173');
if (!Number.isInteger(browserPort) || browserPort < 1 || browserPort > 65535) throw Error('Invalid browser port.');
export default defineConfig({
  testDir: "./browser-tests",
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: `http://127.0.0.1:${browserPort}`,
    channel: process.env.SECAGENT_BROWSER_CHANNEL || "msedge",
    viewport: { width: 1440, height: 1100 },
  },
  webServer: {
    command: "npm run dev",
    url: `http://127.0.0.1:${browserPort}`,
    // Explicit opt-in only after confirming the listener is this workspace's Vite.
    reuseExistingServer: process.env.SECAGENT_REUSE_VITE === "1",
    timeout: 30000,
  },
  reporter: "list",
});
