import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./browser-tests",
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:5173",
    channel: "msedge",
    viewport: { width: 1440, height: 1100 },
  },
  webServer: {
    command: "npm run dev",
    url: "http://127.0.0.1:5173",
    // Explicit opt-in only after confirming the listener is this workspace's Vite.
    reuseExistingServer: process.env.SECAGENT_REUSE_VITE === "1",
    timeout: 30000,
  },
  reporter: "list",
});
