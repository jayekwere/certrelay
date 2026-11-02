import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "e2e",
  workers: 1,
  use: { baseURL: "http://127.0.0.1:18224", viewport: { width: 1440, height: 1100 } },
  webServer: {
    command: "python -m app.cli serve --demo --port 18224",
    url: "http://127.0.0.1:18224/health",
    reuseExistingServer: false,
    timeout: 30000,
    env: { STATE_PATH: "artifacts/browser-state.db", PKI_ROOT: "artifacts/browser-pki" },
  },
});
