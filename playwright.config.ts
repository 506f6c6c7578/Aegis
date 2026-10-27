import { defineConfig, devices } from "@playwright/test";

const port = 4322;
const baseURL = `http://localhost:${port}`;

export default defineConfig({
    testDir: "tests",
    fullyParallel: true,
    forbidOnly: Boolean(process.env.CI),
    retries: process.env.CI ? 2 : 0,
    reporter: "list",
    use: {
        baseURL,
        locale: "fr-FR",
        timezoneId: "Europe/Paris",
        trace: "retain-on-failure"
    },
    projects: [
        { name: "api", testMatch: "integration/**/*.spec.ts" },
        { name: "chromium", testMatch: "e2e/**/*.spec.ts", use: { ...devices["Desktop Chrome"] } },
        { name: "mobile", testMatch: "e2e/**/*.spec.ts", use: { ...devices["Pixel 7"] } }
    ],
    webServer: {
        command: "pnpm preview",
        url: baseURL,
        env: {
            HOST: "localhost",
            PORT: String(port),
            AEGIS_SECRET: "secret-de-test-playwright-uniquement-0123456789abcdef",
            AEGIS_DNS_SERVERS: "127.0.0.1:9"
        },
        reuseExistingServer: false
    }
});
