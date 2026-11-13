import { defineConfig } from "vitest/config";

// Only same-origin loopback requests may cross the development proxy.
export default defineConfig({
  plugins: [
    {
      name: "local-reporting-boundary",
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const host = req.headers.host;
          if (
            !["127.0.0.1:5173", "localhost:5173"].includes(host ?? "") ||
            (req.headers.origin && req.headers.origin !== `http://${host}`) ||
            req.headers["sec-fetch-site"] === "cross-site"
          ) {
            res.statusCode = 403;
            res.end("Local same-origin access required.");
            return;
          }
          if (req.url?.startsWith("/api/")) {
            const workflow = req.url.startsWith('/api/testing/');
            const workflowAllowed = (req.method === 'GET' && ['/api/testing/health','/api/testing/targets','/api/testing/categories','/api/testing/testcases'].includes(req.url)) || (req.method === 'POST' && ['/api/testing/target-drafts/validate','/api/testing/connection-checks','/api/testing/compatibility/preview','/api/testing/plans/preview','/api/testing/readiness/preview','/api/testing/admissions','/api/testing/runs'].includes(req.url) && req.headers.origin === `http://${host}`);
            if (workflow ? !workflowAllowed : (req.method !== "GET" || !req.url.startsWith("/api/reports/"))) {
              res.statusCode = 405;
              res.end("Read-only reporting route required.");
              return;
            }
            // Origin was validated above; describe this local proxy hop to Flask.
            if (req.headers.origin)
              req.headers.origin = workflow ? 'http://127.0.0.1:8092' : "http://127.0.0.1:8091";
          }
          next();
        });
      },
    },
  ],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    cors: false,
    proxy: {
      "/api/reports/": { target: "http://127.0.0.1:8091", changeOrigin: true },
      "/api/testing/": { target: "http://127.0.0.1:8092", changeOrigin: true },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.ts*"],
  },
});
