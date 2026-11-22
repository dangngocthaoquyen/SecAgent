import { defineConfig } from "vitest/config";

// Only same-origin loopback requests may cross the development proxy.
function localPort(name:string,fallback:number){
  const value=process.env[name];
  if(value===undefined)return fallback;
  if(!/^[0-9]{1,5}$/.test(value)||Number(value)<1||Number(value)>65535)throw Error(`Invalid ${name}.`);
  return Number(value);
}
const frontendPort=localPort('SECAGENT_FRONTEND_PORT',5173);
const workflowPort=localPort('SECAGENT_WORKFLOW_PROXY_PORT',8092);
const reportingPort=localPort('SECAGENT_REPORTING_PROXY_PORT',8091);
const localToken=process.env.SECAGENT_LOCAL_PROXY_TOKEN;
if(localToken!==undefined&&localToken.length<32)throw Error('Invalid local proxy credential.');
const workflowOrigin=`http://127.0.0.1:${workflowPort}`;
const reportingOrigin=`http://127.0.0.1:${reportingPort}`;
const privileged=new Set(['/api/testing/managed-targets','/api/testing/managed-targets/validate',
 '/api/testing/managed-targets/create','/api/testing/managed-targets/update',
 '/api/testing/managed-targets/review','/api/testing/connection-checks','/api/testing/discoveries','/api/testing/discovery-probes',
 '/api/testing/execution-grants','/api/testing/runs','/api/testing/run-selected',
 '/api/testing/batches/preview','/api/testing/batches',
 '/api/testing/datasets','/api/testing/datasets/validate','/api/testing/datasets/import',
 '/api/testing/asi03-contracts/drafts','/api/testing/asi03-policies/drafts',
 '/api/testing/asi05-policies/drafts']);
privileged.add('/api/testing/application-contexts/save');
privileged.add('/api/testing/managed-targets/archived');
privileged.add('/api/testing/managed-targets/archive');
privileged.add('/api/testing/managed-targets/restore');
privileged.add('/api/testing/mcp-actions');
privileged.add('/api/testing/mcp-actions/run');
const batchRead=/^\/api\/testing\/batches\/[a-f0-9]{32}(?:\/(?:events|results))?$/;
const discoveryRead=/^\/api\/testing\/discoveries\/[a-f0-9]{32}$/;
const datasetRead=/^\/api\/testing\/datasets\/[a-f0-9]{32}$/;
const asi03Read=/^\/api\/testing\/asi03-contracts\/(?:[a-f0-9]{32}|lookup\/[a-f0-9]{32}\/import-[a-f0-9]{24}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$/;
const asi03Review=/^\/api\/testing\/asi03-contracts\/[a-f0-9]{32}\/review$/;
const asi03PolicyRead=/^\/api\/testing\/asi03-policies\/(?:[a-f0-9]{32}|target\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$/;
const asi03PolicyReview=/^\/api\/testing\/asi03-policies\/[a-f0-9]{32}\/review$/;
const asi05PolicyRead=/^\/api\/testing\/asi05-policies\/(?:[a-f0-9]{32}|target\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$/;
const asi05PolicyReview=/^\/api\/testing\/asi05-policies\/[a-f0-9]{32}\/review$/;
const evidenceRead=/^\/api\/testing\/(?:evidence-sources\/target\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|evidence-captures\/[a-f0-9]{32})$/;
const applicationContextRead=/^\/api\/testing\/application-contexts\/target\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const evidenceWrite=/^\/api\/testing\/evidence-sources\/(?:save|collect)$/;
const batchCancel=/^\/api\/testing\/batches\/[a-f0-9]{32}\/cancel$/;
export default defineConfig({
  plugins: [
    {
      name: "local-reporting-boundary",
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const host = req.headers.host;
          if (
            ![`127.0.0.1:${frontendPort}`, `localhost:${frontendPort}`].includes(host ?? "") ||
            (req.headers.origin && req.headers.origin !== `http://${host}`) ||
            req.headers["sec-fetch-site"] === "cross-site" ||
            (localToken!==undefined && req.headers['x-secagent-operator']!==undefined)
          ) {
            res.statusCode = 403;
            res.end("Local same-origin access required.");
            return;
          }
          if (req.url?.startsWith("/api/")) {
            const workflow = req.url.startsWith('/api/testing/');
            const workflowAllowed = (req.method === 'GET' && (['/api/testing/health','/api/testing/targets','/api/testing/categories','/api/testing/testcases','/api/testing/managed-targets','/api/testing/managed-targets/archived','/api/testing/datasets','/api/testing/mcp-actions'].includes(req.url)||batchRead.test(req.url)||discoveryRead.test(req.url)||datasetRead.test(req.url)||asi03Read.test(req.url)||asi03PolicyRead.test(req.url)||asi05PolicyRead.test(req.url)||evidenceRead.test(req.url)||applicationContextRead.test(req.url))) || (req.method === 'POST' && (['/api/testing/target-drafts/validate','/api/testing/connection-checks','/api/testing/discovery-probes','/api/testing/managed-targets/validate','/api/testing/managed-targets/create','/api/testing/managed-targets/update','/api/testing/managed-targets/review','/api/testing/managed-targets/archive','/api/testing/managed-targets/restore','/api/testing/discoveries','/api/testing/execution-grants','/api/testing/run-selected','/api/testing/compatibility/preview','/api/testing/plans/preview','/api/testing/readiness/preview','/api/testing/admissions','/api/testing/runs','/api/testing/batches/preview','/api/testing/batches','/api/testing/datasets/validate','/api/testing/datasets/import','/api/testing/asi03-contracts/drafts','/api/testing/asi03-policies/drafts','/api/testing/asi05-policies/drafts','/api/testing/application-contexts/save','/api/testing/mcp-actions/run'].includes(req.url)||batchCancel.test(req.url)||asi03Review.test(req.url)||asi03PolicyReview.test(req.url)||asi05PolicyReview.test(req.url)||evidenceWrite.test(req.url)) && req.headers.origin === `http://${host}`);
            if (workflow ? !workflowAllowed : (req.method !== "GET" || !req.url.startsWith("/api/reports/"))) {
              res.statusCode = 405;
              res.end("Read-only reporting route required.");
              return;
            }
            // Origin was validated above; describe this local proxy hop to Flask.
            if (req.headers.origin)
              req.headers.origin = workflow ? workflowOrigin : reportingOrigin;
          }
          next();
        });
      },
    },
  ],
  server: {
    host: "127.0.0.1",
    port: frontendPort,
    strictPort: true,
    cors: false,
    proxy: {
      "/api/reports/": { target: reportingOrigin, changeOrigin: true },
      "/api/testing/": { target: workflowOrigin, changeOrigin: true,
        configure(proxy){proxy.on('proxyReq',(upstream,req)=>{
          if(localToken!==undefined&&(privileged.has(req.url??'')||batchRead.test(req.url??'')||batchCancel.test(req.url??'')||discoveryRead.test(req.url??'')||datasetRead.test(req.url??'')||asi03Read.test(req.url??'')||asi03Review.test(req.url??'')||asi03PolicyRead.test(req.url??'')||asi03PolicyReview.test(req.url??'')||asi05PolicyRead.test(req.url??'')||asi05PolicyReview.test(req.url??'')||applicationContextRead.test(req.url??'')||evidenceRead.test(req.url??'')||evidenceWrite.test(req.url??'')))upstream.setHeader('X-SecAgent-Operator',localToken);
        });}},
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.ts*"],
  },
});
