# Offline HTTP JSON schema fixtures

These are synthetic examples of source-verified shapes, not captured execution evidence, labels, or human ground truth. They contain no operator data. No test contacts DVAA.

Read-only source inspection in the existing `dvaa-deepseek` container:

- `/app/src/dashboard/server.js:743`: `GET /api/attack-log` returns an array. `/app/src/index.js:289` constructs detector records. A `successful` flag is not an execution receipt.
- `/app/src/dashboard/server.js:853`: `GET /api/sandbox/cmd-log` returns the parsed array, or `[]` on failure. `/app/src/index.js:1778–1788` logs `{timestamp, command, agent}` in the simulated execute branch.
- `/app/src/dashboard/server.js:817–831`: `GET /api/sandbox/files` returns `{root, files}` with path/type/optional size. This is a point-in-time directory listing, with no run attribution.

None supplies trustworthy testcase/run/invocation correlation or a complete agent trace. An empty array is not proof of absence. These paths are fixture inputs only; production does not discover or assume any of them.
