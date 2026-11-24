# SecAgent UI reference — design specification

## Purpose
This is a standalone, offline presentation prototype, not the SecAgent runtime. Its six primary views are New Scan Configuration, Scan Preview, Live Progress, Scan Results, Testcase Detail and Execution History (two tabs). The remaining sidebar routes are navigation placeholders, not replacement implementations. Use it as a visual and interaction reference; do not integrate its mock engine or fixture data into production.

## Source and precedence
- `index.html`: application shell and reference structure.
- `styles.css`: authoritative visual tokens, spacing, responsive layout and component appearance.
- `app.js`: markup patterns and demo interactions only. The timer, fixture-based verdicts, simulated authorization, reconnect and download are not production implementations.
- `mock-data.json` / `mock-data.js`: sanitized reference data from historical run `1082079f46d343b0bec767d2caeaa76e`. Counts, case IDs, verdicts, classifications, timing and Judge invocation metadata are based on the supplied report; subject titles and response summaries are paraphrased. Raw prompt/response/native report files are intentionally not included. Other runs are summary-only references from the history screen; the native reports tab displays only 30 sample rows out of 62 observed historical reports.
- `screenshots/`: browser-rendered reference images; the screenshots supplement the HTML and CSS. If visual and behavioral requirements conflict, production security contracts take precedence.

## Visual tokens
| Token | Value |
|---|---|
| Background | #F5F7FA |
| Surface | #FFFFFF |
| Text | #172B3A |
| Secondary text | #64748B |
| Border | #E1E7ED |
| Primary | #0D5C63 |
| Primary soft | #E7F2F2 |
| PASS | #18774B |
| FAIL | #B93838 |
| INCONCLUSIVE | #94620A |
| ERROR | #586579 |
| Radius | 10px cards, 7px buttons |
| Typography | Segoe UI/system sans; 14px body, 28px page heading, 17px section title, 12px metadata, 13px table |
| Desktop | 236px sidebar, 32px content gutter, responsive main region, max 1540px content |
| Spacing | 8–16px controls/gaps; 20px cards; 22px section headings |

## Screen mapping
| Screenshot | Production component focus |
|---|---|
| 01-new-scan.png | SecurityScanWizard configuration |
| 02-scan-preview.png | SecurityScanWizard preview |
| 03-live-progress.png | ScanProgressComponents / SecurityScanWizard |
| 04-scan-results.png | SecurityScanWizard results |
| 05-testcase-detail.png | Results details drawer or existing Detail route |
| 06-execution-history.png | SavedRuns grouped runs |
| 07-native-reports.png | SavedRuns native and legacy reports |
| 08-reconnect.png | Actual recovery presentation |
| 09-results-*.png | Responsive results examples |

## Interaction reference
Configuration → Preview → authorize demo → historical replay. Progress may be paused, completed or deliberately disconnected and reconnected. Results show all 30 cases via search, ASI/verdict/evidence filters and pagination. Detail opens six tabs, and supports sample copy/download. History shows grouped runs and a separate native sample tab. The demo has no live execution, no real API authentication and no external requests. The preview mode/engine controls demonstrate presentation only; the replay always uses the fixed Live Hybrid historical fixture, as explicitly noted in the UI.

## Production mapping principles
Use existing React components, API responses and authorization behavior. Copy the visual structure and design tokens, not hardcoded fixture values, simulated clocks, mock results or fake capabilities. Maintain original data accessibility, exact verdict semantics and unknown/missing evidence metadata. All target output must be rendered inertly. Keep wide tables locally scrollable, never the entire page. Preserve all report and navigation functions, including older MCP and other legacy workflows.
