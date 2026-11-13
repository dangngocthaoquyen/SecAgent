# Controlled-run reporting handoff (Phase 3D.4.1)

The reporting API keeps its selected historical dataset as a startup snapshot.
To permit read-only lookup of a new authorized run, an operator explicitly
selects the `ControlledDispatcher` output directory in the reporting manifest:

```json
{
  "dataset_schema_version": "1.0.0",
  "allowed_roots": {"controlled": "../../results/controlled-runs"},
  "controlled_runs_root": "controlled",
  "reports": [],
  "verification_jobs": []
}
```

The selected directory must be local and operator controlled. The API does
not scan or import it into overview counts. It reads only a requested
`<32-hex-run-id>/run-summary.json` and the report basename recorded there.
The run ID, report SHA-256, native execution ID, testcase ID, and target ID
must match the saved report. Unknown, invalid, unselected, missing, and
tampered references are rejected.

After a run persists, the workflow response includes
`reporting_run_reference` and `reporting_view` (`run/<run-id>`). The browser
can open `#run/<run-id>` through the reporting API's read-only
`GET /api/reports/runs/<run-id>` endpoint. The detail retains the report's
historical verdict and evidence. It does not change the startup snapshot,
historical reports, or existing execution-detail identifiers.
