# `oc compliance` plugin

`oc-compliance` is a set of `oc` utilities that make the Compliance Operator
easier to work with. Once the binary is on your `PATH` next to `oc`, the
subcommands are available as `oc compliance <subcommand>`.

Run `oc compliance <subcommand> --help` for the full flags and examples of any
command below.

## Subcommands

| Subcommand | Description |
| ---------- | ----------- |
| `bind` | Create a `ScanSettingBinding` from the given profiles/settings. |
| `controls` | Report which regulatory controls a profile complies with. |
| `fetch-fixes` | Download the fixes/remediations for a rule, profile, or `ComplianceRemediation`. |
| `fetch-raw` | Download the raw compliance results (ARF/XCCDF) of a scan, suite, or binding. |
| `fetch-stig-results` | Generate DISA STIG Viewer XCCDF results from a `ScanSettingBinding`. |
| `rerun-now` | Force a re-scan for one or more `ComplianceScans`. |
| `view-result` | View a `ComplianceCheckResult`. |

## Troubleshooting

If `oc compliance` is not recognized, `oc` could not find the plugin on your
`PATH`. Confirm that:

* the binary is named exactly `oc-compliance` (that is how `oc` discovers it),
* it is executable (`chmod +x oc-compliance`), and
* its directory is on your `PATH` (`which oc-compliance`).

Run `oc plugin list` to see which plugins `oc` has discovered.

## Additional documentation

* [Viewing STIG results in DISA STIG Viewer](../../doc/stig-viewer-results.md) —
  generating XCCDF results with the DISA `SV-*` rule ids and importing them into
  DISA STIG Viewer.
