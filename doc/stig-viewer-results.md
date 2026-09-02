# Viewing STIG results in DISA STIG Viewer

The `oc compliance fetch-stig-results` plugin command turns the
`ComplianceCheckResult` objects produced by a STIG `ScanSettingBinding` into
XCCDF results files that can be imported into
[DISA STIG Viewer](https://public.cyber.mil/stigs/srg-stig-tools/).

The compliance content ships the srg-stig-tools reference for every STIG rule,
which the Compliance Operator surfaces on each result as the
`control.compliance.openshift.io/STIG-RULE` annotation (the `SV-*_rule` id). The
command reads those results, rewrites each rule id to its STIG reference, and
writes XCCDF `TestResult` documents that match the output of
`oscap --stig-viewer`, which STIG Viewer imports natively.

The command only reads from the cluster — it performs a `get` on the
`ScanSettingBinding` and a `list` of its `ComplianceCheckResult` objects — and
makes no changes. It reads from the namespace in your current context (override
with `-n`), which for the Compliance Operator is typically
`openshift-compliance`.

## Prerequisites

* The [`oc compliance` plugin](https://github.com/ComplianceAsCode/compliance-operator/tree/master/cmd/oc-compliance)
  is installed alongside `oc`.
* You have read access (`get`/`list`) to `scansettingbindings` and
  `compliancecheckresults` in the compliance namespace.
* A STIG `ScanSettingBinding` (for example, one binding the `ocp4-stig` and
  `rhcos4-stig` profiles) has finished scanning, so its `ComplianceCheckResult`
  objects exist:

  ```console
  $ oc get scansettingbindings -n openshift-compliance
  NAME   STATUS
  stig   READY
  ```

  Wait until the binding's `STATUS` is `READY` (or `DONE`) before generating
  results; a scan that is still running produces only partial results.

## Generating XCCDF results

By default the command collapses every scan in the binding into a single
combined file, named after the binding, in the output directory:

```console
$ oc compliance fetch-stig-results stig -o stig-results/
Wrote 74 STIG rule results to stig-results/stig.xml
```

Because STIG rule ids are globally unique, that combined file can be imported
against either the platform (`ocp4-stig`) or node (`rhcos4-stig`) STIG in STIG
Viewer — each import picks up its relevant rules and ignores the rest.

To emit one file per scan instead, use `--per-scan`:

```console
$ oc compliance fetch-stig-results stig --per-scan -o stig-results/
Wrote 38 STIG rule results to stig-results/ocp4-stig.xml
Wrote 8 STIG rule results to stig-results/ocp4-stig-node-master.xml
Wrote 8 STIG rule results to stig-results/ocp4-stig-node-worker.xml
Wrote 46 STIG rule results to stig-results/rhcos4-stig-master.xml
Wrote 46 STIG rule results to stig-results/rhcos4-stig-worker.xml
```

To restrict output to a single scan, use `--scan`:

```console
$ oc compliance fetch-stig-results stig --scan ocp4-stig -o stig-results/
Wrote 38 STIG rule results to stig-results/ocp4-stig.xml
```

`--per-scan` and `--scan` are mutually exclusive.

## How results are aggregated

A single STIG `SV-*` rule can be produced by more than one
`ComplianceCheckResult`. This happens in two situations:

* **Within a scan**, when several checks map to the same STIG rule (the
  `control.compliance.openshift.io/STIG-RULE` annotation can even list multiple
  `SV-*` ids for one check, separated by `;`).
* **Across scans**, only in the default combined mode, where the same STIG rule
  can appear in more than one scan (for example, the `master` and `worker`
  variants of `rhcos4-stig`). With `--per-scan` or `--scan` each scan is written
  independently, so only within-scan aggregation applies.

When several results contribute to one rule, they are collapsed **worst status
wins**: the most significant status is kept and it overwrites any
less-significant status already recorded for that rule. The intent is that a
rule is only reported as passing if nothing actionable was found for it — a
single failing check makes the rule fail.

The precedence, from most significant (always wins) to least significant, is:

| Precedence | `ComplianceCheckResult` status | XCCDF result in STIG Viewer |
| ---------: | ------------------------------ | --------------------------- |
| 1 (highest, wins over all below) | `FAIL`          | `fail` |
| 2 | `ERROR`                                            | `error` |
| 3 | `INCONSISTENT`                                     | `error` |
| 4 | `MANUAL`                                           | `notchecked` |
| 5 | `INFO`                                             | `informational` |
| 6 | *no result / unrecognized status*                 | `unknown` |
| 7 | `PASS`                                             | `pass` |
| 8 (lowest) | `NOT-APPLICABLE`                         | `notapplicable` |

Reading the table: a `FAIL` overwrites every other status; a `PASS` is kept only
if the only other statuses seen for that rule are `NOT-APPLICABLE`; and a rule
with no verdict (empty status) is ranked above `PASS`/`NOT-APPLICABLE` so a
missing result is not silently masked by a benign one. When two results share
the same precedence, the kept result is equivalent, so ordering does not matter.

## Importing into STIG Viewer

In DISA STIG Viewer, load the matching STIG (for example, the *Red Hat
OpenShift Container Platform* STIG), then import the generated `.xml` file as a
results file. The rule results are matched to the loaded STIG by their `SV-*`
rule ids and displayed as Open / NotAFinding / Not Reviewed / Not Applicable.

## A note on rule revisions

STIG Viewer may warn that some rules "had matching Rule IDs, but mismatched
Revision IDs". The revision is the `r<number>` portion of the id
(`SV-<vuln>r<revision>_rule`), which DISA increments across STIG releases. This
warning is benign: it means the compliance content was built against a
different DISA STIG release baseline than the STIG loaded in STIG Viewer. The
command passes the `SV-*` ids through verbatim, so aligning the content version
with the STIG release loaded in STIG Viewer removes the warning.

## No results were written

If the command reports zero rule results, the `ScanSettingBinding` is likely not
a STIG binding: only checks carrying the
`control.compliance.openshift.io/STIG-RULE` annotation (present on `*-stig`
profiles) contribute rule results. Confirm the binding uses a STIG profile and
that its scans have finished.
