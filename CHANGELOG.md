# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Enhancements

-

### Fixes

-

### Internal Changes

-

### Deprecations

-

### Removals

-

### Security

-


## [1.6.2] - 2025-03-05

### Enhancements

-

### Fixes

-

### Internal Changes

-

### Deprecations

-

### Removals

-

### Security

-


## [1.6.0] - 2024-09-12

### Enhancements

- The operator now supports timestamps on each `ComplianceCheckResult` with the
  `compliance.openshift.io/last-scanned-timestamp` annotation. This annotation
  is updated each time a scan runs.
- Each `ComplianceScan` resource now includes a total `ComplianceCheckResult`
  count using the `compliance.openshift.io/check-count` annotation.

## [1.5.0] - 2024-05-31

### Enhancements

-

### Fixes

-

### Internal Changes

-

### Deprecations

-

### Removals

-

### Security

-


## [1.4.1] - 2024-04-17

### Fixes

- [CMP-29272](https://issues.redhat.com/browse/OCPBUGS-29272) The Compliance
  Operator will now clean up scan results when they're removed from a
  `ScanSettingBinding`.
- The Compliance Operator nows supports running multiple node profiles in the
  same `ScanSettingBinding`. This makes it easier to have a single
  `ScanSettingBinding` that contains all profiles for a benchmark.

## [1.4.0] - 2023-12-01

### Enhancements

- Users can now pause scan schedules by setting the `ScanSetting.suspend`
  attribute to `True`. This allows users to suspend a scan, and reactivate it
  without having to delete and recreate the `ScanSettingBinding`, making it
  more ergonomic to pause scans during maintenance periods. See the
  [enhancement](https://github.com/ComplianceAsCode/compliance-operator/pull/375)
  for more details.
- Implemented support for an optional `version` attribute on `Profile` custom
  resources.
- `Rule` custom resources now contain an annotation
  (`compliance.openshift.io/profiles`) that maps the rule to the profiles that
  use it, making it easier to understand where a rule is used. The alternative
  to this approach would be to query each `Profile` and join all rules.

### Fixes

- Optimize how the operator checks `KubeletConfig` rules by storing the runtime
  `KubeletConfig` in a `ConfigMap` per node when a node scan is launched. The
  `ConfigMap` is then mounted to the scanner pod for evaluation. The operator
  will wait to apply `ComplianceRemediation` objects until all scans are
  processed. This also fixes issues when comparing the `KubeletConfig` options
  for each node, and removes `/api/v1/nodes/NODE_NAME/proxy/configz` warning
  messages in the log [OCPBUGS-11037](https://issues.redhat.com/browse/OCPBUGS-11037).
- Fix api-checks-pod crashes issues caused by an outdated Machine Config Operator
  dependency. The dependency bump allows the operator to support Ignition 3.4,
  and therefore solves the issue [OCPBUGS-18025](https://issues.redhat.com/browse/OCPBUGS-18025).
- Stale `ComplianceCheckResult` resources are now pruned on each rescan
  [OCPBUGS-3009](https://issues.redhat.com/browse/OCPBUGS-3009).

### Internal Changes

- All compatibility code for the `CronJob` beta API has been removed [CMP-2310](https://issues.redhat.com/browse/CMP-2310).

### Removals

- We have reverted commit
  [9cbf874](https://github.com/ComplianceAsCode/compliance-operator/commit/9cbf874),
  which is a fix for
  [OCPBUGS-3864](https://issues.redhat.com/browse/OCPBUGS-3864), the fix is not
  needed anymore with how `KubeletConfig` rules are processed.

## [1.3.1] - 2023-10-11

### Fixes

- Fix an issue caused by outdated Machine Config Operator dependencies where
  the API check pod crashes due to Machine Config Operator using newer versions
  of Ignition (3.4).
  [OCPBUGS-18025](https://issues.redhat.com/browse/OCPBUGS-18025)

## [1.3.0] - 2023-09-11

## [1.2.0] - 2023-07-21

### Enhancements

-

### Fixes

-

### Internal Changes

-

### Deprecations

-

### Removals

-

### Security

-


## [1.1.0] - 2023-06-12

### Enhancements
- Added start and end timestamp to the ComplianceScan CRD status.

- The operator can now be deployed on HyperShift HostedCluster using OLM with 
  a special subscription file in `config/catalog/subscriptions-hypershift.yaml`.
  This can be used to deploy from both downstream and upstream source. See
  `doc/usage.md` for more details.

- The `SCAP_DEBUG_LEVEL` variable can now be used to set a custom OpenScap debug level
  including the highest level `DEVEL`. This can be useful when debugging failed scans or issues
  in the OpenScap scanner itself. Setting the variable takes precedence over the
  `debug` attribute of the `ComplianceScan` CR. See `doc/usage.md` for more details.

### Fixes

- The operator now parses links from the compliance content and renders it in
  custom resources accordingly.
- `ComplianceCheckResult` objects are automatically cleaned up on each scan.
  This prevents the [illusion](https://issues.redhat.com/browse/OCPBUGS-3009)
  that changes to profiles, like excluding rules, aren't taking effect because
  stale `ComplianceCheckResult` objects are leftover from previous runs.

- The operator have the ability to hide warnings for certain failed to fetched
  resources, this is useful when the user does not want to see the warnings
  for certain resources, for example, the user does not want to see the
  warnings for rules that used to detect HyperShift.

- Fix values used rendering issues for some rules that reference variables in
  the rule's instruction.
  [OCPBUGS-7456](https://issues.redhat.com/browse/OCPBUGS-7456)

### Internal Changes

- Update Kustomize and make target to be able to deploy on generic Kubernetes cluster.

- Added an ability to identify which platform we are on using a CPE. We always
  fetch api-checks-pod pod object, and save it to a dump file
  when api-resource collector is running, CPE can use the dump file to
  check the command line arguments to see if we are running on a specific
  platform.

### Deprecations

-

### Removals

-

### Security

-


## [1.0.0] - 2023-04-08

The Compliance Operator is now stable and follows semantic versioning rules. No
backwards incompatible changes were made between version 0.1.61 and 1.0.0 to
allow for smoother upgrades.

### Internal Changes

- Fix openscap image substitution in Makefile so that the correct image is used.

- Fix github operator image workflow to listen to the master branch, added
  bundle image, and openscap image build jobs to the workflow. Also added
  a special Dockerfile for the bundle image so that the bundle image can
  point to the correct images.

- Modify API resource collector to detect if fetched resource is yaml string and
  convert it to json when found, this is necessary because some of the API resources
  are not available in json format, and we need to convert it to json format so that
  it can be read by OpenSCAP.

- Added documentation on how to run a platform scan on HyperShift Management
  Cluster in `doc/usage.md`.

### Removals

- The `compliance_scan_error_total` metric was designed to count individual
  scan errors. As a result, one of the metric keys contained the scan error,
  which is large. The length and uniqueness of the metric itself can cause
  issues in Prometheus, as noted in [Metric and Label Naming best
  practices](https://prometheus.io/docs/practices/naming/#labels). The error
  in the metric has been removed to reduce cardinality. Please see the [bug
  report](https://issues.redhat.com/browse/OCPBUGS-1803) for more details.


## [0.1.61] - 2023-02-08

### Fixes

- On re-running scans, remediations that were previously Applied might
  have been marked as Outdated after a re-run finished
  despite no changes in the actual remediation content because of
  a buggy comparison that did not take into account trivial differences
  in remediation metadata (tracked with [OCPBUGS-6710](https://issues.redhat.com/browse/OCPBUGS-6710))

- Fixed a [regression](https://issues.redhat.com/browse/OCPBUGS-6827) where
  attempting to create a `ScanSettingBinding` that was using a `TailoredProfile`
  that was in turn using a non-default `MachineConfigPool` would mark
  the `ScanSettingBinding` as failed. Note that this bug was only affecting
  setups where the TailoredProfile wasn't annotated with
  `compliance.openshift.io/product-type`.

## [0.1.60] - 2023-01-23

### Enhancements

- Added support for timeout for Scanner Pod. The timeout is
  specified in the `ComplianceScanSettings` object as a duration string,
  e.g. `1h30m`. If the scan is not completed within the timeout, the
  corresponding scan will either fail or retry.
  See [To use timeout option for scan](https://github.com/ComplianceAsCode/compliance-operator/blob/master/doc/usage.md#to-use-timeout-option-for-scan) in `doc/usage.md` for details usage.

### Fixes

- Fixes an [issue](https://issues.redhat.com/browse/OCPBUGS-3420) where
  `ScanSettingBindings` created without a `settingRef` did not use a proper
  default value. `ScanSettingBindings` without a `settingRef` will now use the
  `default` `ScanSetting`.
  
- System reserved parameters do not get generated into `/etc/kubernetes/kubelet.conf`,
  and it is causing Compliance Operator to fail to unpause the machine config pool,
  this PR excludes node sizing, and system reserved parameters from checking if 
  KubeletConfig is not part of the generated Machine Config since it does not get
  generated into `/etc/kubernetes/kubelet.conf` file.
  [OCPBUGS-4445] https://issues.redhat.com/browse/OCPBUGS-4445

- Fixes an [issue](https://issues.redhat.com/browse/OCPBUGS-4615) where
  `ComplianceCheckResult` objects do not have correct descriptions, we
  corrected the descriptions, and also added a new `rationale` field to
  `ComplianceCheckResult` objects. And we fixed variable rendering in 
  in the `instructions` field.

- Added check for nil pointer before comparing if KubeletConfig is fully rendered。
  This is necessary because setting the KubeletConfig object incorrectly can result
  in an empty KubeletConfig Spec, which can cause a panic error. This check will prevent
  this issue and ensure the comparison is performed safely.
  [OCPBUGS-4621](https://issues.redhat.com/browse/OCPBUGS-4621)

- Make Compliance Operator to apply all the related remediations for 
  one ComplianceCheckResult at once, this helps users who use manual
  remediation, this feature will look for all the related remediations
  for a ComplianceCheckResult when one remediation is applied. For ex.
  we have `cp4-cis-kubelet-evictio...-inodesfree`, `cp4-cis-kubelet-evictio...-inodesfree-1`,
  remediations, when a user applies either one of them, we will apply
  all the other remediations associate with the rule.
  [OCPBUGS-4338]https://issues.redhat.com/browse/OCPBUGS-4338


### Internal Changes

- The Compliance Operator now marks a `ScanSettingBinding` that uses a
  `ScanSetting` which in turn uses a non-default node role as failed
  unless the `ScanSettingBinding` points to a `TailoredProfile` that sets
  a variable which tailors the content to generate remediations for that
  pool only. This prevents [issues](https://issues.redhat.com//browse/OCPBUGS-3864)
  where some remediations were applied cluster-wide and some only for a
  custom pool by forcing the user to select the pool explicitly and thus
  generating all remediations consistently for that pool only.

- Added the ability to hide compliance check result for helper rule, we will
  scan for "ocp-hide-rule" in the warning, and if it exist we will not show
  the rule in the compliance check result.

- Added permission to fetch HyperShift version resources, please refer to
  [HyperShift Version Detection](https://github.com/ComplianceAsCode/content/pull/9726)
  on how to use tailoredProfile for HyperShift version detection.

### Deprecations

-

### Removals

-

### Security

-


## [0.1.59] - 2022-11-16

### Internal Changes

- OpenShift platforms were added as an annotation. This helps organize
  operators across the OpenShift ecosystem.
- The `preamble.json` file was included in release targets, making it easier to
  include changes when releasing new versions of the operator.

## [0.1.58] - 2022-11-14

### Enhancements

-

### Fixes

- The `rerunner` Service Account was not properly owned by the operator CSV
  after the recent upgrade of the Operator SDK and as an effect could be removed
  when Compliance Operator was upgraded from a version built with the older
  Operator SDK version (from 0.1.53 or older). This issue is also
  [tracked](https://issues.redhat.com/browse/OCPBUGS-3452) in
  Red Hat's issue tracker.
- Fix metrics port during operator startup.
  The metrics port configuration was being set to a default of 8080 due to an
  unused options setup variable, this is corrected to be hard-coded to 8383 as
  required by OCP monitoring. Fixes [OCP-3097](https://issues.redhat.com/browse/OCPBUGS-3097).
- Pass namespace to the controller manager on startup, which now allows the
  WATCH_NAMESPACE adjustments to take place. The operator pod will now only
  watch in the operator namespace, reducing memory usage when there are many
  namespaces.

### Internal Changes

- Ensure `preamble.json` is included in the release process so the catalog is
  up-to-date with the latest version of the operator.

### Deprecations

-

### Removals

-

### Security

-


## [0.1.57] - 2022-10-20

### Fixes

- Fix broken-content script to include a new image tag, and add test content datastream xml files.
  We pushed a new test content image to `quay.io/compliance-operator/test-broken-content:kublet_default`
  for our Compliance Operator e2e test. In order to run e2e test on other architectures, we need to store
  the test content datastream xml files under images/testcontent, and update the broken-content script
  to include that image tag.
- The Compliance Operator now falls back to using the v1beta1 CronJob API
  on clusters where the v1 CronJob API is not available which fixes a
  [regression](https://issues.redhat.com/browse/OCPBUGS-2156) which was introduced
  in the previous release (v0.1.56)
- Minor development enhancements to the `Makefile` help text. See `make help`.

### Internal Changes

- Added a utility script to make it easier for maintainers to propose releases,
  regardless of the git remote configuration. See the previously closed
  [issue](https://github.com/ComplianceAsCode/compliance-operator/issues/8) for
  more details.
- There was a regression in `quay.io/compliance-operator/test-broken-content:kubelet_default`
  on OCP 4.12 cluster, which caused the e2e test to fail. Since we have fix the test image,
  here we updated datastream xml files for the test content image.
- Modify the `make e2e` target to save test logs to `tests/data/e2e-test.log`.
  This is useful when initiating end-to-end tests locally and debugging the
  output.
- The upstream catalog image is now built using the
  [file format](https://olm.operatorframework.io/docs/reference/file-based-catalogs/)
  replacing the now deprecated SQLite format.

## [0.1.56] - 2022-09-27

### Fixes

- Fixed a bug where, if  the Compliance Operator was running on OCP 4.6, it
  would have failed on startup with the following error message:
  ```
  "Error creating metrics service/secret","error":"Service \"metrics\" is invalid: spec.clusterIP:
  Invalid value: \"\": field is immutable"
  ```
  This bug was introduced with the operator-sdk update in 0.1.54.

### Internal Changes

- Add `KubletConfig` remediation to compliance remediation section in the usage doc.
- The `batch/v1beta1` Kubernetes API interfaces are no longer used. Instead,
  the Compliance Operator now uses the `batch/v1` interfaces
  ([BZ: #2098581](https://bugzilla.redhat.com/show_bug.cgi?id=2098581))

## [0.1.55] - 2022-09-15

### Enhancements

- Documented support for evaluating rules against default `KubeletConfig` objects.
  Please refer to the [usage guide](./doc/usage.md) for more information on this feature.
- The `ScanSetting` Custom Resource now allows to override the default
  CPU and memory limits of scanner pods through the `scanLimits` attribute.
  Please refer to the [Kubernetes documentation](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
  for syntax reference.
  In order to set the memory limits of the operator itself, modify the
  `Subscription` object, if installed through OLM or the operator deployment
  itself otherwise. Increasing the memory limit for the operator or the scanner
  might be needed in case the default limits are not sufficient and either the operator
  or the scanner pods are killed by the OOM killer.


### Fixes

-

### Internal Changes

-

### Deprecations

-

### Removals

-

### Security

-


## [0.1.54] - 2022-09-08

### Enhancements

- Added the ability to set `PriorityClass` through `ScanSetting`. All the scanner pods
  will be launched using the `PriorityClass` if set. This is an optional attribute, the
  scan pods will be launched without `PriorityClass` if not set.

- Added the ability to check default `KubeletConfig` configuration. Compliance Operator
  will fetch `KubeletConfig` for each node and save it to `/kubeletconfig/role/{{role}}`.

- `ComplianceScan` custom resources now contain conditions, similar to `ComplianceSuite`
  conditions that were implemented earlier in 0.1.28. This aids in debugging of scheduled scans.

### Fixes

- Compliance Operator failed to resume `MachineConfigPool` after remediation
  is applied, some `KubeletConfig` configuration are rendered into multiple 
  files in `MachineConfig`, and Compliance Operator failed to counter this situation.
  The Compliance Operator addresses this issue by only checking `/etc/kubernetes/kubelet.conf`
  Please see the related [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2102511)
  for more information. No action is required from users to consume this fix.
- When Compliance Operator was gathering API resources to check and encountered
  a `MachineConfig` file with no `Ignition` specification, fetching of the API
  resources would error out. This manifested as the `api-checks-pod` ending up in
  a `CrashLoopBackOff`. More information can be found in the related
  [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2117268)
- When the scan settings set the `debug` attribute to `true`, Compliance Operator
  wasn't deleting the scan pods properly when the scan was deleted. This
  [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2092913) was fixed and
  the scanner pods are deleted when the scan is removed regardless of the
  value of the `debug` attribute.


### Internal Changes

- Added a template for proposing and discussing
  [enhancements](https://github.com/ComplianceAsCode/compliance-operator/tree/master/enhancements).
- Use the upstream remote URL for the repository during the release process.
  This makes the release process consistent for all contributors, regardless of
  how they configure their remotes. See the corresponding
  [issue](https://github.com/ComplianceAsCode/compliance-operator/issues/8) for
  more information.
- Updated Operator SDK version from 0.18.2 to 1.20.0. This updates transitive
  dependencies used in the Compliance Operator through Operator SDK. It also
  allows developers to use more automation for maintaining dependencies.

### Deprecations

- Specifying "Install into all namespaces in the cluster" or otherwise setting
  the `WATCH_NAMESPACES` environment variable to `""` has no effect anymore. This was
  done to improve operator's memory usage as reported in
  [an upstream issue](https://github.com/ComplianceAsCode/compliance-operator/issues/40)
  All Compliance Operator's CRs must be installed in operator's own namespace
  (typically `openshift-compliance`) in order for the operator to pick them up
  anyway.

### Removals

-

### Security

-


## [0.1.53] - 2022-06-29

### Fixes

- The `openshift-compliance` namespace was labeled with `pod-security.kubernetes.io/`
  labels. Previously, clusters using Pod Security Admission and restricted
  profiles, the Compliance Operator privileged pods would have either been
  denied or, in case the cluster is configured to only warn about non-compliant
  pods, would trigger events with warnings. See this
  [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2088202) for more
  information. No action is required from users to consume this fix.
- The `api-resource-collector` no longer fetches and keeps the whole MachineConfig
  objects when the content needs to examine and filter them, but instead filters
  out the file contents of the MachineConfigs. This addressses
  [bugs](https://bugzilla.redhat.com/show_bug.cgi?id=2094854) where especially
  with the PCI-DSS profile, the `api-resource-collector` pod would have crashed
  due to reaching its memory limit. At the same time, the memory limit of the
  `api-resource-collector` container was doubled from 100Mi to 200Mi to allow
  the container to fetch large amount of objects the profile might need to examine.
- Fixes to OCP4/RHCOS4 compliance content:
  - A previous update to compliance content broke rules that are checking for the proper
    file ownership of API server's and kubelet's certificates and keys on OCP 4.8 and earlier
    as reported in this [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2079813). New
    compatibility rules were added for those older releases, thus fixing the issue.
  - The automatic remediations for several rules that were setting `sysctl` parameters
    did not work correctly as tracked by this [bug report](https://bugzilla.redhat.com/show_bug.cgi?id=2094382)
  - The rule `kubelet_enable_streaming_connections` was not honoring the value of the
    variable `streaming_connection_timeouts` but instead was checking if the `streamingConnectionIdleTimeout`
    value in kubelet's config was non-zero. This was preventing checks where the user
    set the variable's value to zero from passing. Please refer to the [bug report](https://bugzilla.redhat.com/show_bug.cgi?id=2069891)
    for more information.
  - Rules that check for proper group ownership of OVS config file were always failing
    on OCP clusters running on s390x as the OVS configuration files are owned by a different
    UID and GID. New rules specific to the s390x architecture were introduced to cover
    this difference. See this [bug report](https://bugzilla.redhat.com/show_bug.cgi?id=2072597)
    for more information.

### Internal Changes

- The MachineConfigOperator dependency was bumped to one supporting Ignition
  3.2.0 in preparation of adding code that parses and filters out MachineConfig
  objects

### Security

- Several workloads have had their permissions tightened, including explicitly
  running as a non-root user or dropping all capabilities as appropriate. This
  is an internal change and doesn't require any action from users.


## [0.1.52] - 2022-05-19


### Fixes

- It came to notice that Machine Config Operator is using base64 encoding
  instead of url-encoding for Machine Config source on OVN cluster. And it
  is causing remediation to fail on OVN cluster. This fix addresses that issue
  by checking encoding to handle both base64 and url-encoded MC source, so
  that the remediation will work properly. 
  [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2082431) for more information.


## [0.1.51] - 2022-05-10

### Enhancements

- Added `maunalRules` to `TailoredProfile` CRD, user can choose to add the rule
  there so that those rules will show Manual as results and remediation will not be 
  created.

### Fixes

- Fix OpenScap scanner container crashloop caused by script mount permission issue
  on a security environment where DAC_OVERRIDE capability is dropped. This PR changes
  script mount permission to give execute permission to all users.
  [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2082151) for more information.


## [0.1.50] - 2022-05-02

### Enhancements

- The `api-resource-collector` `ClusterRole` has been updated to fetch network
  resources for the `operator.openshift.io` API group. This is necessary to
  automate checks that ensure the cluster is using a CNI that supports network
  policies. Please refer to the
  [bug](https://bugzilla.redhat.com/show_bug.cgi?id=2072431) for more
  information.
- The `api-resource-collector` `ClusterRole` has been updated to fetch network
  resources for the `pipelines.openshift.io` API group. This is
  necessary to automate checks that ensure the cluster is using GitOps operator.
- Added necessary permissions for api-resource-collector so that the new
  [rule](https://github.com/ComplianceAsCode/content/pull/8511)
  `cluster_logging_operator_exist` can be evaluated properly.

### Fixes

- The compliance content images have moved to
  [compliance-operator/compliance-operator-content](https://quay.io/repository/compliance-operator/compliance-operator-content)
  Quay repository. This should be a transparent change for end users and fixes
  CI that relies on content for end-to-end testing.
- Improve how the Compliance Operator checks for Machine Config Pool readiness.
  This prevents an [issue](https://bugzilla.redhat.com/show_bug.cgi?id=2071854)
  where the Compliance Operator unpaused Machine Config Pools too soon after
  applying remediations, causing the kubelet to go into a `NotReady` state.
- Fix memory pointer crashloop
  [issue](https://github.com/ComplianceAsCode/compliance-operator/issues/6)
  when there is invalid `MachineConfigPool` in the cluster.
- The scan pods and the aggregator pod were never removed after a scan run which
  might have [prevented](https://bugzilla.redhat.com/show_bug.cgi?id=2075029)
  the cluster-autoscaler from running. Now those resources are removed from
  each node by default unless explicitly saved for debug purposes.

### Internal Changes

- Added node resource to the list of resources we always fetch so that arch CPEs will
  be evaluated appropriately.

- Modify `push-release` make target to sync `ocp-0.1` branch to the latest release branch.


## [0.1.49] - 2022-03-22

### Enhancements

- Restructured the project documentation into separate guides for different
  audiences. This primarily includes an installation guide, a usage guide, and
  a contributor guide.

### Fixes

- Added network resource to the list of resources we always fetch [1] so that network
  OVN/SDN CPEs will be able to verify if the cluster has an OVN/SDN network type.
  The CPEs have added here [2]. The SDN rules have been updated [3] to use SDN CPE,
  so that these rules will show correct results based on cluster network type.
  ([1](https://github.com/openshift/compliance-operator/pull/785)).
  ([2](https://github.com/ComplianceAsCode/content/pull/8134)).
  ([3](https://github.com/ComplianceAsCode/content/pull/8141)).
  ([bug](https://bugzilla.redhat.com/show_bug.cgi?id=1994609)).
- When a TailoredProfile transitions from Ready to Error, the corresponding
  ConfigMap is removed. This prevents the ConfigMap from being reused with
  obsolete data while the parent object is in fact marked with an error
- The ScanSettingBinding controller now reconciles TailoredProfile instances
  related to a ScanSettingBinding. This ensures that the controller can
  proceed with generating scans in case the binding used to point to
  TailoredProfile that had been marked with an error, but was subsequently
  fixed ([upstream issue 791](https://github.com/openshift/compliance-operator/issues/791))
- Node scans are only scheduled on nodes running Linux. This allows running
  scans on cluster with a mix of Linux and Windows nodes. ([RHBZ #2059611](https://bugzilla.redhat.com/show_bug.cgi?id=2059611))

### Internal Changes

- Implemented a multi-step release process to prevent unintentional changes
  from making their way into the release
  ([bug](https://github.com/openshift/compliance-operator/issues/783)).
- The TestInconsistentResult e2e test was relying on a certain order of results.
  This bug was fixed and the test now passes with any order of results.

### Removals

- The Deployment resource in `deploy/eks.yaml` has been removed in favor of a
  generic resource in the compliance-operator-chart Helm templates. The
  `deploy/eks.yaml` file conflicted with various development and build tools
  that assumed a single Deployment resource in the `deploy/` directory. Please
  use the Helm chart for
  [deploying](https://github.com/openshift/compliance-operator/blob/master/doc/install.md#deploying-with-helm)
  the operator on AWS EKS.


## [0.1.48] - 2022-01-28

### Enhancements

- The operator is now aware of other Kubernetes distributions outside of
  OpenShift to accommodate running the operator on other platforms. This allows
  `ScanSettings` to have different behaviors depending on the platform.
  `ScanSettings` will automatically schedule to `worker` and `master` nodes
  when running in an OpenShift cluster, maintaining the previous default
  behavior for OpenShift clusters. When running on AWS EKS, `ScanSettings` will
  schedule to all available nodes, by default. The operator will also inherit
  the `nodeSelector` and `tolerations` from the operator pod when running on
  EKS.
- Improved support for running the operator in
  [Hypershift](https://github.com/openshift/hypershift) environments by
  allowing the rules to load values at runtime. For example, loading in the
  `ConfigMap` based on different namespaces for each cluster, which affects the
  API resource path of the `ConfigMap`. Previous versions of the operator
  included hard-coded API paths, where now they can be loaded in from the
  compliance content, better enabling operator usage in Hypershift deployments.
- You can now install the operator using a Helm chart. This includes support
  for deploying on OpenShift and AWS EKS. Please see the
  [documentation](https://github.com/openshift/compliance-operator/#deploying-with-helm)
  on how to deploy the operator using Helm.
- Introduced a process and guidelines for writing release notes
  ([documentation](https://github.com/openshift/compliance-operator/#writing-release-notes))

### Fixes

- Improved rule parsing to check for extended OVAL definitions ([bug](https://bugzilla.redhat.com/show_bug.cgi?id=2040282))
  - Previous versions of the operator wouldn't process extended OVAL
    defintions, allowing some rules to have `CheckType=None`. This version
    includes support for processing extended defintions so `CheckType` is
    properly set.
- Properly detect `MachineConfig` ownership for `KubeletConfig` objects
  ([bug](https://bugzilla.redhat.com/show_bug.cgi?id=2040401))
  - Previous versions of the operator assumed that all `MachineConfig` objects
    were created by a `KubeletConfig`. In instances where a `MachineConfig` was
    not generated using a `KubeletConfig`, the operator would stall during
    remediation attempting to find the `MachineConfig` owner. The operator now
    gracefully handles `MachineConfig` ownership checks during the remediation
    process.
- Updated documentation `TailoredProfile` example to be consistent with
  `TailoredProfile` CRD
- Minor grammatical documentation updates.

## [0.1.47] - 2021-12-15
### Changes

 - enhancements
      - Add status descriptor for CRDs - the CRDs' status attributes were annotated
        with [status descriptors](https://github.com/openshift/console/blob/master/frontend/packages/operator-lifecycle-manager/src/components/descriptors/reference/reference.md)
        that would provide a nicer UI for the status subresources of Compliance Operator's
        CRs in the OpenShift web UI console.
      - ScanSetting: Introduce special `@all` role to match all nodes - Introduces
        the ability to detect `@all` in the ScanSettings roles. When used, the
        scansettingbinding controller will set an empty `nodeSelector` which
        will then match all nodes available. This is mostly intended for
        non-OpenShift deployments.
      - Inherit scheduling for workloads from Compliance Operator manager - This
        enhancement removed hardcoded assumptions that all nodes are labeled
        with 'node-role.kubernetes.io/'. The Compliance Operator was using these
        labels for scheduling workloads, which works fine in OpenShift, but not
        on other distributions. Instead, all controllers inherit the placement
        information (nodeSelector and tolerations) from the controller manager.
        This enhancement is mostly aimed at non-OpenShift distributions.
      - Enable defaults per platform - This enables the Compliance Operator
        to specify defaults per specific platform. At the moment, OpenShift and
        EKS are supported. For OpenShift, the ScanSettings created by defaults
        target master and worker nodes and allow the resultserver to be created
        on master nodes. For EKS, ScanSettings schedule on all available nodes
        and inherit the nodeSelector and tolerations from the operator.
 - bug fixes
      - Remove regex checks for url-encoded content - When parsing remediations,
        the Compliance Operator used to verify the remediation content using a
        too strict regular expression and would error out processing
        valid remediations. The bug was affecting sshd related remediations from
        the ComplianceAsCode project in particular. The check was not
        necessary and was removed. ([RHBZ #2033009](https://bugzilla.redhat.com/show_bug.cgi?id=2033009))
      - Fix bugs where kubeletconfig gets deleted when unapplying - a
        KubeletConfig remediation was supposed to be re-applied on a subsequent
        scan run (typically with `auto_apply_remediations=true`), the remediation
        might not be applied correctly, leading to some of the remediations
        not being applied at all. Because the root cause of the issue
        was in code that was handling unapplying KubeletConfig remediations, the
        unapplying of KubeletConfig remediations was disabled until a better fix
        is developed. ([RHBZ #2032420](https://bugzilla.redhat.com/show_bug.cgi?id=2032420))
 - internal changes
      - Add human-readable changelog for 0.1.45 and 0.1.46
      - Add documentation for E2E test

## [0.1.46] - 2021-12-01
### Changes
 - enhancements
     - Make showing `NotApplicable` results optional - the `ComplianceScan` and
       the `ScanSetting` CR were extended (through extending of a shared structure)
       with a new field `showNotApplicable` which defaults to `false`. When set
       to `false`, the Compliance Operator will not render
       `ComplianceCheckResult` objects that do not apply to the system being
       scanned, but are part of the benchmark, e.g.  rules that check for etcd
       properties on worker nodes.  When set to `true`, all checks results,
       including those not applicable would be created.
     - metrics: Add `ComplianceSuite` status gauge and alert - enables monitoring
       of Compliance Suite status through metrics.
       - Add the `compliance_operator_compliance_state` gauge metric that
         switches to 1 for a ComplianceSuite with a NON-COMPLIANT result,
         0 when COMPLIANT, 2 when INCONSISTENT, and 3 when ERROR.
       - Create a `PrometheusRule` warning alert for the gauge.
     - Support deployments on all namespaces - adds support for watching all
       namespaces by passing an empty value to the `WATCH_NAMESPACE`
       environment variable. Please note that the default objects
       (`ProfileBundles`, `ScanSettings`) are always only created in the operator's
       namespace.
 - bug fixes
     - Fix documentation for remediation templating - the `doc/remediation-templating.md`
       document was improved to reflect the current state of the remediation
       templating.
 - internal changes
     - Log creation of default objects - There were cases where we need
       to debug if our default objects have been created. It was non-trivial
       to figure this out from the current logs, so the logging was extended
       to include the creation of the default `ProfileBundle` and `ScanSetting`
       objects.


## [0.1.45] - 2021-10-28
### Changes
 - enhancements
     - Implement version applicability for remediations - remediations coming
       from the ComplianceAsCode project can now express their minimal requires
       Kubernetes or OpenShift versions. If the remediation is applied on a
       cluster that does not match the version requirement, such remediation
       would not be created. This functionality is used e.g. by the
       `rhcos4-configure-usbguard-auditbackend` rule, as seen from the
       `complianceascode.io/ocp-version: '>=4.7.0'` annotation on its fix.
     - Add "infrastructure" to resources we always fetch - this is an
       enhancement for content writers. The 'infrastructure/cluster' object
       is now always fetched, making it possible to determine the platform
       that CO is running at. This allows to support checks that are only
       valid for a certain cloud platform (e.g. only for AWS)
 - bug fixes
     - Add support for rendering variable in rule objects - if a
       ComplianceAsCode check uses a variable in a rule's description or
       rationale, the variable's value is now correctly rendered
     - Remove permissions for aggregator to list nodes - a previous version
       of the Compliance Operator assigned the permissions to list and get
       nodes to the aggregator pod. Those permissions were not needed and
       were removed.
     - Fix Kubernetes version dependency parsing bug - a bug in the version
       applicability for remediations. This is a bug introduced and fixed
       in this release.
 - internal changes
     - Add permissions to get and list machineset in preparation for
       implementation of req 3.4.1 pcidss - the RBAC rules were extended
       to support the PCI-DSS standard.
     - Add a more verbose Changelog for the recent versions

## [0.1.44] - 2021-10-20
### Changes
 - enhancements
     - Add option to make scan scheduling strict/not strict - adds a new
       ComplianceScan/Suite/ScanSetting option called strictNodeScan.
       This option defaults to true meaning that the operator will error
       out of a scan pod can't be scheduled. Switching the option to
       true makes the scan more permissive and go forward. Useful for
       clouds with ephemeral nodes.
     - Result Server: Make nodeSelector and tolerations configurable -
       exposes the nodeSelector and tolerations attributes through the
       ScanSettings object. This enables deployers to configure where
       the Result Server will run, and thus what node will host the
       Persistent Volume that will contain the raw results. This is needed
       for cases where the storage driver doesn't allow us to schedule
       a pod that makes use of a persistent volume on the master nodes.
 - bug fixes
     - Switch to using openscap 1.3.5 - The latest openscap version fixes
       a potential crash.
     - Create a kubeletconfig per pool - Previously, only one global
       KubeletConfig object would have been created. A per-pool KubeletConfig
       is created now.
 - internal changes
     - Add Vincent Shen to OWNERS file
     - e2e: Fix TestRulesAreClassifiedAppropriately test

## [0.1.43] - 2021-10-14
### Changes
 - enhancements
      - Add KubeletConfig Remediation Support - adds the needed logic
        for the Compliance Operator to remediate KubeletConfig objects.
 - bug fixes
      - none
 - internal changes
      - Update api-resource-collector comment
      - Add permission for checking the kubeadmin user
      - Add variable support for non-urlencoded content
      - Revamp CRD docs
      - Makefile: Make container image bundle depend on $TAG

## [0.1.42] - 2021-10-04
### Changes
 - enhancements
      - Add error to the result object as comment - For content developers.
        Allows to differentiate between objects that don't exist in
        the cluster versus objects that can't be fetched.
 - bug fixes
      - Validate that rules in tailored profile are of appropriate type -
        tightens the validation of TailoredProfiles so that only rules
        of the same type (Platform/Node) are included
      - Fix needs-review unpause pool - remediations that need a varible
        to be set have the NeedsReview state. When auto-applying remediations,
        these need to have all variables set before the MachineConfig pool
        can be unpaused and the remediations applied.
 - internal changes
      - Add description to TailoredProfile yaml
      - Fix error message json representation in CRD
      - Update 06-troubleshooting.md
      - Remove Benchmark unit tests
      - add openscap image build
      - aggregator: Remove MachineConfig validation
      - TailoredProfiles: Allocate rules map with expected number of items
      - Makefile: Add push-openscap-image target
      - docs: Document the default-auto-apply ScanSetting
      - Proposal for Kubelet Config Remediation

## [0.1.41] - 2021-09-20
### Changes
  - enhancements
      - Add instructions and check type to Rule object - The rule objects now
        contain two additional attributes, `checkType` and `description` that
        allow the user to see if the Rule pertains to a Node or a Platform
        check and allow the user to audit what the check represented by the
        Rule does.
      - Add support for multi-value variable templating - When templating
        remediations with variables, a multi-valued variable is expanded
        as per the template.
  - bug fixes
      - Specify fsgroup, user and non-root user usage in resultserver - when
        running on OpenShift, the user and fsgroup pod attributes are selected
        from namespace annotations. On other Kubernetes distributions,
        this wouldn't work. If Compliance Operator is not running on OpenShift,
        a hardcoded default is selected instead.
      - Fix value-required handling - Ensures that the set variable is read
        from the tailoring as opposed to reading it from the datastream
        itself. Thus, ensuring that we actually detect when a variable is
        set and allow the remediation to be created appropriately.
      - Use ClusterRole/ClusterRoleBinding for monitoring permissions - the
        RBAC Role and RoleBinding used for Prometheus metrics
        were changed to Cluster-wide to ensure that monitoring works out of
        the box.
  - internal changes
      - Gather /version when doing Platform scans
      - Add flag to skip the metrics deployment
      - fetch openscap version during build time
      - e2e: Mark logging functions as helper functions
      - Makefile: Rename IMAGE_FORMAT var

## [0.1.40] - 2021-09-09
### Changes
 - enhancements
      - Add support for remediation templating for operator - The Compliance
        Operator is now able to change remediations based on variables set
        through the compliance profile. This is useful e.g. for remediations
        that include deployment-specific values such as time outs, NTP server
        host names or similar. Note that the ComplianceCheckResult objects
        also now use the label `compliance.openshift.io/check-has-value`
        that lists which variables the check can use.
      - Enable Creation of TailoredProfiles without extending existing
        ones - This enhancement removes the requirement to extend an
        existing Profile in order to create a tailored Profile. The
        `extends` field from the field from the TailoredProfile CRD is
        no longer mandatory. The user can now select a list of Rule objects
        to crate a Tailored Profile from scratch. Note that you need to
        set if the Profile is meant for Nodes or Platform. You can either
        do that by setting the `compliance.openshift.io/product-type:` annotation
        or by setting the `-node` suffix for the TailoredProfile CR.
      - Make default scanTolerations more tolerant - The Compliance Operator
        now tolerates all taints, making it possible to schedule scans on
        all nodes. Previously, only master node taints were tolerated.
 - bug fixes
      - compliancescan: Fill the element and the `urn:xccdf:fact:identifier`
        for node checks - The scan results as in the ARF format now include
        the host name of the system being scanned in the `<target>`
        XML element as well as the Kubernetes Node name in the `<fact>`
        element under the `id=urn:xccdf:fact:identifier` attribute. This
        helps associate ARF results with the systems being scanned.
      - Restart profileparser on failures - In case of any failure when
        parsing a profile, we would skip annotating the object with a
        temporary annotation that prevents the object from being garbage
        collected after parsing is done. This would have manifested as
        Rules or Variables objects being removed during an upgrade.
        RHBZ: 1988259
      - Disallow empty titles and descriptions for tailored profiles - the
        XCCDF standard discourages empty titles and descriptions, so the
        Compliance Operator now requires them to be set in the TailoredProfile
        CRs
      - Remove tailorprofile variable selection check - Previously, all
        variables were only allowed to be set to a value from a selection
        set in the compliance content. This restriction is now removed, allowing
        for any values to be used.
 - internal changes:
      - Remove dead code
      - Don't shadow an import with a variable name
      - Skip e2e TestNodeSchedulingErrorFailsTheScan for now
      - e2e: Migrate TestScanProducesRemediations to use ScanSettingBinding
      - Associate variable with compliance check result

## [0.1.39] - 2021-08-23
### Changes
 - enhancements
     - Allow profileparser to parse PCI-DSS references - The Compliance
       Operator needs to be able to parse PCI-DSS references in order
       to parse compliance content that ships PCI-DSS profiles
     - Add permission for operator to remediate prometheusrule objects -
       the AU-5 control in the Moderate Compliance Profile requires the
       Compliance Operator to check for Prometheus rules, therefore the
       operator must be able to read prometheusrules.monitoring.coreos.com
       objects, otherwise it wouldn't be able to execute the rules covering
       the AU-5 control in the moderate profile
 - internal changes:
     - Print Compliance Operator version on startup
     - Update wording in TailoredProfile CRD

## [0.1.38] - 2021-08-11
### Changes
- e2e: aggregating/NA metric value
- Bug 1990836: Move metrics service creation back into operator startup
- Add fetch-git-tags make target
- Add a must-gather plugin

## [0.1.37] - 2021-08-04
### Changes
- Bug 1946512: Use latest for CSV documentation link
- doc: note that rolling back images in ProfileBundle is not well supported
- Controller metrics e2e testing
- Add initial controller metrics support
- vendor deps
- Bump the suitererunner resource limits
- Fix instructions on building VMs
- Add NERC-CIP reference support
- The remediation templating design doc Squashed
- Add implementation of enforcement remediations
- tailoring: Update the tailoring CM on changes
- Move Compliance Operator to use ubi-micro

## [0.1.36] - 2021-06-28
### Changes
- Issue warning if filter issues more than one object
- This checks for the empty remediation yaml file before creating a remediation
- Enable filtering using `jq` syntax
- Wrap warning fetching with struct
- Persist resources as JSON and not YAML
- Bug 1975358: Refresh pool reference before trying to unpause it
- TailoredProfiles: When transitioning to Ready, remove previous error message
- docs: Add an example of setting a variable in a tailoredProfile

## [0.1.35] - 2021-06-09
### Changes
- Collect all ocp-api-endpoint elements
- RBAC: Add permissions to update oauths config

## [0.1.34] - 2021-06-02
### Changes
- Switch to using go 1.16
- Remove unused const definitions
- Update dependencies
- RBAC: Allow api-resource-collector to list FIO objects

## [0.1.33] - 2021-05-24
### Changes
- Allow api-resource-collector to read PrometheusRules
- Allow api-resource-collector to read oauthclients
- Add CHANGELOG.md and make release update target
- Add permission to get fileintegrity objects
- Update go.uber.org/zap dependency
- Add permission to api-resource-collector to read MCs
- Convert XML from CaC content to markdown in the k8s objects
- Allow the api-resource collector to read ComplianceSuite objects
- Die xmldom! Die!
- Set the operators.openshift.io/infrastructure-features:proxy-aware annotation
- Make use of the HTTPS_PROXY environment variable

## [0.1.32] - 2021-04-26
### Changes
- Add Workload management annotations
- Make use of the HTTPS_PROXY environment variable
- Enhance TailoredProfile validation
- Move relevant workloads to be scheduled on the master nodes only
- Updated dependencies
- Limit resource usage for all workloads
- Updated gosec to v2.7.0
