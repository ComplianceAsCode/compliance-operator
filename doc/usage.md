# Usage Guide

Before starting to use the operator, it's worth checking the descriptions of
the different custom resources it introduces. These definitions are in the
[following
document](https://github.com/ComplianceAsCode/compliance-operator/blob/master/doc/crds.md).
The primary interface for the compliance-operator is the `ComplianceSuite`
object, representing a set of scans. The `ComplianceSuite` can be defined
either manually or with the help of `ScanSetting` and `ScanSettingBinding`
objects. Note that while it is possible to use the lower-level `ComplianceScan`
directly as well, it is not recommended.

As part of this guide, it's assumed that you have installed the compliance operator
in the `openshift-compliance` namespace. You can find more information about
installation methods and directions in the [Installation
Guide](https://github.com/ComplianceAsCode/compliance-operator/blob/master/doc/install.md).

After you've installed the operator, set the `NAMESPACE` environment to the
namespace you installed the operator. By default, the operator is installed in
the `openshift-compliance` namespace.

```
export NAMESPACE=openshift-compliance
```

## Listing profiles

There are several profiles that come out-of-the-box as part of the operator
installation.

To view them, use the following command:

```
$ oc get -n $NAMESPACE profiles.compliance
NAME              AGE
ocp4-cis          2m50s
ocp4-cis-node     2m50s
ocp4-e8           2m50s
ocp4-moderate     2m50s
rhcos4-e8         2m46s
rhcos4-moderate   2m46s
```

## Scan types

These profiles define different compliance benchmarks and as well as
the scans fall into two basic categories - platform and node. The
platform scans are targeting the cluster itself, in the listing above
they're the `ocp4-*` scans, while the purpose of the node scans is to
scan the actual cluster nodes. All the `rhcos4-*` profiles above can be
used to create node scans.

Before taking one into use, we'll need to configure how the scans
will run. We can do this with the `ScanSettings` custom resource. The
compliance-operator already ships with a default `ScanSettings` object
that you can take into use immediately:

```
$ oc get -n $NAMESPACE scansettings default -o yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
rawResultStorage:
  rotation: 3
  size: 1Gi
roles:
- worker
- master
scanTolerations:
- effect: NoSchedule
  key: node-role.kubernetes.io/master
  operator: Exists
schedule: '0 1 * * *'
```

So, to assert the intent of complying with the `rhcos4-moderate` profile, we can use
the `ScanSettingBinding` custom resource. The example that already exists in this repo
will do just this.

```
$ cat deploy/crds/compliance.openshift.io_v1alpha1_scansettingbinding_cr.yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: nist-moderate
profiles:
  - name: ocp4-moderate
    kind: Profile
    apiGroup: compliance.openshift.io/v1alpha1
settingsRef:
  name: default
  kind: ScanSetting
  apiGroup: compliance.openshift.io/v1alpha1
```

To take it into use, do the following:

```
$ oc create -n $NAMESPACE -f deploy/crds/compliance.openshift.io_v1alpha1_scansettingbinding_cr.yaml
scansettingbinding.compliance.openshift.io/nist-moderate created
```

At this point the operator reconciles a `ComplianceSuite` custom resource,
we can use this to track the progress of our scan.

```
$ oc get -n $NAMESPACE compliancesuites -w
NAME            PHASE     RESULT
nist-moderate   RUNNING   NOT-AVAILABLE
```

You can also make use of conditions to wait for a suite to produce results:

```
$ oc wait --for=condition=ready compliancesuite cis-compliancesuite
```

This subsequently creates the `ComplianceScan` objects for the suite.
The `ComplianceScan` then creates scan pods that run on each node in
the cluster. The scan pods execute `openscap-chroot` on every node and
eventually report the results. The scan takes several minutes to complete.

If you're interested in seeing the individual pods, you can do so with:

```
$ oc get -n $NAMESPACE pods -w
```

When the scan is done, the operator changes the state of the ComplianceSuite
object to "Done" and all the pods are transition to the "Completed"
state. You can then check the `ComplianceRemediations` that were found with:

```
$ oc get -n $NAMESPACE complianceremediations
NAME                                                             STATE
workers-scan-auditd-name-format                                  NotApplied
workers-scan-coredump-disable-backtraces                         NotApplied
workers-scan-coredump-disable-storage                            NotApplied
workers-scan-disable-ctrlaltdel-burstaction                      NotApplied
workers-scan-disable-users-coredumps                             NotApplied
workers-scan-grub2-audit-argument                                NotApplied
workers-scan-grub2-audit-backlog-limit-argument                  NotApplied
workers-scan-grub2-page-poison-argument                          NotApplied
```

To apply a remediation, edit that object and set its `Apply` attribute
to `true`:

```
$ oc edit -n $NAMESPACE complianceremediation/workers-scan-no-direct-root-logins
```

The operator then creates a `MachineConfig` or `KubeletConfig` object per remediation. 
This object is rendered to a `MachinePool` and the `MachineConfigDaemon` running on
nodes in that pool pushes the configuration to the nodes and reboots the nodes.

The more documentation on how `KubeletConfig` remediation work [following document](https://github.com/ComplianceAsCode/compliance-operator/blob/master/doc/kubeletConfig-remediations.md)


You can watch the node status with:

```
$ oc get nodes -w
```

Once the nodes reboot, you might want to run another Suite to ensure that
the remediation that you applied previously was no longer found.

## Evaluating rules against default configuration values

Kubernetes infrastructure may contain incomplete configuration files. At run time, 
nodes will assume default configuration values for missing configuration options.
And some configuration can be passed as command line arguments, therefore,
the Compliance Operator cannot assume the configuration file on the node is complete
and it may be missing options used in rule checks.

To prevent false negative findings where the default configuration value passes
a check, the Compliance Operator uses the node proxy API to fetch the configuration
for each node, then evaluates the properties for each and stores a "consistent" 
copy to be evaluated against the rules. This increases the accuracy of the
scan results.

The  enchantment documentation can be found in the [following document](https://github.com/ComplianceAsCode/compliance-operator/blob/master/enhancements/improve-kubeletconfig-default-configuration-check-enhancement.md)

No additional changes are required to use this feature with `master` and
`worker` node pools. See the following sections for details on how to
use this feature with custom node pools.



### Custom node pools

For scalability reasons, the Compliance Operator doesn't persist a copy of
each node configuration. Instead, it aggregates consistent configuration
options for all nodes within a single node pool into one copy of the configuration
file. It then uses the configuration file for a particular node pool to evaluate
rules against nodes within that pool.

If your cluster uses custom node pools outside the default `worker` and `master`
node pools, you'll need to supply additional variables to ensure the Compliance
Operator aggregates a configuration file for that node pool.

For example, in a cluster that has `master`, `worker` and `infra` pools, If a user wants 
to check against all pools, they need to set the value of `ocp-var-role-master` and
`ocp-var-role-worker` to `infra` in `TailoredProfile`:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: cis-infra-tp
spec:
  extends: ocp4-cis
  title: My modified nist profile with a custom value
  setValues:
  - name: ocp4-var-role-master
    value: infra
    rationale: test for infra nodes
  - name: ocp4-var-role-worker
    value: infra
    rationale: test for infra nodes
  description: cis-infra-scan
```

User will need to add `infra` role to the `ScanSetting` that will be in the `ScanSettingBinding.
```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
rawResultStorage:
  rotation: 3
  size: 1Gi
roles:
- worker
- master
- infra
scanTolerations:
- effect: NoSchedule
  key: node-role.kubernetes.io/master
  operator: Exists
schedule: '0 1 * * *'
```
And launch a scan using `ScanSettingBinding`:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: cis
  namespace: openshift-compliance
profiles:
- apiGroup: compliance.openshift.io/v1alpha1
  kind: Profile
  name: ocp4-cis
- apiGroup: compliance.openshift.io/v1alpha1
  kind: Profile
  name: ocp4-cis-node
- apiGroup: compliance.openshift.io/v1alpha1
  kind: TailoredProfile
  name: cis-infra-tp
settingsRef:
  apiGroup: compliance.openshift.io/v1alpha1
  kind: ScanSetting
  name: default
```

#### `KubeletConfig` Remediation on sub-pools

If a user wants to use `KubeletConfig` remediation on sub-pools [Remediation for Customized MachineConfigPool](https://docs.openshift.com/container-platform/4.11/security/compliance_operator/compliance-operator-remediation.html#compliance-operator-apply-remediation-for-customized-mcp), they need to add a label
to the sub-pool `MachineConfigPool`:

`$ oc label mcp <sub-pool-name> pools.operator.machineconfiguration.openshift.io/<sub-pool-name>=`

### How does it work?
To give an example on the CIS benchmark:
Compliance Operator checks runtime `KubeletConfig` through Kubernetes `Node/Proxy` object, and it uses variables
`ocp-var-role-master` and `ocp-var-role-master` to determine the nodes it performs the check against.
And in `ComplianceCheckResult`, `KubeletConfig` rules will be shown as `ocp4-cis-kubelet-*`. The scan only
passes if all selected nodes pass the check.



### List of `KubeletConfig` rules checked through `Node/Proxy` object:

A user can find out if a rule is checked through `Node/Proxy` object by
checking if `valuesUsed` of the ComplianceCheckResult contains `ocp4-var-role-master`
or `ocp4-var-role-worker`:

`oc get ccr -n openshift-compliance -o yaml | jq '.items[] | select(.valuesUsed | contains("ocp4-var-role-master") or contains("ocp4-var-role-worker"))'`


## Suspending and resuming scan schedules

The `ScanSetting` CRD exposes a `schedule` attribute that allows you to
schedule compliance scans as a cron job syntax. The Compliance Operator uses
Kubernetes `CronJob` resources to implement the schedule for a scan suite,
which is sometimes referred to as a suite rerunner.

Scan schedules are associated with a `ComplianceSuite`, which may contain at
least one `ComplianceScan`. This means the schedule associated with a
`ComplianceSuite` applies to all `ComplianceScan` objects within that suite.
This may be useful to prevent scans from happening during planned maintenance
windows, where results might be inaccurate depending on the state of the
cluster.

You can suspend a `ComplianceSuite` by updating the `ScanSetting` you used when
you created the `ScanSettingBinding`.

```
$ oc patch ss/default -p 'suspend: true' --type merge
```

Any `ScanSettingBinding` using the suspended `ScanSetting` will show a
`SUSPENDED` status:

```
$ oc get ssb
NAME       STATUS
cis-node   SUSPENDED
```

You can disable the `suspend` attribute to resume the scan schedule:

```
$ oc patch ss/default -p 'suspend: false' --type merge
```

The `ScanSettingBinding` will return to a `READY` state:

```
$ oc get ssb
NAME       STATUS
cis-node   READY
```

Note that this functionality does not pause, suspend, or stop a scan that is
already in progress.

## Extracting raw results

The scans provide two kinds of raw results: the full report in the ARF format
and just the list of scan results in the XCCDF format. The ARF reports are,
due to their large size, copied into persistent volumes:

```
$ oc get pv
NAME                                       CAPACITY  CLAIM
pvc-5d49c852-03a6-4bcd-838b-c7225307c4bb   1Gi       openshift-compliance/workers-scan
pvc-ef68c834-bb6e-4644-926a-8b7a4a180999   1Gi       openshift-compliance/masters-scan
$ oc get pvc
NAME                     STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
ocp4-moderate            Bound    pvc-01b7bd30-0d19-4fbc-8989-bad61d9384d9   1Gi        RWO            gp2            37m
rhcos4-with-usb-master   Bound    pvc-f3f35712-6c3f-42f0-a89a-af9e6f54a0d4   1Gi        RWO            gp2            37m
rhcos4-with-usb-worker   Bound    pvc-7837e9ba-db13-40c4-8eee-a2d1beb0ada7   1Gi        RWO            gp2            37m
```

An example of extracting ARF results from a scan called `workers-scan` follows:

Once the scan had finished, you'll note that there is a `PersistentVolumeClaim` named
after the scan:

```
oc get pvc/workers-scan
NAME            STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
workers-scan    Bound    pvc-01b7bd30-0d19-4fbc-8989-bad61d9384d9   1Gi        RWO            gp2            38m
```

You'll want to start a pod that mounts the PV, for example:

```yaml
apiVersion: "v1"
kind: Pod
metadata:
  name: pv-extract
spec:
  containers:
    - name: pv-extract-pod
      image: registry.access.redhat.com/ubi8/ubi
      command: ["sleep", "3000"]
      volumeMounts:
        - mountPath: "/workers-scan-results"
          name: workers-scan-vol
  volumes:
    - name: workers-scan-vol
      persistentVolumeClaim:
        claimName: workers-scan
```

You can inspect the files by listing the `/workers-scan-results` directory and copy the
files locally:

```
$ oc exec pods/pv-extract -- ls /workers-scan-results/0
lost+found
workers-scan-ip-10-0-129-252.ec2.internal-pod.xml.bzip2
workers-scan-ip-10-0-149-70.ec2.internal-pod.xml.bzip2
workers-scan-ip-10-0-172-30.ec2.internal-pod.xml.bzip2
$ oc cp pv-extract:/workers-scan-results .
```

The files are bzipped. To get the raw ARF file:

```
$ bunzip2 -c workers-scan-ip-10-0-129-252.ec2.internal-pod.xml.bzip2 > workers-scan-ip-10-0-129-252.ec2.internal-pod.xml
```

The XCCDF results are much smaller and can be stored in a configmap, from
which you can extract the results. For easier filtering, the configmaps
are labeled with the scan name:

```
$ oc get cm -l=compliance.openshift.io/scan-name=masters-scan
NAME                                            DATA   AGE
masters-scan-ip-10-0-129-248.ec2.internal-pod   1      25m
masters-scan-ip-10-0-144-54.ec2.internal-pod    1      24m
masters-scan-ip-10-0-174-253.ec2.internal-pod   1      25m
```

To extract the results, use:

```
$ oc extract cm/masters-scan-ip-10-0-174-253.ec2.internal-pod
```

Note that if the results are too big for the ConfigMap, they'll be bzipped and
base64 encoded.

## Operating system support

### Node scans

Note that the current testing has been done in RHCOS. In the absence of
RHEL/CentOS support, one can simply run OpenSCAP directly on the nodes.

### Platform scans

Current testing has been done on OpenShift (OCP). The project is open to
getting other platforms tested, so volunteers are needed for this.

The current supported versions of OpenShift are 4.6 and up.

## Additional documentation

See the [self-paced workshop](tutorials/README.md) for a hands-on tutorial,
including advanced topics such as content building.

## Must-gather support

The Compliance Operator CSV contains a reference to a related container image
for [must-gather](https://github.com/openshift/must-gather) support. This image
is built automatically as needed, with the latest version is always tagged
and available at `ghcr.io/complianceascode/must-gather-ocp:latest`:

```console
$ oc adm must-gather --image=ghcr.io/complianceascode/must-gather-ocp:latest
```

You can also discover the must-gather image using the `relatedImages` attribute of the CSV:

```console
$ oc adm must-gather --image=$(oc get csv compliance-operator.v1.5.0 -o=jsonpath='{.spec.relatedImages[?(@.name=="must-gather")].image}')
```

Please consider using this image when filing bug reports as it provides
additional details about the operator configuration and logs.

## Metrics

The compliance-operator exposes the following metrics to Prometheus when cluster-monitoring is available.

    # HELP compliance_operator_compliance_remediation_status_total A counter
    # for the total number of updates to the status of a ComplianceRemediation
    # TYPE compliance_operator_compliance_remediation_status_total counter
    compliance_operator_compliance_remediation_status_total{name="remediation-name",state="NotApplied"} 1

    # HELP compliance_operator_compliance_scan_status_total A counter for the
    # total number of updates to the status of a ComplianceScan
    # TYPE compliance_operator_compliance_scan_status_total counter
    compliance_operator_compliance_scan_status_total{name="scan-name",phase="AGGREGATING",result="NOT-AVAILABLE"} 1

    # HELP compliance_operator_compliance_scan_error_total A counter for the
    # total number errors
    # TYPE compliance_operator_compliance_scan_error_total counter
    compliance_operator_compliance_scan_error_total{name="scan-name",error="some_error"} 1

    # HELP compliance_operator_compliance_state A gauge for the compliance
    # state of a ComplianceSuite. Set to 0 when COMPLIANT, 1 when NON-COMPLIANT,
    # 2 when INCONSISTENT, and 3 when ERROR
    # TYPE compliance_operator_compliance_state gauge
    compliance_operator_compliance_state{name="some-compliance-suite"} 1

After logging into the console, navigating to Observe -> Metrics, the
compliance_operator* metrics can be queried using the metrics dashboard. The
`{__name__=~"compliance.*"}` query can be used to view the full set of metrics.

Testing for the metrics from the cli can also be done directly with a pod that
curls the metrics service. This is useful for troubleshooting.

```
oc run --rm -i --restart=Never --image=registry.fedoraproject.org/fedora-minimal:latest -n openshift-compliance metrics-test -- bash -c 'curl -ks -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://metrics.openshift-compliance.svc:8585/metrics-co' | grep compliance
```

## To use PriorityClass for scans

When heavily using Pod Priority and Preemption[1] for automated scaling and
the default `PriorityClass` is too low to guarantee pods to run then scans
are not executed and reports are missing. Since the Compliance Operator
is important for ensuring compliance, we should give administrators the
ability to associate a `PriorityClass` with the operator. This will ensure
the Compliance Operator is prioritized and minimizes the chance that the
cluster will fall out of compliance because the Compliance Operator wasn’t
running.

An admin can set PriorityClass[1] in `ScanSetting`, below is an example of a
`ScanSetting` with a PriorityClass:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
strictNodeScan: true
metadata:
  name: default
  namespace: openshift-compliance
priorityClass: compliance-high-priority
kind: ScanSetting
showNotApplicable: false
rawResultStorage:
  nodeSelector:
    node-role.kubernetes.io/master: ''
  pvAccessModes:
    - ReadWriteOnce
  rotation: 3
  size: 1Gi
  tolerations:
    - effect: NoSchedule
      key: node-role.kubernetes.io/master
      operator: Exists
    - effect: NoExecute
      key: node.kubernetes.io/not-ready
      operator: Exists
      tolerationSeconds: 300
    - effect: NoExecute
      key: node.kubernetes.io/unreachable
      operator: Exists
      tolerationSeconds: 300
    - effect: NoSchedule
      key: node.kubernetes.io/memory-pressure
      operator: Exists
schedule: 0 1 * * *
roles:
  - master
  - worker
scanTolerations:
  - operator: Exists
```

If the `PriorityClass` referenced in the ScanSetting can't be found,
the operator will leave `PriorityClass` empty, issue a warning, and
continue scheduling scans without a `PriorityClass`.

[1]: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#priorityclass

## Increasing operator's memory or CPU limits

In some cases, the compliance-operator might require more memory than the default
limits allow. If the operator had been installed through OLM (which is the case when
the operator is installed through the OCP Web Console), the best way is to set
custom limits in the [Subscription object](https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/design/subscription-config.md#resources).

For example, in order to increase the operator's memory limits to 500Mi, create
the following patch file:

```yaml
spec:
  config:
    resources:
      limits:
        memory: 500Mi
```

and apply it:
```shell
$ oc patch sub compliance-operator -n openshift-compliance --patch-file co-memlimit-patch.yaml --type=merge
```

Please note that this only sets the limit for the compliance-operator
deployment, not the pods actually performing the scan.

## To use timeout option for scan

The scan has a timeout option that can be specified in the `ComplianceScanSetting`
object as a duration string (e.g. 1h30m). If the scan does not finish within the
specified timeout, it will either be reattempted (up to a maximum of `MaxRetryOnTimeout`
times) or considered a failure, depending on the value of `MaxRetryOnTimeout`.
The timeout can be disabled by setting it to 0s, and the default value is 30m.
The default value for `MaxRetryOnTimeout` is 3, so the timeout scan will be retried
up to three times if it fails.

To set a `Timeout` and `MaxRetryOnTimeout` in `ScanSetting`:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
rawResultStorage:
  rotation: 3
  size: 1Gi
roles:
- worker
- master
scanTolerations:
- effect: NoSchedule
  key: node-role.kubernetes.io/master
  operator: Exists
schedule: '0 1 * * *'
timeout: '10m0s'
maxRetryOnTimeout: 3
```

Compliance Operator will check the creation timestamp of the Scanner pod age,
if it is longer than timeout, we will terminate the scan or retry.

A timeout scan will send a warning on retries, and the scan will have an
error result.

## How to Use Compliance Operator with HyperShift Management Cluster

[Hypershift](https://hypershift-docs.netlify.app/) allows one to create and manage clusters on existing infrastructure.
Compliance Operator is able to create a platform scan on the [HyperShift Management Cluster](https://hypershift-docs.netlify.app/reference/concepts-and-personas/)
for the Hosted Cluster with a `TailoredProfile`.

Currently, we only support CIS profile and PCI-DSS profile,
you can either extend `ocp4-cis` or `ocp4-pci-dss`.

In order to scan a Hosted Cluster, you need to create a `TailoredProfile` specifying the
name and namespace of the Hosted Cluster that you want to scan.
Set the value of `ocp4-hypershift-cluster` to the name of the target Hosted Cluster,
and set the value of `ocp4-hypershift-namespace-prefix` to the namespace where the
Hosted Cluster resides, e.g.: `local-cluster`, or `clusters`.

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
 name: cis-compliance-hypershift
 namespace: openshift-compliance
 annotations:
   compliance.openshift.io/product-type: Platform
spec:
 title: CIS Benchmark for Hypershift
 description: CIS Benchmark for Hypershift Master-plane components
 extends: ocp4-cis
 setValues:
   - name: ocp4-hypershift-cluster
     value: "<hypershift-hosted-cluster-name>"
     rationale: This value is used for HyperShift version detection
   - name: ocp4-hypershift-namespace-prefix
     value: "<hypershift-hosted-namespace-prefix>"
     rationale: This value is used for HyperShift control plane namespace detection
```

And after you save the edit, you can then apply the edited `tailoredProfile`,
and create a `ScanSettingBinding` to run the scan:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
 name: cis-compliance-hypershift
 namespace: openshift-compliance
profiles:
 - name: cis-compliance-hypershift
   kind: TailoredProfile
   apiGroup: compliance.openshift.io/v1alpha1
settingsRef:
 name: default
 kind: ScanSetting
 apiGroup: compliance.openshift.io/v1alpha1
 ```

## How to Use Compliance Operator with HyperShift Hosted Cluster

Compliance Operator is able to run a platform scan on the [HyperShift Hosted Cluster](https://hypershift-docs.netlify.app/reference/concepts-and-personas/)
without any tailoredProfile. Any unsupport rules will be hidden from the `ComplianceCheckResult`.

However, you need to use a special subscription file to install Compliance Operator on the
Hosted Cluster from the OperatorHub. You can either add `spec.config` section from the following
example to the existing subscription object, or use the following subscription file directly:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: compliance-operator-
  namespace: openshift-compliance
spec:
  channel: stable
  installPlanApproval: Automatic
  name: compliance-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  startingCSV: compliance-operator.v1.0.0
  config:
    nodeSelector:
      node-role.kubernetes.io/worker: ""
    env: 
    - name: PLATFORM
      value: "HyperShift"
```

To install Compliance Operator on the Hosted Cluster from upstream using OLM, you can run the following command:

`make catalog-deploy PLATFORM=HyperShift`

## Verbose OpenScap debugging information

Compliance Operator uses OpenScap under the hood to perform the scans. In order to
enable verbose debugging information from OpenScap, you can set the `OSCAP_DEBUG_LEVEL`
environment variable.

Setting the variable depends on your deployment method: if you installed the operator
directly from upstream manifests, just add the variable to the main operator deployment
(`.spec.template.spec.containers[0].env`), and then wait for restart of the operator pod.

If the operator was installed through OLM, you can set the variable in the Subscription
object, e.g.:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
  name: compliance-operator-sub
  namespace: openshift-compliance
spec:
  channel: alpha
  name: compliance-operator
  source: compliance-operator
  sourceNamespace: openshift-marketplace
  config:
    nodeSelector:
      node-role.kubernetes.io/worker: ""
    env:
      - name: OSCAP_DEBUG_LEVEL
        value: DEVEL
 ```
