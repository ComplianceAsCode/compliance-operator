---
title: results-forwarding
authors:
  - JAORMX
  - rhmdnd
reviewers: # Include a comment about what domain expertise a reviewer is expected to bring and what area of the enhancement you expect them to focus on. For example: - "@networkguru, for networking aspects, please look at IP bootstrapping aspect"
  - TBD
approvers:
  - TBD
api-approvers: # In case of new or modified APIs or API extensions (CRDs, aggregated apiservers, webhooks, finalizers). If there is no API change, use "None"
  - TBD
creation-date: yyyy-mm-dd
last-updated: yyyy-mm-dd
tracking-link: # link to the tracking ticket (for example: Jira Feature or Epic ticket) that corresponds to this enhancement
  - TBD
see-also:
  - "/enhancements/this-other-neat-thing.md"
replaces:
  - "/enhancements/that-less-than-great-idea.md"
superseded-by:
  - "/enhancements/our-past-effort.md"
---

# Compliance Results Forwarding

## Summary

This will allow for a flexible and extendible mechanism to forward compliance
results to a centralized service or storage endpoint.

## Motivation

While the current approach of generating results and remediations via CRDs
has worked so far for Compliance Operator, this has several draw-backs that
prove painful in multi-cluster environments:

* `ComplianceCheckResults` and `ComplianceRemediations` are specific to the
  cluster being scanned. Comparing these CRDs across multiple clusters is
  cumbersome without some sort of filtering mechanism.

* `ComplianceCheckResults` and `ComplianceRemediations` take space in etcd. This
  space may be better used by other operation-critical components in
  resource-constrained deployments. These resources also scale with deployment
  infrastructure size. This can be a significant aspect to consider when
  running the compliance operator, or providing useful data for evidence and
  auditing.
  
* By using CRDs we depend on etcd, which is not a generic database and doesn't
  provide all the assurances that one would expect when querying persistent
  data stores. The following are a few short-comings of using etcd as a
  persistent store for compliance data:
  
  - It's non-trivial to do disaster recovery: An object snapshot contains
    CRD metadata which contains uniquely generated information (e.g., like
    UUIDs), making it hard to reproduce and replicate. SOme of this data is
    also irrelevant to compliance checks. Full etcd restore is a tedious and
    complicated
    [process](https://platform9.com/kb/kubernetes/restore-etcd-cluster-from-quorum-loss).

  - Values are limited to a size of 1.5Mb, imposing a limit on the data that
    can be persisted in etcd. This is especially applicable to evidence
    storage, which will be covered in a separate enhancement proposal.

  - The current CRDs may be very verbose, resulting in large objects, which
    may interfer with known scalability
    [limitations](https://kubernetes.io/blog/2020/09/02/scaling-kubernetes-networking-with-endpointslices/#scalability-limitations-of-the-endpoints-api)
    in Kubernetes, causing performance and scalability issues.

While projects such as [StackRox](https://www.stackrox.io/) have successfully
integrated Compliance Operator using CRDs as the primary interface, we can
improve the experience of aggregating results into a single place by providing
a forwarding mechanism.

By sending results to a central store, we'll be able to:

* View Compliance results and suggested fixes for multiple clusters in one place.

* Address the aforementioned limitations with Etcd by choosing an alternative
  store. e.g. a relational database or a cloud-managed database.

The Compliance Operator also stores raw results (currently ARF) in a PVC by default.
While this is useful, not everyone has access to persistent storage. This issue
is apparent in shared testing clusters where automation attempts to delete the
Compliance Operator namespace, only to have the request fail because of a
failed physical volume allocation.

#### Gathering Evidence

ARF files contain a lot of information about the state of the system where the
compliance scan was effectuated. We could take the view that this is "evidence"
gathered for the system in check. With this in mind, we can generalize and
expand the concept to allow for forwarding this evidence to an alternative
object store, e.g. S3.

In the future, we could expand the "evidence" gathered, e.g. for Kubernetes
compliance scans we could simply compress the gathered objects the
`api-resource-collector` downloads and send that too.

While evidence is important to consider, we're going to dedicated a separate
enhancement to that problem. This particular enhancement is focused on
forwarding results.

### Goals

* Provide a generic way to implement compliance result forwarding for
  Compliance Operator. This should be flexible enough to accommodate the
  current implementation (CRDs and PVCs), while allowing for custom forwarding
  implementations.

* Define and implement a stable API for forwarder implementations.

* Implement an interface for forwarding result CRDs

* Implement an interface for forwarding remediation CRDs

* Implement a switch to disable in-cluster storage if forwarding is enabled and valid

### Non-Goals

* Deprecate the current CRD/PVC approach: There is still a use-case for this.

* Expand the "evidence" that's currently gathered by the Compliance Operator. This is
  needed but should be done as part of a separate initiative.

## Proposal

The Compliance Operator will forward compliance results and remediation
recommendations if the supplied forwarding endpoint is valid. The Compliance
Operator will also continue to use CRDs and PVCs to store results,
remediations, and evidence as it does today.

A user may explicitly disable in-cluster storage if forwarding is enabled. The
Compliance Operator will not support disabling PVC storage without a valid
forwarding endpoint.

This will require changing the **aggregator** to always forward via a gRPC API
to a configured implementation. In this case, the **aggregator** will act as a
gRPC client. The **resultserver** then becomes a gRPC server, subject to the
evidence forwarding provider and will be renamed **evidence-persistor** and
responsible for writing results.

Forwarder implementations would be configured via the `ScanSetting` and they'd be called "providers".
For backwards compatibility, we'd have defaults that would point to the current mode of operation
of the Compliance Operator. e.g. a `pvc` provider for evidence storage.

For more detail on the proposed API, see the *API Extensions* section.

### User Stories

* As an Site Reliability Engineer managing multiple clusters, I'd like to run compliance
  scans on my fleet in such a way that uses the minimal amount of resources.

* As a Site Reliability Engineer managing multiple clusters, I'd like to have
  one place to view the compliance stance of my whole fleet.

### API Extensions

Given the scope of the change, we'd upgrade the ScanSetting's version to `v1alpha2`.

A sample `ScanSetting` object with Compliance Operator's current mode of operation would look as follows:

```yaml
apiVersion: compliance.openshift.io/v1alpha2
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
generateResultCRDs: true  # Adds CRD creator and sets forwarder config to send info there
resultForwarding:
  ... # Potential configuration goes here.
evidenceForwarding:
  provider: pvc
  pvc: # configuration goes here. This would be the same as `rawResultStorage` in ScanSetting v1alpha1
    pvAccessModes:
      - ReadWriteOnce 
    rotation: 3 
    size: 1Gi
roles:
- worker 
- master 
scanTolerations: 
  default:
  - operator: Exists
  schedule: 0 1 * * * 
```

To forward results, we'd implement a `grpc` provider. A sample would look as follows:

```yaml
apiVersion: compliance.openshift.io/v1alpha2
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
generateResultCRDs: false # no CRD-creator container will be provisioned
storeEvidenceInPVC: false # no PVC store container will be provisioned
evidenceStorage: null # No storage options are needed
resultForwarding:
  provider: grpc
  grpc:
    version: v1  # we'll start at v1
    endpoint: <URL to GRPC service (could be in-cluster or outside of it)>
    tls:
      dynamic: 
      caSecretName: <ref to CA cert/key pair for TLS> . # This is mandatory
      serverSecretName: <ref to server cert/key pair secret for mTLS>
      clientSecretName: <ref to client cert/key pair secret for mTLS> # Mandatory if mtls authentication is used
    authentication:
      type: <mtls or token>
      token:  # May be nil if mtls is chosen
        tokenSecretName: <ref to secret containing token>
    extraMetadata:  # defined as a map[string]string
      cluster_name: foo
      cluster_type: bar
      randomKey: random value
...
```

Note that `generateResultCRDs` is set to `false`, as well as `storeEvidenceInPVC`

```yaml
evidenceForwarding:
  provider: s3
  s3:
    bucketName: <name of the s3 bucket>
    objectPrefix:
    accessKeyID: 
```

Potential evidence forwarding providers could be implemented with a similar scheme. e.g.
a potential `http` provider could look as follows:

```yaml
evidenceForwarding:
  provider: http
  http:
    version: v1
    endpoint: <URL of the receiving endpoint>
    tls:
      caSecretName: <ref to CA cert/key pair for TLS>
      serverSecretName: <ref to server cert/key pair secret for mTLS>
      clientSecretName: <ref to client cert/key pair secret for mTLS>
```

Note that the current implementation proposal will include the `s3` and `pvc`
providers only.

### Implementation Details/Notes/Constraints

A First step in implementing the forwarding proposal would be to work with the existing
`v1alpha1` `ScanSetting` object. All changes would need to be done in how the Compliance
Operator effectuates scans, and thus we'd ensure that backwards compatibility is
taken into account. A new `crd-creator` pod would be introduced to receive the results
from the `aggregator` and ensure that the known `ComplianceCheckResult` and
`ComplianceRemediation` objects are created.

A subsequent step would be introduce the `v1alpha2` `ScanSetting` object, which would
contain all the tunables needed for the forwarding architecture.

A webhook would be introduced to ensure compatibility between the `v1alpha1` objects
and the new `v1alpha2` objects.


### Risks and Mitigations

`v1alpha1` objects would be easily translated to `v1alpha2` objects, but not the
other way around. This needs to be thoroughly documented and communicated.

## Design Details

### Open Questions

1. If the configured provider for either the result forwarder or the evidence
   persistor would be unavailable, do we error the scan entirely?

### Test Plan

The base case of generating CRDs and storing evidence in PVCs would be covered
in our prow-based pre-existing CI.

New cases with forwarders would be introduced in more light-weight testing
environments. e.g. we could deploy a KinD cluster via a GitHub action and run
[MinIO](https://min.io/) to test the s3 provider. We'd then need to provide a
reference GRPC receiver for the test.

### Upgrade / Downgrade Strategy

Upgrade expectations:
- Existing `ScanSettings` should simply work and be seamlessly translated to `v1alpha2`

Downgrade expectations:
- Compliance Operator, as it is today, does not provide Downgrade options. This
  is not expected to change.

### Version Skew Strategy (TODO)

How will the component handle version skew with other components?
What are the guarantees? Make sure this is in the test plan.

Consider the following in developing a version skew strategy for this
enhancement:
- During an upgrade, we will always have skew among components, how will this impact your work?
- Does this enhancement involve coordinating behavior in the control plane and
  in the kubelet? How does an n-2 kubelet without this feature available behave
  when this feature is used?
- Will any other components on the node change? For example, changes to CSI, CRI
  or CNI may require updating that component before the kubelet.

### Operational Aspects of API Extensions (TODO)

Describe the impact of API extensions (mentioned in the proposal section, i.e. CRDs,
admission and conversion webhooks, aggregated API servers, finalizers) here in detail,
especially how they impact the system architecture and operational aspects.

- For conversion/admission webhooks and aggregated apiservers: what are the SLIs (Service Level
  Indicators) an administrator or support can use to determine the health of the API extensions

- What impact do these API extensions have on existing SLIs (e.g. scalability, API throughput,
  API availability)

  Examples:
  - Adds 1s to every pod update in the system, slowing down pod scheduling by 5s on average.
  - Fails creation of ConfigMap in the system when the webhook is not available.
  - Adds a dependency on the SDN service network for all resources, risking API availability in case
    of SDN issues.
  - Expected use-cases require less than 1000 instances of the CRD, not impacting
    general API throughput.

- How is the impact on existing SLIs to be measured and when (e.g. every release by QE, or
  automatically in CI) and by whom (e.g. perf team; name the responsible person and let them review
  this enhancement)

#### Failure Modes 

- If the GRPC forwarder or the evidence persistor error out due to the endpoint not being available
  for any reason; we'd need to output relevant Kubernetes events.

#### Support Procedures

Describe how to
- detect the failure modes in a support situation, describe possible symptoms (events, metrics,
  alerts, which log output in which component)

  Examples:
  - If the webhook is not running, kube-apiserver logs will show errors like "failed to call admission webhook xyz".
  - Operator X will degrade with message "Failed to launch webhook server" and reason "WehhookServerFailed".
  - The metric `webhook_admission_duration_seconds("openpolicyagent-admission", "mutating", "put", "false")`
    will show >1s latency and alert `WebhookAdmissionLatencyHigh` will fire.

- disable the API extension (e.g. remove MutatingWebhookConfiguration `xyz`, remove APIService `foo`)

  - What consequences does it have on the cluster health?

    Examples:
    - Garbage collection in kube-controller-manager will stop working.
    - Quota will be wrongly computed.
    - Disabling/removing the CRD is not possible without removing the CR instances. Customer will lose data.
      Disabling the conversion webhook will break garbage collection.

  - What consequences does it have on existing, running workloads?

    Examples:
    - New namespaces won't get the finalizer "xyz" and hence might leak resource X
      when deleted.
    - SDN pod-to-pod routing will stop updating, potentially breaking pod-to-pod
      communication after some minutes.

  - What consequences does it have for newly created workloads?

    Examples:
    - New pods in namespace with Istio support will not get sidecars injected, breaking
      their networking.

- Does functionality fail gracefully and will work resume when re-enabled without risking
  consistency?

  Examples:
  - The mutating admission webhook "xyz" has FailPolicy=Ignore and hence
    will not block the creation or updates on objects when it fails. When the
    webhook comes back online, there is a controller reconciling all objects, applying
    labels that were not applied during admission webhook downtime.
  - Namespaces deletion will not delete all objects in etcd, leading to zombie
    objects when another namespace with the same name is created.

## Implementation History

Major milestones in the life cycle of a proposal should be tracked in `Implementation
History`.

## Drawbacks

The idea is to find the best form of an argument why this enhancement should _not_ be implemented.

## Alternatives

Similar to the `Drawbacks` section the `Alternatives` section is used to
highlight and record other possible approaches to delivering the value proposed
by an enhancement.

## Infrastructure Needed [optional]

Use this section if you need things from the project. Examples include a new
subproject, repos requested, github details, and/or testing infrastructure.

Listing these here allows the community to get the process for these resources
started right away.
