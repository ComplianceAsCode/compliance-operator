---
title: last-scanned-timestamps
authors:
  - TBD
reviewers: # Include a comment about what domain expertise a reviewer is expected to bring and what area of the enhancement you expect them to focus on. For example: - "@networkguru, for networking aspects, please look at IP bootstrapping aspect"
  - @rhmdnd
approvers:
  - TBD
api-approvers: # In case of new or modified APIs or API extensions (CRDs, aggregated apiservers, webhooks, finalizers). If there is no API change, use "None"
  - TBD
creation-date: 2024-04-10
last-updated: 2024-04-10
tracking-link: # link to the tracking ticket (for example: Jira Feature or Epic ticket) that corresponds to this enhancement
  - TBD
see-also:
  - /
replaces:
  - /
superseded-by:
  - /
---

# Add `last_scanned_timestamp` to `compliancecheckresults.compliance.openshift.io` objects

## Summary

ACS implements an integration with Compliance Operator. For this, ACS reports when a scan was completed. Currently
Compliance Operator does not update results when a scan did not changed, this makes it impossible for ACS to determenistically
indicate a completed scan (e.g. to send scan reports to users automatically).

## Motivation

Identify deterministically when a scan is completed.

### Goals

Goal is to identify when a `profiles.compliance.openshift.io`, `compliancesuites.compliance.openshift.io` or `compliancescans.compliance.openshift.io` is completed.

### Non-Goals

N/A

## Proposal

Add a `LastTimeStamp` field to the `ComplianceCheckResult` which is updated after every scan.

Field: ```LastScannedTimestamp `json:"lastScannedTimestamp,omitempty"` ```.

```go
type ComplianceCheckResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// A unique identifier of a check
	ID string `json:"id"`
	// The result of a check
	Status ComplianceCheckStatus `json:"status"`
	// The severity of a check status
	Severity ComplianceCheckResultSeverity `json:"severity"`
	// A human-readable check description, what and why it does
	Description string `json:"description,omitempty"`
	// The rationale of the Rule
	Rationale string `json:"rationale,omitempty"`
	// How to evaluate if the rule status manually. If no automatic test is present, the rule status will be MANUAL
	// and the administrator should follow these instructions.
	Instructions string `json:"instructions,omitempty"`
	// Any warnings that the user should be aware about.
	// +nullable
	Warnings []string `json:"warnings,omitempty"`
	// It stores a list of values used by the check
	ValuesUsed []string `json:"valuesUsed,omitempty"`
	
	// Stores the timestamp of the last performed scan. 
	LastScannedTimestamp `json:"lastScannedTimestamp,omitempty"`
}
```

### API Extensions

N/A

## Design Details

### Open Questions [optional]

1. The timestamp could be stored in an annotation, however as it is part of the result preference is on a CR field.
2. Is this a reasonable feature request? If yes, I am going to investigate the implementation details.