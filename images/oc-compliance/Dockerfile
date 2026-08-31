# Throwaway build of the oc-compliance oc plugin for testing.
# Adapted from the downstream Containerfile.ocp to build from public bases.
FROM golang:1.25.11 AS builder

COPY . /go/src/github.com/ComplianceAsCode/compliance-operator
WORKDIR /go/src/github.com/ComplianceAsCode/compliance-operator
RUN CGO_ENABLED=0 go build -o /oc-compliance ./cmd/oc-compliance

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL io.k8s.display-name="OpenShift oc compliance" \
      io.k8s.description="An OpenShift CLI plugin to interact with the Compliance Operator." \
      io.openshift.tags="openshift,compliance,security" \
      maintainer="ComplianceAsCode"

# openscap-scanner is needed at runtime by "oc compliance fetch-raw --html".
RUN microdnf -y install openscap-scanner glibc && microdnf clean all

COPY --from=builder /oc-compliance /usr/bin/oc-compliance

WORKDIR /usr/bin
CMD ["/usr/bin/oc-compliance"]
