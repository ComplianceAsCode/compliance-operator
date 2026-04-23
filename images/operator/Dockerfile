FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:v1.25.8 as builder

WORKDIR /go/src/github.com/ComplianceAsCode/compliance-operator

ENV GOFLAGS="-mod=vendor" BUILD_FLAGS="-tags strictfipsruntime"

COPY . .

# Verify the Go version in the builder image matches go.mod. Patch versions
# carry security fixes and CVE scanners use go.mod to determine the Go
# version, so these must stay in sync.
RUN expected=$(awk '/^go / { print $2 }' go.mod) && \
    actual=$(go version | awk '{print $3}' | sed 's/go//') && \
    if [ "$expected" != "$actual" ]; then \
        echo "Go version mismatch: go.mod expects go${expected} but builder image has go${actual}." && \
        echo "Update go.mod or the builder image to resolve this." && \
        exit 1; \
    fi

RUN make manager

FROM registry.redhat.io/ubi9/ubi-minimal:latest

RUN microdnf install -y --setopt=tsflags=nodocs tar
RUN microdnf clean all && rm -rf /var/cache/*

LABEL \
        io.k8s.display-name="OpenShift Compliance Operator" \
        io.k8s.description="An operator that performs compliance scanning and remediation on a cluster." \
        io.openshift.tags="openshift,compliance,security" \
        com.redhat.delivery.appregistry="false" \
        summary="OpenShift Compliance Operator" \
        description="An operator that performs compliance scanning and remediation on a cluster" \
        maintainer="Red Hat ISC <isc-team@redhat.com>" \
        License="GPLv2+" \
        name="compliance/openshift-compliance-rhel8-operator" \
        cpe="cpe:/a:redhat:openshift_compliance_operator:1::el9" \
        com.redhat.component="openshift-compliance-operator-container" \
        io.openshift.maintainer.product="OpenShift Container Platform" \
        io.openshift.maintainer.component="Compliance Operator" \
        version=1.7.1

WORKDIR /

ENV OPERATOR_BIN=/usr/local/bin/compliance-operator

COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/LICENSE /licenses/LICENSE
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/build/_output/bin/compliance-operator ${OPERATOR_BIN}
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/build/bin/entrypoint /usr/local/bin/entrypoint
# This is required for the bundle build.
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/bundle /bundle

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER 1001
