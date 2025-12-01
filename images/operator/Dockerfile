FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:v1.24 as builder

WORKDIR /go/src/github.com/ComplianceAsCode/compliance-operator

ENV GOFLAGS="-mod=vendor" BUILD_FLAGS="-tags strictfipsruntime"

COPY . .

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

# Needed by the user_setup and entrypoint scripts
ENV OPERATOR_BIN=/usr/local/bin/compliance-operator \
    USER_NAME=compliance-operator \
    USER_UID=1001

COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/LICENSE /licenses/LICENSE
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/build/_output/bin/compliance-operator ${OPERATOR_BIN}
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/build/bin/* /usr/local/bin
# This is required for the bundle build.
COPY --from=builder /go/src/github.com/ComplianceAsCode/compliance-operator/bundle /bundle

RUN  /usr/local/bin/user_setup

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}
