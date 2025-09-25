ARG CO_OLD_VERSION="1.7.0"
ARG CO_NEW_VERSION="1.7.1"

FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:v1.23 as builder

COPY . .
WORKDIR bundle-hack

# Bring the version variables into scope
ARG CO_OLD_VERSION
ARG CO_NEW_VERSION

RUN go run ./update_csv.go ../bundle/manifests ${CO_OLD_VERSION} ${CO_NEW_VERSION}
RUN ./update_bundle_annotations.sh

FROM scratch

ARG CO_NEW_VERSION

LABEL name=compliance/openshift-compliance-operator-bundle
LABEL version=${CO_NEW_VERSION}
LABEL summary='OpenShift Compliance Operator'
LABEL maintainer='Infrastructure Security and Compliance Team <isc-team@redhat.com>'

LABEL io.k8s.display-name='Compliance Operator'
LABEL io.k8s.description='OpenShift Compliance Operator'
LABEL description='Compliance Operator'
LABEL vendor='Red Hat, Inc.'
LABEL release=${CO_NEW_VERSION}
LABEL url="https://github.com/ComplianceAsCode/compliance-operator"
LABEL distribution-scope=public

LABEL com.redhat.component=openshift-compliance-operator-bundle-container
LABEL cpe=cpe:/a:redhat:openshift_file_integrity_operator:1::el9
LABEL com.redhat.delivery.appregistry=false
LABEL com.redhat.delivery.operator.bundle=true
LABEL com.redhat.openshift.versions="v4.10"

LABEL io.openshift.maintainer.product='OpenShift Container Platform'
LABEL io.openshift.tags=openshift,security,compliance,openscap

LABEL operators.operatorframework.io.bundle.channel.default.v1=stable
LABEL operators.operatorframework.io.bundle.channels.v1=stable
LABEL operators.operatorframework.io.bundle.manifests.v1=manifests/
LABEL operators.operatorframework.io.bundle.mediatype.v1=registry+v1
LABEL operators.operatorframework.io.bundle.metadata.v1=metadata/
LABEL operators.operatorframework.io.bundle.package.v1=compliance-operator

LABEL License=GPLv2+

# Copy files to locations specified by labels.
COPY --from=builder bundle/manifests /manifests/
COPY --from=builder bundle/metadata /metadata/
COPY bundle/tests/scorecard /tests/scorecard
