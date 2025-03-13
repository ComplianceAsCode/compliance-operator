FROM registry.redhat.io/ubi9/ubi:latest AS builder

COPY . .
RUN ./bundle-hack/hermetic.sh
COPY manifests /manifests
COPY metadata /metadata

FROM scratch

LABEL name=openshift-compliance-operator-bundle
LABEL version=${CO_VERSION}
LABEL summary='OpenShift Compliance Operator'
LABEL maintainer='Infrastructure Security and Compliance Team <isc-team@redhat.com>'

LABEL io.k8s.display-name='Compliance Operator'
LABEL io.k8s.description='OpenShift Compliance Operator'

LABEL com.redhat.component=openshift-compliance-operator-bundle-container
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
COPY --from=builder /manifests /manifests/
COPY --from=builder /metadata /metadata/
COPY bundle/tests/scorecard /tests/scorecard

