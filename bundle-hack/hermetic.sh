#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
VERSION=$(grep -oP 'VERSION\?=\K.*' version.Makefile)

REDHAT_REGISTRY_OPERATOR="registry.redhat.io/compliance/openshift-compliance-rhel8-operator"
REDHAT_REGISTRY_MUST_GATHER="registry.redhat.io/compliance/openshift-compliance-must-gather-rhel8"
REDHAT_REGISTRY_CONTENT="registry.redhat.io/compliance/openshift-compliance-content-rhel8"
REDHAT_REGISTRY_SCANNER="registry.redhat.io/compliance/openshift-compliance-openscap-rhel8"

QUAY_REGISTRY_OPERATOR="quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator"
QUAY_REGISTRY_MUST_GATHER="quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-must-gather"
QUAY_REGISTRY_CONTENT="quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-content"
QUAY_REGISTRY_SCANNER="quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-openscap"

KUSTOMIZE_FILE="config/openshift-bundle/kustomization.yaml"
ANNOTATIONS_FILE="config/openshift-bundle/annotations.yaml"
IMAGES_FILE="config/openshift-bundle/images.yaml"
ICON_FILE="config/openshift-bundle/icon.yaml"

# Replace the quay.io references with the equivalent locations from registry.redhat.io.
sed -i -e "s@${QUAY_REGISTRY_OPERATOR}@${REDHAT_REGISTRY_OPERATOR}@g" "${IMAGES_FILE}"
sed -i -e "s@${QUAY_REGISTRY_MUST_GATHER}@${REDHAT_REGISTRY_MUST_GATHER}@g" "${IMAGES_FILE}"
sed -i -e "s@${QUAY_REGISTRY_CONTENT}@${REDHAT_REGISTRY_CONTENT}@g" "${IMAGES_FILE}"
sed -i -e "s@${QUAY_REGISTRY_SCANNER}@${REDHAT_REGISTRY_SCANNER}@g" "${IMAGES_FILE}"

# Could we just update our release tooling to update these files to include the correct version?
sed -i -e "s@VERSION@${VERSION}@g" "${KUSTOMIZE_FILE}"
sed -i -e "s@VERSION@${VERSION}@g" "${IMAGES_FILE}"
sed -i -e "s@VERSION@${VERSION}@g" "${ICON_FILE}"
sed -i -e "s@VERSION@${VERSION}@g" "${ANNOTATIONS_FILE}"

# build a manifest with correct image references and annotations for a red hat operator release
oc kustomize "$PROJECT_ROOT/config/openshift-bundle" > "$PROJECT_ROOT/bundle/manifests/compliance-operator.clusterserviceversion.yaml"
mv "$PROJECT_ROOT/bundle/manifests/compliance-operator.clusterserviceversion.yaml" "$PROJECT_ROOT/bundle/manifests/compliance-operator.v${VERSION}.clusterserviceversion.yaml"
