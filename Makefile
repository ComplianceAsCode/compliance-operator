include version.Makefile

# Operator variables
# ==================
export APP_NAME=compliance-operator
export GOARCH = $(shell go env GOARCH)
export PLATFORM?=openshift # target platform for the operator (openshift, generic)

# Runtime variables
# =================
DEFAULT_REPO=ghcr.io/complianceascode
IMAGE_REPO?=$(DEFAULT_REPO)
RUNTIME?=podman
# Required for podman < 3.4.7 and buildah to use microdnf in fedora 35
RUNTIME_BUILD_OPTS=--security-opt seccomp=unconfined
BUILD_DIR := build
TOOLS_DIR := $(BUILD_DIR)/_tools

# Detect the OS to set per-OS defaults
OS_NAME=$(shell uname -s)
# Container runtime
ifeq ($(OS_NAME), Linux)
    RUNTIME?=podman
    SED=sed -i
else ifeq ($(OS_NAME), Darwin)
    RUNTIME?=docker
    SED=sed -i ''
endif

ARCH?=$(shell uname -m)
ifeq ($(ARCH), x86_64)
    OPM_ARCH?=amd64
else
    OPM_ARCH?=$(ARCH)
endif

ifeq ($(RUNTIME), podman)
    LOGIN_PUSH_OPTS="--tls-verify=false"
else ifeq ($(RUNTIME), docker)
    LOGIN_PUSH_OPTS=
endif


ifeq ($(RUNTIME),buildah)
	RUNTIME_BUILD_CMD=bud
else
	RUNTIME_BUILD_CMD=build
endif

# Git options.
GIT_OPTS?=
# Set this to the remote used for the upstream repo (for release). Different
# maintainers might use different names for the upstream repository. Since our
# release process expects maintainers to propose release patches directly to
# the upstream repository, let's make sure we're proposing it to the right one.
# We rely on a bash script for this since it's simplier than interating over a
# list with conditionals in GNU make.
GIT_REMOTE?=$(shell ./utils/git-remote.sh)
PREVIOUS_VERSION?=$(shell ./utils/get-current-version.sh)

# Image variables
# ===============
DEFAULT_TAG=latest
# Image tag to use. Set this if you want to use a specific tag for building
# or your e2e tests.
TAG?=$(DEFAULT_TAG)

OPENSCAP_NAME=openscap-ocp
DEFAULT_OPENSCAP_TAG=latest
OPENSCAP_TAG?=$(DEFAULT_OPENSCAP_TAG)
OPENSCAP_DOCKER_FILE=./images/openscap/Containerfile
DEFAULT_OPENSCAP_IMAGE=$(DEFAULT_REPO)/$(OPENSCAP_NAME):$(DEFAULT_OPENSCAP_TAG)
OPENSCAP_IMAGE?=$(DEFAULT_OPENSCAP_IMAGE)

# Image path to use. Set this if you want to use a specific path for building
# or your e2e tests. This is overwritten if we build the image and push it to
# the cluster or if we're on CI.
OPERATOR_TAG_BASE=$(IMAGE_REPO)/$(APP_NAME)
OPERATOR_IMAGE?=$(OPERATOR_TAG_BASE):$(TAG)

# Build variables
# ===============
CURPATH=$(PWD)
TARGET_DIR=$(CURPATH)/build/_output
GOFLAGS?=-mod=vendor
GO=GOFLAGS=$(GOFLAGS) GO111MODULE=auto go
BUILD_GOPATH=$(TARGET_DIR):$(CURPATH)/cmd
TARGET_OPERATOR=$(TARGET_DIR)/bin/$(APP_NAME)
MAIN_PKG=main.go
PKGS=$(shell go list ./... | grep -v -E '/vendor/|/test|/examples')
# This is currently hardcoded to our most performance sensitive package
BENCHMARK_PKG?=github.com/ComplianceAsCode/compliance-operator/pkg/utils

# go source files, ignore vendor directory
SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*" -not -path "./_output/*")

MUST_GATHER_IMAGE_PATH?=$(IMAGE_REPO)/must-gather-ocp
MUST_GATHER_IMAGE_TAG?=$(TAG)

# Kubernetes variables
# ====================
KUBECONFIG?=$(HOME)/.kube/config
export NAMESPACE?=openshift-compliance
export OPERATOR_NAMESPACE?=openshift-compliance

# Operator-sdk variables
# ======================
SDK_BIN?=
SDK_VERSION?=1.20.0
OPM_VERSION?=$(SDK_VERSION)

# Test variables
# ==============
TEST_SETUP_DIR=tests/_setup
TEST_CRD=$(TEST_SETUP_DIR)/crd.yaml
TEST_DEPLOY=$(TEST_SETUP_DIR)/deploy_rbac.yaml

# Pass extra flags to the e2e test run.
# e.g. to run a specific test in the e2e test suite, do:
# 	make e2e E2E_GO_TEST_FLAGS="-v -run TestE2E/Parallel_tests/TestScanWithNodeSelectorFiltersCorrectly"
E2E_GO_TEST_FLAGS?=-v -test.timeout 120m

# By default we run all tests; available options: all, parallel, serial
E2E_TEST_TYPE?=all

# By default, the test runner won't cleanup resources from failed test runs. Set this
# variable to true if you prefer the tests to cleanup regardless of test status, e.g.:
# E2E_CLEANUP_ON_ERROR=true make e2e
E2E_CLEANUP_ON_ERROR?=false
E2E_ARGS=-root=$(PROJECT_DIR) -globalMan=$(TEST_CRD) -namespacedMan=$(TEST_DEPLOY) -cleanupOnError=$(E2E_CLEANUP_ON_ERROR) -testType=$(E2E_TEST_TYPE)
TEST_OPTIONS?=-timeout=20m
# Skip pushing the container to your cluster
E2E_SKIP_CONTAINER_PUSH?=false
# Use default images in the e2e test run. Note that this takes precedence over E2E_SKIP_CONTAINER_PUSH
E2E_USE_DEFAULT_IMAGES?=false
# In a local-env e2e run, push images to the cluster but skip building them. Useful if the container push fails.
E2E_SKIP_CONTAINER_BUILD?=false

# Used for substitutions
DEFAULT_CONTENT_IMAGE=ghcr.io/complianceascode/k8scontent:latest
CONTENT_IMAGE?=$(DEFAULT_CONTENT_IMAGE)
# Specifies the image path to use for the content in the tests
E2E_CONTENT_IMAGE_PATH?=ghcr.io/complianceascode/k8scontent:latest
# We specifically omit the tag here since we use this for testing
# different images referenced by different tags.
E2E_BROKEN_CONTENT_IMAGE_PATH?=ghcr.io/complianceascode/test-broken-content-ocp

MUST_GATHER_IMAGE_PATH?=ghcr.io/complianceascode/must-gather-ocp
MUST_GATHER_IMAGE_TAG?=latest

# New Makefile variables

# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
DEFAULT_CHANNEL="alpha"
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# openshift.io/compliance-operator-bundle:$VERSION and openshift.io/compliance-operator-catalog:$VERSION.
IMAGE_TAG_BASE=$(IMAGE_REPO)/$(APP_NAME)

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_TAG_BASE= $(IMAGE_TAG_BASE)-bundle
BUNDLE_IMG ?= $(BUNDLE_TAG_BASE):$(TAG)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

# Includes additional service accounts into the bundle CSV.
BUNDLE_SA_OPTS ?= --extra-service-accounts remediation-aggregator,api-resource-collector,resultscollector,resultserver,profileparser,rerunner

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):$(TAG)
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.23

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# Used for substitutions
DEFAULT_CATALOG_IMG=$(DEFAULT_REPO)/$(APP_NAME)-catalog:$(DEFAULT_TAG)
# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_TAG_BASE=$(IMAGE_TAG_BASE)-catalog
CATALOG_IMG ?= $(CATALOG_TAG_BASE):$(TAG)
CATALOG_DIR=config/catalog
CATALOG_SRC_FILE=$(CATALOG_DIR)/catalog-source.yaml
CATALOG_GROUP_FILE=$(CATALOG_DIR)/operator-group.yaml
CATALOG_SUB_FILE=$(CATALOG_DIR)/subscription.yaml
# If plafform is set to hypershift, we will use a different subscription file
ifeq ($(PLATFORM), hypershift)
	CATALOG_SUB_FILE=$(CATALOG_DIR)/subscription-hypershift.yaml
endif
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

ROLE ?= $(APP_NAME)

.PHONY: openshift-user
openshift-user:
ifeq ($(shell oc whoami 2>/dev/null),kube:admin)
	$(eval OPENSHIFT_USER = kubeadmin)
else
	$(eval OPENSHIFT_USER = $(shell oc whoami))
endif

.PHONY: check-operator-version
check-operator-version:
ifndef VERSION
	$(error VERSION must be defined)
	$(error PREVIOUS_VERSION must be defined)
endif

# Set CATALOG_DEPLOY_NS= when running `make catalog-deploy` to override the default.
CATALOG_DEPLOY_NS ?= $(NAMESPACE)

BUNDLE_CSV_FILE=bundle/manifests/compliance-operator.clusterserviceversion.yaml
DEFAULT_OPERATOR_IMAGE=$(DEFAULT_REPO)/$(APP_NAME):$(DEFAULT_TAG)

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m \t%s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: clean
clean: clean-modcache clean-cache clean-output clean-test clean-kustomize clean-tools ## Run all of the clean targets.

.PHONY: clean-output
clean-output: ## Remove the operator bin.
	rm -f $(TARGET_OPERATOR)

.PHONY: clean-tools
clean-tools: ## Remove the locally built tools
	rm -f $(TOOLS_DIR)/*

.PHONY: clean-cache
clean-cache: ## Run go clean -cache -testcache.
	$(GO) clean -cache -testcache $(PKGS)

.PHONY: clean-modcache
clean-modcache: ## Run go clean -modcache.
	$(GO) clean -modcache $(PKGS)

.PHONY: clean-test
clean-test: clean-cache ## Clean up test cache and test setup artifacts.
	rm -rf $(TEST_SETUP_DIR)

.PHONY: clean-kustomize
clean-kustomize: ## Reset kustomize changes in the repo.
	@git restore bundle/manifests/compliance-operator.clusterserviceversion.yaml config/manager/kustomization.yaml

.PHONY: simplify
simplify: ## Run go fmt -s against code.
	@gofmt -s -l -w $(SRC)

fmt: ## Run go fmt against code.
	$(GO) fmt ./...

vet: ## Run go vet against code.
	$(GO) vet $(PKGS)

.PHONY: verify
verify: vet gosec ## Run vet and gosec checks.

.PHONY: gosec
gosec: ## Run gosec against code.
	@$(GO) run github.com/securego/gosec/v2/cmd/gosec -severity medium -confidence medium -quiet $(PKGS)

CONTROLLER_GEN = $(shell pwd)/$(TOOLS_DIR)/controller-gen
.PHONY: controller-gen
controller-gen: ## Build controller-gen locally.
	$(call go-build-tool,./vendor/sigs.k8s.io/controller-tools/cmd/controller-gen)

KUSTOMIZE = $(shell pwd)/$(TOOLS_DIR)/kustomize
.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v4@v4)

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-install-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Installing $(2)" ;\
mkdir -p $(TOOLS_DIR) ;\
GOBIN=$(PROJECT_DIR)/$(TOOLS_DIR) GOFLAGS=-mod=mod go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

# Build a go module from a single argument, which is a file path to a go
# module. The module is built and output to the $(TOOLS_DIR) directory.
define go-build-tool
	mkdir -p $(TOOLS_DIR)
	go build -o $(TOOLS_DIR)/$(shell basename $(1)) $(1)
	@echo > /dev/null
endef

.PHONY: opm
OPM = ./$(TOOLS_DIR)/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(TOOLS_DIR) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v$(SDK_VERSION)/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

.PHONY: operator-sdk
SDK_BIN = ./$(TOOLS_DIR)/operator-sdk
operator-sdk: ## Download operator-sdk locally if necessary.
ifeq (,$(wildcard $(SDK_BIN)))
ifeq (,$(shell which operator-sdk 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(TOOLS_DIR) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(SDK_BIN) https://github.com/operator-framework/operator-sdk/releases/download/v$(SDK_VERSION)/operator-sdk_$${OS}_$${ARCH} ;\
	chmod +x $(SDK_BIN) ;\
	}
else
SDK_BIN = $(shell which operator-sdk)
endif
endif

##@ Generate

.PHONY: update-version-numbers
update-version-numbers: check-operator-version ## Set skip range and version numbers in manifests.
	sed -i "s/\(^  version: \).*/\1$(VERSION)/" config/manifests/bases/compliance-operator.clusterserviceversion.yaml
	sed -i "s/\(^  replaces: compliance-operator.v\).*/\1$(PREVIOUS_VERSION)/" config/manifests/bases/compliance-operator.clusterserviceversion.yaml
	sed -i "s/\(olm.skipRange: '>=.*\)<.*'/\1<$(VERSION)'/" config/manifests/bases/compliance-operator.clusterserviceversion.yaml
	sed -i "s/\(\"name\": \"compliance-operator.v\).*\"/\1$(VERSION)\"/" catalog/preamble.json
	sed -i "s/\(\"skipRange\": \">=.*\)<.*\"/\1<$(VERSION)\"/" catalog/preamble.json
	sed -i "s/\(^[[:space:]]*version=\).*/\1$(VERSION)/" images/must-gather/Containerfile
	sed -i "s/\(^[[:space:]]*version=\).*/\1$(VERSION)/" images/openscap/Containerfile
	sed -i "s/\(^[[:space:]]*version=\).*/\1$(VERSION)/" images/operator/Dockerfile
	sed -i "s/\(^ARG CO_NEW_VERSION=\).*/\1\"$(VERSION)\"/" bundle.openshift.Dockerfile

.PHONY: verify-version-consistency
verify-version-consistency: ## Verify that all container version labels are consistent.
	@echo "Checking version consistency across container files..."
	@MUST_GATHER_VER=$$(grep -E '^[[:space:]]*version=' images/must-gather/Containerfile | sed 's/^[[:space:]]*version=//'); \
	OPENSCAP_VER=$$(grep -E '^[[:space:]]*version=' images/openscap/Containerfile | sed 's/^[[:space:]]*version=//'); \
	OPERATOR_VER=$$(grep -E '^[[:space:]]*version=' images/operator/Dockerfile | sed 's/^[[:space:]]*version=//'); \
	BUNDLE_VER=$$(grep '^ARG CO_NEW_VERSION=' bundle.openshift.Dockerfile | sed 's/^ARG CO_NEW_VERSION=//' | tr -d '"'); \
	echo "  must-gather: $$MUST_GATHER_VER"; \
	echo "  openscap:    $$OPENSCAP_VER"; \
	echo "  operator:    $$OPERATOR_VER"; \
	echo "  bundle:      $$BUNDLE_VER"; \
	if [ "$$MUST_GATHER_VER" = "$$OPENSCAP_VER" ] && [ "$$OPENSCAP_VER" = "$$OPERATOR_VER" ] && [ "$$OPERATOR_VER" = "$$BUNDLE_VER" ]; then \
		echo "✓ All versions are consistent: $$OPERATOR_VER"; \
	else \
		echo "✗ Version mismatch detected!"; \
		exit 1; \
	fi

.PHONY: namespace
namespace: ## Create the default namespace for the operator (e.g., openshift-compliance).
	@oc apply -f config/ns/ns.yaml

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=$(ROLE) crd webhook paths=./pkg/apis/compliance/v1alpha1 output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths=./pkg/apis/compliance/v1alpha1


##@ Build

.PHONY: all
all: images images-extra  ## Builds the operator, bundle, and extra images.

.PHONY: image
image: ## Build the operator image.
	$(RUNTIME) $(RUNTIME_BUILD_CMD) -f build/Dockerfile -t ${IMG} .

.PHONY: images
images: image bundle-image  ## Build operator and bundle images.

.PHONY: images-extra
images-extra: openscap-image e2e-content-images  ## Build the openscap and test content images.

.PHONY: build
build: generate fmt vet test-unit ## Build the operator binary.
	$(GO) build \
		-trimpath \
		-ldflags=-buildid= \
		-o $(TARGET_OPERATOR) $(BUILD_FLAGS) $(MAIN_PKG)

.PHONY: manager
manager: build  ## Alias for make build.

.PHONY: verify-bundle
verify-bundle: bundle verify-version-consistency ## Verify the bundle doesn't alter the state of the tree
	hack/tree-status

.PHONY: bundle
bundle: check-operator-version operator-sdk manifests update-version-numbers kustomize ## Generate bundle manifests and metadata, then validate generated files.
	$(SDK_BIN) generate kustomize manifests --apis-dir=./pkg/apis -q
	@echo "kustomize using deployment image $(IMG)"
	cd config/manager && $(KUSTOMIZE) edit set image $(APP_NAME)=$(IMG)
	if [ $(PLATFORM) = "openshift" ]; then \
		sed -i 's%../default-bundle%../openshift-bundle%' config/manifests/kustomization.yaml; \
	fi
	$(KUSTOMIZE) build config/manifests | $(SDK_BIN) generate bundle -q $(BUNDLE_SA_OPTS) --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)
	git restore config/manifests/kustomization.yaml
	@echo "Replacing RELATED_IMAGE_OPERATOR env reference in $(BUNDLE_CSV_FILE)"
	@sed -i 's%$(DEFAULT_OPERATOR_IMAGE)%$(OPERATOR_IMAGE)%' $(BUNDLE_CSV_FILE)
	@echo "Replacing RELATED_IMAGE_OPENSCAP env reference in $(BUNDLE_CSV_FILE)"
	@sed -i 's%$(DEFAULT_OPENSCAP_IMAGE)%$(OPENSCAP_IMAGE)%' $(BUNDLE_CSV_FILE)
	$(SDK_BIN) bundle validate ./bundle

.PHONY: bundle-image
bundle-image: bundle ## Build the bundle image.
	$(RUNTIME) $(RUNTIME_BUILD_CMD) -f bundle.Dockerfile -t $(BUNDLE_IMG) .
	@echo "Restoring RELATED_IMAGE_OPERATOR env reference in $(BUNDLE_CSV_FILE)"
	@sed -i 's%$(OPERATOR_IMAGE)%$(DEFAULT_OPERATOR_IMAGE)%' $(BUNDLE_CSV_FILE)
	@echo "Restoring RELATED_IMAGE_OPENSCAP env reference in $(BUNDLE_CSV_FILE)"
	@sed -i 's%$(OPENSCAP_IMAGE)%$(DEFAULT_OPENSCAP_IMAGE)%' $(BUNDLE_CSV_FILE)

.PHONY: openscap-image
openscap-image:
	$(RUNTIME) $(RUNTIME_BUILD_CMD) $(RUNTIME_BUILD_OPTS) --no-cache -t $(OPENSCAP_IMAGE) -f $(OPENSCAP_DOCKER_FILE) .

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm render' to build a file-based catalog.
# For more information, see https://olm.operatorframework.io/docs/reference/file-based-catalogs/
.PHONY: catalog-image
catalog-image: opm ## Build a catalog image.
	$(eval TMP_DIR := $(shell mktemp -d))
	$(eval CATALOG_DOCKERFILE := $(TMP_DIR).Dockerfile)
	cp catalog/preamble.json $(TMP_DIR)/compliance-operator-catalog.json
	$(OPM) render $(BUNDLE_IMGS) >> $(TMP_DIR)/compliance-operator-catalog.json
	$(OPM) generate dockerfile $(TMP_DIR)
	$(RUNTIME) build -f $(CATALOG_DOCKERFILE) -t $(CATALOG_IMG)
	rm -rf $(TMP_DIR) $(CATALOG_DOCKERFILE)
# Generate the catalog dockerfile and the catalog json file
# This is mainly used for github workflows to build the catalog image
.PHONY: catalog-docker
catalog-docker: opm ## Prepare the catalog dockerfile and the catalog json file.
	$(eval CATALOG_DIR := catalog)
	$(eval CATALOG_DOCKERFILE := $(CATALOG_DIR).Dockerfile)
	rm -f $(CATALOG_DIR).Dockerfile
	rm -f $(CATALOG_DIR)/compliance-operator-catalog.json
	mv catalog/preamble.json $(CATALOG_DIR)/compliance-operator-catalog.json
	$(OPM) render $(BUNDLE_IMGS) >> $(CATALOG_DIR)/compliance-operator-catalog.json
	$(OPM) generate dockerfile $(CATALOG_DIR)

.PHONY: catalog
catalog: catalog-image catalog-push ## Build and push a catalog image.

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	$(GO) run ./$(MAIN_PKG)


##@ Deploy

ifndef ignore-not-found
  ignore-not-found = true
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f - 

.PHONY: uninstall
uninstall: kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize install ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image $(APP_NAME)=${IMG}
	$(KUSTOMIZE) build config/default | sed -e 's%$(DEFAULT_OPERATOR_IMAGE)%$(OPERATOR_IMAGE)%' -e 's%$(DEFAULT_CONTENT_IMAGE)%$(CONTENT_IMAGE)%' | kubectl apply -f -

.PHONY: deploy-local
deploy-local: manifests kustomize image-to-cluster install  ## Deploy after pushing images to the cluster registry.
	cd config/manager && $(KUSTOMIZE) edit set image $(APP_NAME)=${OPERATOR_IMAGE}
	$(KUSTOMIZE) build config/$(PLATFORM) | sed -e 's%$(DEFAULT_OPERATOR_IMAGE)%$(OPERATOR_IMAGE)%' -e 's%$(DEFAULT_CONTENT_IMAGE)%$(CONTENT_IMAGE)%' -e 's%$(DEFAULT_OPENSCAP_IMAGE)%$(OPENSCAP_IMAGE)%' | kubectl apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/no-ns | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: tear-down
tear-down: uninstall undeploy ## Run undeploy and uninstall targets.

.PHONY: catalog-deploy
catalog-deploy: namespace ## Deploy from the config/catalog sources.
	@echo "Replacing image reference in $(CATALOG_SRC_FILE)"
	@sed -i 's%$(DEFAULT_CATALOG_IMG)%$(CATALOG_IMG)%' $(CATALOG_SRC_FILE)
	@oc apply -f $(CATALOG_SRC_FILE)
	@echo "Restoring image reference in $(CATALOG_SRC_FILE)"
	@sed -i 's%$(CATALOG_IMG)%$(DEFAULT_CATALOG_IMG)%' $(CATALOG_SRC_FILE)
	@echo "Replacing namespace reference in $(CATALOG_GROUP_FILE)"
	@sed -i 's%$(NAMESPACE)%$(CATALOG_DEPLOY_NS)%' $(CATALOG_GROUP_FILE)
	@oc apply -f $(CATALOG_GROUP_FILE)
	@echo "Restoring namespace reference in $(CATALOG_GROUP_FILE)"
	@sed -i 's%$(CATALOG_DEPLOY_NS)%$(NAMESPACE)%' $(CATALOG_GROUP_FILE)
	@echo "Replacing namespace reference in $(CATALOG_SUB_FILE)"
	@sed -i 's%$(NAMESPACE)%$(CATALOG_DEPLOY_NS)%' $(CATALOG_SUB_FILE)
	@oc apply -f $(CATALOG_SUB_FILE)
	@echo "Restoring namespace reference in $(CATALOG_SUB_FILE)"
	@sed -i 's%$(CATALOG_DEPLOY_NS)%$(NAMESPACE)%' $(CATALOG_SUB_FILE)

.PHONY: catalog-undeploy
catalog-undeploy: undeploy
	@echo "Replacing namespace reference in $(CATALOG_GROUP_FILE)"
	@sed -i 's%$(NAMESPACE)%$(CATALOG_DEPLOY_NS)%' $(CATALOG_GROUP_FILE)
	@echo "Replacing namespace reference in $(CATALOG_SUB_FILE)"
	@sed -i 's%$(NAMESPACE)%$(CATALOG_DEPLOY_NS)%' $(CATALOG_SUB_FILE)
	@oc delete --ignore-not-found=true -f $(CATALOG_DIR)/
	@echo "Restoring namespace reference in $(CATALOG_GROUP_FILE)"
	@sed -i 's%$(CATALOG_DEPLOY_NS)%$(NAMESPACE)%' $(CATALOG_GROUP_FILE)
	@echo "Restoring namespace reference in $(CATALOG_SUB_FILE)"
	@sed -i 's%$(CATALOG_DEPLOY_NS)%$(NAMESPACE)%' $(CATALOG_SUB_FILE)
	@oc delete --ignore-not-found=true csv -n $(CATALOG_DEPLOY_NS) --all

##@ Push

.PHONY: push
push: image-push bundle-push ## Push the operator and bundle images.

image-push: ## Push the operator image.
	$(RUNTIME) push ${IMG}

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) image-push IMG=$(BUNDLE_IMG)

.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) image-push IMG=$(CATALOG_IMG)


##@ Testing

.PHONY: test-unit
test-unit: fmt ## Run the unit tests
ifndef JUNITFILE
	@$(GO) test $(TEST_OPTIONS) $(PKGS)
else
	@set -o pipefail; $(GO) test $(TEST_OPTIONS) -json $(PKGS) --ginkgo.noColor | gotest2junit -v > $(JUNITFILE)
endif

.PHONY: test-coverage
test-coverage: fmt ## Run the unit tests and generate a coverage report
	@$(GO) test -cover -coverprofile=coverage.out $(PKGS)
	@$(GO) tool cover -func coverage.out

.PHONY: test-benchmark
test-benchmark: ## Run the benchmark tests -- Note that this can only be ran for one package. You can set $BENCHMARK_PKG for this. cpu.prof and mem.prof will be generated
	@$(GO) test -cpuprofile cpu.prof -memprofile mem.prof -bench . $(TEST_OPTIONS) $(BENCHMARK_PKG)
	@echo "The pprof files generated are: cpu.prof and mem.prof"

.PHONY: test-datastreams
test-datastreams:
ifndef DEFAULT_CONTENT_DS_FILE_PATH
	$(error DEFAULT_CONTENT_DS_FILE_PATH is not set)
endif
	@echo "Testing all XCCDF files in $(DEFAULT_CONTENT_DS_FILE_PATH)"
	@$(GO) test -v ./pkg/utils/ -ginkgo.v

.PHONY: e2e
e2e: e2e-set-image prep-e2e e2e-parallel e2e-test-wait e2e-serial ## Run full end-to-end tests that exercise content on an operational cluster.

.PHONY: e2e
e2e-test-wait:
	./utils/e2e-test-wait.sh

.PHONY: e2e-parallel
e2e-parallel: e2e-set-image prep-e2e ## Run non-destructive end-to-end tests concurrently.
	@CONTENT_IMAGE=$(E2E_CONTENT_IMAGE_PATH) BROKEN_CONTENT_IMAGE=$(E2E_BROKEN_CONTENT_IMAGE_PATH) $(GO) test ./tests/e2e/parallel $(E2E_GO_TEST_FLAGS) -args $(E2E_ARGS) | tee tests/e2e-test.log

.PHONY: e2e-serial
e2e-serial: e2e-set-image prep-e2e ## Run destructive end-to-end tests serially.
	@CONTENT_IMAGE=$(E2E_CONTENT_IMAGE_PATH) BROKEN_CONTENT_IMAGE=$(E2E_BROKEN_CONTENT_IMAGE_PATH) $(GO) test ./tests/e2e/serial $(E2E_GO_TEST_FLAGS) -args $(E2E_ARGS) | tee tests/e2e-test.log

## Convert --platform to using $PLATFORM if we make this target more generic
## for other offerings.
.PHONY: e2e-rosa
e2e-rosa: e2e-set-image prep-e2e ## Run tests against managed ROSA environment concurrently
	@$(GO) test ./tests/e2e/rosa $(E2E_GO_TEST_FLAGS) -args $(E2E_ARGS) --platform rosa | tee tests/e2e-test.log

.PHONY: prep-e2e
prep-e2e: kustomize
	rm -rf $(TEST_SETUP_DIR)
	mkdir -p $(TEST_SETUP_DIR)
	$(KUSTOMIZE) build config/no-ns | sed -e 's%$(DEFAULT_OPERATOR_IMAGE)%$(OPERATOR_IMAGE)%' -e 's%$(DEFAULT_CONTENT_IMAGE)%$(E2E_CONTENT_IMAGE_PATH)%' -e 's%$(DEFAULT_OPENSCAP_IMAGE)%$(OPENSCAP_IMAGE)%'  > $(TEST_DEPLOY)
	$(KUSTOMIZE) build config/crd > $(TEST_CRD)

ifdef IMAGE_FROM_CI
e2e-set-image: kustomize
	cd config/manager && $(KUSTOMIZE) edit set image $(APP_NAME)=$(IMAGE_FROM_CI)
	$(eval OPERATOR_IMAGE = $(IMAGE_FROM_CI))
else
e2e-set-image: kustomize
	cd config/manager && $(KUSTOMIZE) edit set image $(APP_NAME)=$(IMG)
endif

.PHONY: e2e-cluster
e2e-cluster: image-to-cluster e2e  ## Builds and pushes the operator and openscap images to the cluster registry, and starts an e2e test suite against the cluster images.

.PHONY: image-to-cluster
image-to-cluster: image openscap-image namespace openshift-user  ## Builds and pushes the operator and openscap images to the cluster registry.
	@echo "Temporarily exposing the default route to the image registry"
	@oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{"spec":{"defaultRoute":true}}' --type=merge
	@echo "Pushing image $(OPERATOR_IMAGE) to the image registry"
	IMAGE_REGISTRY_HOST=$$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}'); \
		$(RUNTIME) login $(LOGIN_PUSH_OPTS) -u $(OPENSHIFT_USER) -p $(shell oc whoami -t) $${IMAGE_REGISTRY_HOST}; \
		$(RUNTIME) push $(LOGIN_PUSH_OPTS) $(OPERATOR_IMAGE) $${IMAGE_REGISTRY_HOST}/openshift/$(APP_NAME):$(TAG); \
		$(RUNTIME) push $(LOGIN_PUSH_OPTS) $(OPENSCAP_IMAGE) $${IMAGE_REGISTRY_HOST}/openshift/$(OPENSCAP_NAME):$(OPENSCAP_TAG)
	@echo "Removing the route from the image registry"
	@oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{"spec":{"defaultRoute":false}}' --type=merge
	$(eval OPERATOR_IMAGE = image-registry.openshift-image-registry.svc:5000/openshift/$(APP_NAME):$(TAG))
	$(eval IMG = image-registry.openshift-image-registry.svc:5000/openshift/$(APP_NAME):$(TAG))
	$(eval OPENSCAP_IMAGE = image-registry.openshift-image-registry.svc:5000/openshift/$(OPENSCAP_NAME):$(OPENSCAP_TAG))

.PHONY: e2e-content-images
e2e-content-images:  ## Build the e2e-content-image
	RUNTIME=$(RUNTIME) images/testcontent/broken-content.sh build ${E2E_BROKEN_CONTENT_IMAGE_PATH}

.PHONY: push-e2e-content
push-e2e-content: e2e-content-images  ## Build and push the e2e-content-images
	RUNTIME=$(RUNTIME) images/testcontent/broken-content.sh push ${E2E_BROKEN_CONTENT_IMAGE_PATH}

.PHONY: must-gather-image
must-gather-image:  ## Build the must-gather image
	$(RUNTIME) build -t $(MUST_GATHER_IMAGE_PATH):$(MUST_GATHER_IMAGE_TAG) -f images/must-gather/Dockerfile.ocp .

.PHONY: must-gather-push
must-gather-push: must-gather-image
	$(RUNTIME) push $(MUST_GATHER_IMAGE_PATH):$(MUST_GATHER_IMAGE_TAG)

.PHONY: must-gather
must-gather: must-gather-image must-gather-push  ## Build and push the must-gather image

##@ Release

.PHONY: package-version-to-tag
package-version-to-tag: check-operator-version ## Explicitly override $TAG with $VERSION. This is a useful utility for other release targets.
	@echo "Overriding default tag '$(TAG)' with release tag '$(VERSION)'"
	$(eval TAG = $(VERSION))

.PHONY: git-release
git-release: fetch-git-tags package-version-to-tag changelog ## Update project files with new version information.
	git checkout -b "release-v$(TAG)"
	sed -i "s/\(replaces: \).*/\1$(APP_NAME).$(PREVIOUS_VERSION)/" $(BUNDLE_CSV_FILE)
	sed -i "s/\(.*Version = \"\).*/\1$(TAG)\"/" version/version.go
	sed -i "s/\(.*VERSION?=\).*/\1$(TAG)/" version.Makefile
	git add version* bundle CHANGELOG.md config/manifests/bases
	git add "config/helm/Chart.yaml"
	git add "catalog/preamble.json"
	git restore config/manager/kustomization.yaml

.PHONY: fetch-git-tags
fetch-git-tags: ## Fetch tags for the repository. This is a useful utility for other release targets.
	# Make sure we are caught up with tags
	git fetch -t

.PHONY: prepare-release
prepare-release: set-current-version package-version-to-tag images git-release ## Make local changes to release a new version of the operator. Changes are staged locally for review.

.PHONY: push-release
push-release: package-version-to-tag ## Create a commit for the release change, tag the new version, and push the change for review using a dedicated release branch. Requires a ComplianceAsCode/compliance-operator maintainer.
	git commit -m "Release v$(TAG)"
	git tag "v$(TAG)"
	git push $(GIT_REMOTE) "v$(TAG)"
	git push $(GIT_REMOTE) "release-v$(TAG)"
	git checkout ocp-1.0
	git merge "release-v$(TAG)"
	git push $(GIT_REMOTE) ocp-1.0

.PHONY: release-images
release-images: package-version-to-tag push catalog ## Build container images, bundle images, and catalog images and push them to an image registry (default: ghcr.io/complianceascode).
	$(RUNTIME) image tag $(OPERATOR_IMAGE) $(OPERATOR_TAG_BASE):latest
	$(RUNTIME) image tag $(BUNDLE_IMG) $(BUNDLE_TAG_BASE):latest
	$(RUNTIME) image tag $(CATALOG_IMG) $(CATALOG_TAG_BASE):latest
	# This will ensure that we also push to the latest tag
	$(MAKE) push TAG=latest
	$(MAKE) catalog-push TAG=latest

.PHONY: changelog
changelog: ## Move all unreleased notes in the CHANGELOG to a section dedicated to $TAG. This is a useful utility for other release targets.
	@utils/update_changelog.sh "$(TAG)"

.PHONY: set-current-version
set-current-version:
	@echo "Using $(PREVIOUS_VERSION) as previous version"
