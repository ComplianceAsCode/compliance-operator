# Contributor Guide

This guide provides useful information for contributors.

## Deploying Changes

You may want to test changes you made locally in a cluster. This requires you
to build new container images with the new changes and push them to the
cluster. This process is encapsulated in a Makefile target called
`deploy-local`.

Please note this process assumes you have not deployed the operator already. If
you have deployed the operator using packages, Helm, or from source, you will
need to uninstall the operator before deploying your local changes.

The `deploy-local` target needs API access to the cluster. You must
authenticate to the cluster before running `deploy-local` using `oc login`.

The following command will build images container local changes and push them
to the cluster:

```
$ make deploy-local
```

## Testing Changes

This repository contains unit and functional tests for the compliance-operator.
Both are invoked using Makefile targets.

### Unit Tests

Unit tests have no dependency on external systems, or a Kubernetes cluster. You
can run them using:

```console
$ make test-unit
```

### Coverage Tests

There is a separate target specifically for unit test coverage that outputs a
coverage report in `coverage.out`. It also provides a coverage summary.

```console
$ make test-coverage
```

### Functional Tests

The end-to-end tests for the compliance-operator require a Kubernetes
deployment. You can also change test and test setup behavior using environment
variables when invoking the tests.

For example, you can specify a container registry for content images using
`DEFAULT_CONTENT_IMAGE_PATH` and `E2E_CONTENT_IMAGE_PATH`. The default registry
for these container images is available on
[Quay](https://quay.io/repository/compliance-operator/compliance-operator-content).
The [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content/) is
built and published to compliance-operator/compliance-operator-content so that
we run end-to-end tests against the latest content images available from
ComplianceAsCode. The content is built using a
[Dockerfile](https://github.com/ComplianceAsCode/content/blob/master/Dockerfiles/ocp4_content)
maintained in the ComplianceAsCode/content repository. You may not have a
reason to change these values unless you want to test with different content
images.

```console
$ make e2e
```

You can run a single functional tests using the `E2E_GO_TEST_FLAGS`, but it
must contain the fully rendered test name, which you may have to build manually.

```console
$ E2E_GO_TEST_FLAGS="-v -run TestE2E/Parallel_tests/TestScanWithNodeSelectorFiltersCorrectly" make e2e
```

The first part of the test name is actually the test suite (`TestE2E`), which
is responsible for setting up and tearing down resources for all tests. The
second portion of the test name is either `Parallel_tests` or `Serial_tests`,
depending on the `IsParallel` attribute of the test. The final part of the test
name is the actual test name. Note that using `-run
TestScanWithNodeSelectorFiltersCorrectly` will not match when go invokes the tests.

## Writing Release Notes

Release notes are maintained in the [changelog](CHANGELOG.md) and follow
guidelines based on [keep a changelog](https://keepachangelog.com/en/1.0.0/).
This section describes additional guidelines, conventions, and the overall
process for writing release notes.

### Guidelines

* Each release should contain release notes
* Changes should be applicable to at least one of the six types listed below
* Use literals for code and configuration (e.g. `defaultScanSettingsSchedule`
  or `nodeSelector`)
* Write your notes with users as the audience
* Link to additional documentation
  - Bug fixes should link to bug reports (GitHub Issues or Jira items)
  - Features or enhancements should link to RFEs (GitHub Issues or Jira items)
* Use active voice
  - Active voice is more direct and concise than passive voice, perfect for
    release notes
  - Focus on telling the user how a change will affect them
  - Examples
    - *You can now adjust the frequency of your scans by...*
    - *The compliance-operator no longer supports...*

### Change Types

The following describe each potential section for a release changelog.

1. Enhancements
2. Fixes
3. Internal Changes
4. Deprecations
5. Removals
6. Security

*Enhancements* are reserved for communicating any new features or
functionality. You should include any new configuration or processes a user
needs to take to use the new feature.

*Fixes* are for noting improvements to any existing functionality.

*Internal Changes* are ideal for communicating refactors not exposed to end
users. Even if a change does not directly impact end users, it is still
important to highlight paying down technical debt and the rationale for those
changes, especially since they impact the project's roadmap.

*Deprecations* is for any functionality, feature, or configuration that is
being deprecated and staged for removal. Deprecations should include why we're
preparing to remove the functionality and signal any suitable replacements
users should adopt.

*Removals* is for any functionality, feature, or configuration that is being
removed. Typically, entries in this section will have been deprecated for some
period of time. The compliance-operator follows the
[Kubernetes deprecation policy](https://kubernetes.io/docs/reference/using-api/deprecation-policy/).

*Security* is reserved for communicating security fixes and remediations for
CVEs.

A change can apply to multiple change types. For example, a bug fix for a CVE
should be mentioned in the *Fixes* and *Security* sections.

### Process

Contributors must include a release note with their changes. New notes should
be added to the [Unreleased section](CHANGELOG.md#unreleased) of the
[changelog](CHANGELOG.md). Reviewers will assess the accuracy of the release
note against the change.

Maintainers preparing a new release will propose a change that renames the
[Unreleased release notes](CHANGELOG.md#unreleased) to the newly released
version and release date. Maintainers can remove empty sections if it does not
contain any release notes for a specific release.

Maintainers will remove the content of the [Unreleased section](CHANGELOG.md#unreleased)
to allow for new release notes for the next release.

Following this process makes it easier to maintain and release accurate release
notes without having to retroactively write release notes for merged changes.

### Examples

The following is an example release note for a feature with a security note.

```
## Unreleased
### Enhancements

- Allow configuring result servers using `nodeSelector` and `tolerations`
  ([RFE](https://github.com/openshift/compliance-operator/issues/696))
  - You can now specify which nodes to use for storing raw compliance results
    using the `nodeSelector` and `tolerations` from `ScanSettings`.
  - By default, raw results are stored on nodes labeled
    `node-role.kubernetes.io/master`.
  - Please refer to the upstream Kubernetes
    [documentation](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/)
    for details on how to use `nodeSelector` and `tolerations`.

### Security

- Allow configuring result servers using `nodeSelector` and `tolerations`
  ([RFE](https://github.com/openshift/compliance-operator/issues/696))
  - Raw compliance results may contain sensitive information about the
    deployment, its infrastructure, or applications. Make sure you send raw
    results to trusted nodes.
```

## Proposing Releases

The release process is separated into multiple phases, with dedicated `make`
targets. All targets require that you set the environment variable `VERSION` prior to
running `make`, which should be a semantic version formatted string (e.g.,
`VERSION=0.1.49`).

Additionally, before preparing an official release, it is important to remember
to unset the `IMAGE_REPO` and  `TAG` environment variables in your shell, if you
have been previously developing test images. This ensures that the release applies
to the correct upstream images.

### Understanding the Dual Release Workflow

The compliance-operator has **two separate release workflows** that produce different artifacts:

**Upstream Releases (GitHub → ghcr.io)**
- **Purpose**: Community users and upstream installations
- **Triggered by**: Git tags (v*)
- **Destination**: ghcr.io/complianceascode (GitHub Container Registry)
- **Bundle images**: Use quay.io Konflux images with SHA256 digests (deterministic, publicly accessible)
- **Process**: GitHub Actions builds bundle image from committed bundle/manifests in git

**Downstream Releases (Tekton → registry.redhat.io)**
- **Purpose**: Red Hat customers and downstream installations
- **Triggered by**: Changes to bundle/*** or bundle-hack/*** paths in any branch
- **Destination**: registry.redhat.io (Red Hat Container Registry)
- **Bundle images**: Use registry.redhat.io images (automatically copied from quay.io)
- **Process**: Tekton builds bundle using bundle.openshift.Dockerfile which regenerates the CSV with registry.redhat.io URLs

**Key distinction**: Upstream bundles use what's committed to git (quay.io images). Downstream bundles are regenerated during the Tekton build to replace quay.io → registry.redhat.io.

**Image naming conventions:**
- Master branch: Images have `-dev` suffix (e.g., compliance-operator-dev)
- Release branches: Images have `-release` suffix (e.g., compliance-operator-release)
- This is managed in bundle-hack/update_csv.go per branch

### Step 1: Update Konflux Image References

Before preparing the release, update the Konflux image references in
`bundle-hack/update_csv.go` with the latest SHA256 digests from the Konflux builds.
These digests will be used to pin images in the upstream manifests.

### Step 2: Pin Images for Upstream Release

**This step is for upstream GitHub releases only.** Downstream Tekton builds automatically
handle image registry replacement via bundle.openshift.Dockerfile and do not use these pinned manifests.

Pin the Konflux images with SHA256 digests in the upstream manifests by running:

```
make release-pin-images
```

This target:
- Extracts the latest Konflux image specs from `bundle-hack/update_csv.go`
- Pins them in `config/manager/deployment.yaml` with SHA256 digests (RELATED_IMAGE_* env vars)
- Pins them in `config/manager/kustomization.yaml`

This ensures that upstream users installing from GitHub releases get deterministic,
SHA-pinned quay.io images that match the exact images tested in Konflux CI.

**What gets committed to git:**
- config/manager/deployment.yaml with SHA-pinned quay.io images
- bundle/manifests/*.clusterserviceversion.yaml with SHA-pinned quay.io images (generated in Step 3)
- These files are used by GitHub Actions to build the ghcr.io bundle image

**Downstream workflow:** Tekton builds ignore these git files and regenerate the bundle
during the image build process, automatically replacing quay.io → registry.redhat.io.

### Step 3: Preparing the Release

Prepare the release locally by running the `make prepare-release` target. All changes are
staged locally. This is intentional so that you have the opportunity to
review the changes before proposing the release in the next step.

**Note:** The `prepare-release` target internally runs `make bundle`, which will
preserve the SHA-pinned images from the previous step.

### Step 4: Proposing the Release

Push the release to a dedicated branch against the origin repository using the `make
push-release` target.

Please note, this step makes changes to the upstream repository, so it is
imperative that you review the changes you're committing prior to this step.
This step also requires that you have necessary permissions on the repository.

### Step 5: Releasing Images

The final step of the release is to build new images and push them to
an official image registry. You can build new images and push using `make
release-images`. Note that this operation also requires you have proper
permissions on the remote registry.

### Purpose of `ocp-1.0` Branch

In order to fetch the source for OCP downstream pipeline, we have added a branch `ocp-1.0`,
this branch should be synced to the latest upstream release branch. The sync process has 
been included in `push-release` make target.
