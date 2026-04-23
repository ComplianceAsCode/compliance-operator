# Step one: build compliance-operator
FROM golang:1.25.8 AS builder

WORKDIR /go/src/github.com/openshift/compliance-operator

ENV GOFLAGS=-mod=vendor

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

# Step two: containerize compliance-operator
FROM registry.access.redhat.com/ubi9/ubi-micro:latest

ENV OPERATOR=/usr/local/bin/compliance-operator

# install operator binary
COPY --from=builder /go/src/github.com/openshift/compliance-operator/build/_output/bin/compliance-operator ${OPERATOR}

COPY build/bin/entrypoint /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER 1001
