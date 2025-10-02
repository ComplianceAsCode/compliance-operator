# Step one: build compliance-operator
FROM golang:1.23 AS builder

WORKDIR /go/src/github.com/openshift/compliance-operator

ENV GOFLAGS=-mod=vendor

COPY . . 
RUN make manager

# Step two: containerize compliance-operator
FROM registry.access.redhat.com/ubi9/ubi-micro:latest

ENV OPERATOR=/usr/local/bin/compliance-operator

# install operator binary
COPY --from=builder /go/src/github.com/openshift/compliance-operator/build/_output/bin/compliance-operator ${OPERATOR}

COPY build/bin/entrypoint /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER 1001
