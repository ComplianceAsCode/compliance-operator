FROM gitpod/workspace-full

# Install go
RUN rm -rf $HOME/go $HOME/go-packages

RUN echo "export GOPATH=/workspace/go" >> ~/.bashrc.d/300-go && \
    echo "export GOBIN=\$GOPATH/bin" >> ~/.bashrc.d/300-go && \
    echo "export GOROOT=${HOME}/go" >> ~/.bashrc.d/300-go && \
    echo "export PATH=\$GOROOT/bin:\$GOBIN:\$PATH" >> ~/.bashrc
RUN bash -c "source ~/.bashrc && source ~/.bashrc.d/300-go"

RUN export CUSTOM_GO_VERSION=$(curl -sSL "https://raw.githubusercontent.com/ComplianceAsCode/compliance-operator/master/go.mod" | awk '/^go/{print $2}') && \
    curl -fsSL "https://dl.google.com/go/go${CUSTOM_GO_VERSION}.linux-amd64.tar.gz" | \
    tar -xz -C $HOME

# Setup for content build https://github.com/ComplianceAsCode/content/.gitpod.Dockerfile
ENV PYTHONUSERBASE=/workspace/.pip-modules
ENV PATH=$PYTHONUSERBASE/bin:$PATH
ENV PIP_USER=yes
USER gitpod
RUN sudo apt-get update -q && \
        sudo apt-get install -yq \
        cmake \
        ninja-build \
        libxml2-utils \
        xsltproc \
        python3-jinja2 \
        python3-yaml \
        python3-setuptools \
        ansible-lint \
        python3-github \
        bats \
        python3-pytest \
        python3-pytest-cov \
        libdbus-1-dev libdbus-glib-1-dev libcurl4-openssl-dev \
        libgcrypt20-dev libselinux1-dev libxslt1-dev libgconf2-dev libacl1-dev libblkid-dev \
        libcap-dev libxml2-dev libldap2-dev libpcre3-dev python3-dev swig libxml-parser-perl \
        libxml-xpath-perl libperl-dev libbz2-dev librpm-dev g++ libapt-pkg-dev libyaml-dev \
        libxmlsec1-dev libxmlsec1-openssl \
        shellcheck \
        bats \
        yamllint

RUN wget https://github.com/OpenSCAP/openscap/releases/download/1.3.6/openscap-1.3.6.tar.gz

RUN tar -zxvf openscap-1.3.6.tar.gz

RUN cd openscap-1.3.6 && \
        mkdir -p build && cd build && \
        cmake -DCMAKE_INSTALL_PREFIX=/ .. && \
        sudo make install && \
        cd ../..

# Setup podman
RUN sudo apt-get install -y podman

RUN cp /usr/share/containers/containers.conf /etc/containers/storage.conf \
    # use vfs storage driver add the following line to /etc/containers/storage.conf
    # [storage]

    # # Default Storage Driver, Must be set for proper operation.
    # driver = "vfs"
    # rootless_storage_path = "$HOME/.local/share/containers/storage"
    echo "[storage]\n  driver = \"vfs\"\n  rootless_storage_path = \"$HOME/.local/share/containers/storage\"" | sudo tee -a /etc/containers/storage.conf

RUN sudo sed -i 's/^"net.ipv4.ping_group_range=0 0",/# "net.ipv4.ping_group_range=0 0",/' /etc/containers/storage.conf

# OC
ARG REPO_URL="https://github.com/okd-project/okd/releases/download"
ARG RELEASE_TAG="4.13.0-0.okd-2023-05-22-052007"

ARG RELEASE_PKG="openshift-client-linux-4.13.0-0.okd-2023-05-22-052007.tar.gz"
ARG INSTALL_URL="${REPO_URL}/${RELEASE_TAG}/${RELEASE_PKG}"
ARG TEMP_DIR="/tmp/openshift-client"
ARG TEMP_FILE="openshift-client-linux.tar.gz"
RUN bash -c "mkdir -p '${TEMP_DIR}' \
    && wget -nv -O '${TEMP_DIR}/${TEMP_FILE}' '${INSTALL_URL}' \
    && tar zxvf '${TEMP_DIR}/${TEMP_FILE}' -C '${TEMP_DIR}' \
    && sudo mv  '${TEMP_DIR}/oc' '/usr/local/bin/' \
    && sudo mv  '${TEMP_DIR}/kubectl' '/usr/local/bin/' \
    && rm '${TEMP_DIR}/${TEMP_FILE}' \
    && oc version --client \
    && kubectl version --client \
    " 
