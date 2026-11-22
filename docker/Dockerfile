FROM --platform=linux/arm64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    CLANG_BIN=/usr/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    bc \
    bison \
    ca-certificates \
    clang \
    cpio \
    curl \
    flex \
    git \
    libelf-dev \
    libssl-dev \
    lld \
    llvm \
    lz4 \
    make \
    python3 \
    xz-utils \
    zip \
    && rm -rf /var/lib/apt/lists/* \
    && clang --version | head -n 1 \
    && ld.lld --version | head -n 1

WORKDIR /workspace
COPY build-kernel-inner.sh /workspace/build-kernel-inner.sh
RUN chmod +x /workspace/build-kernel-inner.sh
