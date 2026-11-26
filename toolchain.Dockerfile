ARG RUST_IMAGE=docker.io/library/rust:1.100.0-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2

FROM ${RUST_IMAGE} AS tools

RUN apt-get update \
    && apt-get install --yes --no-install-recommends make \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_INSTALL_ROOT=/opt/tools
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-nextest@0.9.151
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-deny@0.20.2
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-vet@0.10.3
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-fuzz@0.13.2
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-mutants@27.1.0
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-llvm-cov@0.9.1
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked hyperfine@2.0.0
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked gungraun-runner@0.20.0
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked zizmor@1.32.0

FROM ${RUST_IMAGE}

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        g++=4:14.2.0-1 \
        git \
        valgrind=1:3.24.0-3 \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

RUN rustup component add --toolchain 1.100.0 clippy rustfmt llvm-tools

COPY rust-toolchain-nightly /etc/debar/rust-toolchain-nightly
RUN nightly="$(cat /etc/debar/rust-toolchain-nightly)" \
    && rustup toolchain install "$nightly" --profile minimal \
        --component miri,rust-src,llvm-tools \
    && rm -rf /usr/local/rustup/downloads /usr/local/rustup/tmp

COPY --from=tools /opt/tools/bin/ /usr/local/bin/

WORKDIR /work
