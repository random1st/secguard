FROM rust:1.94-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends clang libclang-dev cmake && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p secguard-server --features ml && \
    strip target/release/secguard-server

FROM debian:bookworm-slim
# libgomp1: OpenMP runtime — llama.cpp (via llama-cpp-2) links against it
# dynamically. Without it the secguard-server binary built with
# `--features ml` fails on launch with
# `error while loading shared libraries: libgomp.so.1`. v0.4.1 hit
# exactly this — workflow built and pushed cleanly, but the image
# wouldn't start. ca-certificates stays for outbound TLS (HF model
# downloads, telemetry, etc).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /usr/sbin/nologin -d /var/lib/secguard secguard && \
    mkdir -p /var/lib/secguard/.secguard/models && \
    chown -R secguard:secguard /var/lib/secguard
COPY --from=builder /src/target/release/secguard-server /usr/local/bin/secguard-server

# OCI labels — `image.source` is what GitHub uses to auto-link a GHCR package
# to its source repository. Without this link the workflow's GITHUB_TOKEN
# cannot push to a pre-existing org-owned package, which is what bit us on
# the v0.4.0 release.
LABEL org.opencontainers.image.source="https://github.com/diana-random1st/secguard"
LABEL org.opencontainers.image.description="Security guard HTTP service for AI agent hooks (Claude Code, Codex, Gemini CLI, MCP)."
LABEL org.opencontainers.image.licenses="Apache-2.0"

EXPOSE 8080
ENV RUST_LOG=info
ENV HOME=/var/lib/secguard
USER secguard
ENTRYPOINT ["secguard-server"]
CMD ["--port", "8080"]
