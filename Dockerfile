# The mlsbond image: mlsbond-server and mlsbond-client in one image. It runs the server by default;
# a client's pod names mlsbond-client as its command. Both base images can be replaced, for example
# with a registry's mirror, through --build-arg.
ARG BUILDER_IMAGE=docker.io/library/rust:1.95-trixie
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot

FROM ${BUILDER_IMAGE} AS builder
WORKDIR /src
# the Rust build brings its own protoc (build.rs), so the builder needs nothing else
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto/ proto/
COPY src/ src/
RUN cargo build --release --locked \
	&& install -D -t /out target/release/mlsbond-server target/release/mlsbond-client

# glibc and libgcc only: the cryptography is Rust (openmls_rust_crypto), no OpenSSL
FROM ${RUNTIME_IMAGE}
COPY --from=builder /out/ /usr/local/bin/
USER 65532:65532
# the delivery stream (server) and the client API (client); the server's admin API stays on loopback
EXPOSE 4750 4752
ENTRYPOINT []
CMD ["mlsbond-server"]
