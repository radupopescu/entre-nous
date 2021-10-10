# Dockerfile for creating a statically-linked Rust application using docker's
# multi-stage build feature. This also leverages the docker build cache to avoid
# re-downloading dependencies if they have not changed.
FROM rust:1.55.0-slim AS build

# Download the target for static linking.
RUN rustup target add x86_64-unknown-linux-musl

RUN apt-get update && apt-get install -y \
    musl-tools \
    file \
    make

# Create a dummy project and build the app's dependencies.
# If the Cargo.toml or Cargo.lock files have not changed,
# we can use the docker build cache and skip these (typically slow) steps.
WORKDIR /usr/src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
RUN cargo install --features web --target x86_64-unknown-linux-musl --path .

# Copy the statically-linked binary into a scratch container.
FROM scratch
COPY --from=build /usr/local/cargo/bin/server ./entre-nous-server
USER 1000
CMD ["./entre-nous-server"]