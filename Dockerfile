FROM rust:alpine as builder

# Dependencies for some crates and AWS CLI to simplify downloading files from S3
RUN apk add --no-cache alpine-sdk openssl-dev openssl-libs-static aws-cli

WORKDIR /usr/src/app

# First build a dummy target to cache dependencies in a separate Docker layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() { println!("Dummy image called!"); }' > src/main.rs
RUN cargo build --release

# Now build the real target
COPY src ./src
COPY proto ./proto
COPY build.rs .
# Update modified attribute as otherwise cargo won't rebuild it
RUN touch -a -m ./src/main.rs
RUN cargo build --release

FROM alpine as runtime
COPY --from=builder /usr/src/app/target/release/valhalla-gatling /usr/local/bin/valhalla-gatling
# CMD ["valhalla-gatling"]
# Do nothing, just keep the container running
CMD ["tail", "-f", "/dev/null"]
