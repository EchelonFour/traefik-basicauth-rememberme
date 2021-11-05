FROM rust:1.55 as builder
WORKDIR /usr/src/traefik-basicauth-rememberme
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
RUN DEBIAN_FRONTEND="noninteractive" apt-get update && apt-get install -y dumb-init tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/traefik-basicauth-rememberme /usr/local/bin/traefik-basicauth-rememberme
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["traefik-basicauth-rememberme"]
EXPOSE 80
ENV RUN_MODE=production
