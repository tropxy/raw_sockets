FROM rust:latest

WORKDIR /usr/src/app

RUN apt update -y && apt upgrade -y -qq && apt install -y -qq build-essential gcc-arm-linux-gnueabihf tcpdump net-tools
RUN rustup target add armv7-unknown-linux-gnueabihf

RUN dpkg --add-architecture armhf && \
    apt update && apt install --assume-yes \
      libssl-dev:armhf \
      libasound2-dev:armhf \
      libdbus-1-dev:armhf \
      libsystemd-dev:armhf

ENV PKG_CONFIG_LIBDIR=/usr/lib/arm-linux-gnueabihf/pkgconfig

# generate hello world
ENV USER root
ENV PATH $PATH:/usr/src/app/.cargo/bin

COPY Cargo.toml .
COPY src/ src/


CMD ["sleep", "infinity"]
