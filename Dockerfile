FROM node:26.10.0-slim

# The C++ witness generator builds with g++, gmp, nlohmann-json and nasm
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip build-essential libgmp-dev nlohmann-json3-dev nasm \
    && rm -rf /var/lib/apt/lists/*

ARG CIRCOM_VERSION=v2.2.3
RUN curl -fsSL -o /usr/local/bin/circom \
    https://github.com/iden3/circom/releases/download/${CIRCOM_VERSION}/circom-linux-amd64 \
    && chmod +x /usr/local/bin/circom \
    && circom --version

# rapidsnark's release binary needs the libstdc++ of Debian trixie or later
ARG RAPIDSNARK_VERSION=v0.0.8
RUN curl -fsSL -o /tmp/rapidsnark.zip \
    https://github.com/iden3/rapidsnark/releases/download/${RAPIDSNARK_VERSION}/rapidsnark-linux-x86_64-${RAPIDSNARK_VERSION}.zip \
    && unzip -p /tmp/rapidsnark.zip rapidsnark-linux-x86_64-${RAPIDSNARK_VERSION}/bin/prover > /usr/local/bin/rapidsnark \
    && chmod +x /usr/local/bin/rapidsnark \
    && rm /tmp/rapidsnark.zip

WORKDIR /work
