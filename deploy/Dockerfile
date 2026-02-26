# Stage 1: Build custom Caddy with rate limiting module
FROM golang:1.23-alpine AS caddy-builder
WORKDIR /build
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN xcaddy build --with github.com/mholt/caddy-ratelimit
# Binary output: /build/caddy

# Stage 2: Build frontend
FROM node:24-slim AS frontend-builder
RUN corepack enable
WORKDIR /build
COPY frontend/package.json frontend/pnpm-lock.yaml ./frontend/
RUN cd frontend && pnpm install --frozen-lockfile
COPY frontend/ ./frontend/
RUN cd frontend && pnpm build
# Inject Caddy template directive for subpath base path
RUN sed -i 's|<head>|<head>\n  <base href="{{ .Req.Header.Get "X-Base-Path" }}">|' ./frontend/dist/index.html

# Stage 3: Build C++ backend
FROM ubuntu:24.04 AS cpp-builder
ENV DEBIAN_FRONTEND=noninteractive

# Install build tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    libssl-dev \
    libcurl4-openssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install vcpkg
ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone --depth 1 https://github.com/microsoft/vcpkg.git $VCPKG_ROOT \
    && $VCPKG_ROOT/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /build

# Copy vcpkg manifest and install dependencies first (layer caching)
COPY vcpkg.json ./
RUN $VCPKG_ROOT/vcpkg install --triplet x64-linux

# Copy source and build
COPY CMakeLists.txt ./
COPY src/ ./src/
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    && cmake --build build
# Binary output: /build/build/cpp-text-to-speech

# Stage 4: Runtime
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libcurl4 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy custom Caddy binary
COPY --from=caddy-builder /build/caddy /usr/bin/caddy

WORKDIR /app

# Copy C++ binary
COPY --from=cpp-builder /build/build/cpp-text-to-speech ./cpp-text-to-speech

# Copy config files
COPY deepgram.toml sample.env ./

# Copy built frontend
COPY --from=frontend-builder /build/frontend/dist/ ./frontend/dist/

# Copy shared deployment files
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY deploy/start.sh ./start.sh
RUN chmod +x ./start.sh

ENV PORT=8081
ENV HOST=0.0.0.0
EXPOSE 8080

ENV BACKEND_CMD="./cpp-text-to-speech"
CMD ["./start.sh"]
