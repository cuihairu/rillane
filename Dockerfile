# Multi-stage build for minimal image
FROM rust:1.75 as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy cargo files
COPY Cargo.toml Cargo.lock ./
COPY seep-config/Cargo.toml ./seep-config/
COPY seep-core/Cargo.toml ./seep-core/
COPY seep-routing/Cargo.toml ./seep-routing/

# Create dummy source files to cache dependencies
RUN mkdir -p seep-config/src seep-core/src seep-routing/src
RUN echo "fn main() {}" > seep-config/src/main.rs
RUN echo "fn main() {}" > seep-core/src/main.rs
RUN echo "fn main() {}" > seep-routing/src/main.rs

# Build dependencies
RUN cargo build --release && rm -rf seep-config/src seep-core/src seep-routing/src

# Copy actual source code
COPY . .

# Build the application
RUN touch seep-config/src/main.rs seep-core/src/main.rs seep-routing/src/lib.rs
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false seep

# Copy binary from builder
COPY --from=builder /app/target/release/seep /usr/local/bin/seep

# Create directories
RUN mkdir -p /etc/seep /var/log/seep && \
    chown -R seep:seep /etc/seep /var/log/seep

# Switch to non-root user
USER seep

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD seep --version || exit 1

# Set entrypoint
ENTRYPOINT ["seep"]
CMD ["--config", "/etc/seep/config.yaml"]