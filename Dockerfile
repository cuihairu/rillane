# 多阶段构建（双层布局 crates/ + apps/）：
# - 依赖预热层 = 仅根清单 + 全部成员清单 + 虚拟源桩（不依赖 BuildKit cache mount，
#   旧版构建器亦可跑；成员清单枚举按根 Cargo.toml members 核对，新增成员需同步此处）
# - 基础镜像 rust:1-bookworm 滚动稳定（对齐 CI 其余 job 的 stable；MSRV 验证归
#   ci.yml 的 msrv job 独立覆盖——镜像构建目标是产物，不是 MSRV 验证）
# - 产物：rillaned（daemon，ENTRYPOINT）+ rillanectl（容器内运维/排障）
FROM rust:1-bookworm AS builder

# 构建依赖（ring/aws-lc 需的 perl/make/cc 基础镜像自带；此处补 pkg-config + openssl 头）
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- 依赖预热：只复制清单与锁文件，虚拟源桩占位（11 lib 桩 + 2 bin 桩）----
COPY Cargo.toml Cargo.lock ./
COPY crates/rillane-config/Cargo.toml      crates/rillane-config/Cargo.toml
COPY crates/rillane-core/Cargo.toml        crates/rillane-core/Cargo.toml
COPY crates/rillane-routing/Cargo.toml     crates/rillane-routing/Cargo.toml
COPY crates/rillane-protocols/Cargo.toml   crates/rillane-protocols/Cargo.toml
COPY crates/rillane-telemetry/Cargo.toml   crates/rillane-telemetry/Cargo.toml
COPY crates/rillane-platform/Cargo.toml    crates/rillane-platform/Cargo.toml
COPY crates/rillane-runtime/Cargo.toml     crates/rillane-runtime/Cargo.toml
COPY crates/rillane-mesh/Cargo.toml        crates/rillane-mesh/Cargo.toml
COPY crates/rillane-subscription/Cargo.toml crates/rillane-subscription/Cargo.toml
COPY crates/rillane-plugins/Cargo.toml      crates/rillane-plugins/Cargo.toml
COPY crates/rillane-ffi/Cargo.toml          crates/rillane-ffi/Cargo.toml
COPY apps/rillaned/Cargo.toml              apps/rillaned/Cargo.toml
COPY apps/rillanectl/Cargo.toml            apps/rillanectl/Cargo.toml

RUN for c in rillane-config rillane-core rillane-routing rillane-protocols rillane-telemetry \
             rillane-platform rillane-runtime rillane-mesh rillane-subscription \
             rillane-plugins rillane-ffi; do \
        mkdir -p "crates/$c/src" && touch "crates/$c/src/lib.rs"; \
    done \
    && mkdir -p crates/rillane-core/benches \
    && touch crates/rillane-core/benches/relay_throughput.rs crates/rillane-core/benches/write_frame.rs \
    && mkdir -p apps/rillaned/src apps/rillanectl/src \
    && echo 'fn main() {}' > apps/rillaned/src/main.rs \
    && echo 'fn main() {}' > apps/rillanectl/src/main.rs \
    && cargo build --release \
    && rm -rf crates/*/src crates/*/benches apps/*/src

# ---- 真实构建：源码全量拷入，仅 workspace 层重编 ----
COPY . .
RUN touch crates/rillane-config/src/lib.rs crates/rillane-core/src/lib.rs \
      crates/rillane-routing/src/lib.rs crates/rillane-protocols/src/lib.rs \
      crates/rillane-telemetry/src/lib.rs crates/rillane-platform/src/lib.rs \
      crates/rillane-runtime/src/lib.rs crates/rillane-mesh/src/lib.rs \
      crates/rillane-subscription/src/lib.rs crates/rillane-plugins/src/lib.rs \
      crates/rillane-ffi/src/lib.rs \
      apps/rillaned/src/main.rs apps/rillanectl/src/main.rs \
    && cargo build --release --bin rillaned --bin rillanectl \
    && cp target/release/rillaned target/release/rillanectl /usr/local/bin/

# 运行镜像：最小化 + iproute2（rillane-platform TUN/路由 shell-out 依赖 `ip` 命令）
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false rillane \
    && mkdir -p /etc/rillane /var/log/rillane \
    && chown -R rillane:rillane /etc/rillane /var/log/rillane

COPY --from=builder /usr/local/bin/rillaned /usr/local/bin/rillaned
COPY --from=builder /usr/local/bin/rillanectl /usr/local/bin/rillanectl
# 样例配置：api_bind 127.0.0.1:9090 / 入口 0.0.0.0:7890，容器内按需挂载覆盖
COPY config/rillane.yaml /etc/rillane/config.yaml

# rillaned 无 --config 参数面，配置路径经 RILLANE_CONFIG 注入（apps/rillaned/src/main.rs）
ENV RILLANE_CONFIG=/etc/rillane/config.yaml

USER rillane
EXPOSE 7890 9090
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD rillaned --version || exit 1

ENTRYPOINT ["rillaned"]
