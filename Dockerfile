# 多阶段构建（双层布局 crates/ + apps/）：
# - 依赖预热层 = 仅根清单 + 全部成员清单 + 虚拟源桩（不依赖 BuildKit cache mount，
#   旧版构建器亦可跑；成员清单枚举按根 Cargo.toml members 核对，新增成员需同步此处）
# - 基础镜像 rust:1-bookworm 滚动稳定（对齐 CI 其余 job 的 stable；MSRV 验证归
#   ci.yml 的 msrv job 独立覆盖——镜像构建目标是产物，不是 MSRV 验证）
# - 产物：seepd（daemon，ENTRYPOINT）+ seepctl（容器内运维/排障）
FROM rust:1-bookworm AS builder

# 构建依赖（ring/aws-lc 需的 perl/make/cc 基础镜像自带；此处补 pkg-config + openssl 头）
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- 依赖预热：只复制清单与锁文件，虚拟源桩占位（11 lib 桩 + 2 bin 桩）----
COPY Cargo.toml Cargo.lock ./
COPY crates/seep-config/Cargo.toml      crates/seep-config/Cargo.toml
COPY crates/seep-core/Cargo.toml        crates/seep-core/Cargo.toml
COPY crates/seep-routing/Cargo.toml     crates/seep-routing/Cargo.toml
COPY crates/seep-protocols/Cargo.toml   crates/seep-protocols/Cargo.toml
COPY crates/seep-telemetry/Cargo.toml   crates/seep-telemetry/Cargo.toml
COPY crates/seep-platform/Cargo.toml    crates/seep-platform/Cargo.toml
COPY crates/seep-runtime/Cargo.toml     crates/seep-runtime/Cargo.toml
COPY crates/seep-mesh/Cargo.toml        crates/seep-mesh/Cargo.toml
COPY crates/seep-subscription/Cargo.toml crates/seep-subscription/Cargo.toml
COPY crates/seep-plugins/Cargo.toml      crates/seep-plugins/Cargo.toml
COPY crates/seep-ffi/Cargo.toml          crates/seep-ffi/Cargo.toml
COPY apps/seepd/Cargo.toml              apps/seepd/Cargo.toml
COPY apps/seepctl/Cargo.toml            apps/seepctl/Cargo.toml

RUN for c in seep-config seep-core seep-routing seep-protocols seep-telemetry \
             seep-platform seep-runtime seep-mesh seep-subscription \
             seep-plugins seep-ffi; do \
        mkdir -p "crates/$c/src" && touch "crates/$c/src/lib.rs"; \
    done \
    && mkdir -p crates/seep-core/benches \
    && touch crates/seep-core/benches/relay_throughput.rs crates/seep-core/benches/write_frame.rs \
    && mkdir -p apps/seepd/src apps/seepctl/src \
    && echo 'fn main() {}' > apps/seepd/src/main.rs \
    && echo 'fn main() {}' > apps/seepctl/src/main.rs \
    && cargo build --release \
    && rm -rf crates/*/src crates/*/benches apps/*/src

# ---- 真实构建：源码全量拷入，仅 workspace 层重编 ----
COPY . .
RUN touch crates/seep-config/src/lib.rs crates/seep-core/src/lib.rs \
      crates/seep-routing/src/lib.rs crates/seep-protocols/src/lib.rs \
      crates/seep-telemetry/src/lib.rs crates/seep-platform/src/lib.rs \
      crates/seep-runtime/src/lib.rs crates/seep-mesh/src/lib.rs \
      crates/seep-subscription/src/lib.rs crates/seep-plugins/src/lib.rs \
      crates/seep-ffi/src/lib.rs \
      apps/seepd/src/main.rs apps/seepctl/src/main.rs \
    && cargo build --release --bin seepd --bin seepctl \
    && cp target/release/seepd target/release/seepctl /usr/local/bin/

# 运行镜像：最小化 + iproute2（seep-platform TUN/路由 shell-out 依赖 `ip` 命令）
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false seep \
    && mkdir -p /etc/seep /var/log/seep \
    && chown -R seep:seep /etc/seep /var/log/seep

COPY --from=builder /usr/local/bin/seepd /usr/local/bin/seepd
COPY --from=builder /usr/local/bin/seepctl /usr/local/bin/seepctl
# 样例配置：api_bind 127.0.0.1:9090 / 入口 0.0.0.0:7890，容器内按需挂载覆盖
COPY config/seep.yaml /etc/seep/config.yaml

# seepd 无 --config 参数面，配置路径经 SEEP_CONFIG 注入（apps/seepd/src/main.rs）
ENV SEEP_CONFIG=/etc/seep/config.yaml

USER seep
EXPOSE 7890 9090
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD seepd --version || exit 1

ENTRYPOINT ["seepd"]
