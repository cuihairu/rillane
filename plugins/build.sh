#!/usr/bin/env bash
# P3-2 示例插件构建（docs/design/plugin-loader.md §4.2/§7 P-load）：
# 产物落 plugins/output/*.wasm（非 workspace 成员，独立 wasm32 交叉编译）。
set -euo pipefail
cd "$(dirname "$0")"

rustup target list --installed | grep -q wasm32-unknown-unknown || {
  echo "缺 wasm32-unknown-unknown target：rustup target add wasm32-unknown-unknown" >&2
  exit 1
}

mkdir -p output
# cdylib 产物名随包名（seep_plugin_<name>.wasm）——复制为对外名 <name>.wasm
build_one() {
  local dir="$1" out="$2"
  (cd "$dir" && cargo build --release --target wasm32-unknown-unknown)
  cp "$dir/target/wasm32-unknown-unknown/release/seep_plugin_${dir//-/_}.wasm" "output/${out}.wasm"
  echo "built output/${out}.wasm"
}
build_one rate-limit rate_limit
build_one content-filter content_filter

echo "宿主侧验收实况：cargo run -p seep-plugins --example plugins_smoke"
