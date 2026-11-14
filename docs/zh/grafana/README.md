# Grafana 仪表板（Prometheus）

本目录提供 Rillane 的 Grafana Dashboard 模板：`rillane-dashboard.json`。

## 1) 启用 metrics

在 `rillane.yaml` 中启用：

```yaml
telemetry:
  enable_metrics: true
```

然后从控制面拉取指标：
- `http://<control.api_bind>/metrics`

## 1.1) （可选）启用 Mesh data-plane mTLS

Rillane 支持通过环境变量启用 mesh data-plane mTLS（用于 hop-by-hop 转发的加密与鉴权）：

```bash
export RILLANE_MESH_MTLS=1
export RILLANE_MESH_MTLS_CA=/path/to/ca.cert.pem
export RILLANE_MESH_MTLS_CERT=/path/to/<node_id>.cert.pem
export RILLANE_MESH_MTLS_KEY=/path/to/<node_id>.key.pem
export RILLANE_MESH_MTLS_SERVER_NAME=rillane
```

证书可通过 `rillanectl mtls init-ca` 与 `rillanectl mtls issue` 生成。

## 1.2) （可选）启用控制面日志抓取

`rillanectl diagnose` 会尝试抓取 `GET /logs`（最近日志）。该端点默认关闭，需要在运行 `rillaned` 的环境中开启：

```bash
export RILLANE_CAPTURE_LOGS=1
```

## 2) Prometheus 抓取配置示例

```yaml
scrape_configs:
  - job_name: rillaned
    metrics_path: /metrics
    static_configs:
      - targets:
          - 127.0.0.1:9090
```

## 3) 导入 Grafana Dashboard

Grafana -> Dashboards -> New -> Import，选择 `docs/grafana/rillane-dashboard.json`。

该 dashboard 使用了数据源变量 `${DS_PROMETHEUS}`，导入后选择你的 Prometheus 数据源即可。
