# Grafana 仪表板（Prometheus）

本目录提供 Seep 的 Grafana Dashboard 模板：`seep-dashboard.json`。

## 1) 启用 metrics

在 `seep.yaml` 中启用：

```yaml
telemetry:
  enable_metrics: true
```

然后从控制面拉取指标：
- `http://<control.api_bind>/metrics`

## 1.1) （可选）启用 Mesh data-plane mTLS

Seep 支持通过环境变量启用 mesh data-plane mTLS（用于 hop-by-hop 转发的加密与鉴权）：

```bash
export SEEP_MESH_MTLS=1
export SEEP_MESH_MTLS_CA=/path/to/ca.cert.pem
export SEEP_MESH_MTLS_CERT=/path/to/<node_id>.cert.pem
export SEEP_MESH_MTLS_KEY=/path/to/<node_id>.key.pem
export SEEP_MESH_MTLS_SERVER_NAME=seep
```

证书可通过 `seepctl mtls init-ca` 与 `seepctl mtls issue` 生成。

## 1.2) （可选）启用控制面日志抓取

`seepctl diagnose` 会尝试抓取 `GET /logs`（最近日志）。该端点默认关闭，需要在运行 `seepd` 的环境中开启：

```bash
export SEEP_CAPTURE_LOGS=1
```

## 2) Prometheus 抓取配置示例

```yaml
scrape_configs:
  - job_name: seepd
    metrics_path: /metrics
    static_configs:
      - targets:
          - 127.0.0.1:9090
```

## 3) 导入 Grafana Dashboard

Grafana -> Dashboards -> New -> Import，选择 `docs/grafana/seep-dashboard.json`。

该 dashboard 使用了数据源变量 `${DS_PROMETHEUS}`，导入后选择你的 Prometheus 数据源即可。
