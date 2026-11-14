# Grafana Dashboard (Prometheus)

This directory provides the Grafana Dashboard template for Rillane: `rillane-dashboard.json`.

## 1) Enable metrics

Enable in `rillane.yaml`:

```yaml
telemetry:
  enable_metrics: true
```

Then scrape metrics from the control plane:
- `http://<control.api_bind>/metrics`

## 1.1) (Optional) Enable Mesh data-plane mTLS

Rillane supports enabling mesh data-plane mTLS via environment variables (for encryption and authentication of hop-by-hop forwarding):

```bash
export RILLANE_MESH_MTLS=1
export RILLANE_MESH_MTLS_CA=/path/to/ca.cert.pem
export RILLANE_MESH_MTLS_CERT=/path/to/<node_id>.cert.pem
export RILLANE_MESH_MTLS_KEY=/path/to/<node_id>.key.pem
export RILLANE_MESH_MTLS_SERVER_NAME=rillane
```

Certificates can be generated via `rillanectl mtls init-ca` and `rillanectl mtls issue`.

## 1.2) (Optional) Enable control plane log capture

`rillanectl diagnose` will attempt to scrape `GET /logs` (recent logs). This endpoint is disabled by default and must be enabled in the environment where `rillaned` runs:

```bash
export RILLANE_CAPTURE_LOGS=1
```

## 2) Prometheus scrape configuration example

```yaml
scrape_configs:
  - job_name: rillaned
    metrics_path: /metrics
    static_configs:
      - targets:
          - 127.0.0.1:9090
```

## 3) Import Grafana Dashboard

Grafana -> Dashboards -> New -> Import, select `docs/grafana/rillane-dashboard.json`.

This dashboard uses the data source variable `${DS_PROMETHEUS}`; after import, select your Prometheus data source.
