# Grafana Dashboard (Prometheus)

This directory provides the Grafana Dashboard template for Seep: `seep-dashboard.json`.

## 1) Enable metrics

Enable in `seep.yaml`:

```yaml
telemetry:
  enable_metrics: true
```

Then scrape metrics from the control plane:
- `http://<control.api_bind>/metrics`

## 1.1) (Optional) Enable Mesh data-plane mTLS

Seep supports enabling mesh data-plane mTLS via environment variables (for encryption and authentication of hop-by-hop forwarding):

```bash
export SEEP_MESH_MTLS=1
export SEEP_MESH_MTLS_CA=/path/to/ca.cert.pem
export SEEP_MESH_MTLS_CERT=/path/to/<node_id>.cert.pem
export SEEP_MESH_MTLS_KEY=/path/to/<node_id>.key.pem
export SEEP_MESH_MTLS_SERVER_NAME=seep
```

Certificates can be generated via `seepctl mtls init-ca` and `seepctl mtls issue`.

## 1.2) (Optional) Enable control plane log capture

`seepctl diagnose` will attempt to scrape `GET /logs` (recent logs). This endpoint is disabled by default and must be enabled in the environment where `seepd` runs:

```bash
export SEEP_CAPTURE_LOGS=1
```

## 2) Prometheus scrape configuration example

```yaml
scrape_configs:
  - job_name: seepd
    metrics_path: /metrics
    static_configs:
      - targets:
          - 127.0.0.1:9090
```

## 3) Import Grafana Dashboard

Grafana -> Dashboards -> New -> Import, select `docs/grafana/seep-dashboard.json`.

This dashboard uses the data source variable `${DS_PROMETHEUS}`; after import, select your Prometheus data source.
