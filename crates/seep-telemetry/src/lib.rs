use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tracing_subscriber::{fmt, EnvFilter};

static TELEMETRY: OnceCell<()> = OnceCell::const_new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryOptions {
    pub level: String,
    pub enable_json: bool,
}

impl Default for TelemetryOptions {
    fn default() -> Self {
        Self {
            level: "info".into(),
            enable_json: false,
        }
    }
}

pub async fn init(opts: TelemetryOptions) -> Result<()> {
    TELEMETRY
        .get_or_try_init(|| async move {
            let filter = EnvFilter::try_new(&opts.level).unwrap_or_else(|_| EnvFilter::new("info"));
            if opts.enable_json {
                fmt().with_env_filter(filter).json().init();
            } else {
                fmt().with_env_filter(filter).init();
            }
            Ok(())
        })
        .await
        .map(|_| ())
}
