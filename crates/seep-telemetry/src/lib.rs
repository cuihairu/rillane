use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, Mutex},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tracing_subscriber::{fmt, EnvFilter};

static TELEMETRY: OnceCell<TelemetryState> = OnceCell::const_new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryOptions {
    pub level: String,
    pub enable_json: bool,
    #[serde(default)]
    pub capture_logs: bool,
    #[serde(default = "default_capture_max_lines")]
    pub capture_max_lines: usize,
}

impl Default for TelemetryOptions {
    fn default() -> Self {
        Self {
            level: "info".into(),
            enable_json: false,
            capture_logs: false,
            capture_max_lines: default_capture_max_lines(),
        }
    }
}

fn default_capture_max_lines() -> usize {
    2000
}

#[derive(Clone)]
struct TelemetryState {
    log_ring: Option<Arc<Mutex<LineRing>>>,
}

struct LineRing {
    max_lines: usize,
    lines: VecDeque<String>,
    partial: Vec<u8>,
}

impl LineRing {
    fn new(max_lines: usize) -> Self {
        Self {
            max_lines: max_lines.max(1),
            lines: VecDeque::new(),
            partial: Vec::new(),
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.partial.extend_from_slice(bytes);
        while let Some(pos) = self.partial.iter().position(|b| *b == b'\n') {
            let mut line = self.partial.drain(..=pos).collect::<Vec<_>>();
            let s = String::from_utf8_lossy(&line).to_string();
            self.lines.push_back(s);
            while self.lines.len() > self.max_lines {
                self.lines.pop_front();
            }
            line.clear();
        }
        if self.partial.len() > 1024 * 1024 {
            // Avoid unbounded growth if no newline is ever written.
            self.partial.clear();
        }
    }

    fn snapshot_text(&self, limit: usize) -> String {
        let limit = limit.max(1).min(self.max_lines);
        let start = self.lines.len().saturating_sub(limit);
        let mut out = String::new();
        for line in self.lines.iter().skip(start) {
            out.push_str(line);
        }
        out
    }
}

#[derive(Clone)]
struct CaptureMakeWriter {
    ring: Arc<Mutex<LineRing>>,
    mirror_stderr: bool,
}

struct CaptureWriter {
    ring: Arc<Mutex<LineRing>>,
    stderr: io::Stderr,
    mirror_stderr: bool,
}

impl<'a> fmt::MakeWriter<'a> for CaptureMakeWriter {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter {
            ring: self.ring.clone(),
            stderr: io::stderr(),
            mirror_stderr: self.mirror_stderr,
        }
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.mirror_stderr {
            self.stderr.write_all(buf)?;
        }
        if let Ok(mut guard) = self.ring.lock() {
            guard.push_bytes(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.mirror_stderr {
            self.stderr.flush()?;
        }
        Ok(())
    }
}

pub async fn init(opts: TelemetryOptions) -> Result<()> {
    TELEMETRY
        .get_or_try_init(|| async move {
            let filter = EnvFilter::try_new(&opts.level).unwrap_or_else(|_| EnvFilter::new("info"));
            let (writer, state) = if opts.capture_logs {
                let ring = Arc::new(Mutex::new(LineRing::new(opts.capture_max_lines)));
                let writer = CaptureMakeWriter {
                    ring: ring.clone(),
                    mirror_stderr: true,
                };
                (
                    Some(writer),
                    TelemetryState {
                        log_ring: Some(ring),
                    },
                )
            } else {
                (None, TelemetryState { log_ring: None })
            };

            if opts.enable_json {
                if let Some(w) = writer {
                    fmt().with_env_filter(filter).json().with_writer(w).init();
                } else {
                    fmt().with_env_filter(filter).json().init();
                }
            } else {
                if let Some(w) = writer {
                    fmt().with_env_filter(filter).with_writer(w).init();
                } else {
                    fmt().with_env_filter(filter).init();
                }
            }
            Ok(state)
        })
        .await
        .map(|_| ())
}

pub fn logs_text(limit: usize) -> Option<String> {
    let state = TELEMETRY.get()?;
    let ring = state.log_ring.as_ref()?;
    let guard = ring.lock().ok()?;
    Some(guard.snapshot_text(limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_ring_splits_and_caps_lines() {
        let mut ring = LineRing::new(2);
        ring.push_bytes(b"a\nb\nc\n");
        assert_eq!(ring.lines.len(), 2);
        assert_eq!(ring.snapshot_text(10), "b\nc\n");
        assert_eq!(ring.snapshot_text(1), "c\n");
    }

    #[test]
    fn line_ring_handles_partial_lines_and_bounds_partial_growth() {
        let mut ring = LineRing::new(10);
        ring.push_bytes(b"hello");
        assert_eq!(ring.lines.len(), 0);
        assert_eq!(ring.partial, b"hello");

        ring.push_bytes(b"\n");
        assert_eq!(ring.snapshot_text(10), "hello\n");
        assert!(ring.partial.is_empty());

        ring.push_bytes(&vec![b'x'; 1024 * 1024 + 1]);
        assert!(ring.partial.is_empty());
    }

    #[test]
    fn logs_text_none_before_init() {
        assert!(logs_text(10).is_none());
    }

    #[test]
    fn default_capture_max_lines_is_reasonable() {
        assert_eq!(default_capture_max_lines(), 2000);
        let ring = LineRing::new(0);
        assert_eq!(ring.max_lines, 1);
    }
}
