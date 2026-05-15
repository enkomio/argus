//! Logging setup for Argus

use anyhow::Result;
use std::sync::Mutex;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn init(level: &str, log_file: Option<&str>) -> Result<()> {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    let terminal = fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_timer(fmt::time::ChronoLocal::new("%Y-%m-%d %H:%M:%S".to_string()))
        .compact();

    let file_layer = log_file
        .map(|path| -> Result<_> {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| anyhow::anyhow!("Cannot open log file '{}': {}", path, e))?;
            Ok(fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_timer(fmt::time::ChronoLocal::new("%Y-%m-%d %H:%M:%S".to_string()))
                .with_ansi(false)
                .compact()
                .with_writer(Mutex::new(file)))
        })
        .transpose()?;

    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(filter)
            .with(terminal)
            .with(file_layer),
    )?;

    Ok(())
}
