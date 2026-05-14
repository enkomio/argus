//! Logging setup for Argus

use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn init(level: &str, log_file: Option<&str>) -> Result<()> {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_thread_ids(false).compact());

    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}
