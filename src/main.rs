//! Argus — Network traffic interception tool for malware analysis

mod config;
mod conn_table;
mod forward_to;
mod listeners;
mod diverter;
mod logger;
mod request_logger;

use anyhow::Result;
use clap::Parser;
use colored::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use config::ArgusConfig;
use listeners::ListenerManager;

const VERSION:&str = "1.0.0" ;

/// Checks whether the current process is running with Administrator privileges.
/// If not, prints a clear error message and exits with code 1.
fn require_admin() {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let elevated = unsafe {
        let mut token = HANDLE::default();
        if !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).as_bool() {
            false
        } else {
            let mut elev = TOKEN_ELEVATION::default();
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elev as *mut _ as *mut core::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            ).as_bool();
            let _ = CloseHandle(token);
            ok && elev.TokenIsElevated != 0
        }
    };

    if !elevated {
        eprintln!();
        eprintln!("{}", "  [ERROR] Argus requires Administrator privileges.".bright_red().bold());
        eprintln!("{}", "  Right-click argus.exe and choose \"Run as administrator\",".bright_yellow());
        eprintln!("{}", "  or launch from an elevated Command Prompt / PowerShell.".bright_yellow());
        eprintln!();
        std::process::exit(1);
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "argus",
    about = "Argus: Network traffic interception tool for malware analysis",
    version = "1.0.0",
    long_about = None
)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long = "config", default_value = "configs/default.ini")]
    config: String,

    /// Verbose logging
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Bind address
    #[arg(short = 'b', long = "bind", default_value = "0.0.0.0")]
    bind: String,

    /// Log to file
    #[arg(short = 'l', long = "log")]
    log_file: Option<String>,

    /// List available listeners
    #[arg(long = "list-listeners")]
    list_listeners: bool,

    /// Directory where received-request log files are saved (default: current directory)
    #[arg(long = "log-dir")]
    log_dir: Option<String>,
}

fn print_banner() {
    println!("{}", r#"
    _    ____   ____  _   _ ____
   / \  |  _ \ / ___|| | | / ___|
  / _ \ | |_) || |  _| | | \___ \
 / ___ \|  _ < | |_| | |_| |___) |
/_/   \_\_| \_\ \____|\___/ |____/
"#.bright_cyan());
    println!("{}", format!("  Network traffic interception tool for malware analysis  |  v{VERSION}").bright_white());
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Must be the very first check — WinDivert and port binding both require admin.
    require_admin();

    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    logger::init(log_level, args.log_file.as_deref())?;

    print_banner();

    if args.list_listeners {
        println!("{}", "Available listeners:".bright_green().bold());
        println!("  {} - HTTP/HTTPS traffic interception (ports 80, 443)", "HTTPListener".bright_white());
        println!("  {} - DNS query interception (port 53)", "DNSListener".bright_white());
        println!("  {} - Raw TCP/UDP interception (any port)", "RawListener".bright_white());
        println!("  {} - SMTP email interception (port 25)", "SMTPListener".bright_white());
        println!("  {} - FTP traffic interception (port 21)", "FTPListener".bright_white());
        println!("  {} - IRC traffic interception (port 6667)", "IRCListener".bright_white());
        println!("  {} - POP3 email retrieval interception (port 110)", "POPListener".bright_white());
        println!("  {} - TFTP file transfer interception (port 69)", "TFTPListener".bright_white());
        return Ok(());
    }

    info!("Loading configuration from: {}", args.config);

    // Load configuration
    let config = match ArgusConfig::load(&args.config) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!("Failed to load config: {}", e);
            info!("Using default configuration...");
            Arc::new(ArgusConfig::default())
        }
    };

    // Override bind address from args
    let bind_addr = args.bind.clone();

    info!("Starting Argus on {}", bind_addr);

    // Shared connection table — written by the diverter, read by listeners.
    let conn_table = conn_table::new_shared_table();

    let log_dir = args.log_dir.as_deref().unwrap_or("capture");
    info!("Request logging → {}", log_dir);
    let request_logger: Option<crate::request_logger::SharedRequestLogger> =
        Some(request_logger::new_request_logger(log_dir));

    // Create listener manager
    let manager = Arc::new(Mutex::new(
        ListenerManager::new(config.clone(), bind_addr, conn_table.clone(), request_logger).await?
    ));

    // Start all listeners
    {
        let mut mgr = manager.lock().await;
        mgr.start_all().await?;
    }

    // Start traffic diverter (requires Administrator + WinDivert driver)
    let diverter: Option<diverter::Diverter> = if config.argus.divert_traffic {
        match diverter::Diverter::start(&config, conn_table.clone()) {
            Ok(d) => Some(d),
            Err(e) => {
                error!("Diverter failed to start: {:#}", e);
                warn!("Traffic will NOT be redirected automatically.");
                warn!("You can still point malware to this machine's IP manually.");
                None
            }
        }
    } else {
        None
    };

    println!();
    println!("{}", "═".repeat(60).bright_cyan());
    println!("{}", "  Argus is running. Press Ctrl+C to stop.".bright_green().bold());
    println!("{}", "═".repeat(60).bright_cyan());
    println!();

    // Wrap diverter in Arc<Mutex> so it can be moved into the ctrlc handler.
    let diverter_arc = Arc::new(std::sync::Mutex::new(diverter));
    let diverter_clone = diverter_arc.clone();

    // Setup graceful shutdown
    let manager_clone = manager.clone();
    ctrlc::set_handler(move || {
        println!();
        println!("{}", "Shutting down Argus...".bright_yellow());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut mgr = manager_clone.lock().await;
            mgr.stop_all().await;
        });
        if let Some(d) = diverter_clone.lock().unwrap().take() {
            d.stop();
        }
        std::process::exit(0);
    })?;

    // Keep alive
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
