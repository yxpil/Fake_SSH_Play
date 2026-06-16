// Entry point — loads frames, daemon-style restart loop, spawns SSH + Web.
#[path = "Read/config.rs"]
mod config;
#[path = "Read/state.rs"]
mod state;
#[path = "Read/frames.rs"]
mod frames;
#[path = "Control/ssh.rs"]
mod ssh;
#[path = "Control/web.rs"]
mod web;
#[path = "Tools/geoip.rs"]
mod geoip;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{error, info};

use crate::config::{AppConfig, MAX_RESTART, RESTART_DELAY_MS};
use crate::frames::load_frames;
use crate::state::{safe_append, SharedState};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let app_cfg = AppConfig::default();

    if !app_cfg.host_key_path.exists() {
        anyhow::bail!(
            "Host key not found: {}. Generate: ssh-keygen -t rsa -f {} -N ''",
            app_cfg.host_key_path.display(),
            app_cfg.host_key_path.display()
        );
    }
    if !app_cfg.ascii_frames_path.exists() {
        anyhow::bail!(
            "ASCII frames not found: {}",
            app_cfg.ascii_frames_path.display()
        );
    }

    let frames = load_frames(&app_cfg.ascii_frames_path)?;
    let state = Arc::new(SharedState::new(frames, app_cfg));

    info!("🎬 SSH ASCII Art Honeypot — Bad Apple Animation 🎬");

    // Daemon loop: if SSH or Web panics, restart up to MAX_RESTART times.
    let mut restarts = 0u32;
    loop {
        match run_honeypot(Arc::clone(&state)).await {
            Ok(()) => break,
            Err(e) => {
                restarts += 1;
                error!("Crash ({}/{}): {:?}", restarts, MAX_RESTART, e);
                if restarts >= MAX_RESTART {
                    error!("Max restarts reached, exiting");
                    break;
                }
                info!("Restarting in {}s...", RESTART_DELAY_MS / 1000);
                tokio::time::sleep(Duration::from_millis(RESTART_DELAY_MS)).await;
            }
        }
    }
    Ok(())
}

async fn run_honeypot(state: Arc<SharedState>) -> Result<()> {
    use chrono::Utc;
    use std::sync::atomic::Ordering;

    use crate::config::ANIM_FRAME_MS;

    let init_time = Utc::now().to_rfc3339();
    if !state.config.attack_log_path.exists() {
        safe_append(
            &state.config.attack_log_path,
            &format!(
                "# SSH ASCII Art Honeypot Attack Logs\n# Started: {}\n",
                init_time
            ),
        );
    }
    if !state.config.connection_log_path.exists() {
        safe_append(
            &state.config.connection_log_path,
            &format!(
                "# SSH ASCII Art Honeypot Connection Logs\n# Started: {}\n",
                init_time
            ),
        );
    }

    // Periodic stats dump every 30s.
    let ss = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            info!(
                "=== STATS === Attacks:{} Active:{} Data:{:.2}KB Frames:{} Dur:{:.1}s Cache:{}",
                ss.attack_counter.load(Ordering::SeqCst),
                ss.active_count(),
                ss.total_data.load(Ordering::SeqCst) as f64 / 1024.0,
                ss.frames.len(),
                ss.frames.len() as f64 / (1000.0 / ANIM_FRAME_MS as f64),
                ss.ip_cache.lock().unwrap().len(),
            );
        }
    });

    // Run SSH and Web concurrently — if either dies the other gets dropped.
    let ssh = tokio::spawn(crate::ssh::start_ssh(Arc::clone(&state)));
    let web = tokio::spawn(crate::web::start_web(Arc::clone(&state)));

    tokio::select! {
        r = ssh => { if let Err(e) = r? { error!("SSH: {:?}", e); } }
        r = web => { if let Err(e) = r? { error!("Web: {:?}", e); } }
    }
    Ok(())
}
