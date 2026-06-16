// SSH honeypot — russh server that accepts ALL authentication and plays
// ASCII animation frame-by-frame at 10 FPS through the SSH channel.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use rand::Rng;
use russh::server::{Auth, Handle, Handler, Msg, Server as RusshServer, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::load_secret_key;
use russh_keys::key;
use tracing::info;

use crate::config::ANIM_FRAME_MS;
use crate::geoip::get_country;
use crate::state::{log_attack, log_conn, SharedState};

// ─── Handler — one per SSH connection ───────────────────────────────────────

pub struct SshHandler {
    state: Arc<SharedState>,
    client_ip: String,
    connection_id: String,
}

#[async_trait]
impl Handler for SshHandler {
    type Error = anyhow::Error;

    // Accept everything — this is a honeypot.
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let country = get_country(&self.state, &self.client_ip).await;
        let aid = self.state.next_attack_id();
        log_attack(&self.state, &aid, &self.client_ip, &country, user, "none", "");
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        let country = get_country(&self.state, &self.client_ip).await;
        let aid = self.state.next_attack_id();
        log_attack(&self.state, &aid, &self.client_ip, &country, user, "password", "");
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _key: &key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let country = get_country(&self.state, &self.client_ip).await;
        let aid = self.state.next_attack_id();
        log_attack(&self.state, &aid, &self.client_ip, &country, user, "publickey", "");
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    // Spawn animation task and return immediately — russh keeps the channel open.
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        self.spawn_animation(handle, channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        let _ = handle
            .data(
                channel,
                CryptoVec::from_slice(b"Interactive shell only. Starting animation...\r\n"),
            )
            .await;
        self.spawn_animation(handle, channel);
        Ok(())
    }

    // Stub acceptors — required by the Handler trait but we don't use them.
    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        _col: u32,
        _row: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn env_request(
        &mut self,
        _channel: ChannelId,
        _name: &str,
        _value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        _col: u32,
        _row: u32,
        _pw: u32,
        _ph: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn signal(
        &mut self,
        _channel: ChannelId,
        _signal: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ─── Animation player — tokio::spawn per connection ─────────────────────────

impl SshHandler {
    fn spawn_animation(&self, handle: Handle, channel_id: ChannelId) {
        let conn_id = self.connection_id.clone();
        let client_ip = self.client_ip.clone();
        let state = Arc::clone(&self.state);
        let frames = state.frames.clone();
        let total = frames.len();

        tokio::spawn(async move {
            info!("Starting animation for {}, {} frames", conn_id, total);
            let country = get_country(&state, &client_ip).await;
            log_conn(
                &state,
                &conn_id,
                &client_ip,
                &country,
                "ascii_animation_started",
                &format!("frames={}", total),
            );

            // ANSI: clear screen, hide cursor.
            let _ = handle
                .data(channel_id, CryptoVec::from_slice(b"\x1b[2J\x1b[H\x1b[?25l"))
                .await;

            let start = std::time::Instant::now();

            for (i, frame) in frames.iter().enumerate() {
                // Normalise line endings to CRLF so terminals render correctly.
                let normalized = frame.replace('\n', "\r\n");
                let frame_data = format!(
                    "\x1b[2J\x1b[H{}\r\n\x1b[38;2;220;20;60mFrame: {}/{}\r\n",
                    normalized,
                    i + 1,
                    total
                );
                let data = CryptoVec::from_slice(frame_data.as_bytes());
                let len = frame_data.len() as u64;

                // Fire and forget — don't care if hacker disconnected.
                let _ = handle.data(channel_id, data).await;
                state.add_data(len);

                if i % 100 == 0 {
                    let pct = (i as f64 / total as f64 * 100.0) as u32;
                    info!("Anim progress {}: {}% ({}/{})", conn_id, pct, i, total);
                    log_conn(
                        &state,
                        &conn_id,
                        &client_ip,
                        &country,
                        "animation_progress",
                        &format!("{}%", pct),
                    );
                }
                tokio::time::sleep(Duration::from_millis(ANIM_FRAME_MS)).await;
            }

            let dur = start.elapsed().as_millis();

            // Restore cursor, show closing banner.
            let _ = handle
                .data(channel_id, CryptoVec::from_slice(b"\x1b[?25h\x1b[2J\x1b[H"))
                .await;
            let closing = "\r\n\r\n🎬 ASCII动画播放完成！感谢观看！bilibili：https://space.bilibili.com/515222887 more info https://yxp.hk/🎬\r\n";
            let _ = handle
                .data(channel_id, CryptoVec::from_slice(closing.as_bytes()))
                .await;
            let _ = handle
                .data(
                    channel_id,
                    CryptoVec::from_slice(
                        b"\xf0\x9f\x8c\x9f Thanks for visiting the SSH ASCII Art Honeypot! \xf0\x9f\x8c\x9f\r\n",
                    ),
                )
                .await;

            info!("Animation done for {}, {}ms", conn_id, dur);
            log_conn(
                &state,
                &conn_id,
                &client_ip,
                &country,
                "ascii_animation_completed",
                &format!("duration={}ms", dur),
            );

            // Give the client a few seconds to read the closing message, then disconnect.
            tokio::time::sleep(Duration::from_secs(3)).await;
            let _ = handle.close(channel_id).await;
            state.del_conn(&conn_id);
            log_conn(
                &state,
                &conn_id,
                &client_ip,
                &country,
                "client_disconnected",
                "",
            );
        });
    }
}

// ─── Server — creates a new handler per inbound SSH connection ───────────────

pub struct SshServer {
    state: Arc<SharedState>,
}

impl SshServer {
    pub fn new(state: Arc<SharedState>) -> Self {
        Self { state }
    }
}

impl RusshServer for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        let ip = peer_addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".into());
        let conn_id = format!(
            "CONN_{}_{}",
            Utc::now().timestamp_millis(),
            rand::thread_rng().gen_range(100_000_000..999_999_999)
        );

        self.state.add_conn(conn_id.clone());

        // Fire-and-forget geolocation + logging.
        let state = Arc::clone(&self.state);
        let ip_c = ip.clone();
        let cid = conn_id.clone();
        tokio::spawn(async move {
            let country = get_country(&state, &ip_c).await;
            info!("[+] New connection from {} ({}) (ID: {})", ip_c, country, cid);
            log_conn(
                &state,
                &cid,
                &ip_c,
                &country,
                "connection_established",
                "",
            );
        });

        SshHandler {
            state: Arc::clone(&self.state),
            client_ip: ip,
            connection_id: conn_id,
        }
    }
}

// ─── Bootstrap — load host key, configure russh, bind port ──────────────────

pub async fn start_ssh(state: Arc<SharedState>) -> Result<()> {
    let key = load_secret_key(&state.config.host_key_path, None).with_context(|| {
        format!(
            "Failed to load host key: {}",
            state.config.host_key_path.display()
        )
    })?;

    let mut cfg = russh::server::Config::default();
    cfg.server_id = russh::SshId::Standard("SSH-2.0-OpenSSH_8.9p1".into());
    cfg.methods = MethodSet::all();
    cfg.keys.push(key);
    cfg.auth_rejection_time = Duration::from_secs(2);
    cfg.inactivity_timeout = Some(Duration::from_secs(120));
    cfg.max_auth_attempts = 20; // generous — honeypot accepts everything

    let addr = SocketAddr::from(([0, 0, 0, 0], state.config.ssh_port));
    let mut server = SshServer::new(Arc::clone(&state));

    info!("SSH honeypot on 0.0.0.0:{}", state.config.ssh_port);
    info!(
        "Animation: {} frames, {:.1}s @ {} FPS",
        state.frames.len(),
        state.frames.len() as f64 / (1000.0 / ANIM_FRAME_MS as f64),
        1000 / ANIM_FRAME_MS
    );

    server.run_on_address(Arc::new(cfg), addr).await?;
    Ok(())
}
