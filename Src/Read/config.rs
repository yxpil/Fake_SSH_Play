// Config — all tunable constants and paths live here.
use std::path::PathBuf;

pub const SSH_PORT: u16 = 22;
pub const WEB_PORT: u16 = 763;
pub const MAX_IP_CACHE: usize = 500;
pub const ANIM_FRAME_MS: u64 = 33; // 30 FPS
pub const IP_API: &str = "https://ipip.yxpil.com/classify/";
pub const MAX_RESTART: u32 = 10;
pub const RESTART_DELAY_MS: u64 = 2000;

#[derive(Clone)]
pub struct AppConfig {
    pub host_key_path: PathBuf,
    pub ascii_frames_path: PathBuf,
    pub attack_log_path: PathBuf,
    pub connection_log_path: PathBuf,
    pub ssh_port: u16,
    pub web_port: u16,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host_key_path: PathBuf::from("host_rsa.key"),
            ascii_frames_path: PathBuf::from("FAKESSH.txt"),
            attack_log_path: PathBuf::from("attack_logs.txt"),
            connection_log_path: PathBuf::from("connection_logs.txt"),
            ssh_port: SSH_PORT,
            web_port: WEB_PORT,
        }
    }
}
