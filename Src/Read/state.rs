// SharedState — the single source of truth shared across SSH + Web tasks.
// All counters use atomics; mutable collections use Mutex for safe concurrent access.
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::AppConfig;

// ─── Log types (exact JSON shape the Node version produces) ────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackLog {
    pub timestamp: String,
    pub attack_id: String,
    pub source_ip: String,
    #[serde(rename = "countryName")]
    pub country_name: String,
    pub username: String,
    pub auth_method: String,
    pub success: bool,
    pub attack_type: String,
    pub details: String,
    pub user_agent: String,
    pub target_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLog {
    pub timestamp: String,
    pub connection_id: String,
    pub source_ip: String,
    #[serde(rename = "countryName")]
    pub country_name: String,
    pub event: String,
    pub details: String,
    pub active_connections: usize,
}

// Web dashboard uses camelCase field names that match the ECharts frontend.
#[derive(Debug, Clone, Serialize)]
pub struct AccessLogEntry {
    #[serde(rename = "time")]
    pub timestamp: String,
    #[serde(rename = "type")]
    pub log_type: String,
    #[serde(rename = "ip")]
    pub source_ip: String,
    #[serde(rename = "country")]
    pub country_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "auth_method")]
    pub auth_method: Option<String>,
    #[serde(rename = "id")]
    pub log_id: String,
}

// ─── State ──────────────────────────────────────────────────────────────────

pub struct SharedState {
    pub frames: Vec<String>,
    pub config: AppConfig,
    pub attack_counter: AtomicU64,
    pub total_data: AtomicU64,
    pub active_connections: Mutex<HashSet<String>>,
    pub access_log: Mutex<Vec<AccessLogEntry>>,
    pub ip_cache: Mutex<HashMap<String, String>>,
}

impl SharedState {
    pub fn new(frames: Vec<String>, config: AppConfig) -> Self {
        Self {
            frames,
            config,
            attack_counter: AtomicU64::new(0),
            total_data: AtomicU64::new(0),
            active_connections: Mutex::new(HashSet::new()),
            access_log: Mutex::new(Vec::new()),
            ip_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn next_attack_id(&self) -> String {
        let n = self.attack_counter.fetch_add(1, Ordering::SeqCst) + 1;
        format!("ATTACK_{:06}", n)
    }

    pub fn add_data(&self, n: u64) {
        self.total_data.fetch_add(n, Ordering::SeqCst);
    }

    pub fn add_conn(&self, id: String) {
        self.active_connections.lock().unwrap().insert(id);
    }

    pub fn del_conn(&self, id: &str) {
        self.active_connections.lock().unwrap().remove(id);
    }

    pub fn active_count(&self) -> usize {
        self.active_connections.lock().unwrap().len()
    }
}

// ─── Logging — JSON lines appended to disk + pushed to in-memory ring ────────

pub fn safe_append(path: &Path, content: &str) {
    if let Err(e) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| writeln!(f, "{}", content))
    {
        warn!("Log write failed {}: {}", path.display(), e);
    }
}

pub fn log_attack(
    state: &SharedState,
    id: &str,
    ip: &str,
    country: &str,
    user: &str,
    method: &str,
    details: &str,
) {
    let entry = AttackLog {
        timestamp: Utc::now().to_rfc3339(),
        attack_id: id.to_string(),
        source_ip: ip.to_string(),
        country_name: country.to_string(),
        username: user.to_string(),
        auth_method: method.to_string(),
        success: true,
        attack_type: "ssh_brute_force".into(),
        details: details.to_string(),
        user_agent: "ssh_client".into(),
        target_port: state.config.ssh_port,
    };
    let json = serde_json::to_string(&entry).unwrap_or_default();
    safe_append(&state.config.attack_log_path, &json);

    let access = AccessLogEntry {
        timestamp: entry.timestamp.clone(),
        log_type: "attack".into(),
        source_ip: ip.to_string(),
        country_name: country.to_string(),
        event: None,
        auth_method: Some(method.to_string()),
        log_id: id.to_string(),
    };
    state.access_log.lock().unwrap().push(access);
    info!(
        "[ATTACK] {} from {} ({}) user={} method={}",
        id, ip, country, user, method
    );
}

pub fn log_conn(
    state: &SharedState,
    conn_id: &str,
    ip: &str,
    country: &str,
    event: &str,
    details: &str,
) {
    let entry = ConnectionLog {
        timestamp: Utc::now().to_rfc3339(),
        connection_id: conn_id.to_string(),
        source_ip: ip.to_string(),
        country_name: country.to_string(),
        event: event.to_string(),
        details: details.to_string(),
        active_connections: state.active_count(),
    };
    let json = serde_json::to_string(&entry).unwrap_or_default();
    safe_append(&state.config.connection_log_path, &json);

    let access = AccessLogEntry {
        timestamp: entry.timestamp.clone(),
        log_type: "connection".into(),
        source_ip: ip.to_string(),
        country_name: country.to_string(),
        event: Some(event.to_string()),
        auth_method: None,
        log_id: conn_id.to_string(),
    };
    state.access_log.lock().unwrap().push(access);
    info!(
        "[CONN] {} {} from {} ({})",
        conn_id, event, ip, country
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> SharedState {
        let dir = std::env::temp_dir().join(format!("fakessh-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = AppConfig {
            host_key_path: dir.join("host.key"),
            ascii_frames_path: dir.join("frames.txt"),
            attack_log_path: dir.join("attack.jsonl"),
            connection_log_path: dir.join("conn.jsonl"),
            ssh_port: 2222,
            web_port: 7630,
        };
        SharedState::new(Vec::new(), cfg)
    }

    #[test]
    fn attack_ids_are_monotonic_and_padded() {
        let s = test_state();
        assert_eq!(s.next_attack_id(), "ATTACK_000001");
        assert_eq!(s.next_attack_id(), "ATTACK_000002");
        assert_eq!(s.next_attack_id(), "ATTACK_000003");
    }

    #[test]
    fn connection_set_add_remove_count() {
        let s = test_state();
        assert_eq!(s.active_count(), 0);
        s.add_conn("c1".into());
        s.add_conn("c2".into());
        s.add_conn("c1".into()); // 集合去重
        assert_eq!(s.active_count(), 2);
        s.del_conn("c1");
        assert_eq!(s.active_count(), 1);
        s.del_conn("nope");
        assert_eq!(s.active_count(), 1);
    }

    #[test]
    fn add_data_accumulates() {
        let s = test_state();
        s.add_data(100);
        s.add_data(50);
        assert_eq!(s.total_data.load(Ordering::SeqCst), 150);
    }

    #[test]
    fn safe_append_writes_line() {
        let dir = std::env::temp_dir().join(format!("fakessh-append-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("log.txt");
        safe_append(&p, "first");
        safe_append(&p, "second");
        let body = std::fs::read_to_string(&p).unwrap();
        assert_eq!(body, "first\nsecond\n");
    }

    #[test]
    fn safe_append_bad_path_does_not_panic_failure_isolation() {
        // 失败隔离：日志写到一个"目录"路径会失败，应仅 warn 不 panic，
        // 调用方（SSH 任务）不会因此崩溃。
        let dir = std::env::temp_dir().join(format!("fakessh-badpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        safe_append(&dir, "should fail because path is a directory");
        // 走到这里即证明没有 panic
    }

    #[test]
    fn log_attack_and_conn_push_access_log_in_order() {
        let s = test_state();
        log_attack(&s, "A1", "1.2.3.4", "CN", "root", "password", "brute");
        log_conn(&s, "C1", "1.2.3.4", "CN", "connected", "");
        let log = s.access_log.lock().unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].log_type, "attack");
        assert_eq!(log[0].auth_method.as_deref(), Some("password"));
        assert_eq!(log[0].log_id, "A1");
        assert_eq!(log[1].log_type, "connection");
        assert_eq!(log[1].event.as_deref(), Some("connected"));
    }

    // --- 注入测试：攻击者可控的 username/details 进入 JSON 日志，
    //     必须被 serde 正确转义（尤其是双引号），不能打破 JSON 字符串注入伪造字段。
    #[test]
    fn quote_in_username_is_json_escaped() {
        // 含双引号，试图闭合 JSON 字符串注入伪造字段
        let evil = "root\"}</script><script>alert(1)</script>";
        let entry = AttackLog {
            timestamp: "2026-01-01T00:00:00Z".into(),
            attack_id: "A1".into(),
            source_ip: "1.2.3.4".into(),
            country_name: "CN".into(),
            username: evil.into(),
            auth_method: "password".into(),
            success: true,
            attack_type: "ssh_brute_force".into(),
            details: String::new(),
            user_agent: "ssh_client".into(),
            target_port: 22,
        };
        let json = serde_json::to_string(&entry).unwrap();
        // 内部双引号必须被转义为 \"，不能裸出现在 JSON 字符串里
        assert!(json.contains("\\\""), "内部双引号应被转义: {json}");
        // 整个串仍是合法 JSON，能原样反序列化回来（没有注入伪造字段）
        let back: AttackLog = serde_json::from_str(&json).unwrap();
        assert_eq!(back.username, evil);
    }

    #[test]
    fn newline_injection_does_not_break_jsonl_lines() {
        // 攻击者在 details 里塞换行，试图伪造下一条日志行
        let evil = "normal\n{\"fake\":\"log\",\"injected\":true}";
        let entry = AttackLog {
            timestamp: "2026-01-01T00:00:00Z".into(),
            attack_id: "A1".into(),
            source_ip: "1.2.3.4".into(),
            country_name: "CN".into(),
            username: "root".into(),
            auth_method: "password".into(),
            success: true,
            attack_type: "ssh_brute_force".into(),
            details: evil.into(),
            user_agent: "ssh_client".into(),
            target_port: 22,
        };
        let json = serde_json::to_string(&entry).unwrap();
        // 序列化结果必须是单行（\n 被转义为 \\n）
        assert!(!json.lines().nth(1).is_some(), "JSON 不得含裸换行: {json}");
        assert!(json.contains("\\n"));
    }
}
