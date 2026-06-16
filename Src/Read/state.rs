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
