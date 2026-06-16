// Web dashboard — axum server with ECharts-powered stats page.
// Matches the Node version's /api/logs/stats JSON shape exactly.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use axum::{extract::State, response::Html, routing::get, Json, Router};
use serde::Serialize;
use tracing::info;

use crate::config::IP_API;
use crate::state::{AccessLogEntry, SharedState};

#[derive(Serialize)]
struct Stats {
    code: u16,
    data: StatsData,
}

#[derive(Serialize)]
struct StatsData {
    pie: Vec<PieItem>,
    #[serde(rename = "ipPie")]
    ip_pie: Vec<PieItem>,
    #[serde(rename = "countryPie")]
    country_pie: Vec<PieItem>,
    timeline: Vec<AccessLogEntry>,
    #[serde(rename = "totalAttacks")]
    total_attacks: u64,
    #[serde(rename = "activeConnections")]
    active_connections: usize,
    #[serde(rename = "totalDataTransferred")]
    total_data_transferred: String,
    #[serde(rename = "ipCacheCount")]
    ip_cache_count: usize,
}

#[derive(Serialize)]
struct PieItem {
    name: String,
    value: u64,
}

// GET /api/logs/stats — returns last 100 log entries + aggregated pie data.
async fn api_stats(State(state): State<Arc<SharedState>>) -> Json<Stats> {
    let log = state.access_log.lock().unwrap();
    let recent: Vec<AccessLogEntry> = log.iter().rev().take(100).cloned().collect();
    drop(log);

    let mut auth_methods: HashMap<String, u64> = HashMap::new();
    let mut ips: HashMap<String, u64> = HashMap::new();
    let mut countries: HashMap<String, u64> = HashMap::new();

    for e in &recent {
        if e.log_type == "attack" {
            if let Some(ref m) = e.auth_method {
                *auth_methods.entry(m.clone()).or_default() += 1;
            }
        }
        if e.source_ip != "unknown" {
            *ips.entry(e.source_ip.clone()).or_default() += 1;
        }
        *countries.entry(e.country_name.clone()).or_default() += 1;
    }

    let to_pie = |m: HashMap<String, u64>| -> Vec<PieItem> {
        let mut v: Vec<_> = m
            .into_iter()
            .map(|(n, v)| PieItem { name: n, value: v })
            .collect();
        if v.is_empty() {
            v.push(PieItem {
                name: "暂无数据".into(),
                value: 1,
            });
        }
        v
    };

    Json(Stats {
        code: 200,
        data: StatsData {
            pie: to_pie(auth_methods),
            ip_pie: to_pie(ips),
            country_pie: to_pie(countries),
            timeline: recent,
            total_attacks: state.attack_counter.load(Ordering::SeqCst),
            active_connections: state.active_count(),
            total_data_transferred: format!(
                "{:.2}",
                state.total_data.load(Ordering::SeqCst) as f64 / 1024.0
            ),
            ip_cache_count: state.ip_cache.lock().unwrap().len(),
        },
    })
}

// GET / — serve the ECharts dashboard HTML.
async fn index_page() -> Html<String> {
    Html(include_str!("../dashboard.html").to_string())
}

pub async fn start_web(state: Arc<SharedState>) -> Result<()> {
    let app = Router::new()
        .route("/", get(index_page))
        .route("/api/logs/stats", get(api_stats))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], state.config.web_port));
    info!("Web dashboard: http://0.0.0.0:{}", state.config.web_port);
    info!("IP geolocation API: {}", IP_API);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
