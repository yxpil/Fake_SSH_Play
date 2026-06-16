// IP geolocation via ipip.yxpil.com — cached in SharedState, LRU eviction at MAX_IP_CACHE.
use std::time::Duration;

use serde::Deserialize;
use tracing::warn;

use crate::config::{IP_API, MAX_IP_CACHE};
use crate::state::SharedState;

pub async fn get_country(state: &SharedState, ip: &str) -> String {
    // Short-circuit private/local addresses — no API call needed.
    if ip == "unknown"
        || ip == "127.0.0.1"
        || ip.starts_with("192.168.")
        || ip.starts_with("10.")
        || ip.starts_with("172.")
        || ip == "::1"
    {
        return "本地IP".into();
    }

    // Cache hit: return immediately.
    {
        let cache = state.ip_cache.lock().unwrap();
        if let Some(n) = cache.get(ip) {
            return n.clone();
        }
    }

    // Cache full → evict oldest half.
    {
        let mut cache = state.ip_cache.lock().unwrap();
        if cache.len() >= MAX_IP_CACHE {
            let keys: Vec<String> = cache.keys().take(MAX_IP_CACHE / 2).cloned().collect();
            for k in keys {
                cache.remove(&k);
            }
        }
    }

    let url = format!("{}{}", IP_API, ip);
    match reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(3))
        .header("User-Agent", "SSH-Honeypot/1.0")
        .send()
        .await
    {
        Ok(resp) => {
            #[derive(Deserialize)]
            struct R {
                classification: Option<C>,
            }
            #[derive(Deserialize)]
            struct C {
                #[serde(rename = "countryName")]
                country_name: Option<String>,
            }
            let name = resp
                .json::<R>()
                .await
                .ok()
                .and_then(|r| r.classification)
                .and_then(|c| c.country_name)
                .unwrap_or_else(|| "未知地区".into());
            state.ip_cache.lock().unwrap().insert(ip.to_string(), name.clone());
            name
        }
        Err(e) => {
            warn!("IP lookup failed for {}: {}", ip, e);
            state
                .ip_cache
                .lock()
                .unwrap()
                .insert(ip.to_string(), "未知地区".into());
            "未知地区".into()
        }
    }
}
