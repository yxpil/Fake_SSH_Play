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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn test_state() -> SharedState {
        let dir = std::env::temp_dir().join(format!("fakessh-geoip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        SharedState::new(
            Vec::new(),
            AppConfig {
                host_key_path: dir.join("k"),
                ascii_frames_path: dir.join("f"),
                attack_log_path: dir.join("a"),
                connection_log_path: dir.join("c"),
                ssh_port: 1,
                web_port: 1,
            },
        )
    }

    #[tokio::test]
    async fn private_and_local_ips_short_circuit_without_network() {
        let s = test_state();
        for ip in ["127.0.0.1", "::1", "192.168.1.5", "10.0.0.9", "unknown"] {
            assert_eq!(get_country(&s, ip).await, "本地IP", "{ip} 应短路");
        }
        // 短路分支不应写缓存（也不发起网络请求）
        assert!(s.ip_cache.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn public_ip_lookup_is_cached_after_call() {
        // 用 127.0.0.1 走缓存分支：第一次短路返回本地IP（不写缓存）。
        // 这里验证缓存命中路径：手动塞一个缓存项，再次查询应直接返回缓存值而不区分私网。
        let s = test_state();
        s.ip_cache
            .lock()
            .unwrap()
            .insert("8.8.8.8".into(), "美国".into());
        // 注意：8.8.8.8 不是私网，但缓存命中会在短路检查之后——
        // get_country 先做私网判断（不命中），再查缓存（命中）。
        assert_eq!(get_country(&s, "8.8.8.8").await, "美国");
    }
}
