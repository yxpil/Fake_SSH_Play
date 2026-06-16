# Fake SSH Play

SSH ASCII Art Honeypot — accepts ALL SSH connections and plays [Bad Apple](https://en.wikipedia.org/wiki/Bad_Apple!!) frame-by-frame in the terminal. Built in Rust for maximum performance.

> 假的 SSH，只能放视频的那种 🍎

## Architecture

```
Src/
├── main.rs              # Entry point, daemon restart loop
├── Control/
│   ├── ssh.rs           # SSH server (russh) — accepts all auth
│   └── web.rs           # Web dashboard (axum) — ECharts stats
├── Read/
│   ├── config.rs        # Constants & paths
│   ├── state.rs         # Shared state, logging, concurrency
│   └── frames.rs        # ASCII frame loader (auto-detect format)
└── Tools/
    └── geoip.rs         # IP geolocation via ipip.yxpil.com
```

## Features

- **SSH Honeypot** — accepts ALL authentication, plays animation at 30 FPS
- **Web Dashboard** — ECharts-powered stats on port 763 (`/api/logs/stats`)
- **IP Geolocation** — auto-lookup attacker country
- **Daemon Restart** — auto-restarts on crash (up to 10 times)
- **Cross-platform** — macOS (ARM), Linux (x86_64), Windows (x86_64)
- **Two frame formats** — `---FRAME_SEPARATOR---` and `=== FRAME NNNNN ===`

## Download

Pre-built binaries for [v1.0.0](https://github.com/yxpil/Fake_SSH_Play/releases/tag/v1.0.0-rust):

| Platform | Binary |
|---|---|
| macOS (Apple Silicon) | [fakesshplay](https://github.com/yxpil/Fake_SSH_Play/releases/download/v1.0.0-rust/fakesshplay) |
| Linux (x86_64) | [fakesshplay-linux](https://github.com/yxpil/Fake_SSH_Play/releases/download/v1.0.0-rust/fakesshplay-linux) |
| Windows (x86_64) | [fakesshplay.exe](https://github.com/yxpil/Fake_SSH_Play/releases/download/v1.0.0-rust/fakesshplay.exe) |

[Old JS version (v0.1.0)](https://github.com/yxpil/Fake_SSH_Play/releases/tag/v0.1.0-js) — original Node.js SSH audio honeypot.

## Quick Start

```bash
# Generate host key
ssh-keygen -t rsa -f host_rsa.key -N ''

# Build
cargo build --release

# Run (requires root for port 22)
sudo ./target/release/fakesshplay
```

## Requirements

- `host_rsa.key` — SSH host key (generate with ssh-keygen)
- `FAKESSH.txt` — ASCII animation frames

## API

| Endpoint | Description |
|---|---|
| `GET /` | Web dashboard (ECharts) |
| `GET /api/logs/stats` | JSON stats (attacks, countries, timeline) |

## License

MIT
