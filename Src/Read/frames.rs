// Frame loader — detects format automatically.
// Two formats supported:
//   1. badapple_ascii.txt  →  ---FRAME_SEPARATOR---
//   2. FAKESSH.txt         →  === FRAME NNNNN === headers with ==== borders
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

pub fn load_frames(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Cannot read {}", path.display()))?;

    // Format 1: traditional Bad Apple separator
    if content.contains("---FRAME_SEPARATOR---") {
        let frames: Vec<String> = content
            .split("---FRAME_SEPARATOR---\n")
            .map(|s| s.trim_end().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        info!(
            "Loaded {} frames (FRAME_SEPARATOR format) from {}",
            frames.len(),
            path.display()
        );
        return Ok(frames);
    }

    // Format 2: FAKESSH.txt — frame headers + border lines
    if content.contains("=== FRAME ") {
        let frames = parse_fakessh(&content);
        info!(
            "Loaded {} frames (FAKESSH format) from {}",
            frames.len(),
            path.display()
        );
        return Ok(frames);
    }

    anyhow::bail!("Unknown frame format in {}", path.display());
}

/// Extract frames from FAKESSH.txt: skip border lines, split on frame headers.
fn parse_fakessh(content: &str) -> Vec<String> {
    let mut frames = Vec::new();
    let mut current = Vec::new();
    let mut in_frame = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("=== FRAME") && trimmed.ends_with("===") {
            if in_frame && !current.is_empty() {
                frames.push(current.join("\n"));
            }
            current = Vec::new();
            in_frame = true;
            continue;
        }

        if trimmed.chars().all(|c| c == '=') && trimmed.len() > 10 {
            continue;
        }

        if in_frame {
            current.push(line.to_string());
        }
    }

    if in_frame && !current.is_empty() {
        frames.push(current.join("\n"));
    }

    frames
}
