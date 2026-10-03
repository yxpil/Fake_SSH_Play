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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fakessh-frames-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("frames.txt");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn loads_frame_separator_format() {
        let body = "AAA\n---FRAME_SEPARATOR---\nBBB\n---FRAME_SEPARATOR---\nCCC\n";
        let p = tmp("sep", body);
        let frames = load_frames(&p).unwrap();
        assert_eq!(frames, vec!["AAA", "BBB", "CCC"]);
    }

    #[test]
    fn separator_format_drops_empty_frames() {
        let body = "AAA\n---FRAME_SEPARATOR---\n---FRAME_SEPARATOR---\nBBB\n";
        let p = tmp("sepempty", body);
        let frames = load_frames(&p).unwrap();
        // 空帧被 filter 掉
        assert_eq!(frames, vec!["AAA", "BBB"]);
    }

    #[test]
    fn loads_fakessh_format_and_skips_borders() {
        let body = concat!(
            "=== FRAME 00001 ===\n",
            "================================\n",   // 长 = 边框行（>10），应跳过
            "row1\n",
            "row2\n",
            "=== FRAME 00002 ===\n",
            "================================\n",
            "row3\n",
        );
        let p = tmp("fakessh", body);
        let frames = load_frames(&p).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], "row1\nrow2");
        assert_eq!(frames[1], "row3");
    }

    #[test]
    fn unknown_format_errors() {
        let p = tmp("unknown", "just some plain text without any markers\n");
        assert!(load_frames(&p).is_err());
    }

    #[test]
    fn missing_file_errors() {
        let p = Path::new("definitely-not-here-fakessh-xyz.txt");
        assert!(load_frames(p).is_err());
    }
}
