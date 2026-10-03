//! 启动引导 / 错误路径 集成测试
//!
//! 二进制是 SSH 蜜罐，启动需要 host_rsa.key 与 FAKESSH.txt。这里在一个空临时目录里
//! 拉起真实二进制，验证它在缺少 host key 时**干净地报错退出**（而不是 panic / 监听端口 /
//! 静默挂起）。这是对真实进程启动路径的冒烟测试。
//!
//! 运行：cargo test --test bootstrap_smoke -- --nocapture

use std::process::{Command, Stdio};

#[test]
fn exits_cleanly_when_host_key_missing() {
    let dir = std::env::temp_dir().join(format!("fakessh-bootstrap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_fakesshplay"))
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("无法启动 fakesshplay 二进制");

    // 应非零退出
    assert!(!out.status.success(), "缺 host key 时应非零退出");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stderr}{stdout}");
    assert!(
        combined.contains("Host key not found"),
        "应提示 host key 缺失，实际: {combined}"
    );
    // 不应在当前目录留下随机产物
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.ok()).flatten().collect();
    assert!(
        entries.is_empty(),
        "引导失败时不应创建文件，实际留下: {:?}",
        entries
    );

    let _ = std::fs::remove_dir_all(&dir);
}
