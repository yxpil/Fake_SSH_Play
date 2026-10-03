# Fake_SSH_Play 测试说明

ASCII Art SSH 蜜罐。本 crate 为纯二进制（无 lib target），测试分两部分。

## 测试约定

- **单元测试**：`Src/**/*.rs` 内 `#[cfg(test)] mod tests`（直接访问私有项）。
- **集成测试**：仓库根 `tests/`。由于二进制启动需要 host key + FAKESSH.txt 且 SSH 绑定特权端口 22，
  集成测试改为对真实二进制做**启动引导/错误路径冒烟**（子进程）。

## 运行命令

```powershell
cargo test                 # 全部
cargo test --bins          # 仅单元测试
cargo test --test bootstrap_smoke   # 仅集成
```

## 覆盖清单

### 单元测试（共 15 个）

| 模块 | 覆盖点 |
|---|---|
| `Read/frames.rs` | 两种帧格式自动识别（`---FRAME_SEPARATOR---` 与 `=== FRAME N ===`）、空帧过滤、长 `=` 边框行跳过、未知格式报错、文件缺失报错 |
| `Read/state.rs` | `next_attack_id` 单调递增且零填充、连接集合增删计数、`add_data` 累加、`safe_append` 写盘（单行追加）、`log_attack`/`log_conn` 按序入访问日志环 |
| `Tools/geoip.rs` | 私网/本地 IP（127.0.0.1/::1/192.168./10./unknown）短路返回“本地IP”且不触网、缓存命中直接返回 |

### 集成测试（`tests/bootstrap_smoke.rs`，共 1 个）

- `exits_cleanly_when_host_key_missing`：在空临时目录拉起真实二进制，缺少 host key 时应**非零退出、
  打印 `Host key not found`、不残留任何文件**（不 panic、不静默挂起、不监听端口）。

## 注入测试（输入被转义/拒绝，不透传）

- **JSON 注入**：攻击者可控的 `username` 含双引号试图闭合 JSON 字符串注入伪造字段——
  `quote_in_username_is_json_escaped` 断言内部 `"` 被转义为 `\"`，整串仍为合法 JSON 且能原样反序列化。
- **日志行注入**：`details` 内嵌 `\n` 与伪造 JSON——`newline_injection_does_not_break_jsonl_lines`
  断言序列化结果为单行（`\n` 被转义），不能伪造下一条日志记录。
- 注：XSS 的最终防御在前端（dashboard 经 `JSON.parse` 后以文本方式渲染）；本层保证日志是合法、可往返的 JSON。

## 钩子 / 事件测试

- 蜜罐的“事件回调”即 `log_attack` / `log_conn`：分别向内存访问日志环写入 attack / connection 两类条目，
  `log_attack_and_conn_push_access_log_in_order` 验证注册顺序与字段（auth_method / event）正确传递。
- **失败隔离**：`safe_append_bad_path_does_not_panic_failure_isolation` 验证磁盘日志写入失败
  （目标是目录）时仅告警、不 panic，SSH 任务不会因此崩溃。

## 预期结果

- `cargo test --bins`：**15 passed, 0 failed**。
- `cargo test --test bootstrap_smoke`：**1 passed, 0 failed**。
