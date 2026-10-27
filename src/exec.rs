//! 远程命令执行（五期 MCP）：hub 的 MCP 租约经过 OAuth 授权后，AI 客户端可
//! 以在节点上跑一次性的 shell 命令。超时钳制 1–120 秒（默认 30），输出每流
//! 封顶 64 KB——AI 客户端的上下文放不下也不该放无界输出。
//!
//! 安全边界：agent 不做鉴权（ws 通道本身就是 root 通道，与配置下发同信
//! 任域），开关与审计都在 hub 侧（mcp_enabled + 操作审计）。

use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};

const MAX_OUTPUT: usize = 64 * 1024;

pub async fn run(params: Value) -> Result<Value, anyhow::Error> {
    let command = params["command"].as_str().ok_or_else(|| anyhow::anyhow!("缺少 command"))?.trim();
    if command.is_empty() {
        return Err(anyhow::anyhow!("command 不能为空"));
    }
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(30_000).clamp(1_000, 120_000);
    // sh -c 而非 exec：管道、重定向、多命令是远程运维的常态。
    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn 失败：{e}"))?;
    let output = tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait_with_output())
        .await
        .map_err(|_| anyhow::anyhow!("命令超过 {timeout_ms}ms 超时被终止"))?
        .map_err(|e| anyhow::anyhow!("执行失败：{e}"))?;
    let cap = |bytes: &[u8]| -> String {
        let bytes = &bytes[..bytes.len().min(MAX_OUTPUT)];
        String::from_utf8_lossy(bytes).into_owned()
    };
    Ok(json!({
        "exit_code": output.status.code().unwrap_or(-1),
        "stdout": cap(&output.stdout),
        "stderr": cap(&output.stderr),
    }))
}

/// 与 proxy::dispatch 同形的入口。
pub fn dispatch(
    method: String,
    params: Value,
    id: Option<String>,
    result_tx: &tokio::sync::mpsc::Sender<tokio_tungstenite::tungstenite::Message>,
) {
    let Some(id) = id else { return };
    let tx = result_tx.clone();
    tokio::spawn(async move {
        let outcome = run(params).await;
        let frame = match outcome {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(e) => {
                eprintln!("[exec] {method} failed: {e:#}");
                json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": "EXEC_ERROR", "message": format!("{e:#}")},
                })
            }
        };
        let _ = tx.send(tokio_tungstenite::tungstenite::Message::Text(frame.to_string().into())).await;
    });
}
