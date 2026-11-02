//! 代理协议管控（M3）：hub 经 WebSocket 下发的 sing-box 生命周期命令。
//!
//! 设计文档 5.4：apply_config 先写临时文件、`sing-box check` 校验、原子替换、
//! 再重启；校验不过不碰正在运行的服务。进程守护分两路：有 systemd 时交给
//! `monitor-singbox@main` 单元（Restart=always），否则 agent 自己拉起子进程。
//! 期望状态（开/关）落在磁盘的 desired 文件里，agent 重启后据此恢复。
//!
//! 本文件只留三样：①方法分发（run() 的 match，白名单在 main.rs route()）；
//! ②跨子系统共享的小工具（unit_active / run_cmd / hex / systemd 探测）；
//! ③聚合帧组装（hash_frame / stats_frame / status）。各子系统在子模块：
//! singbox（核心生命周期）/ relay（realm 转发执行器）/ gost（隧道）/
//! events（连接事件流）/ probe（网络探测）/ fetch（发布包下载与落位）。

mod events;
mod fetch;
mod gost;
mod probe;
mod relay;
mod singbox;

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// One apply at a time, so two overlapping requests cannot interleave their
/// file swaps. sing-box 与 realm/gost 的 apply 各用各的锁（子模块内），
/// 这里是 sing-box 主锁：proxy.apply_config 与 relay.apply 旧协议臂共用，
/// 防 hub 侧过渡期两类推送交错写盘。
async fn main_apply_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    let lock = LOCK.get_or_init(|| tokio::sync::Mutex::new(()));
    lock.lock().await
}

fn systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

/// 进程守护走哪条路：有 systemd 交给单元，否则 agent 自己看。main 据此决定
/// 是否拉起守护任务。
pub(crate) fn has_systemd() -> bool {
    systemd()
}

/// Where this agent keeps its sing-box binary, config and state. Re-exported:
/// main.rs（sub-dist 缓存落点）与 shaper.rs（shaper.json 落点）共用它。
pub(crate) use singbox::base_dir;

/// Re-exported for main.rs: 常驻订阅 sing-box api 连接事件流（dev 模式）与
/// 每 5s drain 连接日志帧。
pub use events::{api_events_loop, connection_logs_frame};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// systemd 单元是否在跑。is-active 用退出码判（--quiet 无输出）：`Ok(_)`
/// 只代表命令执行了——inactive 是 exit 3，必须 status.success()。曾 4 处
/// 同款误判导致拉活 poke 空转（eac4e56），tests/unit_active_guard.rs 保证
/// 直接调 is-active 只许出现在这里。
async fn unit_active(unit: &str) -> bool {
    matches!(run_cmd("systemctl", &["is-active", "--quiet", unit]).await, Ok(out) if out.status.success())
}

async fn run_cmd(program: &str, args: &[&str]) -> Result<std::process::Output> {
    tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("无法运行 {program} {}", args.join(" ")))
}

/// The hash report the agent sends on connect and every minute; the hub
/// compares it against its desired config and re-pushes on drift.
/// relay_units 捎带每 unit 的 {sha256, active}（喂转发页徽标；老 hub 忽略
/// 此字段）。relay_hash = 机器级指纹（信封聚合或旧 main 文件，见 realm_hash）。
pub async fn hash_frame() -> Message {
    Message::Text(
        serde_json::json!({
            "jsonrpc": "2.0", "method": "proxy.hash",
            "params": {"hash": singbox::local_hash(), "relay_hash": relay::realm_hash(), "relay_units": relay::realm_units_snapshot().await, "gost_hash": gost::gost_hash(), "version": singbox::singbox_version_cached()},
        })
        .to_string()
        .into(),
    )
}

/// 汇总一帧推给 hub（proxy.stats）：节点级 tags 与用户级 users 都来自
/// sing-box api 事件流聚合（events::api_events_loop），这里只 drain。
/// （M15 前节点级走 clash_api /connections 差分——对亚秒级短连接有盲区，
/// 实测 20MB/0.3s 的下载整段漏记，故整体切换到事件流 inbound 维度。）
pub async fn stats_frame() -> Option<Message> {
    let tags: serde_json::Map<String, serde_json::Value> = events::drain_api_tag_deltas()
        .into_iter()
        .map(|(t, (rx, tx))| (t, serde_json::json!([rx, tx])))
        .collect();
    // 用户级（M12）：api_events_loop 常驻订阅 sing-box api 连接事件流，
    // 这里只 drain 它聚合好的增量（含短连接关闭事件，无盲区）。
    let users = events::drain_api_user_deltas();
    if tags.is_empty() && users.is_empty() {
        return None;
    }
    let users_json: serde_json::Map<String, serde_json::Value> =
        users.into_iter().map(|(n, v)| (n, serde_json::json!(v))).collect();
    Some(Message::Text(
        serde_json::json!({
            "jsonrpc": "2.0", "method": "proxy.stats",
            "params": {"tags": tags, "users": users_json},
        })
        .to_string()
        .into(),
    ))
}

/// Handles one hub request. Everything runs in a spawned task — an install
/// downloads tens of megabytes and must not stall the read loop — and answers
/// on the same outbound channel the probes use.
pub fn dispatch(
    method: String,
    params: serde_json::Value,
    id: Option<String>,
    result_tx: &mpsc::Sender<Message>,
) {
    let Some(id) = id else { return };
    let tx = result_tx.clone();
    tokio::spawn(async move {
        let outcome = run(&method, params).await;
        let frame = match outcome {
            Ok(result) => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(e) => {
                if method == "proxy.apply_config" {
                    for (i, frame_err) in e.chain().enumerate() {
                        eprintln!("[proxy] chain[{i}] {frame_err}");
                    }
                }
                eprintln!("[proxy] {method} failed: {e:#}");
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": "PROXY_ERROR", "message": format!("{e:#}")},
                })
            }
        };
        let _ = tx.send(Message::Text(frame.to_string().into())).await;
    });
}

/// 三个 apply 臂（proxy.apply_config / relay.apply 旧协议 / gost.apply）
/// 共享的指纹比对小段：want 非空且不等 → 同句报错（hub 侧按文案分类）。
/// want 为空 = 旧 hub 不带指纹，放行。**空体短路不在本函数**：relay/gost
/// 的空体语义（停服清文件 / relay 还要多删 envelope.hash）是真差异，留在
/// 各调用臂——这里只收「比对+报错」，别把语义差异抽象掉。
fn verify_sha(want: &str, got: &str) -> Result<()> {
    if !want.is_empty() && want != got {
        bail!("配置指纹不符：期望 {want}，收到 {got}");
    }
    Ok(())
}

async fn run(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    match method {
        "proxy.core.install" => {
            let version = singbox::install(params["version"].as_str().map(str::to_owned)).await?;
            Ok(serde_json::json!({ "version": version }))
        }
        "proxy.apply_config" => {
            let _guard = main_apply_guard().await;
            let body = params["config"].as_str().context("缺少 config")?.to_owned();
            // proxy.apply_config 无空体语义：指纹必比（与 relay/gost 的
            // 「空体短路指纹」差异是真差异，见 verify_sha）。
            let got = hex(&Sha256::digest(body.as_bytes()));
            verify_sha(params["sha256"].as_str().unwrap_or_default(), &got)?;
            singbox::apply(body, params["desired_running"].as_bool().unwrap_or(true), &got).await?;
            Ok(serde_json::json!({ "hash": got }))
        }
        "proxy.core.status" => Ok(status().await),
        "proxy.core.set_desired" => {
            let running = params["running"].as_bool().unwrap_or(true);
            singbox::write_desired(running)?;
            if systemd() {
                let action = if running { "start" } else { "stop" };
                run_cmd("systemctl", &[action, singbox::UNIT_NAME]).await?;
            } else if running {
                singbox::spawn_child().await?;
            } else {
                singbox::stop_child().await;
            }
            Ok(serde_json::json!({ "ok": true }))
        }
        "proxy.core.uninstall" => {
            singbox::write_desired(false)?;
            if systemd() {
                let _ = run_cmd("systemctl", &["stop", singbox::UNIT_NAME]).await;
            } else {
                singbox::stop_child().await;
            }
            let _ = std::fs::remove_file(singbox::bin_path());
            let _ = std::fs::remove_file(singbox::config_path());
            Ok(serde_json::json!({ "ok": true }))
        }
        "relay.install" => {
            let version = relay::install(params["version"].as_str().map(str::to_owned)).await?;
            Ok(serde_json::json!({ "version": version }))
        }
        // 只拉起不碰配置的 poke（批次1b 独立方法）：曾借道 relay.apply 靠
        // __noop__ 字面量+空 sha+ensure_started 三暗号区分——检查顺序就是
        // 约定，检查顺序就是事故（字面量曾被旧版当配置写盘）。
        "relay.ensure_started" => {
            relay::ensure_started().await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "relay.apply" => {
            let _guard = main_apply_guard().await;
            // 双格式过渡（hub 先 agent 后的部署序）：units 数组 = 机器级信封
            // （逐 unit diff）；config 字符串 = 旧整份 toml（main 单 unit）。
            if params["units"].is_array() {
                let units = params["units"].as_array().cloned().unwrap_or_default();
                let want = params["sha256"].as_str().unwrap_or_default();
                let got = relay::apply_envelope(units, want).await?;
                Ok(serde_json::json!({ "hash": got }))
            } else {
                let body = params["config"].as_str().context("缺少 config")?.to_owned();
                // 空体语义（停服清文件）是真差异：空体指纹恒为空串、跳过比对
                // ——比对收口在 verify_sha，空体短路留在这里。
                let got = if body.is_empty() { String::new() } else { hex(&Sha256::digest(body.as_bytes())) };
                verify_sha(params["sha256"].as_str().unwrap_or_default(), &got)?;
                let desired = params["desired_running"].as_bool().unwrap_or(true);
                relay::apply_legacy(body, desired, &got).await?;
                Ok(serde_json::json!({ "hash": got }))
            }
        }
        "relay.probe" => {
            let result = probe::dispatch_probe(method, &params).await;
            Ok(result)
        }
        // gost 转发/隧道：与 relay.apply 同构（指纹校验 + 幂等短路在文件层），
        // 应用走热重载——未变更规则的已建立连接不受影响（批次0 spike 实测）。
        "gost.apply" => {
            let _guard = gost::apply_lock().await;
            let body = params["config"].as_str().context("缺少 config")?.to_owned();
            // 空体语义（gost 空期望=停服清文件）是真差异：空体指纹恒为空串、
            // 跳过比对——比对收口在 verify_sha，空体短路留在这里。
            let got = if body.is_empty() { String::new() } else { hex(&Sha256::digest(body.as_bytes())) };
            verify_sha(params["sha256"].as_str().unwrap_or_default(), &got)?;
            let desired = params["desired_running"].as_bool().unwrap_or(true);
            gost::apply(body, desired, &got).await?;
            Ok(serde_json::json!({ "hash": got }))
        }
        "gost.ensure_started" => {
            gost::ensure_started().await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "gost.install" => {
            let version = gost::install(params["version"].as_str().map(str::to_owned)).await?;
            Ok(serde_json::json!({ "version": version }))
        }
        "net.http_probe" => {
            let result = probe::dispatch_probe(method, &params).await;
            Ok(result)
        }
        "shaper.apply" => crate::shaper::apply(&params).await,
        other => bail!("未知方法 {other}"),
    }
}

async fn status() -> serde_json::Value {
    let installed = singbox::bin_installed();
    let version = if installed { singbox::detect_version().await.unwrap_or_default() } else { String::new() };
    let desired = singbox::desired();
    let running = singbox::running_or_orphaned().await;
    // Realm 状态（M5）
    let realm_installed = relay::bin_installed();
    let realm_version = relay::version_string().await;
    let realm_running = relay::api_process_active().await && realm_installed;
    let gost_installed = gost::bin_installed();
    serde_json::json!({
        "installed_version": version,
        "running": running && desired,
        "desired": desired,
        "hash": singbox::local_hash(),
        "listen_ports": [],
        "realm_version": realm_version,
        "realm_running": realm_running,
        "realm_units": relay::realm_units_snapshot().await,
        "gost_version": gost::gost_version_string().await,
        "gost_running": gost_installed && gost::active().await,
    })
}

/// Without systemd this agent supervises the children itself: a task checks
/// every two seconds and restarts them while the desired state says on.
/// systemd 副本由 Restart=always 承担同样的职责。三套子进程槽各随子系统走：
/// sing-box 与 realm-api 在这里轮询，gost 的 dev 子进程由 apply/ensure
/// 生命周期管理（无常驻）。
pub async fn supervisor() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let mut backed_off = false;
        if singbox::supervise_tick().await.is_err() {
            // 起不来（典型：端口被孤儿占用）就退避，避免每 2s 空转。
            backed_off = true;
        }
        relay::supervise_tick();
        if backed_off {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

/// MONITOR_PROXY_DIR 是进程级环境变量：proxy 各子模块所有隔离落点的测试
/// 共用这把锁串行执行，防止并行测试互相改掉对方的环境。拆分前是 proxy.rs
/// tests 单模块内的一把锁，拆分后必须继续跨子模块共享。
#[cfg(test)]
pub(crate) mod testutil {
    pub static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
}
