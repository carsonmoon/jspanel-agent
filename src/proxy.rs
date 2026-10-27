//! 代理协议管控（M3）：hub 经 WebSocket 下发的 sing-box 生命周期命令。
//!
//! 设计文档 5.4：apply_config 先写临时文件、`sing-box check` 校验、原子替换、
//! 再重启；校验不过不碰正在运行的服务。进程守护分两路：有 systemd 时交给
//! `monitor-singbox@main` 单元（Restart=always），否则 agent 自己拉起子进程。
//! 期望状态（开/关）落在磁盘的 desired 文件里，agent 重启后据此恢复。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Where this agent keeps its sing-box binary, config and state. /opt on a
/// real deployment; a local directory wherever systemd cannot be found, which
/// is also where a macOS hub runs its stand-in agent.
pub(crate) fn base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MONITOR_PROXY_DIR") {
        return PathBuf::from(dir);
    }
    // install.sh 固定把核心装在 /opt/monitor-proxy；Windows 之外一律用它，
    // 相对目录只留给本机联调（MONITOR_PROXY_DIR 显式指定）。
    PathBuf::from("/opt/monitor-proxy")
}

fn bin_path() -> PathBuf {
    base_dir().join("bin").join("sing-box")
}

fn config_path() -> PathBuf {
    base_dir().join("instances").join("main").join("config.json")
}

fn desired_path() -> PathBuf {
    base_dir().join("desired")
}

/// Where the sing-box releases are published. Forking implies rebuilding this.
const SINGBOX_REPO: &str = "SagerNet/sing-box";

const UNIT_NAME: &str = "monitor-singbox@main";

fn systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

/// 进程守护走哪条路：有 systemd 交给单元，否则 agent 自己看。main 据此决定
/// 是否拉起守护任务。
pub(crate) fn has_systemd() -> bool {
    systemd()
}

/// One apply at a time, so two overlapping requests cannot interleave their
/// file swaps.
fn apply_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// The supervised child, where there is no systemd to do it for us.
fn child_slot() -> &'static Mutex<Option<tokio::process::Child>> {
    static CHILD: OnceLock<Mutex<Option<tokio::process::Child>>> = OnceLock::new();
    CHILD.get_or_init(|| Mutex::new(None))
}

/// 期望状态文件：hub 的每次 apply 都带着它；缺失视为 on。
fn desired() -> bool {
    std::fs::read_to_string(desired_path()).map(|s| s.trim() != "off").unwrap_or(true)
}

fn write_desired(running: bool) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(desired_path(), if running { "on" } else { "off" })?;
    Ok(())
}

/// hub 侧的配置指纹存在伴随文件里：apply 时本机会向 hub 下发的 body 注入
/// clash_api，文件字节与 hub 的期望不再一一对应，指纹以伴随文件为准。
fn local_hash() -> String {
    std::fs::read_to_string(config_path().with_extension("json.hash"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn write_local_hash(hash: &str) -> Result<()> {
    std::fs::write(config_path().with_extension("json.hash"), hash)?;
    Ok(())
}

/// 本机注入的 sing-box api service 端口。None = 尚未 apply 过。
fn api_listen() -> &'static Mutex<Option<u16>> {
    static V: OnceLock<Mutex<Option<u16>>> = OnceLock::new();
    V.get_or_init(|| Mutex::new(None))
}

/// agent 重启后从配置文件恢复注入的 api service 端口（无需等下一次 apply）。
fn restore_api() -> Option<u16> {
    let cached = *api_listen().lock().unwrap();
    if let Some(port) = cached {
        return Some(port);
    }
    let body = std::fs::read_to_string(config_path()).ok()?;
    let cfg: serde_json::Value = serde_json::from_str(&body).ok()?;
    let port = cfg
        .get("services")?
        .as_array()?
        .iter()
        .find(|sv| sv.get("type").and_then(|t| t.as_str()) == Some("api"))
        .and_then(|sv| sv.get("listen_port"))
        .and_then(|p| p.as_u64())? as u16;
    api_listen().lock().unwrap().replace(port);
    Some(port)
}

/// 在本机挑一个空闲的 api service 端口，与 clash_api 的候选段错开。
fn pick_api_port() -> Option<u16> {
    (19200..19300).find(|&p| std::net::TcpListener::bind(("127.0.0.1", p)).is_ok())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash report the agent sends on connect and every minute; the hub
/// compares it against its desired config and re-pushes on drift.
pub fn hash_frame() -> Message {
    Message::Text(
        serde_json::json!({
            "jsonrpc": "2.0", "method": "proxy.hash",
            "params": {"hash": local_hash(), "relay_hash": realm_hash(), "version": singbox_version_cached()},
        })
        .to_string()
        .into(),
    )
}

/// sing-box 版本随 60s 心跳捎带给 hub（喂协议页的版本过旧黄条）。进程内
/// 只探测一次：核心版本只在安装/切换后变化，而那之后 agent 会被重启，缓存
/// 随进程一起换新。
fn singbox_version_cached() -> String {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        std::process::Command::new(bin_path())
            .arg("version")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .and_then(|text| {
                text.lines().next().and_then(|line| line.split_whitespace().nth(2).map(str::to_owned))
            })
            .unwrap_or_default()
    })
    .clone()
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

async fn run(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    match method {
        "proxy.core.install" => {
            let version = install(params["version"].as_str().map(str::to_owned)).await?;
            Ok(serde_json::json!({ "version": version }))
        }
        "proxy.apply_config" => {
            let _guard = apply_lock().lock().await;
            let body = params["config"].as_str().context("缺少 config")?.to_owned();
            let want = params["sha256"].as_str().unwrap_or_default();
            let got = hex(&Sha256::digest(body.as_bytes()));
            if want != got {
                bail!("配置指纹不符：期望 {want}，收到 {got}");
            }
            apply(body, params["desired_running"].as_bool().unwrap_or(true), &got).await?;
            Ok(serde_json::json!({ "hash": got }))
        }
        "proxy.core.status" => Ok(status().await),
        "proxy.core.set_desired" => {
            let running = params["running"].as_bool().unwrap_or(true);
            write_desired(running)?;
            if systemd() {
                let action = if running { "start" } else { "stop" };
                run_cmd("systemctl", &[action, UNIT_NAME]).await?;
            } else if running {
                spawn_child().await?;
            } else {
                stop_child().await;
            }
            Ok(serde_json::json!({ "ok": true }))
        }
        "proxy.core.uninstall" => {
            write_desired(false)?;
            if systemd() {
                let _ = run_cmd("systemctl", &["stop", UNIT_NAME]).await;
            } else {
                stop_child().await;
            }
            let _ = std::fs::remove_file(bin_path());
            let _ = std::fs::remove_file(config_path());
            Ok(serde_json::json!({ "ok": true }))
        }
        "relay.install" => {
            let version = relay_install(params["version"].as_str().map(str::to_owned)).await?;
            Ok(serde_json::json!({ "version": version }))
        }
        // 只拉起不碰配置的 poke（批次1b 独立方法）：曾借道 relay.apply 靠
        // __noop__ 字面量+空 sha+ensure_started 三暗号区分——检查顺序就是
        // 约定，检查顺序就是事故（字面量曾被旧版当配置写盘）。
        "relay.ensure_started" => {
            ensure_realm_started().await?;
            Ok(serde_json::json!({ "ok": true }))
        }
        "relay.apply" => {
            let _guard = apply_lock().lock().await;
            let body = params["config"].as_str().context("缺少 config")?.to_owned();
            let want = params["sha256"].as_str().unwrap_or_default().to_owned();
            let got = if body.is_empty() { String::new() } else { hex(&Sha256::digest(body.as_bytes())) };
            if !want.is_empty() && want != got {
                bail!("配置指纹不符：期望 {want}，收到 {got}");
            }
            let desired = params["desired_running"].as_bool().unwrap_or(true);
            relay_apply(body, desired, &got).await?;
            Ok(serde_json::json!({ "hash": got }))
        }
        "relay.probe" => {
            let results = relay_probe(&params).await;
            Ok(serde_json::json!({ "results": results }))
        }
        "net.http_probe" => {
            let result = http_probe(&params).await;
            Ok(result)
        }
        "shaper.apply" => crate::shaper::apply(&params).await,
        other => bail!("未知方法 {other}"),
    }
}

// ---- install（设计文档 5.1：agent 直连下载，版本号 + 平台自动匹配）----

async fn install(version: Option<String>) -> Result<String> {
    let version = match version {
        Some(v) => {
            let v = v.trim().trim_start_matches('v').to_owned();
            if v.is_empty() || !v.chars().all(|c| c.is_ascii_digit() || c == '.') {
                bail!("版本号格式不对：{v}");
            }
            v
        }
        None => latest_version().await?,
    };
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => bail!("暂不支持在 {other} 上自动安装核心"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("暂不支持架构 {other}"),
    };
    let name = format!("sing-box-{version}-{os}-{arch}.tar.gz");
    let url = format!("https://github.com/{SINGBOX_REPO}/releases/download/v{version}/{name}");
    let client =
        reqwest::Client::builder().timeout(Duration::from_secs(300)).build().context("构建下载客户端失败")?;
    let bytes = client
        .get(url)
        .header("User-Agent", "monitor-agent")
        .send()
        .await
        .context("下载 sing-box 失败")?
        .error_for_status()
        .context("下载 sing-box 失败：远端返回错误")?
        .bytes()
        .await
        .context("读取下载内容失败")?;
    let bin = bin_path();
    tokio::fs::create_dir_all(bin.parent().expect("bin has a parent")).await?;
    // 临时名 + 原子替换，避免覆盖运行中的二进制（Linux ETXTBSY）。
    let staging = bin.with_extension("new");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if entry.header().entry_type().is_file() && path.file_name().is_some_and(|n| n == "sing-box") {
            entry.unpack(&staging)?;
            found = true;
        }
    }
    if !found {
        let _ = tokio::fs::remove_file(&staging).await;
        bail!("压缩包中没有找到 sing-box 可执行文件");
    }
    tokio::fs::rename(&staging, &bin).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    }
    if systemd() {
        write_unit()?;
        run_cmd("systemctl", &["daemon-reload"]).await?;
    }
    let detected = detect_version().await?;
    Ok(detected)
}

/// The systemd template unit（设计文档 5.7）。Written once; instance `%i` is
/// `main`, the one instance M3 runs per server.
fn write_unit() -> Result<()> {
    let unit = format!(
        "[Unit]\n\
         Description=monitor sing-box instance %i\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} run -c {}\n\
         Restart=always\n\
         RestartSec=3\n\
         LimitNOFILE=65535\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin_path().display(),
        config_path().display(),
    );
    let path = Path::new("/etc/systemd/system/monitor-singbox@.service");
    if !path.exists() {
        std::fs::write(path, unit)?;
    }
    Ok(())
}

async fn latest_version() -> Result<String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
    let v: serde_json::Value = client
        .get(format!("https://api.github.com/repos/{SINGBOX_REPO}/releases/latest"))
        .header("User-Agent", "monitor-agent")
        .send()
        .await
        .context("无法访问 GitHub")?
        .error_for_status()
        .context("GitHub 返回错误")?
        .json()
        .await
        .context("解析 GitHub 响应失败")?;
    let tag = v["tag_name"].as_str().unwrap_or_default().trim_start_matches('v').to_owned();
    if tag.is_empty() {
        bail!("无法获取 sing-box 最新版本号");
    }
    Ok(tag)
}

// ---- apply（设计文档 5.4：校验、原子替换、失败不动运行中的服务）----

/// systemd 单元是否在跑。is-active 用退出码判（--quiet 无输出）：`Ok(_)`
/// 只代表命令执行了——inactive 是 exit 3，必须 status.success()。曾 4 处
/// 同款误判导致拉活 poke 空转（eac4e56），tests/unit_active_guard.rs 保证
/// 直接调 is-active 只许出现在这里。
async fn unit_active(unit: &str) -> bool {
    matches!(run_cmd("systemctl", &["is-active", "--quiet", unit]).await, Ok(out) if out.status.success())
}

/// 核心当前运行态是否与 desired 一致（systemd 查单元，否则查子进程槽——
/// 判死语义与 supervisor 相同：try_wait 到退出码才算死）。
async fn running_state_is(desired: bool) -> bool {
    let running = if systemd() {
        unit_active(UNIT_NAME).await
    } else {
        child_slot().lock().unwrap().as_mut().map(|c| !matches!(c.try_wait(), Ok(Some(_)))).unwrap_or(false)
    };
    running == desired
}

async fn apply(body: String, desired_running: bool, hash: &str) -> Result<()> {
    write_desired(desired_running)?;
    // 指纹相同且核心运行态已与期望一致：无事可做，跳过写盘与重启。hub 有
    // 多条推送路径会盲推相同配置（每小时到期对账等，5 分钟去重窗口拦不住
    // 整点节奏），没有这个短路就会周期性 systemctl restart 打断所有代理连接。
    if hash == local_hash() && config_path().exists() && running_state_is(desired_running).await {
        return Ok(());
    }
    tokio::fs::create_dir_all(config_path().parent().expect("config has a parent")).await?;
    // hub 下发的配置不含 api service（M12）：本机自选空闲端口注入，连接
    // 事件流是用户级与节点级计量的唯一数据源。指纹校验针对 hub 的原始
    // body，注入在验证之后。（M3.5 的 clash_api 注入已随 M15 移除：轮询
    // 差分对亚秒级短连接有盲区，采样改走事件流。）
    let mut cfg: serde_json::Value = serde_json::from_str(&body).context("配置不是合法 JSON")?;
    if cfg.get("services").and_then(|sv| sv.as_array()).map(|a| a.is_empty()).unwrap_or(true) {
        let Some(port) = pick_api_port() else { bail!("本机没有可用的 api service 端口") };
        cfg["services"] = serde_json::json!([{ "type": "api", "listen": "127.0.0.1", "listen_port": port }]);
        api_listen().lock().unwrap().replace(port);
    }
    let body = serde_json::to_string_pretty(&cfg)?;
    let new_path = config_path().with_extension("json.new");
    tokio::fs::write(&new_path, &body).await?;
    let bin = bin_path();
    if !bin.is_file() {
        let _ = tokio::fs::remove_file(&new_path).await;
        bail!("sing-box 尚未安装，请先安装核心");
    }
    let out = tokio::process::Command::new(&bin)
        .arg("check")
        .arg("-c")
        .arg(&new_path)
        .output()
        .await
        .context("无法运行 sing-box check")?;
    if !out.status.success() {
        let _ = tokio::fs::remove_file(&new_path).await;
        let detail = String::from_utf8_lossy(&out.stderr);
        bail!("配置校验未通过：{}", detail.trim());
    }
    let last_good = config_path().with_extension("json.last_good");
    if config_path().exists() {
        tokio::fs::rename(config_path(), &last_good).await?;
    }
    tokio::fs::rename(&new_path, config_path()).await?;
    write_local_hash(hash)?;
    if systemd() {
        write_unit()?;
        run_cmd("systemctl", &["daemon-reload"]).await?;
        // 核心即将重启/停止：旧连接的 id 不会再有事件，先定稿并清空。
        reset_conn_state();
        let rs = run_cmd("systemctl", &[if desired_running { "restart" } else { "stop" }, UNIT_NAME]).await?;
        if !rs.status.success() {
            eprintln!("[proxy] systemctl restart failed: {}", String::from_utf8_lossy(&rs.stderr));
        }
    } else if desired_running {
        reset_conn_state();
        spawn_child().await?;
    } else {
        reset_conn_state();
        stop_child().await;
    }
    let _ = hash;
    Ok(())
}

async fn detect_version() -> Result<String> {
    let out =
        tokio::process::Command::new(bin_path()).arg("version").output().await.context("无法运行核心")?;
    if !out.status.success() {
        bail!("核心版本探测失败");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let v = text.lines().next().unwrap_or("").split_whitespace().nth(2).unwrap_or("").trim();
    if v.is_empty() {
        bail!("无法解析核心版本号");
    }
    Ok(v.to_owned())
}

async fn status() -> serde_json::Value {
    let installed = bin_path().is_file();
    let version = if installed { detect_version().await.unwrap_or_default() } else { String::new() };
    let desired = desired();
    let running = if systemd() {
        unit_active(UNIT_NAME).await
    } else {
        let ours = child_slot()
            .lock()
            .map(|mut c| c.as_mut().is_some_and(|c| c.try_wait().map_or(true, |w| w.is_none())))
            .unwrap_or(false);
        // 孤儿检测：上一个 agent 进程被硬杀时留下来的 sing-box 还在服务同一
        // 份配置——对「这个节点在不在跑」而言，它就是答案。
        let orphaned = !ours
            && config_path().exists()
            && std::process::Command::new("pgrep")
                .args(["-f", config_path().to_str().unwrap_or_default()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        ours || orphaned
    };
    // Realm 状态（M5）
    let realm_installed = realm_bin().is_file();
    let realm_version = if realm_installed {
        tokio::process::Command::new(realm_bin())
            .arg("--version")
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().nth(1).unwrap_or("").to_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let realm_running = if realm_installed {
        if systemd() {
            unit_active("monitor-realm@main").await
        } else {
            realm_child_slot()
                .lock()
                .map(|mut c| c.as_mut().is_some_and(|c| c.try_wait().map_or(true, |w| w.is_none())))
                .unwrap_or(false)
        }
    } else {
        false
    };
    serde_json::json!({
        "installed_version": version,
        "running": running && desired,
        "desired": desired,
        "hash": local_hash(),
        "listen_ports": [],
        "realm_version": realm_version,
        "realm_running": realm_running,
    })
}

async fn run_cmd(program: &str, args: &[&str]) -> Result<std::process::Output> {
    tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("无法运行 {program} {}", args.join(" ")))
}

/// Without systemd this agent supervises the child itself: a task checks every
/// two seconds and restarts it while the desired state says on. systemd 副本
/// 由 Restart=always 承担同样的职责。
pub async fn supervisor() {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !desired() || !config_path().exists() {
            continue;
        }
        let dead = {
            let mut slot = child_slot().lock().unwrap();
            match slot.as_mut() {
                Some(child) => matches!(child.try_wait(), Ok(Some(_))),
                None => true,
            }
        };
        if dead && spawn_child().await.is_err() {
            // 起不来（典型：端口被孤儿占用）就退避，避免每 2s 空转。
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        // Realm 子进程守护：配置存在且进程不在就重新拉起。
        if realm_config().exists() {
            let dead = realm_child_slot()
                .lock()
                .unwrap()
                .as_mut()
                .map(|c| c.try_wait().map(|w| w.is_some()).unwrap_or(true))
                .unwrap_or(true);
            if dead {
                let child = tokio::process::Command::new(realm_bin())
                    .arg("-c")
                    .arg(realm_config())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn();
                let _ = child.map(|c| realm_child_slot().lock().unwrap().replace(c));
            }
        }
    }
}

async fn spawn_child() -> Result<()> {
    stop_child().await;
    let child = tokio::process::Command::new(bin_path())
        .arg("run")
        .arg("-c")
        .arg(config_path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("无法启动 sing-box")?;
    child_slot().lock().unwrap().replace(child);
    Ok(())
}

async fn stop_child() {
    let old = child_slot().lock().unwrap().take();
    if let Some(mut child) = old {
        let _ = child.kill().await;
    }
}

// ---- 流量统计（M4）：轮询本机 clash_api，按连接做差，推给 hub ----

/// 汇总一帧推给 hub（proxy.stats）：节点级 tags 与用户级 users 都来自
/// sing-box api 事件流聚合（api_events_loop），这里只 drain。
/// （M15 前节点级走 clash_api /connections 差分——对亚秒级短连接有盲区，
/// 实测 20MB/0.3s 的下载整段漏记，故整体切换到事件流 inbound 维度。）
pub async fn stats_frame() -> Option<Message> {
    let tags: serde_json::Map<String, serde_json::Value> =
        drain_api_tag_deltas().into_iter().map(|(t, (rx, tx))| (t, serde_json::json!([rx, tx]))).collect();
    // 用户级（M12）：api_events_loop 常驻订阅 sing-box api 连接事件流，
    // 这里只 drain 它聚合好的增量（含短连接关闭事件，无盲区）。
    let users = drain_api_user_deltas();
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

// ---- sing-box api 连接事件流（M12）：用户级计量数据源 ----
//
// sing-box 1.14+ 官方自带的 api service 把每条连接的增量（含连接关闭
// 事件）流式推送，Connection.user 就是入站认证的凭据用户名——短连接零
// 盲区，官方 release 无需任何编译 tag。

/// 一条连接的生命周期明细（M14 连接日志）：New 建、Update 累加、Closed
/// 定稿推入待推缓冲。
#[derive(Debug, Clone)]
struct ConnLife {
    id: String,
    user: String,
    inbound: String,
    network: String,
    source: String,
    destination: String,
    domain: String,
    first: i64,
    last: i64,
    up: i64,
    down: i64,
}

fn conn_lives() -> &'static Mutex<HashMap<String, ConnLife>> {
    static C: OnceLock<Mutex<HashMap<String, ConnLife>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 待推给 hub 的连接日志行（定稿与活跃快照混合，hub 按 conn id upsert）。
fn pending_conn_logs() -> &'static Mutex<Vec<ConnLife>> {
    static P: OnceLock<Mutex<Vec<ConnLife>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(Vec::new()))
}

/// 把待推行 drain 成 JSON 数组（connection.logs 的 params）。行不可用时返回 None。
pub fn connection_logs_frame() -> Option<Message> {
    let rows = std::mem::take(&mut *pending_conn_logs().lock().unwrap());
    if rows.is_empty() {
        return None;
    }
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|l| {
            serde_json::json!({
                "id": l.id, "user": l.user, "inbound": l.inbound,
                "network": l.network, "source": l.source,
                "destination": l.destination, "domain": l.domain,
                "first": l.first, "last": l.last, "up": l.up, "down": l.down,
            })
        })
        .collect();
    Some(Message::Text(
        serde_json::json!({"jsonrpc": "2.0", "method": "connection.logs", "params": arr}).to_string().into(),
    ))
}

/// 连接 id → 凭据用户名（M12）：NEW 事件建立映射，UPDATE/CLOSED 按 id 查。
fn users_of_conn() -> &'static Mutex<HashMap<String, String>> {
    static U: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    U.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 用户级流量增量（按凭据用户名聚合）：订阅任务写入，stats_frame 每 5s
/// drain 一次推给 hub。
fn api_user_deltas() -> &'static Mutex<HashMap<String, (i64, i64)>> {
    static D: OnceLock<Mutex<HashMap<String, (i64, i64)>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

fn drain_api_user_deltas() -> HashMap<String, (i64, i64)> {
    std::mem::take(&mut api_user_deltas().lock().unwrap())
}

/// 节点级流量增量（按入站 tag 聚合，M15 起替代 clash_api 差分）：事件流的
/// UPDATE/CLOSED 把增量按所属连接的 inbound 累在这里，stats_frame 每 5s
/// drain 推给 hub 落采样。clash 轮询做差对亚秒级短连接存在系统性盲区
/// （连接在下一次轮询前就消失了），事件流每笔增量必达，无此问题。
fn api_tag_deltas() -> &'static Mutex<HashMap<String, (i64, i64)>> {
    static D: OnceLock<Mutex<HashMap<String, (i64, i64)>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

fn drain_api_tag_deltas() -> HashMap<String, (i64, i64)> {
    std::mem::take(&mut api_tag_deltas().lock().unwrap())
}

/// 核心（重）启/停止前清空连接态：连接 id 属于 sing-box 进程生命周期，
/// 重启后旧 id 不会再有任何事件，不清理则 conn_lives 泄漏且永不定稿。
/// 已知总量先移交 pending 落库；api_user_deltas 按 user 记账、与连接 id
/// 无关，保留给 ticker 正常 drain。订阅意外断开（核心仍在运行）时**不清**：
/// 存量连接的 id 依旧有效，清了反而停掉它们的计量。
fn reset_conn_state() {
    let stale: Vec<ConnLife> = conn_lives().lock().unwrap().drain().map(|(_, l)| l).collect();
    pending_conn_logs().lock().unwrap().extend(stale);
    users_of_conn().lock().unwrap().clear();
}

/// 常驻任务：订阅本机 sing-box api 的连接事件流，把 uplink/downlink 增量
/// 按用户累加。断开（核心重启/升级）后 3s 重连；核心未运行或未配置 api
/// service 时静默等待。
pub async fn api_events_loop() {
    loop {
        let Some(port) = restore_api() else {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        match subscribe_connections(port).await {
            Ok(()) => {}
            Err(e) => eprintln!("[stats] sing-box api 订阅断开: {e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// 订阅连接事件流直到断开。每个事件帧按 user 把 delta 累加进聚合表；
/// NEW 事件（delta 为零）天然被过滤。
async fn subscribe_connections(port: u16) -> Result<()> {
    use h2::client;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut send_request, connection) = client::handshake(tcp).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://127.0.0.1/daemon.StartedService/SubscribeConnections")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .context("gRPC 请求头")?;
    let (response, mut send_body) = send_request.send_request(request, false).context("gRPC 连接")?;
    // SubscribeConnectionsRequest{ interval: 5000 }：field1 int64。
    let mut msg = vec![0x08];
    push_varint(&mut msg, 5000);
    let mut frame = Vec::with_capacity(5 + msg.len());
    frame.push(0);
    frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    frame.extend_from_slice(&msg);
    send_body.send_data(frame.into(), true).context("gRPC 请求体")?;
    let response = response.await.context("gRPC 响应")?;
    if !response.status().is_success() {
        bail!("sing-box api 返回 {}", response.status());
    }
    let mut body = response.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("gRPC 数据流")?;
        buf.extend_from_slice(chunk.as_ref());
        let _ = body.flow_control().release_capacity(chunk.len());
        while buf.len() >= 5 {
            let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + len {
                break;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            match decode_connection_event(&buf[5..5 + len]) {
                Some(ConnEvent::New { id, user, inbound, network, source, destination, domain }) => {
                    users_of_conn().lock().unwrap().insert(id.clone(), user.clone());
                    conn_lives().lock().unwrap().insert(
                        id.clone(),
                        ConnLife {
                            id,
                            user,
                            inbound,
                            network,
                            source,
                            destination,
                            domain,
                            first: now,
                            last: now,
                            up: 0,
                            down: 0,
                        },
                    );
                }
                Some(ConnEvent::Update { id, up, down }) => {
                    // 配额计量（M12 管道，保持不变）。
                    let user = users_of_conn().lock().unwrap().get(&id).cloned();
                    if let Some(user) = user {
                        let mut d = api_user_deltas().lock().unwrap();
                        let e = d.entry(user).or_insert((0, 0));
                        e.0 += up;
                        e.1 += down;
                    }
                    // 连接日志（M14）：明细累加；节点级（M15）按 inbound 同步入账。
                    if let Some(l) = conn_lives().lock().unwrap().get_mut(&id) {
                        l.up += up;
                        l.down += down;
                        l.last = now;
                        let mut td = api_tag_deltas().lock().unwrap();
                        // 表按 (rx, tx) 存：事件 up=客户端上传→tx，down=下载→rx。
                        let e = td.entry(l.inbound.clone()).or_insert((0, 0));
                        e.0 += down;
                        e.1 += up;
                    }
                }
                Some(ConnEvent::Closed { id, up, down }) => {
                    // 定稿补最后一拍：CLOSED 若带增量（官方核心当前不带）
                    // 先入账，避免关闭前最后一拍丢失。
                    if up > 0 || down > 0 {
                        let user = users_of_conn().lock().unwrap().get(&id).cloned();
                        if let Some(user) = user {
                            let mut d = api_user_deltas().lock().unwrap();
                            let e = d.entry(user).or_insert((0, 0));
                            e.0 += up;
                            e.1 += down;
                        }
                        if let Some(l) = conn_lives().lock().unwrap().get_mut(&id) {
                            l.up += up;
                            l.down += down;
                            l.last = now;
                            let mut td = api_tag_deltas().lock().unwrap();
                            // 表按 (rx, tx) 存：事件 up=客户端上传→tx，down=下载→rx。
                            let e = td.entry(l.inbound.clone()).or_insert((0, 0));
                            e.0 += down;
                            e.1 += up;
                        }
                    }
                    users_of_conn().lock().unwrap().remove(&id);
                    if let Some(l) = conn_lives().lock().unwrap().remove(&id) {
                        pending_conn_logs().lock().unwrap().push(l);
                    }
                }
                None => {}
            }
            buf.drain(..5 + len);
        }
    }
    Ok(())
}

/// 一条连接事件（M12）：NEW 带完整连接（含用户），UPDATE 只带 id 与增量，
/// CLOSED 带 id 与可能的收尾增量——用户归属需要调用方按 id 从 NEW 里记的
/// 映射查回。
#[derive(Debug, PartialEq)]
enum ConnEvent {
    New {
        id: String,
        user: String,
        inbound: String,
        network: String,
        source: String,
        destination: String,
        domain: String,
    },
    Update {
        id: String,
        up: i64,
        down: i64,
    },
    /// 官方核心（1.14 实测）CLOSED 不带增量，up/down 恒零；字段保留以兼容
    /// 带增量的版本——带了就由聚合分支补最后一拍。
    Closed {
        id: String,
        up: i64,
        down: i64,
    },
}

/// 解码一条连接事件帧（实测线上格式：gRPC 帧之内最外层是一个 wire2 信封，
/// 里面才是 type=1 varint、id=2 bytes、connection=3 bytes、uplinkDelta=4、
/// downlinkDelta=5、closedAt=6；connection 里 user=10 bytes）。
fn decode_connection_event(buf: &[u8]) -> Option<ConnEvent> {
    let mut event: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < buf.len() {
        let (key, n) = read_varint(buf, i).ok()?;
        i = n;
        match (key >> 3, key & 7) {
            (1, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                event = Some(buf[i..end].to_vec());
                i = end;
            }
            _ => {
                let (_, n) = skip_field(buf, i, key & 7).ok()?;
                i = n;
            }
        }
    }
    let buf: &[u8] = &event?;
    let mut kind = 0u64;
    let mut id = String::new();
    let mut connection: Option<Vec<u8>> = None;
    let mut up = 0i64;
    let mut down = 0i64;
    let mut i = 0;
    while i < buf.len() {
        let (key, n) = read_varint(buf, i).ok()?;
        i = n;
        let (num, wire) = (key >> 3, key & 7);
        match (num, wire) {
            (1, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                kind = v;
            }
            (2, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                id = String::from_utf8_lossy(&buf[i..end]).into_owned();
                i = end;
            }
            (3, 2) => {
                let (len, n) = read_varint(buf, i).ok()?;
                i = n;
                let end = (i + len as usize).min(buf.len());
                connection = Some(buf[i..end].to_vec());
                i = end;
            }
            (4, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                up = v as i64;
            }
            (5, 0) => {
                let (v, n) = read_varint(buf, i).ok()?;
                i = n;
                down = v as i64;
            }
            _ => {
                let (_, n) = skip_field(buf, i, wire).ok()?;
                i = n;
            }
        }
    }
    // UPDATE 只带 id 与增量（无 connection）；NEW 才携带完整连接。
    if kind == 2 {
        return Some(ConnEvent::Closed { id, up, down });
    }
    if kind == 1 {
        return Some(ConnEvent::Update { id, up, down });
    }
    let connection = connection?;
    let conn: &[u8] = &connection;
    let mut user = String::new();
    let mut inbound = String::new();
    let mut network = String::new();
    let mut source = String::new();
    let mut destination = String::new();
    let mut domain = String::new();
    let mut i = 0;
    while i < conn.len() {
        let (key, n) = read_varint(conn, i).ok()?;
        i = n;
        let (num, wire) = (key >> 3, key & 7);
        if wire == 2 {
            let (len, n) = read_varint(conn, i).ok()?;
            i = n;
            let end = (i + len as usize).min(conn.len());
            let val = String::from_utf8_lossy(&conn[i..end]).into_owned();
            i = end;
            match num {
                2 => inbound = val,
                6 => source = val,
                7 => destination = val,
                8 => domain = val,
                10 => user = val,
                _ => {}
            }
        } else {
            match (num, wire) {
                (5, 0) => {
                    let (v, n) = read_varint(conn, i).ok()?;
                    i = n;
                    // network 枚举：sing-box adapter.Network，1=tcp 2=udp。
                    network = if v == 2 { "udp".into() } else { "tcp".into() };
                }
                _ => {
                    let (_, n) = skip_field(conn, i, wire).ok()?;
                    i = n;
                }
            }
        }
    }
    Some(ConnEvent::New { id, user, inbound, network, source, destination, domain })
}

fn read_varint(buf: &[u8], mut i: usize) -> Result<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *buf.get(i).context("protobuf 截断")?;
        i += 1;
        v |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok((v, i));
        }
        shift += 7;
        if shift > 63 {
            bail!("protobuf varint 过长");
        }
    }
}

/// 跳过一个未知 protobuf 字段，返回 (wire type 0 时的值, 新偏移)。
fn skip_field(buf: &[u8], i: usize, wire: u64) -> Result<(Option<u64>, usize)> {
    match wire {
        0 => {
            let (v, n) = read_varint(buf, i)?;
            Ok((Some(v), n))
        }
        1 => Ok((None, (i + 8).min(buf.len()))),
        2 => {
            // 长度前缀在 i 处，值从 i+1 起：新偏移 = (len 前缀之后) + 值长度。
            let (len, n) = read_varint(buf, i)?;
            Ok((None, n + len as usize))
        }
        5 => Ok((None, (i + 4).min(buf.len()))),
        w => bail!("未知 wire type {w}"),
    }
}

fn push_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

// ---- Realm 中转（M5）----

pub const REALM_REPO: &str = "zhboner/realm";

fn realm_bin() -> PathBuf {
    base_dir().join("bin").join("realm")
}

fn realm_config() -> PathBuf {
    base_dir().join("instances").join("main").join("realm.toml")
}

fn realm_hash() -> String {
    std::fs::read_to_string(realm_config().with_extension("toml.hash"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn realm_child_slot() -> &'static Mutex<Option<tokio::process::Child>> {
    static C: OnceLock<Mutex<Option<tokio::process::Child>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

async fn relay_install(version: Option<String>) -> Result<String> {
    let version = match version {
        Some(v) => {
            let v = v.trim().trim_start_matches('v').to_owned();
            if v.is_empty() || !v.chars().all(|c| c.is_ascii_digit() || c == '.') {
                bail!("版本号格式不对：{v}");
            }
            v
        }
        None => {
            let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
            let v: serde_json::Value = client
                .get(format!("https://api.github.com/repos/{REALM_REPO}/releases/latest"))
                .header("User-Agent", "monitor-agent")
                .send()
                .await
                .context("无法访问 GitHub")?
                .error_for_status()?
                .json()
                .await
                .context("解析 GitHub 响应失败")?;
            v["tag_name"].as_str().unwrap_or_default().trim_start_matches('v').to_owned()
        }
    };
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        (os, arch) => bail!("暂不支持 {os}/{arch} 自动安装 Realm"),
    };
    let name = format!("realm-{target}.tar.gz");
    let url = format!("https://github.com/{REALM_REPO}/releases/download/v{version}/{name}");
    let client = reqwest::Client::builder().timeout(Duration::from_secs(180)).build()?;
    let bytes = client
        .get(url)
        .header("User-Agent", "monitor-agent")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let bin = realm_bin();
    tokio::fs::create_dir_all(bin.parent().expect("parent")).await?;
    let staging = bin.with_extension("new");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if entry.header().entry_type().is_file() && path.file_name().is_some_and(|n| n == "realm") {
            entry.unpack(&staging)?;
            found = true;
        }
    }
    if !found {
        bail!("压缩包中没有找到 realm 可执行文件");
    }
    tokio::fs::rename(&staging, &bin).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    }
    let out = tokio::process::Command::new(&bin).arg("--version").output().await?;
    let v = String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).unwrap_or("").to_owned();
    Ok(v)
}

/// 只确保 realm 单元在跑，不碰配置文件（ensure_started poke 的落点）。
async fn ensure_realm_started() -> Result<()> {
    let active = if systemd() {
        unit_active("monitor-realm@main").await
    } else {
        realm_child_slot().lock().unwrap().is_some()
    };
    if active {
        return Ok(());
    }
    restart_realm().await;
    Ok(())
}

/// 重启（或首次拉起）realm 单元；非 systemd 环境回落到直接 spawn 子进程。
/// 成功与否都记一行：拉活/应用链路曾整段静默，服务停了双方都报 ok
/// （is-active 退出码 bug，eac4e56），从这行起 journald 里可见真实动作。
async fn restart_realm() {
    if systemd() {
        match run_cmd("systemctl", &["restart", "monitor-realm@main"]).await {
            Ok(out) if out.status.success() => eprintln!("[proxy] realm unit restarted"),
            // systemctl 跑了但退出非零（如单元被 mask）同样是失败——退出码
            // 语义与 unit_active 同一课。
            Ok(out) => eprintln!(
                "[proxy] systemctl restart realm failed: exit {}, {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => eprintln!("[proxy] systemctl restart realm failed: {e}"),
        }
    } else {
        let old = realm_child_slot().lock().unwrap().take();
        if let Some(mut c) = old {
            let _ = c.kill().await;
        }
        let child = tokio::process::Command::new(realm_bin())
            .arg("-c")
            .arg(realm_config())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        match child {
            Ok(c) => {
                eprintln!("[proxy] realm child restarted");
                realm_child_slot().lock().unwrap().replace(c);
            }
            Err(e) => eprintln!("[proxy] realm child spawn failed: {e}"),
        }
    }
}

async fn relay_apply(body: String, desired_running: bool, hash: &str) -> Result<()> {
    if body.is_empty() {
        // 空配置的语义唯一：desired_running=false，停服务清文件。「空体+true」
        // 曾是 hub 侧语义分叉的遗物——本侧自造占位写盘，指纹与空期望永不相等，
        // 每 60s 心跳重推并重启 realm；占位的定义与下发已收归 hub 独占
        // （relay_expected，2026-10-27 收口），此组合成为协议错误。
        if desired_running {
            bail!("空配置必须带 desired_running=false（期望停服务清理）；占位待命由 hub 以显式配置下发");
        }
        if systemd() {
            let _ = run_cmd("systemctl", &["stop", "monitor-realm@main"]).await;
        } else {
            let old = realm_child_slot().lock().unwrap().take();
            if let Some(mut c) = old {
                let _ = c.kill().await;
            }
        }
        let _ = std::fs::remove_file(realm_config());
        let _ = std::fs::remove_file(realm_config().with_extension("toml.hash"));
        return Ok(());
    }
    tokio::fs::create_dir_all(realm_config().parent().expect("parent")).await?;
    tokio::fs::write(realm_config(), &body).await?;
    std::fs::write(realm_config().with_extension("toml.hash"), hash)?;
    if systemd() {
        let unit = "/etc/systemd/system/monitor-realm@.service";
        if !Path::new(unit).exists() {
            std::fs::write(
                unit,
                format!(
                    "[Unit]\nDescription=monitor realm relay %i\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} -c {}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
                    realm_bin().display(),
                    realm_config().display()
                ),
            )?;
            let _ = run_cmd("systemctl", &["daemon-reload"]).await;
        }
        let rs = run_cmd("systemctl", &["restart", "monitor-realm@main"]).await?;
        if !rs.status.success() {
            eprintln!("[proxy] realm restart failed: {}", String::from_utf8_lossy(&rs.stderr));
        }
    } else {
        let old = realm_child_slot().lock().unwrap().take();
        if let Some(mut c) = old {
            let _ = c.kill().await;
        }
        let child = tokio::process::Command::new(realm_bin())
            .arg("-c")
            .arg(realm_config())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("无法启动 realm")?;
        realm_child_slot().lock().unwrap().replace(child);
    }
    Ok(())
}

/// HTTP 探测（hub 协议测速用）：从本机向 url 发 GET，测到收到响应头的耗时。
/// 与客户端软件测延迟同款语义（目标一般给 gstatic generate_204）——反映的是
/// 本机出口线路的真实访问质量，含 DNS/TCP/TLS 全程。
async fn http_probe(params: &serde_json::Value) -> serde_json::Value {
    let Some(url) = params["url"].as_str().filter(|u| !u.is_empty()) else {
        return serde_json::json!({ "ok": false, "error": "缺少 url" });
    };
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(5000).clamp(500, 15_000);
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        // 不跟随重定向：测的是目标本身的可达性与耗时。
        .redirect(reqwest::redirect::Policy::none());
    // 可选 socks5 出口链：带此参数时经 socks5（socks5h=目标域名由代理端解析）
    // 访问目标，测到的是「本机→socks5→目标」的完整链路。认证从 URL userinfo
    // 读取（socks5 RFC 1929 用户名/密码）。
    if let Some(s5) = params["socks5"].as_object() {
        let server = s5["server"].as_str().unwrap_or_default().trim();
        let port = s5["port"].as_u64().unwrap_or(0);
        if server.is_empty() || port == 0 {
            return serde_json::json!({ "ok": false, "error": "socks5 参数不完整" });
        }
        let auth = match (
            s5.get("username").and_then(|v| v.as_str()),
            s5.get("password").and_then(|v| v.as_str()),
        ) {
            (Some(u), Some(p)) if !u.is_empty() => {
                format!("{}:{}@", pct_url(u), pct_url(p))
            }
            _ => String::new(),
        };
        let proxy = match reqwest::Proxy::all(format!("socks5h://{auth}{server}:{port}")) {
            Ok(p) => p,
            Err(e) => return serde_json::json!({ "ok": false, "error": format!("socks5 配置无效: {e}") }),
        };
        builder = builder.proxy(proxy);
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
    };
    let started = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(resp) => serde_json::json!({
            "ok": true,
            "status": resp.status().as_u16(),
            "ms": started.elapsed().as_millis() as u64,
        }),
        // 错误链全展开：socks 层的失败原因（如 GeneralServerFailure）藏在
        // source 里，只给 to_string 会丢掉诊断信息。
        Err(e) => {
            let mut parts = vec![e.to_string()];
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                parts.push(s.to_string());
                src = s.source();
            }
            serde_json::json!({ "ok": false, "error": parts.join(" ← ") })
        }
    }
}

/// 落地目标健康探测（hub 发起）：从本机对每个 host:port 做 TCP connect。
/// count=1 时与旧版行为一致（results[].ms = 单次耗时）；count>1 为诊断模式，
/// 连发多次（interval_ms 间隔）并聚合 avg_ms / loss_pct 供诊断弹窗分级。
/// 只测 TCP——xwPF 的 `nc -z` 同款；UDP 服务探不了，由 hub 标 unknown。
async fn relay_probe(params: &serde_json::Value) -> Vec<serde_json::Value> {
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(3000).clamp(100, 10_000);
    let count = params["count"].as_u64().unwrap_or(1).clamp(1, 20) as usize;
    let interval_ms = params["interval_ms"].as_u64().unwrap_or(0).min(1000);
    let mut results = Vec::new();
    let Some(targets) = params["targets"].as_array() else { return results };
    for t in targets {
        let Some(addr) = t.as_str() else { continue };
        let mut samples: Vec<Option<u64>> = Vec::with_capacity(count);
        for i in 0..count {
            if i > 0 && interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
            let started = std::time::Instant::now();
            let ok = matches!(
                tokio::time::timeout(Duration::from_millis(timeout_ms), tokio::net::TcpStream::connect(addr))
                    .await,
                Ok(Ok(_))
            );
            samples.push(ok.then(|| started.elapsed().as_millis() as u64));
        }
        let (ok, avg_ms, loss_pct) = summarize_probe(&samples);
        results.push(serde_json::json!({
            "target": addr,
            "ok": ok,
            "ms": samples.iter().flatten().next().copied().unwrap_or(0),
            "avg_ms": avg_ms,
            "loss_pct": loss_pct,
        }));
    }
    results
}

/// 一组探测样本（None=超时/失败）的聚合：是否至少通一次、成功样本平均毫秒、
/// 丢包率（百分比，一位小数精度由调用方按需取整）。
fn summarize_probe(samples: &[Option<u64>]) -> (bool, u64, f64) {
    let ok_count = samples.iter().filter(|s| s.is_some()).count();
    let ok = ok_count > 0;
    let avg_ms = if ok_count == 0 { 0 } else { samples.iter().flatten().sum::<u64>() / ok_count as u64 };
    let loss_pct = 100.0 * (samples.len() - ok_count) as f64 / samples.len().max(1) as f64;
    (ok, avg_ms, loss_pct)
}

/// URL userinfo 的百分号编码（socks5 认证串里的用户名/密码可能含特殊字符）。
fn pct_url(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 极简 socks5 服务（仅 CONNECT，无认证）：http_probe 的 socks5 拨号测试用。
#[cfg(test)]
async fn mini_socks5(listener: tokio::net::TcpListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut sock, _)) = listener.accept().await else { return };
        tokio::spawn(async move {
            let mut hdr = [0u8; 2];
            if sock.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let mut methods = vec![0u8; hdr[1] as usize];
            if sock.read_exact(&mut methods).await.is_err() {
                return;
            }
            if sock.write_all(&[5, 0]).await.is_err() {
                return;
            }
            let mut req = [0u8; 4];
            if sock.read_exact(&mut req).await.is_err() {
                return;
            }
            let addr = match req[3] {
                1 => {
                    let mut b = [0u8; 4];
                    if sock.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                }
                3 => {
                    let mut l = [0u8; 1];
                    if sock.read_exact(&mut l).await.is_err() {
                        return;
                    }
                    let mut b = vec![0u8; l[0] as usize];
                    if sock.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    String::from_utf8(b).unwrap_or_default()
                }
                _ => return,
            };
            let mut p = [0u8; 2];
            if sock.read_exact(&mut p).await.is_err() {
                return;
            }
            let port = u16::from_be_bytes(p);
            let Ok(mut upstream) = tokio::net::TcpStream::connect((addr.as_str(), port)).await else {
                let _ = sock.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            };
            let _ = sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
        });
    }
}

#[cfg(test)]
mod tests {
    /// 空配置语义唯一性：desired_running=false 才是合法组合（停服务清文件）；
    /// true 是 hub 侧语义分叉遗物，现为协议错误。MONITOR_PROXY_DIR 隔离文件
    /// 落点，其余测试不读该变量、无并行干扰。
    #[tokio::test]
    async fn empty_relay_config_must_carry_desired_off() {
        let dir = std::env::temp_dir().join(format!("monitor-agent-relay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("MONITOR_PROXY_DIR", &dir);
        std::fs::create_dir_all(realm_config().parent().unwrap()).unwrap();
        std::fs::write(realm_config(), "old-config").unwrap();
        std::fs::write(realm_config().with_extension("toml.hash"), "old-hash").unwrap();

        let err = relay_apply(String::new(), true, "").await.unwrap_err();
        assert!(err.to_string().contains("desired_running"), "空体+true 是协议错误: {err}");
        assert!(realm_config().exists(), "协议错误不碰盘上文件");

        relay_apply(String::new(), false, "").await.unwrap();
        assert!(!realm_config().exists(), "合法语义：配置文件清除");
        assert!(!realm_config().with_extension("toml.hash").exists(), "指纹文件清除");

        std::env::remove_var("MONITOR_PROXY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    /// http_probe 经 socks5 出口链访问目标：真实拨号链路（本机→socks5→目标）。
    #[tokio::test]
    async fn http_probe_via_socks5_reaches_target() {
        // 目标 HTTP 服务：任何请求回 204。
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut s, _)) = http.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
                });
            }
        });
        // socks5 服务
        let socks = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = socks.local_addr().unwrap().port();
        tokio::spawn(mini_socks5(socks));

        let r = http_probe(&serde_json::json!({
            "url": format!("http://127.0.0.1:{http_port}/"),
            "timeout_ms": 3000,
            "socks5": { "server": "127.0.0.1", "port": socks_port },
        }))
        .await;
        assert_eq!(r["ok"], serde_json::Value::Bool(true), "经 socks5 探测应成功: {r}");
        assert!(r["ms"].as_u64().is_some(), "应有耗时读数: {r}");
    }

    /// 诊断聚合：成功样本取均值、超时计丢包、全超时判不通。
    #[test]
    fn probe_summary_averages_successes_and_counts_loss() {
        let (ok, avg, loss) = summarize_probe(&[Some(5), Some(7), None]);
        assert!(ok);
        assert_eq!(avg, 6);
        assert!((loss - 100.0 / 3.0).abs() < 0.01);
        let (ok, avg, loss) = summarize_probe(&[None, None, None]);
        assert!(!ok, "全超时 = 不通");
        assert_eq!((avg, loss), (0, 100.0));
        let (ok, avg, loss) = summarize_probe(&[Some(10)]);
        assert_eq!((ok, avg, loss), (true, 10, 0.0), "count=1 与旧版单发语义一致");
    }

    /// 手工拼 gRPC 事件帧内的信封：外层 wire2（field2=事件体），事件里
    /// type=1 varint、id=2 bytes、uplinkDelta=4 / downlinkDelta=5 varint。
    fn envelope(event: &[u8]) -> Vec<u8> {
        let mut buf = vec![0x0A, event.len() as u8];
        buf.extend_from_slice(event);
        buf
    }

    /// 架构巡检批次4：与 hub 的 golden_fixture_decodes_identically_across_repos
    /// 共享同一份 src/testdata/singbox-events.golden 与同一个 sha 常量——两仓
    /// 解码器对同一字节必须解出同一事件序列（协议知识单一事实源，夹具改动
    /// 必须两仓同步并同步换常量）。
    #[test]
    fn golden_fixture_decodes_identically_across_repos() {
        const GOLDEN_SHA: &str = "94870bb2c541976ad13a9357bf029bbbcb1d1c0c4dbd48a7f82de3a3f7864791";
        let golden = include_bytes!("testdata/singbox-events.golden");
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(golden)),
            GOLDEN_SHA,
            "golden 夹具与两仓共享版本不一致：任何一侧改动都要同步另一侧"
        );

        let mut rest = &golden[..];
        let mut events = Vec::new();
        while !rest.is_empty() {
            let n = rest[0] as usize;
            events.push(decode_connection_event(&rest[1..1 + n]).expect("golden 帧必须可解码"));
            rest = &rest[1 + n..];
        }
        assert_eq!(events.len(), 3);
        match &events[0] {
            ConnEvent::New { id, user, inbound, network, source, destination, domain } => {
                assert_eq!(
                    (id.as_str(), user.as_str(), inbound.as_str(), network.as_str()),
                    ("conn-1", "alice", "in-11990", "udp")
                );
                assert_eq!(
                    (source.as_str(), destination.as_str(), domain.as_str()),
                    ("1.2.3.4:5", "example.com:443", "example.com")
                );
            }
            other => panic!("第一帧应为 NEW：{other:?}"),
        }
        assert_eq!(
            events[1],
            ConnEvent::Update { id: "e0a2d363-617b-47be-9aca-bbcd376e53ad".into(), up: 1570, down: 0 }
        );
        assert_eq!(events[2], ConnEvent::Closed { id: "c1".into(), up: 111, down: 222 });
    }

    #[test]
    fn a_closed_event_with_final_deltas_decodes_both() {
        // CLOSED { id: "c1", uplinkDelta: 111, downlinkDelta: 222 }
        let event = [0x08, 0x02, 0x12, 0x02, b'c', b'1', 0x20, 0x6F, 0x28, 0xDE, 0x01];
        assert_eq!(
            decode_connection_event(&envelope(&event)),
            Some(ConnEvent::Closed { id: "c1".into(), up: 111, down: 222 })
        );
    }

    #[test]
    fn an_update_event_decodes_id_and_deltas() {
        // UPDATE { id: "u9", uplinkDelta: 1, downlinkDelta: 2 }
        let event = [0x08, 0x01, 0x12, 0x02, b'u', b'9', 0x20, 0x01, 0x28, 0x02];
        assert_eq!(
            decode_connection_event(&envelope(&event)),
            Some(ConnEvent::Update { id: "u9".into(), up: 1, down: 2 })
        );
    }
}
