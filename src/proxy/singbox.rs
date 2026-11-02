//! sing-box 生命周期（M3/M12）：安装、配置 apply（校验/原子替换/重启）、
//! 期望状态（desired 文件）、systemd 模板单元；dev（无 systemd）环境的
//! 子进程槽与守护 tick。分发与共享小工具在上级 proxy.rs。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::{run_cmd, systemd, unit_active};

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

pub(super) fn bin_path() -> PathBuf {
    base_dir().join("bin").join("sing-box")
}

pub(super) fn bin_installed() -> bool {
    bin_path().is_file()
}

pub(super) fn config_path() -> PathBuf {
    base_dir().join("instances").join("main").join("config.json")
}

fn desired_path() -> PathBuf {
    base_dir().join("desired")
}

/// Where the sing-box releases are published. Forking implies rebuilding this.
const SINGBOX_REPO: &str = "SagerNet/sing-box";

pub(super) const UNIT_NAME: &str = "monitor-singbox@main";

/// 期望状态文件：hub 的每次 apply 都带着它；缺失视为 on。
pub(super) fn desired() -> bool {
    std::fs::read_to_string(desired_path()).map(|s| s.trim() != "off").unwrap_or(true)
}

pub(super) fn write_desired(running: bool) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(desired_path(), if running { "on" } else { "off" })?;
    Ok(())
}

/// hub 侧的配置指纹存在伴随文件里：apply 时本机会向 hub 下发的 body 注入
/// clash_api，文件字节与 hub 的期望不再一一对应，指纹以伴随文件为准。
pub(super) fn local_hash() -> String {
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
pub(super) fn restore_api() -> Option<u16> {
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

/// sing-box 版本随 60s 心跳捎带给 hub（喂协议页的版本过旧黄条）。进程内
/// 只探测一次：核心版本只在安装/切换后变化，而那之后 agent 会被重启，缓存
/// 随进程一起换新。
pub(super) fn singbox_version_cached() -> String {
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

// ---- install（设计文档 5.1：agent 直连下载，版本号 + 平台自动匹配）----

pub(super) async fn install(version: Option<String>) -> Result<String> {
    let version = match version {
        Some(v) => super::fetch::validate_version(super::fetch::VersionRule::Digits, &v)?,
        None => latest_version().await?,
    };
    let (os, arch) = super::fetch::os_arch_slug("暂不支持在 {} 上自动安装核心", "暂不支持架构 {}")?;
    let name = format!("sing-box-{version}-{os}-{arch}.tar.gz");
    let url = format!("https://github.com/{SINGBOX_REPO}/releases/download/v{version}/{name}");
    let bytes = super::fetch::fetch_release(&url, 300, "sing-box").await?;
    super::fetch::install_binary(&bytes, &bin_path(), "sing-box").await?;
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

/// 本机 sing-box 是否在跑（status 用）：systemd 查单元；dev 查子进程槽，
/// 孤儿进程也算——上一个 agent 进程被硬杀时留下来的 sing-box 还在服务同一
/// 份配置，对「这个节点在不在跑」而言，它就是答案。
pub(super) async fn running_or_orphaned() -> bool {
    if systemd() {
        unit_active(UNIT_NAME).await
    } else {
        let ours = child_slot()
            .lock()
            .map(|mut c| c.as_mut().is_some_and(|c| c.try_wait().map_or(true, |w| w.is_none())))
            .unwrap_or(false);
        let orphaned = !ours
            && config_path().exists()
            && std::process::Command::new("pgrep")
                .args(["-f", config_path().to_str().unwrap_or_default()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        ours || orphaned
    }
}

pub(super) async fn apply(body: String, desired_running: bool, hash: &str) -> Result<()> {
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
        super::events::reset_conn_state();
        let rs = run_cmd("systemctl", &[if desired_running { "restart" } else { "stop" }, UNIT_NAME]).await?;
        if !rs.status.success() {
            eprintln!("[proxy] systemctl restart failed: {}", String::from_utf8_lossy(&rs.stderr));
        }
    } else if desired_running {
        super::events::reset_conn_state();
        spawn_child().await?;
    } else {
        super::events::reset_conn_state();
        stop_child().await;
    }
    let _ = hash;
    Ok(())
}

pub(super) async fn detect_version() -> Result<String> {
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

/// The supervised child, where there is no systemd to do it for us.
pub(super) fn child_slot() -> &'static Mutex<Option<tokio::process::Child>> {
    static CHILD: OnceLock<Mutex<Option<tokio::process::Child>>> = OnceLock::new();
    CHILD.get_or_init(|| Mutex::new(None))
}

pub(super) async fn spawn_child() -> Result<()> {
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

pub(super) async fn stop_child() {
    let old = child_slot().lock().unwrap().take();
    if let Some(mut child) = old {
        let _ = child.kill().await;
    }
}

/// supervisor 的一拍（每 2s，proxy::supervisor 轮询）：有期望配置且子进程
/// 死了就重新拉起；起不来（典型：端口被孤儿占用）返回 Err，调用方退避 5s。
pub(super) async fn supervise_tick() -> Result<()> {
    if !desired() || !config_path().exists() {
        return Ok(());
    }
    let dead = {
        let mut slot = child_slot().lock().unwrap();
        match slot.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    };
    if dead {
        spawn_child().await?;
    }
    Ok(())
}
