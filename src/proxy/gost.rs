//! gost 转发/隧道：原版 gost v3，配置文件单一事实源 + 热重载。
//!
//! 纪律与 relay 同构：hub 渲染整份配置推 gost.apply，agent 落盘 + 应用，
//! 指纹进心跳对账。gost 原生不持久化 API 变更（flux-panel fork 才加的
//! saveConfig），所以只走「文件 + reload」一条路：盘上文件永远等于运行态
//! 期望，进程重启由文件恢复。

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::{run_cmd, systemd, unit_active};

/// 钉死的 gost 版本：批次0 spike 验证热重载语义用的就是它。升级走显式
/// 变更——同时改这里的常量与 hub 侧的 ensure 安装期望。
///
/// 跨仓同值：hub 仓 monitor/src/gost.rs 有同值常量（注释锁同步）。tests/
/// gost_version_guard.rs 用相对路径读 hub 仓源码比对两侧字面量（只在
/// jspp/monitor 与 jspp/monitor-agent 同级布局下成立）。
pub(super) const GOST_VERSION: &str = "3.3.2";
const GOST_REPO: &str = "go-gost/gost";
/// gost API 服务地址：渲染出的配置固定开在这里（仅环回），热重载打它。
const GOST_API: &str = "http://127.0.0.1:18080/config/reload";

fn gost_bin() -> PathBuf {
    super::singbox::base_dir().join("bin").join("gost")
}

fn gost_dir() -> PathBuf {
    super::singbox::base_dir().join("instances").join("gost")
}

fn gost_config() -> PathBuf {
    gost_dir().join("gost.json")
}

pub(super) fn gost_hash() -> String {
    std::fs::read_to_string(gost_config().with_extension("json.hash"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn gost_apply_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// gost.apply 的串行锁（分发层拿住，apply 全程持有）。
pub(super) async fn apply_lock() -> tokio::sync::MutexGuard<'static, ()> {
    gost_apply_lock().lock().await
}

pub(super) fn bin_installed() -> bool {
    gost_bin().is_file()
}

pub(super) async fn active() -> bool {
    gost_active().await
}

fn gost_child_slot() -> &'static std::sync::Mutex<Option<tokio::process::Child>> {
    static C: OnceLock<std::sync::Mutex<Option<tokio::process::Child>>> = OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(None))
}

async fn gost_active() -> bool {
    if systemd() {
        unit_active("monitor-gost@main").await
    } else {
        gost_child_slot()
            .lock()
            .map(|mut c| c.as_mut().is_some_and(|c| c.try_wait().map_or(true, |w| w.is_none())))
            .unwrap_or(false)
    }
}

/// monitor-gost@.service：WorkingDirectory 定在配置目录，ExecStart 显式
/// -C 指到文件——reload 重读的就是这份（批次0 实测 -C 文件 reload 生效）。
async fn write_gost_unit() -> Result<()> {
    let unit_path = "/etc/systemd/system/monitor-gost@.service";
    if std::path::Path::new(unit_path).exists() {
        return Ok(());
    }
    std::fs::write(
        unit_path,
        format!(
            "[Unit]\nDescription=monitor gost instance %i\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nWorkingDirectory={}\nExecStart={} -C {}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
            gost_dir().display(),
            gost_bin().display(),
            gost_config().display()
        ),
    )?;
    let _ = run_cmd("systemctl", &["daemon-reload"]).await;
    Ok(())
}

fn spawn_gost_child() -> Result<()> {
    let child = tokio::process::Command::new(gost_bin())
        .arg("-C")
        .arg(gost_config())
        .current_dir(gost_dir())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("无法启动 gost（二进制未安装？先 gost.install）")?;
    gost_child_slot().lock().unwrap().replace(child);
    Ok(())
}

/// 热应用：进程在跑 → POST /config/reload（未变更规则的已建立连接不受
/// 影响，批次0 实测）；没跑 → 拉起（首次冷启动完整加载）。reload 失败
/// 回滚盘上文件到旧内容——运行态进程仍持旧配置，盘上指纹必须跟着旧配置
/// 走，否则心跳对账拿新指纹反复重推同一个坏配置。
async fn gost_apply(body: String, desired_running: bool, hash: &str) -> Result<()> {
    if body.is_empty() {
        // 空配置语义唯一：desired_running=false，停服务清文件（与 relay 同款协议）。
        if desired_running {
            bail!("空配置必须带 desired_running=false（期望停服务清理）");
        }
        if systemd() {
            let _ = run_cmd("systemctl", &["stop", "monitor-gost@main"]).await;
        } else {
            let old = gost_child_slot().lock().unwrap().take();
            if let Some(mut c) = old {
                let _ = c.kill().await;
            }
        }
        let _ = std::fs::remove_file(gost_config());
        let _ = std::fs::remove_file(gost_config().with_extension("json.hash"));
        return Ok(());
    }
    if !gost_bin().is_file() {
        bail!("gost 尚未安装，请先安装（gost.install）");
    }
    tokio::fs::create_dir_all(&gost_dir()).await?;
    let old_body = std::fs::read_to_string(gost_config()).ok();
    let old_hash = gost_hash();
    tokio::fs::write(gost_config(), &body).await?;
    std::fs::write(gost_config().with_extension("json.hash"), hash)?;
    if !systemd() {
        let old = gost_child_slot().lock().unwrap().take();
        if let Some(mut c) = old {
            let _ = c.kill().await;
        }
        spawn_gost_child()?;
        return Ok(());
    }
    write_gost_unit().await?;
    if gost_active().await {
        let resp = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("构建 HTTP 客户端失败")?
            .post(GOST_API)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => {
                let status = r.status();
                let detail = r.text().await.unwrap_or_default();
                if let Some(old) = old_body {
                    let _ = tokio::fs::write(gost_config(), old).await;
                } else {
                    let _ = std::fs::remove_file(gost_config());
                }
                std::fs::write(gost_config().with_extension("json.hash"), old_hash)?;
                bail!("gost reload 被拒绝（{status}）：{detail}");
            }
            Err(e) => {
                if let Some(old) = old_body {
                    let _ = tokio::fs::write(gost_config(), old).await;
                } else {
                    let _ = std::fs::remove_file(gost_config());
                }
                std::fs::write(gost_config().with_extension("json.hash"), old_hash)?;
                bail!("gost reload 请求失败：{e:#}——API 未监听？核心可能没在跑");
            }
        }
    }
    let rs = run_cmd("systemctl", &["start", "monitor-gost@main"]).await?;
    if !rs.status.success() || !unit_active("monitor-gost@main").await {
        let msg = String::from_utf8_lossy(&rs.stderr).trim().to_owned();
        eprintln!("[proxy] gost start failed: {msg}");
        bail!("gost 启动失败：{msg}");
    }
    Ok(())
}

async fn ensure_gost_started() -> Result<()> {
    if gost_active().await {
        return Ok(());
    }
    if !gost_bin().is_file() || !gost_config().exists() {
        bail!("gost 未安装或无配置，无法拉起");
    }
    if systemd() {
        write_gost_unit().await?;
        let rs = run_cmd("systemctl", &["start", "monitor-gost@main"]).await?;
        if !rs.status.success() {
            bail!("gost 拉起失败：{}", String::from_utf8_lossy(&rs.stderr).trim());
        }
    } else {
        let old = gost_child_slot().lock().unwrap().take();
        if let Some(mut c) = old {
            let _ = c.kill().await;
        }
        spawn_gost_child()?;
    }
    Ok(())
}

/// gost 安装：官方 GitHub Release 固定版本 tar.gz，解出单二进制到 bin/。
/// 版本缺省取钉死常量；显式传版本用于升级演练。
async fn gost_install(version: Option<String>) -> Result<String> {
    let version = match version {
        Some(v) => super::fetch::validate_version(super::fetch::VersionRule::Digits, &v)?,
        None => GOST_VERSION.to_owned(),
    };
    let (os, arch) = super::fetch::os_arch_slug("暂不支持 {} 自动安装 gost", "暂不支持 {} 自动安装 gost")?;
    let url = format!(
        "https://github.com/{GOST_REPO}/releases/download/v{version}/gost_{version}_{os}_{arch}.tar.gz"
    );
    let bytes = super::fetch::fetch_release(&url, 180, "gost").await?;
    // 历史实现走外部 tar 命令解包整个目录再 copy；install_binary 用 tar
    // crate 直接解出 gost 单文件，落位语义（原子替换 + chmod 0755）一致。
    super::fetch::install_binary(&bytes, &gost_bin(), "gost").await?;
    Ok(version)
}

// ---- proxy.rs 分发入口的壳（命名对齐方法族，逻辑原样）----

pub(super) async fn apply(body: String, desired_running: bool, hash: &str) -> Result<()> {
    gost_apply(body, desired_running, hash).await
}

pub(super) async fn ensure_started() -> Result<()> {
    ensure_gost_started().await
}

pub(super) async fn install(version: Option<String>) -> Result<String> {
    gost_install(version).await
}

/// gost 二进制版本（-V 输出形如 "gost 3.3.2 (go1.27.3 linux/amd64)"）。
pub(super) async fn gost_version_string() -> String {
    if !gost_bin().is_file() {
        return String::new();
    }
    match run_cmd(&gost_bin().to_string_lossy(), &["-V"]).await {
        Ok(out) => String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1).unwrap_or("").to_owned(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MONITOR_PROXY_DIR 是进程级环境变量：所有隔离落点的测试共用
    /// proxy::testutil::ENV_LOCK 串行执行，防止并行测试互相改掉对方的环境。
    use crate::proxy::testutil::ENV_LOCK;

    /// gost 空配置与 relay 同款语义：空体+true 是协议错误且不碰盘；
    /// 空体+false 停服清文件。
    #[tokio::test]
    async fn empty_gost_config_must_carry_desired_off() {
        let _env = ENV_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("monitor-agent-gost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("MONITOR_PROXY_DIR", &dir);
        std::fs::create_dir_all(gost_config().parent().unwrap()).unwrap();
        std::fs::write(gost_config(), "{\"services\":[]}").unwrap();
        std::fs::write(gost_config().with_extension("json.hash"), "old-hash").unwrap();

        let err = gost_apply(String::new(), true, "").await.unwrap_err();
        assert!(err.to_string().contains("desired_running"), "空体+true 是协议错误: {err}");
        assert!(gost_config().exists(), "协议错误不碰盘上文件");

        gost_apply(String::new(), false, "").await.unwrap();
        assert!(!gost_config().exists(), "合法语义：配置文件清除");
        assert!(!gost_config().with_extension("json.hash").exists(), "指纹文件清除");

        std::env::remove_var("MONITOR_PROXY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 二进制未装时拒绝非空 apply，且不写任何盘上文件——hub 的 ensure 流程
    /// 应先 gost.install 再 apply，这里守住「装都没装就推配置」的乱序。
    #[tokio::test]
    async fn gost_apply_without_binary_refuses_and_leaves_disk_untouched() {
        let _env = ENV_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("monitor-agent-gost-nobin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("MONITOR_PROXY_DIR", &dir);

        let err = gost_apply("{\"services\":[]}".to_owned(), true, "abc").await.unwrap_err();
        assert!(err.to_string().contains("尚未安装"), "应提示先安装: {err}");
        assert!(!gost_config().exists(), "拒绝时不落配置文件");
        assert!(!gost_config().with_extension("json.hash").exists(), "拒绝时不落指纹");

        std::env::remove_var("MONITOR_PROXY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
